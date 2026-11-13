# Triage Report

50 in -> 9 duplicates, 32 false positives, 9 confirmed (3 high / 4 med / 2 low), 1 need manual test

Context: interactive; environment = internet-facing web service (webapp, identity-api, mobile-bff public; broker/DB internal); scoring = derived HIGH/MEDIUM/LOW; 3-vote verification for every candidate, precision tie-break.

## Act on these

### [HIGH] GET /api/orders/{orderId} returns any user's order (no ownership check)  (f001)
`src/Ordering.API/Apis/OrdersApi.cs:80` | idor | claimed HIGH (alignment +3) | confidence 9.0/10
**Owner:** component: src/Ordering.API/; no CODEOWNERS; recent committers Rob Conery, David Fowler (1/4 each)
**Verdict:** exploitable, votes {'true_positive': 3, 'false_positive': 0, 'cannot_verify': 0}
**Preconditions (3):**
- Attacker holds a valid Ordering.API bearer token (any self-registered shopper; only group-level RequireAuthorization, Program.cs:21-22)
- Request sent as GET /api/orders/{id}?api-version=1.0 via public mobile-bff (Extensions.cs:146)
- Attacker enumerates target orderId (sequential HiLo ints)

**Threat-model match:** Tenant-to-tenant data leakage (plus compliance-scoped PII: street, city, state, zip, country, items)
**Why:** GetOrderAsync (src/Ordering.API/Apis/OrdersApi.cs:80-91) passes the route orderId straight to OrderQueries.GetOrderAsync, which runs FirstOrDefaultAsync(o => o.Id == id) with no Buyer.IdentityGuid filter (src/Ordering.API/Application/Queries/OrderQueries.cs:8-10) and returns shipping address, items and total (L15-34). The only gate is group-level RequireAuthorization (src/Ordering.API/Program.cs:21-22) with no named policies; the sibling GetOrdersByUserAsync (OrdersApi.cs:95-96) filters by user, so ownership was intended. mobile-bff publicly proxies /api/orders/{*any} (src/eShop.AppHost/Extensions.cs:146) and order ids are sequential HiLo ints (OrderingContextModelSnapshot.cs:161), so any logged-in user can enumerate other customers' orders.

Table gives MEDIUM (cheap preconditions, authenticated-only, self-registration available); a direct match on the cross-tenant leakage and PII threats raises it one step to HIGH. The sibling list endpoint filters by user, so the missing check is a real gap. Textbook production IDOR with enumerable ids.
**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:13, src/eShop.AppHost/Extensions.cs:146

### [HIGH] Catalog create/update/delete endpoints have no authentication and are reachable from the internet via mobile-bff  (f003)
`src/Catalog.API/Apis/CatalogApi.cs:100` | auth-bypass | claimed HIGH (alignment +4) | confidence 8.3/10
**Owner:** component: src/Catalog.API/; no CODEOWNERS; top committer Mike Kistler (3/11)
**Verdict:** exploitable, votes {'true_positive': 3, 'false_positive': 0, 'cannot_verify': 0}
**Preconditions (2):**
- Attacker can reach the public mobile-bff (AppHost.cs:62-63 WithExternalHttpEndpoints)
- Request carries an allowed api-version query parameter (trivial)

**Threat-model match:** Privilege escalation to admin (anonymous caller gets admin-equivalent catalog create/update/delete)
**Why:** Catalog.API maps PUT/POST/DELETE item endpoints at CatalogApi.cs:100-117 with no RequireAuthorization, and Program.cs registers no auth middleware or fallback policy (unlike Basket, Ordering and Webhooks). mobile-bff is published with WithExternalHttpEndpoints (AppHost.cs:62-64) and its YARP routes (Extensions.cs:105, :142) match only on path and api-version, so anonymous PUT/DELETE reach the handlers. UpdateItem mass-assigns via SetValues (CatalogApi.cs:390) and publishes a price-change event, so anyone can reprice, delete or plant catalog items. Rule 3 (sample design) rejected given the stated internet-facing environment.

CatalogApi.cs:100-117 write routes have no RequireAuthorization, Catalog.API has no auth middleware or fallback policy, and BFF routes do not restrict methods, so an anonymous internet request reaches the write handlers. Impact is integrity (repricing that propagates to baskets, deletion, planted items), and an access-free internet-reachable write path justifies HIGH.
**Reachability evidence:** src/eShop.AppHost/Extensions.cs:105

### [HIGH] IdentityServer RSA signing private key is committed to git and shipped in build output  (f004)
`src/Identity.API/tempkey.jwk:1` | hardcoded-secret | claimed HIGH (alignment +3) | confidence 8.0/10
**Owner:** component: src/Identity.API/; no CODEOWNERS; added by Aditya Mandaleeka (1/1, initial commit fc61f90)
**Verdict:** exploitable, votes {'true_positive': 3, 'false_positive': 0, 'cannot_verify': 0}
**Preconditions (2):**
- Deployed Identity.API runs as shipped (KeyManagement disabled Program.cs:29, AddDeveloperSigningCredential Program.cs:37, tempkey.jwk copied to output)
- Attacker reads the private key from the public git repository

**Threat-model match:** Unauthenticated remote code execution (incl. forging tokens for arbitrary users)
**Why:** src/Identity.API/tempkey.jwk is a git-tracked complete RSA-2048 private key (D/P/Q present, HasPrivateKey true) and Identity.API.csproj:50 copies it into build output. Program.cs:29 disables automatic key management and Program.cs:37 AddDeveloperSigningCredential() loads that file as the token-signing key. The consuming APIs (AuthenticationExtensions.cs:33-49) trust the issuer's JWKS, skip audience validation, and take identity from the sub claim (Ordering IdentityService.cs:6), so anyone with the repo can forge tokens as any user. The only mitigation is a 'not for production' comment; rule 3 does not apply to an internet-facing deployment.

Anyone who can read the repo holds the token-signing private key; consuming APIs trust the issuer JWKS, skip audience validation and take identity from sub, so tokens for any user can be forged and sent via mobile-bff or webapp. One deployment precondition gives MEDIUM by the table; the verbatim threat-model match raises it to HIGH. Only a 'not for production' comment mitigates it.
**Reachability evidence:** src/Identity.API/Program.cs:37

### [MEDIUM] PUT /api/orders/ship (admin action) is open to any authenticated user for any order  (f011)
`src/Ordering.API/Apis/OrdersApi.cs:12` | privilege-escalation | claimed MEDIUM (alignment +1) | confidence 8.0/10
**Owner:** component: src/Ordering.API/; no CODEOWNERS; recent committers Rob Conery, David Fowler (1/4 each)
**Verdict:** exploitable, votes {'true_positive': 3, 'false_positive': 0, 'cannot_verify': 0}
**Preconditions (4):**
- Attacker holds a valid token as any self-registered shopper
- Target order is in Paid status (reached automatically)
- Attacker supplies target OrderNumber (sequential ints)
- Non-empty x-requestid header via public mobile-bff /api/orders/{*any} (trivial)

**Threat-model match:** Privilege escalation to admin (partial: performs one admin-documented action, ShipOrderCommandHandler.cs:14-15; no admin role gained; no raise applied)
**Why:** PUT /api/orders/ship (OrdersApi.cs:12, L51-78) is reachable via the public mobile-bff route (Extensions.cs:146) and gated only by a policy-less group RequireAuthorization (Program.cs:22) that accepts any audience (AuthenticationExtensions.cs:49); no role or policy exists anywhere in src. ShipOrderCommandHandler.cs:21-27 loads any order by client-supplied sequential OrderNumber with no ownership or admin check despite its L14-15 comment saying administrators run it, and SetShippedStatus (Order.cs:130-140) only requires Paid status, which orders reach automatically. Any registered shopper can mark other customers' paid orders shipped, blocking cancellation and firing shipped events.

ShipOrderCommandHandler ships any order by client-supplied number with no ownership or role check, and no RequireRole/AddPolicy/IsInRole exists in src. Any shopper can mark others' Paid orders Shipped, blocking cancellation and emitting spurious shipped events. Integrity-only impact with authenticated access gives MEDIUM.
**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:12, src/eShop.AppHost/Extensions.cs:146, src/eShop.AppHost/Extensions.cs:146 -> src/Ordering.API/Apis/OrdersApi.cs:12

### [MEDIUM] Order item prices and product names are taken from the client request  (f006)
`src/Ordering.API/Extensions/BasketItemExtensions.cs:20` | business-logic | claimed HIGH (alignment -2) | confidence 7.7/10
**Owner:** component: src/Ordering.API/; no CODEOWNERS; top committer Aditya Mandaleeka (1/1)
**Verdict:** exploitable, votes {'true_positive': 3, 'false_positive': 0, 'cannot_verify': 0}
**Preconditions (2):**
- Attacker is an authenticated shopper (open self-registration) with a bearer token
- Attacker sends POST /api/orders directly via the public mobile-bff route with a crafted Items[].UnitPrice/ProductName, bypassing WebApp's catalog price reconciliation

**Threat-model match:** none
**Why:** CreateOrderAsync (OrdersApi.cs:141) builds the command from client request.Items and ToOrderItemDTO (BasketItemExtensions.cs:20) copies the client UnitPrice and ProductName unchanged. OrderItem (OrderItem.cs:25-33) checks only units > 0 and discount <= price*units; Ordering never compares against catalog prices, which only the WebApp client does (BasketState.cs:117-141). Any authenticated shopper reaches it via mobile-bff (Extensions.cs:146), so the order total is attacker-controlled. Payment is a stub, but the authoritative order record stores the forged prices.

CreateOrderAsync passes client Items into the command and ToOrderItemDTO (BasketItemExtensions.cs:20) copies UnitPrice/ProductName unchanged, so any shopper sets their own order total. Authenticated plus a direct API call gives MEDIUM; no threat-model entry matches. Damage is on the attacker's own order and payment is a stub, so real loss depends on whether fulfilment trusts the stored total.
**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:120, src/Ordering.API/Apis/OrdersApi.cs:141, src/Ordering.API/Apis/OrdersApi.cs:17

### [MEDIUM] CreateOrder trusts body-supplied UserId/UserName instead of the JWT subject  (f005)
`src/Ordering.API/Apis/OrdersApi.cs:141` | auth-bypass | claimed HIGH (alignment -2) | confidence 7.0/10
**Owner:** component: src/Ordering.API/; no CODEOWNERS; recent committers Rob Conery, David Fowler (1/4 each)
**Verdict:** exploitable, votes {'true_positive': 3, 'false_positive': 0, 'cannot_verify': 0}
**Preconditions (3):**
- Attacker holds a valid Ordering.API token (self-registration)
- Attacker knows the victim's random GUID sub (no confirmed enumeration path)
- Attacker reaches POST /api/orders via mobile-bff with a non-empty x-requestid (trivial)

**Threat-model match:** Tenant-to-tenant data leakage (partial: cross-tenant write/integrity, not disclosure; no raise applied)
**Why:** CreateOrderAsync (src/Ordering.API/Apis/OrdersApi.cs:141) takes UserId/UserName from the request body; CreateOrderCommandHandler injects IIdentityService but never uses it, so the order, OrderStartedIntegrationEvent and Buyer/payment-method update all go to the body-supplied id. Basket.API deletes that user's basket (OrderStartedIntegrationEventHandler.cs:14). The endpoint is public via mobile-bff (Extensions.cs:146) and gated only by RequireAuthorization (Program.cs:22). Severity is reduced because a targeted attack needs the victim's random GUID sub.

CreateOrderAsync passes body UserId/UserName into the command (OrdersApi.cs:141) and the handler never uses IIdentityService, so the attacker chooses whose buyer record gets the order, payment method and basket deletion. Nothing is read back (GetOrders uses the token identity). Authenticated plus an unguessable victim GUID makes it MEDIUM; claimed HIGH is one level inflated.
**Reachability evidence:** src/eShop.AppHost/Extensions.cs:146, src/eShop.AppHost/Extensions.cs:146 -> src/Ordering.API/Apis/OrdersApi.cs:141

### [MEDIUM] Indirect prompt injection via catalog content plus GetUserInfo tool plus auto-rendered images exfiltrates user PII with zero clicks  (f012)
`src/WebApp/Components/Chatbot/MessageProcessor.cs:24` | prompt-injection | claimed HIGH (alignment -2) | confidence 6.7/10
**Owner:** component: src/WebApp/; no CODEOWNERS; committers Stephen Toub, Aditya Mandaleeka (1/2 each)
**Verdict:** needs_manual_test, votes {'true_positive': 3, 'false_positive': 0, 'cannot_verify': 0}
**Preconditions (5):**
- Chatbot is enabled (off by default: useOllama hardcoded false, Foundry opt-in; IChatClient only registered with a chat model)
- Attacker writes a malicious catalog Description anonymously via the mobile-bff catch-all
- A logged-in shopper uses the chatbot and the poisoned item appears in SearchCatalog's top results
- The LLM follows the injected instructions, auto-invokes GetUserInfo and emits a PII-bearing image URL
- No CSP blocks the outbound image fetch (none set in WebApp)

**Threat-model match:** Compliance-scoped data exposure (PII: name, address, email, phone)
**Why:** An anonymous attacker can overwrite a catalog Description via PUT /api/catalog/items/{id} through the public mobile-bff catch-all (Extensions.cs:142); Catalog.API has no auth. SearchCatalog (ChatState.cs:118-128) passes that text to the model and GetUserInfo (ChatState.cs:97-111) returns PII and is auto-invoked (WebApp Extensions.cs:108). AllowImages (MessageProcessor.cs:24,33) turns any markdown link into <img src> with no allowlist, rendered as MarkupString (Chatbot.razor:46), and WebApp sets no CSP, so the shopper's browser sends PII to the attacker host. Rule 6 rejected: the chain ends in a concrete code sink, not just prompt input. Depends on model compliance and the chatbot being configured.

No account needed, but five preconditions including a default-off feature and non-deterministic model compliance give LOW, raised one step to MEDIUM for the PII threat match. The zero-click <img src> sink with no allowlist is real. A human should enable a chat model and measure compliance before raising severity.
**Reachability evidence:** src/WebApp/Components/Chatbot/Chatbot.razor:46, src/eShop.AppHost/Extensions.cs:142

> Recommend a human build a PoC; static reasoning hit its limit.

### [LOW] PUT /api/orders/cancel cancels any user's order  (f002)
`src/Ordering.API/Application/Commands/CancelOrderCommandHandler.cs:21` | idor | claimed HIGH (alignment -4) | confidence 8.3/10
**Owner:** component: src/Ordering.API/; no CODEOWNERS; top committer Aditya Mandaleeka (1/1)
**Verdict:** exploitable, votes {'true_positive': 3, 'false_positive': 0, 'cannot_verify': 0}
**Preconditions (3):**
- Attacker holds a valid token with the orders scope (any self-registered shopper, via mobile-bff)
- Attacker knows or guesses the victim OrderNumber (sequential ints, no ownership check)
- Victim order is still pre-Paid (SetCancelledStatus refuses Paid/Shipped; default flow reaches Paid quickly after the grace period)

**Threat-model match:** none
**Why:** PUT /api/orders/cancel (OrdersApi.cs:11, 22-49) is internet-reachable via the mobile-bff YARP route (AppHost/Extensions.cs:146) and gated only by default RequireAuthorization (Program.cs:22), which any self-registered shopper with the orders scope satisfies. CancelOrderCommandHandler.cs:21 loads the order by sequential int id through a plain FindAsync (OrderRepository.cs:23) with no ownership check, and the validator only checks NotEmpty. SetCancelledStatus (Order.cs:142-153) cancels any order not Paid or Shipped and raises OrderCancelledDomainEvent, enabling bulk cancellation of other customers' pending orders.

The IDOR is real: CancelOrderCommandHandler loads by sequential id and cancels without comparing Buyer.IdentityGuid. Authentication plus three conditions, including landing inside the short pre-Paid window, gives LOW by the lower-column rule. Impact is griefing (cancelling others' pending orders) with no disclosure or privilege gain, so no threat-model bump; a scripted loop during the grace window makes it practical, but HIGH is inflated.
**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:11

### [LOW] CreateItem accepts a client-supplied primary key, allowing sequence collisions that block item creation  (f031)
`src/Catalog.API/Apis/CatalogApi.cs:421` | business-logic | claimed LOW (alignment +3) | confidence 6.0/10
**Owner:** component: src/Catalog.API/; no CODEOWNERS; top committer Mike Kistler (3/11)
**Verdict:** exploitable, votes {'true_positive': 2, 'false_positive': 1, 'cannot_verify': 0}
**Preconditions (3):**
- Attacker reaches anonymous POST /catalog-api/api/catalog/items via public mobile-bff (no method filter, no RequireAuthorization)
- Attacker predicts upcoming identity values (sequential, readable via anonymous GETs)
- Some legitimate consumer later creates items relying on the identity sequence (no shipped admin UI calls CreateItem)

**Threat-model match:** none
**Why:** CreateItem (CatalogApi.cs:415-437) inserts the body-supplied Id (L421) into a Postgres identity-by-default column (CatalogContextModelSnapshot.cs:33), which does not advance the sequence. The POST route (L110) is anonymous and forwarded by the external mobile-bff (Extensions.cs:97), so an anonymous user can pre-claim upcoming ids and make later inserts fail with PK conflicts. Low impact and largely subsumed by the unauthenticated catalog write (f003).

CreateItem copies the client Id (CatalogApi.cs:421) so an unauthenticated attacker can pre-claim identity values and make later sequence-assigned inserts fail. The rank agent derived MEDIUM; impact is only denial of catalog-item creation and is largely subsumed by f003, which already lets an attacker overwrite or delete items. Orchestrator override: rank agent listed 3 preconditions but scored MEDIUM; the rubric lower-column rule (3+ preconditions -> LOW) applied, consistent with f002.
**Reachability evidence:** src/Catalog.API/Apis/CatalogApi.cs:110, src/Catalog.API/Program.cs:26

## Dropped

| id | title | file:line | why dropped |
|---|---|---|---|
| f009 | mobile-bff catch-all /api/catalog/{*any} exposes unauthenticated catalog write endpoints to the internet | `src/eShop.AppHost/Extensions.cs:142` | duplicate of f003 |
| f010 | /api/orders/{*any} BFF route exposes ship/cancel/get-by-id endpoints that lack ownership and role checks | `src/eShop.AppHost/Extensions.cs:146` | duplicate of f001 |
| f017 | Mobile app ships client secret "secret", which is also the confidential webapp client's secret (webapp has no PKCE) | `src/ClientApp/Services/Settings/SettingsService.cs:15` | duplicate of f024 |
| f021 | ID tokens may be accepted as bearer access tokens (no typ check, audience off) | `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:33` | duplicate of f016 |
| f039 | webapp OIDC client secret hardcoded as "secret", with RequireHttpsMetadata=false | `src/WebApp/Extensions/Extensions.cs:78` | duplicate of f024 |
| f040 | Hardcoded OIDC client secret and webhook token in WebhookClient | `src/WebhookClient/Extensions/Extensions.cs:54` | duplicate of f024 |
| f044 | Basket deletion driven by an unauthenticated UserId in a RabbitMQ OrderStarted event | `src/Basket.API/IntegrationEvents/EventHandling/OrderStartedIntegrationEventHandler.cs:14` | duplicate of f023 |
| f047 | Localhost-only Diagnostics page reachable via spoofed X-Forwarded-For | `src/Identity.API/Quickstart/Diagnostics/DiagnosticsController.cs:13` | duplicate of f042 |
| f050 | DEBUG builds trust an extra issuer https://10.0.2.2:5243 | `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:44` | duplicate of f016 |
| f007 | Webhook grant check and delivery send requests to any user-chosen URL, including internal service-discovery names | `src/Webhooks.API/Services/GrantUrlTesterService.cs:21` | implausible_trigger; votes 3-0 |
| f008 | Every customer's order events are delivered to every webhook subscriber regardless of order ownership | `src/Webhooks.API/Services/WebhooksRetriever.cs:7` | implausible_trigger; votes 3-0 |
| f013 | Full card number and CVV logged when x-requestid is the empty GUID | `src/Ordering.API/Apis/OrdersApi.cs:134` | implausible_trigger; rule 12; votes 3-0 |
| f014 | Received hook payloads and the webhook shared-secret token are shown to anonymous visitors | `src/WebhookClient/Components/Pages/Home/ReceivedMessages.razor:13` | implausible_trigger; rule 3; votes 3-0 |
| f015 | WebhookClient token validation is off by default, so anyone can inject received hooks | `src/WebhookClient/Endpoints/WebhookEndpoints.cs:13` | implausible_trigger; rule 12; votes 3-0 |
| f016 | JWT audience validation disabled with no scope enforcement: a token minted for any client/API is accepted by Basket, Ordering and Webhooks | `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:49` | implausible_trigger, not_actionable; rule 13; votes 3-0 |
| f018 | Card number, CVV, expiry and address issued as claims in every token and userinfo response | `src/Identity.API/Services/ProfileService.cs:77` | implausible_trigger, intentional_behavior, not_actionable; rule 13; votes 3-0 |
| f019 | Injected catalog text can make the agent call AddToCart on the victim's basket without confirmation | `src/WebApp/Components/Chatbot/ChatState.cs:136` | not_actionable; rule 12; votes 3-0 |
| f020 | Debug hook drops and acks any message containing "throw-fake-exception"; user-controlled strings reach event payloads | `src/EventBusRabbitMQ/RabbitMQEventBus.cs:163` | implausible_trigger, intentional_behavior; rule 12; votes 3-0 |
| f022 | Default mobile gateway endpoints are plain HTTP, sending bearer tokens and full PAN+CVV in cleartext | `src/ClientApp/ViewModels/SettingsViewModel.cs:58` | implausible_trigger, intentional_behavior; rule 8; votes 3-0 |
| f023 | Event bus dispatches on attacker-chosen routing key with no publisher authentication, so any broker-credential holder can forge order/payment transitions | `src/EventBusRabbitMQ/RabbitMQEventBus.cs:192` | implausible_trigger; rule 13; votes 3-0 |
| f024 | Confidential clients share the hardcoded secret "secret" and webapp disables PKCE | `src/Identity.API/Configuration/Config.cs:82` | already_handled; rule 13; votes 2-1 |
| f025 | Known-password demo users are seeded in every environment and the login page prints the credentials | `src/Identity.API/UsersSeed.cs:33` | intentional_behavior; rule 3; votes 3-0 |
| f026 | GET /Account/Logout signs the user out with no prompt or antiforgery check | `src/Identity.API/Quickstart/Account/AccountOptions.cs:12` | not_actionable; rule 12; votes 3-0 |
| f027 | IsActiveAsync checks the wrong claim type for the security stamp, so revocation by stamp never happens | `src/Identity.API/Services/ProfileService.cs:39` | implausible_trigger; rule 13; votes 3-0 |
| f028 | CreateOrderCommand carrying the unmasked CVV is destructured into logs at several points | `src/Ordering.API/Application/Commands/IdentifiedCommandHandler.cs:79` | misread_code; rule 13; votes 3-0 |
| f029 | Duplicate productId lines overflow Units (unchecked int add), producing negative quantity and total | `src/Ordering.Domain/AggregatesModel/OrderAggregate/OrderItem.cs:61` | not_actionable; rule 12; votes 2-1 |
| f030 | Payment simulation approves any OrderId from an unauthenticated event without checking amount, buyer or order state | `src/PaymentProcessor/IntegrationEvents/EventHandling/OrderStatusChangedToStockConfirmedIntegrationEventHandler.cs:21` | intentional_behavior; rule 3; votes 3-0 |
| f032 | Unauthenticated callers can drive paid embedding-provider calls with unbounded input | `src/Catalog.API/Apis/CatalogApi.cs:431` | not_actionable; rule 1; votes 3-0 |
| f033 | Stock validation confirms orders with unknown product ids and reserves nothing, allowing overselling | `src/Catalog.API/IntegrationEvents/EventHandling/OrderStatusChangedToAwaitingValidationIntegrationEventHandler.cs:17` | intentional_behavior; rule 3; votes 3-0 |
| f034 | DEBUG handlers accept any cert issued by CN=localhost (Android) or any URL starting with https://localhost (iOS) for every host | `src/ClientApp/MauiProgram.cs:127` | intentional_behavior; rule 2; votes 3-0 |
| f035 | Trace-header parsing outside try/catch leaves header-less or malformed messages unacked forever | `src/EventBusRabbitMQ/RabbitMQEventBus.cs:136` | implausible_trigger; rule 12; votes 3-0 |
| f036 | Shared credentials and well-known queue names let any bus participant steal or read other services' events | `src/EventBusRabbitMQ/RabbitMQEventBus.cs:258` | implausible_trigger; rule 13; votes 3-0 |
| f037 | Idempotency request ids are global, not scoped to caller or command | `src/Ordering.Infrastructure/Idempotency/RequestManager.cs:13` | implausible_trigger; rule 15; votes 3-0 |
| f038 | Quadratic regex on unbounded chat messages, rerun on every render | `src/WebApp/Components/Chatbot/MessageProcessor.cs:33` | implausible_trigger; rule 1; votes 2-1 |
| f041 | Webhook secret tokens logged at Information level | `src/Webhooks.API/Services/GrantUrlTesterService.cs:17` | implausible_trigger, not_actionable; rule 13; votes 3-0 |
| f042 | ASPNETCORE_FORWARDEDHEADERS_ENABLED=true on every project, including internet-facing identity-api and webapp | `src/eShop.AppHost/Extensions.cs:36` | intentional_behavior, not_actionable; rule 13; votes 3-0 |
| f043 | RequireHttpsMetadata=false lets OIDC discovery/JWKS be fetched over plain HTTP | `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:39` | implausible_trigger; rule 13; votes 3-0 |
| f045 | Attacker-controlled PictureFileName used as a file path in the picture endpoint (contained by PhysicalFileProvider) | `src/Catalog.API/Apis/CatalogApi.cs:263` | already_handled; rule 13; votes 3-0 |
| f046 | Singleton HttpClient's DefaultRequestHeaders mutated per call, so concurrent requests can carry another call's bearer token | `src/ClientApp/Services/RequestProvider/RequestProvider.cs:116` | implausible_trigger; rule 16; votes 3-0 |
| f048 | Order-status event handlers log the full event including BuyerName and BuyerIdentityGuid | `src/WebApp/Services/OrderStatus/IntegrationEvents/EventHandling/OrderStatusChangedToPaidIntegrationEventHandler.cs:12` | not_actionable; rule 13; votes 3-0 |
| f049 | User access token forwarded unchanged to every AddAuthToken client, including plaintext basket-api and catalog-api | `src/eShop.ServiceDefaults/HttpClientExtensions.cs:43` | intentional_behavior; rule 13; votes 3-0 |
