# Triage Report

66 in -> 6 duplicates, 49 false positives, 11 confirmed (2 high / 8 med / 1 low), 2 need manual test

Context: interactive; environment = Internet-facing web service (HTTP is untrusted; identity-api, webapp and mobile-bff are external, other services internal); scoring = Derived HIGH/MEDIUM/LOW from preconditions (default); verification = 3 votes for the 20 candidates with scanner confidence >= 0.5 (f001-f020), 1 vote for the other 40; ties keep as needs_manual_test (recall).

Source: 66 static candidates from VULN-FINDINGS.json (scanner confidence scores are not used for severity). Verifiers judged each finding against your stated threat boundary, so findings that need broker access or an internal foothold were dropped as defense-in-depth; see the Dropped table.

## Act on these

### [HIGH] Catalog write endpoints (PUT/POST/DELETE) have no authentication or authorization  (f001)
`src/Catalog.API/Apis/CatalogApi.cs:112` | auth-bypass | claimed HIGH (alignment +2) | confidence 8.7/10
**Owner:** top committer: Mike Kistler (3/11 recent commits); no CODEOWNERS entry
**Verdict:** exploitable, votes 3 true / 0 false / 0 cannot-verify
**Preconditions (3):**
- Network reachability to the externally exposed mobile-bff YARP resource (AppHost.cs:62-63 uses WithExternalHttpEndpoints). This is the default deployment, not an extra condition.
- Request includes a matching api-version query parameter (1.0, 1 or 2.0) to satisfy the YARP route match (Extensions.cs:97-105). The value is public and trivially guessable.
- Target item id is known or guessable (integer, enumerable via the unauthenticated GET list endpoint). Only needed for PUT v2 and DELETE.
**Threat-model match:** Privilege escalation to admin (anonymous caller reaches catalog-admin write functions). It does not touch the PII, PCI or tenant-leakage entries. No step raise is applied because severity is already HIGH.
**Why:** The catalog write endpoints (CatalogApi.cs:100-117) have no authorization, and Catalog.API has no auth middleware. The externally exposed mobile-bff YARP resource (AppHost.cs:62-64) routes `/catalog-api/api/catalog/items` and `/items/{id}` (Extensions.cs:97,105) without method or auth restrictions, so anonymous PUT, POST and DELETE reach the service. UpdateItem (CatalogApi.cs:373-399) lets the caller change prices and publishes the price-change event.

An anonymous internet caller can create, modify or delete catalog items, including prices, through the public BFF with a single HTTP request. The only gates are a public api-version query string and an enumerable id, and no control mitigates this on the path. Strictly the "1-2 preconditions" rule would suggest MEDIUM, but the preconditions are trivial and non-restrictive, so they do not reduce exploitability. Impact is integrity and business-logic only (price manipulation, the price-change event, catalog destruction), with no PII/PCI exposure or code execution. The HIGH claim is defensible, though at the low end of HIGH.
**Reachability evidence:** src/eShop.AppHost/Extensions.cs (the /api/catalog/{*any} catch-all route in ConfigureMobileBffRoutes, line number not captured); src/eShop.AppHost/Extensions.cs:142; src/eShop.AppHost/Extensions.cs:97

### [HIGH] Mobile BFF YARP routes have no HTTP method restriction, so unauthenticated catalog create/update/delete is reachable from the internet  (f004)
`src/eShop.AppHost/Extensions.cs:71` | broken_access_control | claimed HIGH (alignment -1) | confidence 8/10
**Owner:** top committer: Eric Erhardt (6/13 recent commits); no CODEOWNERS entry
**Verdict:** exploitable, votes 3 true / 0 false / 0 cannot-verify
**Preconditions (4):**
- Attacker can reach the mobile-bff YARP proxy (external endpoint, AppHost.cs:62-64). This is the default exposure, not a real precondition.
- Request includes a matching api-version query value (1.0, 1 or 2.0). Trivially attacker-supplied.
- The route (Extensions.cs:142-143 catch-all, or the /items and /items/{id} routes) has no method restriction and no auth policy, so POST/PUT/DELETE are forwarded.
- Catalog.API's mutation handlers have no authorization. This is f001, a separate finding, and it is the actual cause of the impact.
**Threat-model match:** Privilege escalation to admin (anonymous caller performs admin-only catalog mutation). It is a loose match, so there is no uplift.
**Why:** mobile-bff is externally exposed (AppHost.cs:62-64). Its catch-all /api/catalog/{*any} (Extensions.cs:142-143) and the specific /items and /items/{id} routes match any HTTP method, gated only by an api-version query value an attacker can supply. catalog-api's POST, PUT and DELETE handlers (CatalogApi.cs:100-114) have no authorization, and nothing in Catalog.API configures authentication. So an anonymous POST, PUT or DELETE reaches catalog mutation through the BFF.

The route config places no auth or method restriction on the externally exposed BFF, so an anonymous caller can forward POST/PUT/DELETE to catalog-api with only an attacker-controlled api-version query. Catalog-api is unauthenticated on its own (f001), so the proxy exposure is the path to it and neither finding is exploitable end to end without the other. The impact is anonymous tampering with or deletion of catalog data, which means integrity and availability loss of product data. There is no RCE, no PII or PCI exposure, and no tenant crossing. This is a duplicate or amplifier of f001, and counting it as a separate HIGH inflates the alert count slightly. The root-cause fix is auth in Catalog.API (f001); a BFF method allowlist is only defense in depth. I did not re-check CatalogApi.cs; that rests on the verifier's account and the routes in Extensions.cs, which I did read.
**Reachability evidence:** /home/tanis/github/depj-proj/eShop/src/eShop.AppHost/Extensions.cs:142; src/eShop.AppHost/Extensions.cs:142

### [MEDIUM] GetOrder returns any order by integer id with no ownership check  (f003)
`src/Ordering.API/Application/Queries/OrderQueries.cs:5` | IDOR / BOLA | claimed HIGH (alignment -1) | confidence 8.7/10
**Owner:** top committers: Aditya Mandaleeka, Almar Aubel, Erin McLaughlin (1/4 each); no CODEOWNERS entry
**Verdict:** exploitable, votes 3 true / 0 false / 0 cannot-verify
**Preconditions (4):**
- Attacker holds a valid authenticated account (any registered user via identity-api); Ordering.API requires auth and the endpoint has no unauthenticated path.
- Attacker reaches GET /api/orders/{orderId:int} through the external mobile-bff YARP route (AppHost Extensions.cs:146), or an internal position.
- Attacker needs a valid integer order id. IDs come from the HiLo sequence "orderseq", so they are sequential and guessable by enumeration.
- At least one other user's order must exist.
**Threat-model match:** Tenant-to-tenant data leakage, and compliance-scoped PII exposure. Orders return street, city, state, country and zip, plus order contents. This match raises the result from the base tier by one step, but the base tier is itself capped at MEDIUM by the authenticated-access column, so the final label stays MEDIUM.
**Why:** `OrdersApi.cs:80-84` passes only `orderId` to `OrderQueries.GetOrderAsync`, which filters only on `o.Id == id` (`OrderQueries.cs:10`). It returns the address, items and status (`OrderQueries.cs:20-26`). Authentication is required (`Program.cs:22`), but no buyer identity is compared, unlike `GetOrdersFromUserAsync` (`OrderQueries.cs:40`). The mobile-bff YARP route (`eShop.AppHost/Extensions.cs:146`) exposes it to external authenticated users. Any user can read other users' orders by iterating integer ids.

I read OrdersApi.cs and OrderQueries.cs. GetOrderAsync(int id) filters only on o.Id == id. The handler never reads the caller's identity, and the route is exposed to authenticated users. Any logged-in user can read any other customer's shipping address, order items and status by walking sequential ids. This is a classic BOLA, and the impact is a PII read with no write path. Under the derived rubric it is MEDIUM (authenticated, 1-2 preconditions, read-only). HIGH is slightly inflated: it needs an account, and it exposes no payment card data or unauthenticated access, though it is a real, trivially exploitable privacy leak that should be fixed.
**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs (api.MapGet("{orderId:int}", GetOrderAsync) in the api/orders group; handler calls services.Queries.GetOrderAsync(orderId) with no user identity); src/Ordering.API/Apis/OrdersApi.cs:13; src/Ordering.API/Apis/OrdersApi.cs:84

### [MEDIUM] Any authenticated user can cancel any order by OrderNumber  (f007)
`src/Ordering.API/Application/Commands/CancelOrderCommandHandler.cs:19` | IDOR / BFLA | claimed HIGH (alignment -1) | confidence 8.3/10
**Owner:** top committer: Aditya Mandaleeka (1/1 recent commits); no CODEOWNERS entry
**Verdict:** exploitable, votes 3 true / 0 false / 0 cannot-verify
**Preconditions (3):**
- Attacker holds a valid authenticated session/JWT (any ordinary buyer account; self-registration on identity-api is presumably open)
- Attacker supplies a valid x-requestid GUID (trivially self-generated)
- Target order exists and is in a non-Paid/non-Shipped state (e.g. Submitted/AwaitingValidation/StockConfirmed); the integer order id is guessable/sequential
**Threat-model match:** Tenant-to-tenant data leakage (cross-user object access; only loosely matches, since it is an integrity/availability impact rather than data disclosure). Not enough of a match to raise severity.
**Why:** `PUT api/orders/cancel` (`OrdersApi.cs:11,22-41`) is reachable by any authenticated user via the Mobile BFF route `/api/orders/{*any}` (`AppHost/Extensions.cs:146`). The command carries only an attacker-controlled `OrderNumber`. `CancelOrderCommandHandler.cs:21-27` and `OrderRepository.GetAsync` (`OrderRepository.cs:21-23`) load by id with no buyer comparison. `Order.SetCancelledStatus` (`Order.cs:142-153`) refuses only Paid or Shipped orders, so any other user's pending order can be cancelled by iterating integer ids.

I read CancelOrderAsync and CancelOrderCommandHandler. The handler loads the order by the attacker-supplied OrderNumber and calls SetCancelledStatus with no buyer-ownership check, so this is a real BOLA/IDOR. Exploitation needs only a low-privilege authenticated user and sequential ids, so it falls at the authenticated/1-2 preconditions tier, which is MEDIUM. The impact is limited to cancelling other users' unshipped, unpaid orders (integrity/availability). It discloses no PII and gives no code execution or privilege escalation, so HIGH is a modest inflation.
**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:11; src/Ordering.API/Apis/OrdersApi.cs:11 (`api.MapPut("/cancel", CancelOrderAsync)`), then OrdersApi.cs:22-41, then CancelOrderCommandHandler.cs:21-27.; src/Ordering.API/Apis/OrdersApi.cs:22

### [MEDIUM] CreateOrder trusts UserId and UserName from the request body  (f006)
`src/Ordering.API/Apis/OrdersApi.cs:111` | Identity spoofing / mass assignment | claimed HIGH (alignment -2) | confidence 8/10
**Owner:** top committers: Aditya Mandaleeka, Chris Martinez, David Fowler (1/4 each); no CODEOWNERS entry
**Verdict:** exploitable, votes 3 true / 0 false / 0 cannot-verify
**Preconditions (4):**
- Attacker holds a valid authenticated session (any registered user) with a token accepted by Ordering.API, directly or via the mobile-bff proxy
- Attacker knows the victim's sub/UserId (a GUID, not trivially guessable or enumerable)
- Attacker sends POST /api/orders with a fresh x-requestid header and a body containing the victim's UserId and UserName; this works because the endpoint trusts body-supplied identity (OrdersApi.cs:141) with no comparison to the caller's claims
- Attacker supplies their own payment card details, so the attacker pays for the forged order
**Threat-model match:** Tenant-to-tenant data leakage (loosely; this is a cross-user integrity/write issue, not a read leak). It does not raise severity.
**Why:** `CreateOrderAsync` copies `request.UserId` and `request.UserName` from the body into `CreateOrderCommand` (`OrdersApi.cs:141`) with no comparison to the caller's identity. The handler uses those values for the Order and the integration event (`CreateOrderCommandHandler.cs:32,40`), and `.RequireAuthorization()` (`Program.cs:22`) only enforces authentication. The externally exposed mobile-bff proxies `/api/orders/*` raw to this endpoint (`Extensions.cs:146`), so an authenticated user can submit another user's `UserId`. Impact is moderate: forged orders and a cleared basket for the victim, with the attacker's own card.

The identity-spoofing flaw is real. CreateOrderAsync takes UserId and UserName from the request body, and the handler uses them for the Order and the OrderStartedIntegrationEvent (CreateOrderCommandHandler.cs:32,40) without checking them against the caller's identity. An attacker can create orders under a victim's identity and trigger the basket-clear event for the victim. Exploitation needs authentication plus knowledge of a victim GUID. The impact is integrity-only: no data is read, the attacker pays with their own card, and the victim's basket is cleared. That puts it at MEDIUM, not HIGH. The threat-model match is weak because no data is exfiltrated, so there is no step up. I did not read the full Ordering.API request path beyond these snippets, so the verdict rests on the verifier's account and the code I read. [Likely 🟡]
**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:141

### [MEDIUM] Token signing key is a committed, publicly known RSA key (AddDeveloperSigningCredential loads tempkey.jwk)  (f002)
`src/Identity.API/Program.cs:38` | hardcoded secret / weak crypto | claimed HIGH (alignment -1) | confidence 7/10
**Owner:** top committers: Aditya Mandaleeka, Brennan, Michael Stonis (1/3 each); no CODEOWNERS entry
**Verdict:** needs_manual_test, votes 3 true / 0 false / 0 cannot-verify
**Preconditions (5):**
- Deployed Identity.API actually loads the committed tempkey.jwk. Duende AddDeveloperSigningCredential() defaults to a "tempkey.jwk" file in the content root and generates one if it is absent. The csproj copies the committed file to the output (Content Include, CopyToOutputDirectory), so it is likely loaded, but this is unconfirmed.
- The deployment runs this sample configuration unchanged (no production signing key swapped in, KeyManagement.Enabled=false, no override). Program.cs has no environment guard and TODO comments mark both lines as non-production.
- The attacker has the repo (public sample) or the key file. No target access is needed to forge a token.
- The downstream APIs validate tokens only by signature against Identity.API's JWKS (issuer and audience), with no extra binding. The verifier cited AuthenticationExtensions.cs:33-38 for this.
- The attacker can send HTTP requests with a bearer token to an endpoint that is reachable, i.e. the BFF or webapp. Internal APIs are reached through the BFF.
**Threat-model match:** Privilege escalation to admin and unauthenticated remote access. The forged-token impact (any subject or scope) maps to both. This raises severity by one step from the precondition-derived level.
**Why:** Program.cs:37 calls AddDeveloperSigningCredential() with no arguments (default tempkey.jwk), and Program.cs:29 disables key management. src/Identity.API/tempkey.jwk is tracked in git and contains the private RSA parameter "D". Identity.API.csproj:50 copies it to the output directory, so a deployed service signs with a publicly known key. .gitignore only excludes wwwroot/lib/ and keys/, not tempkey.jwk. Downstream APIs trust the issuer's JWKS (src/eShop.ServiceDefaults/AuthenticationExtensions.cs:33-38), so anyone with the repo can forge tokens for any subject or scope. The TODO comments at Program.cs:28 and :36 mark this as sample code, which weakens the case (rules 3 and 13), but the key is committed and shipped, so the exploit is concrete for any deployment of this code. I did not confirm how the library resolves the default key file path (needs library source, outside the repo).

The access level is unauthenticated remote, but 3 or more preconditions must hold: the key file is loaded by the deployed server, the sample config is unchanged in the deployment, and the downstream APIs trust the JWKS alone. That count caps the derived severity at MEDIUM or LOW, and the threat-model match for privilege escalation raises it one step to MEDIUM. The impact is full token forgery if the key is loaded, which is serious, but this is an eShop reference sample with explicit "don't use in production" markers, so HIGH is inflated by one level. The verifier could not confirm the Duende default path resolution, so a runtime check is needed: compare the published JWKS kid from /.well-known/openid-configuration/jwks against the committed tempkey.jwk. If they match, this rises to HIGH for any real deployment.
**Reachability evidence:** src/Identity.API/Program.cs:37
> Recommend a human build a PoC or runtime check; static reasoning hit its limit.

### [MEDIUM] Ship endpoint is an admin-only action with no role or ownership check  (f008)
`src/Ordering.API/Application/Commands/ShipOrderCommandHandler.cs:19` | BFLA / privilege escalation | claimed HIGH (alignment -2) | confidence 7/10
**Owner:** top committer: Aditya Mandaleeka (1/1 recent commits); no CODEOWNERS entry
**Verdict:** exploitable, votes 3 true / 0 false / 0 cannot-verify
**Preconditions (4):**
- Attacker holds a registered, authenticated account (valid bearer token from identity-api). Self-registration is assumed, not checked.
- The attacker knows or guesses the target order number. These are sequential integers, so guessing is cheap.
- The target order must be in Paid status, which is a state-dependent window.
- The ship endpoint must be proxied by the BFF. The verifier cites Extensions.cs:146 for this, and I did not re-check it.
**Threat-model match:** Privilege escalation to admin (a normal user invokes the administrator-only ship action, a BFLA). Raised one step from LOW to MEDIUM.
**Why:** `ShipOrderCommandHandler.cs:21-27` ships any order by number with no caller identity check. `Program.cs:21-22` applies only bare `RequireAuthorization()`, with no role or ownership policy in Ordering.API. The BFF route at `Extensions.cs:146` exposes `/api/orders/*` externally. Any registered user can therefore ship any `Paid` order. The impact is limited to business-state integrity, so medium rather than HIGH.

The authorization gap is real. Any logged-in user can ship another user's Paid order, because the code only calls bare RequireAuthorization() and checks no role or ownership. The precondition count (3-4, including the Paid-state window) and the authenticated access level put the base score at LOW. The privilege-escalation threat-model match raises it one step to MEDIUM. The impact is limited to business-state integrity: no data is exposed, there is no code execution, and the order can still be cancelled or corrected. HIGH is inflated for that reason, since it needs an authenticated attacker, a state-dependent window and has low impact. [Likely 🟡]
**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:12; src/Ordering.API/Program.cs:21-22; src/eShop.AppHost/Extensions.cs:146

### [MEDIUM] Order line prices, discount and product names are taken from the client  (f013)
`src/Ordering.API/Application/Commands/CreateOrderCommandHandler.cs:43` | Business logic / price tampering | claimed HIGH (alignment -2) | confidence 7/10
**Owner:** top committer: Aditya Mandaleeka (1/1 recent commits); no CODEOWNERS entry
**Verdict:** exploitable, votes 2 true / 1 false / 0 cannot-verify
**Preconditions (4):**
- Attacker holds a valid authenticated account, e.g. self-registered via Identity.API with a bearer token. Ordering.API only calls RequireAuthorization.
- The mobile-bff YARP route /api/orders/{*any} (eShop.AppHost/Extensions.cs:146) forwards to Ordering.API. I confirmed this route exists.
- The attacker crafts a POST to api/orders with an x-requestid header and a CreateOrderRequest whose Items carry attacker-chosen UnitPrice and Discount. The request needs a card number of at least 4 characters.
- The order's downstream effect is only a tampered total. CreateOrderCommandHandler copies the items into the order unchecked. Payment is a stub (a config flag), so nothing charges the wrong amount. A real loss needs a fulfillment or financial process that trusts the stored price. I did not verify that process.
**Threat-model match:** none
**Why:** The mobile BFF route `/api/orders/{*any}` (src/eShop.AppHost/Extensions.cs:146) reaches Ordering.API, which only requires authorization (Program.cs:22). `CreateOrderAsync` (OrdersApi.cs:141) forwards client-supplied items. CreateOrderCommandHandler.cs:44 copies UnitPrice and Discount into the order with no Catalog or basket check. An authenticated user can therefore order at a tampered price. `UserId` is also client-supplied, which is a related issue. Rule 3 is arguable because this is upstream demo-app design, so I rate it a moderate true positive.

A low-privilege authenticated user can submit an order with arbitrary prices through the externally exposed BFF route, and the handler has no catalog or basket re-pricing, so the flaw is real. It requires authentication, and the impact is limited to financial integrity of one's own order. The shipped payment processor is a stub, so there is no direct monetary loss here. It does not match any operator threat-model entry, so there is no uplift. HIGH is inflated by one level; MEDIUM fits.
**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:127; src/Ordering.API/Apis/OrdersApi.cs:141

### [MEDIUM] Seeded accounts alice and bob with fixed known password "Pass123$" are created on every startup  (f018)
`src/Identity.API/UsersSeed.cs:35` | default credentials | claimed MEDIUM (alignment -1) | confidence 6.5/10
**Owner:** top committers: Aditya Mandaleeka, Rob Conery, toyzoz (1/3 each); no CODEOWNERS entry
**Verdict:** exploitable, votes 2 true / 1 false / 0 cannot-verify
**Preconditions (4):**
- The Identity.API seeder runs (it does on every startup; Program.cs:12 has no environment gate), and the deployment keeps the seeded alice/bob rows and does not change their passwords.
- Attacker can reach the Identity.API login endpoint over HTTP (external endpoint in the AppHost).
- Attacker knows the usernames and the fixed password "Pass123$". These are public in the open-source sample repo.
- The login succeeds as a standard customer account, with no admin role. The impact is limited to those two accounts' own data.
**Threat-model match:** Compliance-scoped data exposure (PII/PCI), weak match. The seeded users hold name, address, phone and a masked card number (XXXXXXXXXXXX1881) with the CVV "123", and this is only the two demo accounts' own data. It does not match the privilege-escalation, RCE or tenant-leak entries. No severity bump applied.
**Why:** Program.cs:12 registers UsersSeed with no environment check, and MigrateDbContextExtensions.cs:23-46 runs it on every startup. UsersSeed.cs:33 and :78 create alice and bob with the fixed password "Pass123$". Identity.API is external, so the known credentials give a working login. The sample-app "intended design" argument is the main doubt.

Anyone can log in as alice or bob using the public default credentials. This is a real default-credential issue, but it only gives a standard-user session on two demo accounts whose card data is masked and whose PII is fictional. It is the eShop reference sample's deliberate demo seed, and the code comment in Program.cs already says the migration approach is not for production. The exposure only matters if the sample is deployed as-is, so MEDIUM is the upper bound and LOW is defensible. The claimed MEDIUM is slightly inflated.
**Reachability evidence:** src/Identity.API/Program.cs:12

### [MEDIUM] BFF /api/orders/{*any} catch-all exposes all ordering write routes (ship, cancel) with no method limits or role check  (f014)
`src/eShop.AppHost/Extensions.cs:119` | broken_access_control | claimed MEDIUM (alignment -2) | confidence 6.5/10
**Owner:** top committer: Eric Erhardt (6/13 recent commits); no CODEOWNERS entry
**Verdict:** exploitable, votes 2 true / 1 false / 0 cannot-verify
**Preconditions (3):**
- Attacker holds a valid logged-in account (self-registered via identity-api) and a bearer token accepted by Ordering.API
- Request carries api-version=1.0 or 1 (the route's query-parameter match), sent to the external mobile-bff /api/orders/{*any} route
- Ordering.API's own missing role/ownership checks (f007/f008) must be what permits the abuse. The BFF route adds no new capability beyond forwarding
**Threat-model match:** Privilege escalation to admin (weak match, via f007/f008 on ship/cancel); no match for the BFF route itself
**Why:** The external mobile-bff catch-all at Extensions.cs:146 forwards every HTTP method to ordering-api. Ordering.API only requires authentication (Program.cs:21-22), so any logged-in user can invoke the ship and cancel routes (OrdersApi.cs:11-12). Ship is a back-office operation that the BFF exposes with no role or method limit.

The catch-all at Extensions.cs:146 does forward PUT /ship and /cancel (OrdersApi.cs:11-12) to the internet, and I confirmed it is scoped only by an api-version query match, so it is reachable by any authenticated user. But a YARP route is a transparent proxy to an API that is meant to be consumed. The defect is the absent role and ownership authorization in Ordering.API, already tracked as f007/f008. This finding is an exposure amplifier of those, not an independent flaw, so it should be merged into them or at most carry MEDIUM. Claimed MEDIUM is slightly inflated as a standalone item because fixing the route alone (for example allow-listing paths) would be defense-in-depth, not the root fix.
**Reachability evidence:** src/eShop.AppHost/Extensions.cs:146

### [LOW] Cross-tenant disclosure: order events are sent to every user's subscriptions, not just the order owner's  (f005)
`src/Webhooks.API/IntegrationEvents/OrderStatusChangedToShippedIntegrationEvent.cs:3` | data-exposure | claimed MEDIUM (alignment -2) | confidence 6/10
**Owner:** top committers: Aditya Mandaleeka, Safia Abdalla (1/2 each); no CODEOWNERS entry
**Verdict:** needs_manual_test, votes 2 true / 1 false / 0 cannot-verify
**Preconditions (4):**
- Attacker must reach webhooks-api over the network. AppHost.cs:56-59 has no WithExternalHttpEndpoints. The mobile-bff has no route to it, and neither does webapp. The WebhookClient app (AppHost.cs:67-69) is also not marked external. So this needs a position on the internal network, or a deployment that exposes webhooks-api. [Certain 🟢]
- Attacker needs a valid identity-api token (RequireAuthorization). Any registered user qualifies, so no admin role is needed. [Certain 🟢]
- Attacker must POST a subscription for the Shipped and/or Paid event type. The grant-URL check can be satisfied with an attacker-controlled endpoint. [Likely 🟡]
- Attacker must host a listener for the callback URL. Other users' orders must also reach Shipped or Paid, and the data is only delivered after that happens. [Likely 🟡]
**Threat-model match:** Tenant-to-tenant data leakage (cross-user PII and order data via subscriptions that are not filtered by user). It matches only loosely, because the exposure is limited and the service is internal.
**Why:** A registered subscriber gets every user's Shipped and Paid event, because WebhooksRetriever.cs filters by event type only and WebhooksSender.SendAll POSTs the whole payload. Registration requires only authentication (Program.cs .RequireAuthorization(), WebHooksApi.cs POST). The grant-URL check is satisfied by an attacker-controlled endpoint, and AppHost.cs:63 exposes the service externally. The leaked data is order IDs, buyer names and, for Paid, items, so impact is moderate. The claim that the Shipped event carries items is wrong.

The flaw is real: WebhooksRetriever filters by event type only, so any subscriber receives every user's Shipped and Paid events. The leaked data is order IDs, buyer names and Paid items. However, webhooks-api is not an external endpoint in the AppHost, and I found no webapp or BFF path to it. Reaching it therefore needs an internal foothold or a non-default exposure, which gives 3 or more preconditions and LOW. A threat-model match could lift this one step to MEDIUM if webhooks-api is exposed in a real deployment, but under the AppHost as written, MEDIUM is somewhat inflated. Confirming the real deployment topology needs a manual check. [Likely 🟡]
**Reachability evidence:** src/Webhooks.API/Services/WebhooksRetriever.cs:7; src/Webhooks.API/Services/WebhooksRetriever.cs:7 (the Where filters on s.Type == type only; the caller is OrderStatusChangedToShippedIntegrationEventHandler.cs, retriever.GetSubscriptionsOfType(WebhookType.OrderShipped))
> Recommend a human build a PoC or runtime check; static reasoning hit its limit.

## Dropped

| id | title | file:line | why dropped |
|---|---|---|---|
| f021 | JWT validation disables audience validation and HTTPS metadata requirement for all APIs | `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:39` | duplicate of f011 |
| f027 | Identity server uses a developer signing credential with key management disabled, and static client secret "secret" for all code clients | `src/Identity.API/Program.cs:37` | duplicate of f002 |
| f030 | OIDC client secret hard-coded as "secret" and RequireHttpsMetadata=false | `src/WebhookClient/Extensions/Extensions.cs:56` | duplicate of f026 |
| f037 | OIDC client secret hardcoded ("secret") in a public mobile client and used for token exchange | `src/ClientApp/Services/Settings/SettingsService.cs:15` | duplicate of f026 |
| f039 | OIDC client secret hardcoded as "secret", UsePkce not set explicitly, RequireHttpsMetadata=false, all tokens saved in the cookie | `src/WebApp/Extensions/Extensions.cs:66` | duplicate of f026 |
| f048 | Full card number and CVV pulled into the client via user-info claims, and exceptions logged raw | `src/ClientApp/Services/Identity/IdentityService.cs:60` | duplicate of f015 |
| f009 | Chatbot renders model-controlled markdown images as raw MarkupString with attacker-chosen external src, enabling zero-click exfiltration | `src/WebApp/Components/Chatbot/MessageProcessor.cs:23` | implausible_trigger (exclusion 6) [0T/3F/0CV] |
| f010 | SSRF via webhook Url/GrantUrl: OPTIONS grant check and later POSTs to any attacker-chosen host, including internal addresses | `src/Webhooks.API/Services/GrantUrlTesterService.cs:5` | implausible_trigger, intentional_behavior (exclusion 3) [0T/3F/0CV] |
| f011 | JWT audience validation disabled and no scope or policy enforcement, so any token from the issuer is accepted by Basket, Ordering and Webhooks | `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:49` | implausible_trigger, intentional_behavior, not_actionable (exclusion 13) [0T/3F/0CV] |
| f012 | Unauthenticated broker messages drive order payment state transitions (forged StockConfirmed / PaymentSucceeded / PaymentFailed) | `src/EventBusRabbitMQ/RabbitMQEventBus.cs:114` | implausible_trigger, intentional_behavior (exclusion 3) [0T/3F/0CV] |
| f015 | Full card number, CVV (card_security_number), expiry and holder name are issued as claims without scope filtering | `src/Identity.API/Services/ProfileService.cs:76` | intentional_behavior (exclusion 3) [0T/3F/0CV] |
| f016 | Webhook token validation is disabled by default because ValidateToken is read from the wrong config key | `src/WebhookClient/Endpoints/WebhookEndpoints.cs:13` | implausible_trigger, intentional_behavior (exclusion 3) [0T/3F/0CV] |
| f017 | UpdateItem copies every client-supplied field onto the entity, including PictureFileName, stock and OnReorder | `src/Catalog.API/Apis/CatalogApi.cs:296` | duplicate, not_actionable (exclusion 13) [0T/3F/0CV] |
| f019 | CVV and cardholder data logged in clear via structured command logging | `src/Ordering.API/Application/Behaviors/LoggingBehavior.cs:10` | implausible_trigger, misread_code (exclusion 13) [1T/2F/0CV] |
| f020 | LLM tools run with the user's identity and no confirmation; untrusted catalog text can drive AddToCart and PII disclosure | `src/WebApp/Components/Chatbot/ChatState.cs:35` | implausible_trigger, not_actionable (exclusion 6) [0T/2F/1CV] |
| f022 | Forged OrderStarted event deletes any user's basket by event UserId | `src/Basket.API/IntegrationEvents/EventHandling/OrderStartedIntegrationEventHandler.cs:13` | implausible_trigger (exclusion 12) [0T/1F/0CV] |
| f023 | Forged or replayed OrderStatusChangedToPaid event decrements arbitrary catalog stock, non-idempotently | `src/Catalog.API/IntegrationEvents/EventHandling/OrderStatusChangedToPaidIntegrationEventHandler.cs:15` | implausible_trigger (exclusion 16) [0T/1F/0CV] |
| f024 | Custom-scheme redirect (maui://authcallback) on an exported activity is hijackable and has no verified-link protection | `src/ClientApp/Platforms/Android/WebAuthenticationCallbackActivity.cs:5` | already_handled (exclusion 13) [0T/1F/0CV] |
| f025 | Handler exceptions are swallowed and the message is Acked, so failures drop events and leave orders in inconsistent states, with no DLX | `src/EventBusRabbitMQ/RabbitMQEventBus.cs:155` | intentional_behavior (exclusion 3) [0T/1F/0CV] |
| f026 | Weak OIDC client settings: shared secret "secret" on all confidential clients, webapp RequirePkce=false, implicit-flow swagger clients, secret on a public native client | `src/Identity.API/Configuration/Config.cs:57` | not_actionable (exclusion 13) [0T/1F/0CV] |
| f028 | Request-id marker is global, committed before processing, and failures are swallowed as success or null | `src/Ordering.API/Application/Commands/IdentifiedCommandHandler.cs:37` | implausible_trigger (exclusion 15) [0T/1F/0CV] |
| f029 | Non-constant-time token comparison, token logged in cleartext, and /check echoes the token header | `src/WebhookClient/Endpoints/WebhookEndpoints.cs:34` | intentional_behavior (exclusion 13) [0T/1F/0CV] |
| f031 | BFF exposes the entire Identity.API app under /identity/* (all methods, no filtering) | `src/eShop.AppHost/Extensions.cs:122` | intentional_behavior (exclusion 13) [0T/1F/0CV] |
| f032 | UpdateBasket persists unvalidated ProductId and Quantity, and the model's validation is never invoked | `src/Basket.API/Grpc/BasketService.cs:144` | already_handled (exclusion 13) [0T/1F/0CV] |
| f033 | Whole-batch dispatch failure and unvalidated DestUrl scheme (only well-formedness checked) | `src/Webhooks.API/Apis/WebHooksApi.cs:46` | intentional_behavior (exclusion 3) [0T/1F/0CV] |
| f034 | Webhook secret token logged in plaintext | `src/Webhooks.API/Services/GrantUrlTesterService.cs:19` | not_actionable (exclusion 13) [0T/1F/0CV] |
| f035 | Cleartext traffic globally enabled on Android, ATS disabled on MacCatalyst (ClientApp and HybridApp), and Android backup allowed | `src/ClientApp/Platforms/Android/AndroidManifest.xml:3` | already_handled (exclusion 13) [0T/1F/0CV] |
| f036 | Bearer token sent to user-editable gateway and identity URLs with no host allowlist or HTTPS enforcement | `src/ClientApp/Services/RequestProvider/RequestProvider.cs:112` | implausible_trigger (exclusion 13) [0T/1F/0CV] |
| f038 | Trace-context header extraction runs outside the try/catch and throws on missing or non-byte[] headers, which can wedge the consumer | `src/EventBusRabbitMQ/RabbitMQEventBus.cs:117` | implausible_trigger (exclusion 13) [0T/1F/0CV] |
| f040 | returnUrl validation relies on Uri.IsAbsoluteUri and is passed to Nav.NavigateTo unchanged | `src/WebApp/Components/Pages/User/LogIn.razor:13` | not_actionable (exclusion 12) [0T/1F/0CV] |
| f041 | WebApp and Webhooks handlers trust event BuyerIdentityGuid and event contents: spoofed notifications and forged webhook payloads | `src/WebApp/Services/OrderStatus/IntegrationEvents/EventHandling/OrderStatusChangedToPaidIntegrationEventHandler.cs:13` | implausible_trigger (exclusion 3) [0T/1F/0CV] |
| f042 | User-controlled Token written to HTTP header without validation | `src/Webhooks.API/Services/WebhooksSender.cs:27` | already_handled [0T/1F/0CV] |
| f043 | Forwarded headers enabled on every project with no trusted proxy restriction | `src/eShop.AppHost/Extensions.cs:24` | not_actionable (exclusion 13) [0T/1F/0CV] |
| f044 | Authentication silently not registered when the "Identity" config section is missing | `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:24` | implausible_trigger (exclusion 13) [0T/1F/0CV] |
| f045 | Manual-only authorization: [AllowAnonymous] on GetBasket, and no [Authorize] or fallback policy on the other RPCs | `src/Basket.API/Grpc/BasketService.cs:120` | already_handled (exclusion 13) [0T/1F/0CV] |
| f046 | User search text is sent to a third-party embedding model without a length limit, and is logged at Trace and Debug level | `src/Catalog.API/Services/CatalogAI.cs:55` | not_actionable (exclusion 1) [0T/1F/0CV] |
| f047 | Logout/refresh-token handling is weak; refresh token is never revoked at the IdP | `src/ClientApp/Services/Identity/IdentityService.cs:1` | misread_code (exclusion 13) [0T/1F/0CV] |
| f049 | Automatic migration and seeding at startup, with default Postgres credential in appsettings.Development.json | `src/Identity.API/Program.cs:13` | intentional_behavior (exclusion 13) [0T/1F/0CV] |
| f050 | Logout without prompt via GET, enabling forced logout from third-party pages | `src/Identity.API/Quickstart/Account/AccountOptions.cs:10` | not_actionable (exclusion 12) [0T/1F/0CV] |
| f051 | Diagnostics page gates on RemoteIpAddress, which is unreliable behind a reverse proxy; it exposes the authenticated user's claims and tokens | `src/Identity.API/Quickstart/Diagnostics/DiagnosticsController.cs:13` | implausible_trigger (exclusion 13) [0T/1F/0CV] |
| f052 | Committed DB superuser password "yourWeak(!)Password" in Development appsettings of 5 services, which are activated by committed launch profiles | `src/Identity.API/appsettings.Development.json:3` | intentional_behavior (exclusion 2) [0T/1F/0CV] |
| f053 | GetOrder swallows all exceptions as 404, and the draft endpoint exposes the builder with no buyer binding | `src/Ordering.API/Apis/OrdersApi.cs:81` | not_actionable (exclusion 13) [0T/1F/0CV] |
| f054 | The card number column is stored without encryption, and only the masked PAN is persisted. The CVV has no column mapping. | `src/Ordering.Infrastructure/EntityConfigurations/PaymentMethodEntityTypeConfiguration.cs:27` | already_handled (exclusion 13) [0T/1F/0CV] |
| f055 | PaymentProcessor does not charge anything and responds to a StockConfirmed event with OrderId only, with no amount, buyer or state verification | `src/PaymentProcessor/IntegrationEvents/EventHandling/OrderStatusChangedToStockConfirmedIntegrationEventHandler.cs:22` | intentional_behavior (exclusion 3) [0T/1F/0CV] |
| f056 | Unauthenticated MapForwarder for /product-images/{id} with an unconstrained id substituted into the catalog-api path | `src/WebApp/Program.cs:32` | implausible_trigger (exclusion 13) [0T/1F/0CV] |
| f057 | Logout is anonymous-callable and does no redirect, so the OIDC sign-out is not completed | `src/WebhookClient/Endpoints/AuthenticationEndpoints.cs:12` | not_actionable (exclusion 13) [0T/1F/0CV] |
| f058 | Postgres uses unpinned third-party image ankane/pgvector:latest, and all databases share a single superuser | `src/eShop.AppHost/AppHost.cs:13` | intentional_behavior (exclusion 13) [0T/1F/0CV] |
| f059 | ESHOP_USE_HTTP_ENDPOINTS toggle switches Identity, webapp and webhooks clients to plain-HTTP launch profiles, combined with RequireHttpsMetadata=false | `src/eShop.AppHost/AppHost.cs:94` | intentional_behavior (exclusion 8) [0T/1F/0CV] |
| f060 | Auth token handler attaches the user's access token to every outgoing request from the client, with no host allow-list | `src/eShop.ServiceDefaults/HttpClientExtensions.cs:92` | implausible_trigger (exclusion 13) [0T/1F/0CV] |
| f061 | OpenAPI document endpoint mapped in all environments when the OpenApi config section exists | `src/eShop.ServiceDefaults/OpenApi.Extensions.cs:153` | not_actionable (exclusion 13) [0T/1F/0CV] |
| f062 | Handler logs the entire integration event object, including the user id, at Information level | `src/Basket.API/IntegrationEvents/EventHandling/OrderStartedIntegrationEventHandler.cs:12` | not_actionable (exclusion 12) [0T/1F/0CV] |
| f063 | Debug-only certificate validation relaxation (trusts any cert whose Issuer is CN=localhost) | `src/ClientApp/MauiProgram.cs:125` | intentional_behavior (exclusion 13) [0T/1F/0CV] |
| f064 | RedirectService.ExtractRedirectUriFromReturnUrl parses the redirect_uri by string splitting, but it appears unused | `src/Identity.API/Services/RedirectService.cs:7` | implausible_trigger (exclusion 2) [0T/1F/0CV] |
| f065 | Outbox deserialization resolves types by name from a DB column, but only against a whitelist of entry-assembly types | `src/IntegrationEventLogEF/Services/IntegrationEventLogService.cs:14` | implausible_trigger (exclusion 13) [0T/1F/0CV] |
| f066 | CheckoutAsync sends a hardcoded test card and ignores the user-submitted BasketCheckoutInfo card fields | `src/WebApp/Services/BasketState.cs:92` | intentional_behavior (exclusion 3) [0T/1F/0CV] |

