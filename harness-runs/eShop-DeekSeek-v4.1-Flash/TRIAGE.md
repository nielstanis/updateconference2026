# Triage Report

61 in -> 4 duplicates, 38 false positives, 19 confirmed (6 high / 11 med / 2 low), 1 needs manual test.

Context: interactive; environment = internet-facing web service (HTTP untrusted); scoring = derived HIGH/MEDIUM/LOW; 3-vote verification; precision tie-break.

## Act on these
### [HIGH] Catalog write endpoints (POST/PUT/DELETE) are completely unauthenticated and reachable through the external mobile BFF  (f001)
`src/Catalog.API/Apis/CatalogApi.cs:100` | auth-bypass | claimed HIGH (alignment +5) | confidence 9.0
**Owner:** top committer: Mike Kistler (3 of 3 recent commits); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 3 / FP 0 / CV 0

**Preconditions (3):**
- External reachability to the mobile BFF
- A trivially supplied api-version query value
- A target item id, freely enumerable from the public GET list

**Threat-model match:** DoS against paid SLA; catalog integrity

**Why:** CatalogApi.cs:100,105,110,114 map PUT/POST/DELETE with no RequireAuthorization, and Catalog.API registers no authentication or authorization middleware (Program.cs). AppHost.cs:63 makes the mobile BFF externally reachable and Extensions.cs:142 forwards /api/catalog/{*any} for all methods with no auth or method restriction; the handlers persist attacker data via SetValues/Add/Remove. An unauthenticated internet client can create, reprice or delete catalog items.

Zero meaningful preconditions: the BFF is internet-facing, the route is method-agnostic, and Catalog.API registers no auth, so any anonymous client can create, reprice or delete items using ids the public GET enumerates. Mass deletion is a direct availability attack and price rewriting is a financial-fraud primitive that propagates over the event bus. Textbook unauthenticated-remote HIGH; the claim is well calibrated.

**Reachability evidence:** src/eShop.AppHost/Extensions.cs:142


### [HIGH] RSA token-signing private key committed to the repository and used as the live signing credential  (f003)
`src/Identity.API/tempkey.jwk:1` | hardcoded-secret | claimed HIGH (alignment +0) | confidence 8.7
**Owner:** top committer: Aditya Mandaleeka (1 of 1 recent commit); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 3 / FP 0 / CV 0

**Preconditions (3):**
- Read access to the repo or a published artifact (the key is committed)
- Knowledge of the issuer URL and a target sub, both public/derivable
- Network reach to the API surface

**Threat-model match:** PII/PCI exposure; tenant-to-tenant data leakage

**Why:** tempkey.jwk:1 contains full RSA private parameters (D/P/Q/DP/DQ/QI, HasPrivateKey true) and Identity.API.csproj:50 copies it to output. Program.cs:37 unconditionally loads it via AddDeveloperSigningCredential while Program.cs:29 disables key management, so it is the live non-rotating issuer key; .gitignore does not exclude it. APIs trust the matching JWKS with ValidateAudience=false (AuthenticationExtensions.cs:33-49), so anyone with the repo can forge tokens for orders/basket/webhooks.

The committed file is a genuine 2048-bit RSA private key, loaded unconditionally with key management disabled, so the deployed IdP signs with a publicly known key. APIs trust that issuer with audience validation off and authorize purely on sub, so anyone can mint tokens for any user. Unauthenticated remote account takeover and cross-user order/PII access; HIGH is warranted, though it is not RCE or true admin escalation.

**Reachability evidence:** src/Identity.API/Program.cs:37


### [HIGH] Any authenticated customer can ship any order  (f004)
`src/Ordering.API/Apis/OrdersApi.cs:51` | auth-bypass | claimed HIGH (alignment +0) | confidence 8.3
**Owner:** top committer: Rob Conery (1 of 1 recent commit); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 3 / FP 0 / CV 0

**Preconditions (4):**
- A valid authenticated principal (no role needed)
- A target order number, trivially enumerable
- The order must already be Paid
- The api-version query value for the external route

**Threat-model match:** privilege escalation to admin

**Why:** PUT /api/orders/ship is gated only by bare RequireAuthorization (Program.cs:21-22) with no role or policy, and ShipOrderCommandHandler.cs:21-27 loads and ships whichever order number the body supplies. The handler comment says ship is an administrator action, yet no admin role exists, and the external BFF forwards /api/orders/* (Extensions.cs:146) so any customer token can ship a victim's Paid order and block cancellation.

Ship is protected by bare authentication and the handler ships whatever order number the body supplies, with no role, buyer or tenant check, despite being documented as an administrator action. Any customer can invoke an admin business function against arbitrary paid orders, permanently blocking cancellation or refund. Two preconditions plus the admin-escalation threat match land on HIGH.

**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:12


### [HIGH] Received-webhook token column is rendered to unauthenticated visitors  (f014)
`src/WebhookClient/Components/Pages/Home/ReceivedMessages.razor:13` | sensitive-data-exposure | claimed MEDIUM (alignment -1) | confidence 8.0
**Owner:** top committer: Steve Sanderson (1 of 1 recent commit); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 3 / FP 0 / CV 0

**Preconditions (3):**
- The home page is anonymous (no [Authorize], plain RouteView, no fallback policy)
- At least one webhook delivery has occurred
- Validation enabled for the leaked token to be a working bypass

**Threat-model match:** PII/PCI exposure

**Why:** ReceivedMessages.razor:13 renders hook.Token, and Home.razor:22 invokes it outside the AuthorizeView on the anonymous / route; Routes.razor uses plain RouteView and no fallback policy exists. The token is the captured X-eshop-whtoken used as the shared delivery secret, and the gated RegisteredHooks column shows it was meant to be hidden. Anonymous visitors can read it after a legitimate delivery.

The token column renders outside the AuthorizeView on the anonymous home page, so any visitor can read the shared delivery secret and the serialized order PII in the Data column. Zero preconditions at unauthenticated access maps to HIGH; the PII threat match would raise it further if it were not already at the ceiling. The claimed MEDIUM understates it.

**Reachability evidence:** src/WebhookClient/Components/Pages/Home/Home.razor:22


### [HIGH] Unauthenticated /add-webhook page renders the configured webhook validation token into the HTML  (f013)
`src/WebhookClient/Components/Pages/AddWebhook.razor:30` | sensitive-data-exposure | claimed MEDIUM (alignment +1) | confidence 7.5
**Owner:** top committer: Steve Sanderson (1 of 1 recent commit); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 2 / FP 1 / CV 0

**Preconditions (3):**
- Network reach to WebhookClient
- Knowing the predictable /add-webhook route
- Server-side prerendering active (the default)

**Threat-model match:** none

**Why:** AddWebhook.razor:1 exposes /add-webhook with no [Authorize], and OnInitialized copies WebhookClientOptions.Token into an input that is emitted during prerender. The token is the configured X-eshop-whtoken secret used by WebhookEndpoints and WebhooksSender, and Home.razor:11 shows the UI intended the area to be login-gated. Validation being off by default lowers impact but does not make the disclosure intentional.

The page has no [Authorize] and prerenders the configured webhook validation token into an input, so a single unauthenticated GET harvests the exact X-eshop-whtoken secret. Possession enables forged deliveries whenever validation is enabled. The 0-precondition/unauthenticated-remote rule lands it at HIGH, one band above the claimed MEDIUM, though the default-off validation tempers marginal gain.

**Reachability evidence:** src/WebhookClient/Program.cs:25


### [HIGH] JWT bearer disables audience validation, so any token from the IdP is accepted by every API  (f007)
`src/eShop.ServiceDefaults/AuthenticationExtensions.cs:49` | auth-bypass | claimed HIGH (alignment +0) | confidence 7.3
**Owner:** top committer: Michael Stonis (1 of 1 recent commit); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 3 / FP 0 / CV 0

**Preconditions (2):**
- A valid IdP-signed token for a different audience (self-registration plus a secretless client suffices)
- The target resource requires no additional scope check

**Threat-model match:** PII/PCI exposure; tenant-to-tenant data leakage

**Why:** AuthenticationExtensions.cs:40 sets the per-service audience but :49 disables ValidateAudience, and all three consumers gate with policy-less RequireAuthorization. The IdP defines disjoint orders/basket/webhooks resources, so a webhooks-audience token or a client ID token is accepted by Ordering and mapped via sub. The claimed cross-user impact depends on separate IDOR findings, but cross-audience token replay is real and reachable.

Audience validation is disabled and every consumer uses policy-less RequireAuthorization, so a token issued for basket or webhooks is accepted by Ordering. Base severity is MEDIUM for the authenticated requirement, but the PII/cross-tenant impact is directly reachable once admitted, raising it one step to HIGH. Claimed severity matches.

**Reachability evidence:** src/Ordering.API/Extensions/Extensions.cs:10


### [MEDIUM] Any authenticated user can cancel any other user's order  (f008)
`src/Ordering.API/Apis/OrdersApi.cs:22` | idor | claimed MEDIUM (alignment +0) | confidence 9.0
**Owner:** top committer: Rob Conery (1 of 1 recent commit); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 3 / FP 0 / CV 0

**Preconditions (4):**
- A valid authenticated account
- A target order in a cancellable state
- A target order number, trivially enumerable
- A non-empty x-requestid GUID

**Threat-model match:** none

**Why:** CancelOrderAsync forwards a body-supplied order number to CancelOrderCommandHandler.cs:21, which loads the order by id and calls SetCancelledStatus with no comparison to the caller's sub. The only gate is authentication, the validator checks only non-zero, and HiLo-sequential ids are enumerable. The listing path proves per-user scoping is intended, so any authenticated user can cancel another buyer's not-yet-paid order.

Cancel loads the order purely by body-supplied number and calls SetCancelledStatus with no comparison to the caller's sub, so any authenticated buyer can cancel another buyer's not-yet-paid order. Impact is unauthorized state change with no PII read or admin escalation. One or two preconditions at authenticated access maps to MEDIUM; the claim is accurate.

**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:41


### [MEDIUM] GET /api/orders/{orderId} returns any order without an ownership check  (f005)
`src/Ordering.API/Application/Queries/OrderQueries.cs:6` | idor | claimed HIGH (alignment -1) | confidence 8.7
**Owner:** top committer: Srushti (1 of 1 recent commit); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 3 / FP 0 / CV 0

**Preconditions (3):**
- A valid authenticated identity with the orders scope
- A valid order id, trivially enumerable from HiLo-sequential ints
- A target order that exists

**Threat-model match:** PII/PCI exposure

**Why:** OrdersApi.cs:84 passes the raw route id to OrderQueries.cs:6-10, which filters only on o.Id and returns the full shipping address and items. The group gate is authentication only, no ownership policy or query filter exists, and order ids are HiLo-sequential. The sibling listing path filters by Buyer.IdentityGuid (OrderQueries.cs:40), proving ownership scoping was intended but omitted here.

GetOrderAsync filters solely on id and returns full shipping address and items, while the only gate is authentication, so any customer can read every other buyer's order by walking sequential ids. It is a genuine cross-buyer confidentiality break with real PII and is trivially automatable, but it requires an authenticated scope-bearing account and is read-only. HIGH overrates an authenticated IDOR by one step.

**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:84


### [MEDIUM] Full PAN and CVV are written to logs on order creation, and CVV is logged by every MediatR behavior  (f026)
`src/Ordering.API/Apis/OrdersApi.cs:134` | sensitive-data-in-logs | claimed HIGH (alignment -1) | confidence 8.7
**Owner:** top committer: Rob Conery (1 of 1 recent commit); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 3 / FP 0 / CV 0

**Preconditions (4):**
- A valid authenticated account
- An explicit empty-GUID x-requestid header
- Warning-level logging enabled and logs retained/forwarded
- A reader not entitled to card data

**Threat-model match:** PII/PCI exposure

**Why:** OrdersApi.cs:134 logs the raw CreateOrderRequest record, whose generated ToString prints the full CardNumber and CardSecurityNumber, and it fires before the masking at line 140. Any authenticated client can trigger it with a zero GUID x-requestid; the code comment at line 130 shows logging the request contradicts intent. The CVV also passes unmasked into CreateOrderCommand, which is logged at lines 148-153 and in IdentifiedCommandHandler.cs:79-84, with no redaction filter.

Line 134 serializes the whole CreateOrderRequest record, PAN and CVV included, before the masking at line 140, so any caller supplying an empty request GUID forces plaintext card data into logs. It stays at MEDIUM because the endpoint is authenticated, the logged values are attacker-supplied, and disclosure needs retained logs readable by an unauthorized party. PCI-relevant, but not admin, RCE or cross-tenant; HIGH is one step high.

**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:17


### [MEDIUM] Order item prices and quantities are accepted from the client request, allowing arbitrary order totals  (f010)
`src/Ordering.API/Extensions/BasketItemExtensions.cs:20` | business-logic | claimed MEDIUM (alignment +0) | confidence 8.3
**Owner:** top committer: Aditya Mandaleeka (1 of 1 recent commit); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 3 / FP 0 / CV 0

**Preconditions (3):**
- A valid authenticated token
- Calling POST /api/orders directly rather than through the repricing WebApp
- Product ids with sufficient stock

**Threat-model match:** none

**Why:** The request body binds a client-controlled item list; BasketItemExtensions.cs:20-21 copies UnitPrice and Quantity verbatim, CreateOrderCommandHandler.cs:44 persists them, and Order.GetTotal derives the total from them. The validator only checks non-emptiness and OrderItem permits unitPrice 0/0.01; no catalog or basket re-fetch exists. The trusted WebApp re-prices server-side (BasketState.cs:141), confirming prices should not come from the client.

UnitPrice and Quantity flow unchanged into the persisted order item and total, with only a non-empty check and no catalog or basket re-fetch. An authenticated buyer can set an arbitrary total. Two preconditions at authenticated access maps to MEDIUM; the payment step is simulated, and no threat-model entry is implicated.

**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:141


### [MEDIUM] CreateOrder trusts body-supplied UserId instead of the JWT sub claim  (f009)
`src/Ordering.API/Apis/OrdersApi.cs:141` | auth-bypass | claimed MEDIUM (alignment +0) | confidence 8.0
**Owner:** top committer: Rob Conery (1 of 1 recent commit); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 3 / FP 0 / CV 0

**Preconditions (2):**
- A valid authenticated token
- For a specific victim, knowledge of their sub GUID

**Threat-model match:** none

**Why:** CreateOrderAsync builds the command from body-supplied request.UserId (OrdersApi.cs:141) while IIdentityService is injected but unused; no validator or policy supplies the missing check. The value becomes Buyer.IdentityGuid and the OrderStartedIntegrationEvent UserId, which Basket.API uses to delete /basket/{UserId}. The external /api/orders route makes this reachable by any authenticated client, enabling order-history poisoning and cross-user basket deletion.

CreateOrder copies body-supplied UserId into the command while IIdentityService is unused, so the token identity is never consulted. That value becomes the buyer identity and the OrderStarted event UserId that Basket uses for deletion, giving cross-user integrity impact. It is not unauthenticated and exposes no victim data back to the attacker, so it stays at the authenticated MEDIUM tier.

**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:17


### [MEDIUM] Webhook signing token written to logs in cleartext at Information level  (f016)
`src/Webhooks.API/Services/GrantUrlTesterService.cs:17` | sensitive-data-in-logs | claimed MEDIUM (alignment +0) | confidence 7.7
**Owner:** top committer: Aditya Mandaleeka (1 of 1 recent commit); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 3 / FP 0 / CV 0

**Preconditions (3):**
- A valid authenticated account on Webhooks.API
- Read access to or compromise of the OTLP log backend
- The caller is the subscription creator whose own token is logged

**Threat-model match:** none

**Why:** GrantUrlTesterService.cs:17 and :25 log the caller and expected webhook tokens verbatim at Information, reached live from WebHooksApi.cs:41. The token is the shared X-eshop-whtoken credential used by WebhooksSender.cs:24 and validated at WebhookEndpoints.cs:37. Logs default to Information and are exported formatted via OTLP (ServiceDefaults/Extensions.cs:54,87-93) with no redaction, so log readers can harvest the secret and forge deliveries.

The caller and expected tokens are logged verbatim at Information and exported over OTLP, so with endpoint configured the secret leaves the process into a shared store. Two preconditions place it at MEDIUM; exposure becomes cross-user only when the log backend is compromised, and the token grants no admin access, PII or RCE. Claimed MEDIUM is correct.

**Reachability evidence:** src/Webhooks.API/Apis/WebHooksApi.cs:41


### [MEDIUM] Authenticated user can force server-side OPTIONS/POST requests to arbitrary hosts  (f021)
`src/Webhooks.API/Services/GrantUrlTesterService.cs:21` | ssrf | claimed HIGH (alignment -1) | confidence 7.7
**Owner:** top committer: Aditya Mandaleeka (1 of 1 recent commit); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 3 / FP 0 / CV 0

**Preconditions (3):**
- A valid authenticated token
- Network reach to Webhooks.API (internal-only in the reference topology)
- The same-origin check is satisfied by submitting the same internal URL twice

**Threat-model match:** none

**Why:** WebHooksApi.cs:41 forwards caller-controlled Url/GrantUrl to TestGrantUrl, which sends an OPTIONS request to that host at GrantUrlTesterService.cs:21. The only checks are Uri.IsWellFormedUriString and a same-origin comparison of two attacker-supplied URLs (GrantUrlTesterService.cs:37-45), both trivially satisfied. Service discovery resolves internal Aspire names, no egress allowlist or private-range block exists, and any authenticated shopper can drive the server-side request.

A caller-supplied URL is fetched server-side with service discovery active and no egress restriction, and the same-origin guard is vacuous. Exploitability is constrained: it needs authenticated credentials and sends a bodyless OPTIONS whose only observable is a success/failure oracle. That is authenticated access with 2-3 preconditions, i.e. MEDIUM rather than HIGH, though the second-order stored-webhook POST keeps it from dropping further.

**Reachability evidence:** src/Webhooks.API/Apis/WebHooksApi.cs:41


### [MEDIUM] Persistent blind SSRF: stored DestUrl is POSTed without re-validation and redirects are followed  (f022)
`src/Webhooks.API/Services/WebhooksSender.cs:32` | ssrf | claimed HIGH (alignment -1) | confidence 7.7
**Owner:** top committer: Aditya Mandaleeka (1 of 1 recent commit); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 3 / FP 0 / CV 0

**Preconditions (4):**
- A valid authenticated account
- A controlled endpoint that passes the grant handshake
- A paid order to trigger delivery
- A redirect or DNS rebind to the internal target

**Threat-model match:** tenant-to-tenant data leakage (partial)

**Why:** DestUrl is stored from caller input at WebHooksApi.cs:48 and POSTed verbatim by WebhooksSender.cs:17,32 with no delivery-time validation. The default HttpClient follows redirects (AllowAutoRedirect is never disabled), so a passing endpoint can later 307/DNS-rebind delivery to internal services or metadata. Delivery is triggered by a paid order via OrderStatusChangedToPaidIntegrationEventHandler.cs:16, and only RequireAuthorization gates registration.

DestUrl is stored after a one-time grant check and later POSTed with no delivery-time validation while the default client follows redirects, so a passing host can redirect to internal services. It is a blind SSRF: no response is returned, only an event body and attacker token are sent, limiting exfiltration. Registration requires authentication plus a token-echoing endpoint, so HIGH is overstated by one step.

**Reachability evidence:** src/Webhooks.API/IntegrationEvents/OrderStatusChangedToPaidIntegrationEventHandler.cs:16


### [MEDIUM] Full raw integration-event bodies (buyer name, identity GUID) are written to span tags and logs  (f035)
`src/EventBusRabbitMQ/RabbitMQEventBus.cs:161` | information-disclosure | claimed LOW (alignment +2) | confidence 7.5
**Owner:** top committer: iem365-michael (1 of 1 recent commit); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 2 / FP 1 / CV 0

**Preconditions (4):**
- A running RabbitMQ consumer subscribed to order events
- A normal order status transition producing buyer PII
- OTEL_EXPORTER_OTLP_ENDPOINT set
- Read access to the trace store

**Threat-model match:** PII/PCI exposure

**Why:** RabbitMQEventBus.cs:157/161 tags every consumed body and line 172 logs it on failure with no redaction, and shipped events carry BuyerName and BuyerIdentityGuid. The bus is live in every service and Warning logs are enabled by default, with formatted OTLP export when configured. Exposure is to log/telemetry readers rather than remote HTTP clients, which keeps it LOW, but the PII data flow is concrete.

Line 161 tags the full raw body of every consumed event before deserialization, shipping BuyerName, BuyerIdentityGuid and UserId to any configured OTLP backend with no redaction. Exploitation needs three-plus preconditions including trace-store access, so it is not HIGH, but the exposure is systematic, persistent PII with long retention and broad telemetry access. Claimed LOW understates it; MEDIUM with a +2 alignment.

**Reachability evidence:** src/EventBusRabbitMQ/RabbitMQEventBus.cs:272


### [MEDIUM] Logout failure leaves access/refresh tokens in SecureStorage; post-logout redirect is unregistered  (f028)
`src/ClientApp/Services/Identity/IdentityService.cs:47` | token-exposure | claimed MEDIUM (alignment +0) | confidence 7.5
**Owner:** top committer: Michael Stonis (4 of 4 recent commits); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 2 / FP 1 / CV 0

**Preconditions (5):**
- A signed-in victim with tokens persisted in SecureStorage
- Logout fails (unregistered post-logout redirect or transient IdP/network error)
- The caller ignores the false result
- Later device or keystore access
- A still-valid access or refresh token

**Threat-model match:** PII/PCI exposure

**Why:** IdentityService.cs:49-54 returns on LogoutAsync error before the only SetUserTokenAsync(default), and LoginViewModel.cs:107 discards the false result. The client sends maui://authcallback while IdentityServer registers only maui://authcallback/Account/Redirecting (Config.cs:57), so logout predictably errors and the access/refresh tokens remain in SecureStorage; the next launch auto-restores the session. Impact needs device access, but the logout operation is genuinely broken.

The error return precedes the sole token wipe, the caller ignores it, and startup re-authenticates from the surviving token, so logout leaves a live session. Impact is genuine order history, address and card claims, but exploitation needs device access plus a failed logout. Three-plus preconditions and local-only access is LOW before the PII threat match, which raises it one step to MEDIUM.

**Reachability evidence:** src/ClientApp/ViewModels/LoginViewModel.cs:107


### [MEDIUM] All confidential OIDC clients share the literal client secret "secret", including the public MAUI client  (f020)
`src/Identity.API/Configuration/Config.cs:52` | hardcoded-secret | claimed HIGH (alignment -1) | confidence 7.5
**Owner:** top committer: Michael Stonis (1 of 1 recent commit); no CODEOWNERS entry
**Verdict:** needs_manual_test; votes TP 2 / FP 1 / CV 0

**Preconditions (4):**
- The client secret is public by construction
- A valid authorization code or refresh token for a victim (separate capture vector)
- Fixed redirect URIs limit re-pointing; maui still requires PKCE
- Network reach to the token endpoint

**Threat-model match:** none

**Why:** Config.cs:52,82,118 register the identical literal secret for maui/webapp/webhooksclient, loaded unconditionally at Program.cs:34 with no override, and the MAUI app ships the same value (SettingsService.cs:15). RequirePkce=true blunts the scheme-hijack chain for maui, but webapp has RequirePkce=false (Config.cs:90) and offline access, so the public secret is the only client-authentication factor for redeeming a captured code or refresh token. Live credential, though the demo context lowers severity.

The hardcoded, client-shipped secret is confirmed and unmitigated, with RequirePkce=false on webapp, so client authentication at the token endpoint is genuinely defeated for three clients. Severity is capped below HIGH because the Code-only grant means the secret alone yields no token; exploitation is contingent on independent code capture against a fixed redirect. Real defense-in-depth collapse that needs a concrete code-capture path to confirm.

**Reachability evidence:** src/Identity.API/Program.cs:34

> Recommend a human build a PoC; static reasoning hit its limit.


### [LOW] GET /Account/Logout signs the user out without a prompt, enabling logout CSRF  (f025)
`src/Identity.API/Quickstart/Account/AccountController.cs:152` | csrf | claimed LOW (alignment +0) | confidence 8.0
**Owner:** top committer: Aditya Mandaleeka (1 of 1 recent commit); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 2 / FP 1 / CV 0

**Preconditions (2):**
- A victim with a live session cookie who issues a top-level GET to /Account/Logout
- ShowLogoutPrompt stays false (the global default)

**Threat-model match:** none

**Why:** ShowLogoutPrompt=false (AccountOptions.cs:12) makes the anonymous GET handler call the POST logout overload directly at AccountController.cs:156, bypassing the [ValidateAntiForgeryToken] filter at line 166, and SignOutAsync runs at line 175. SameSite=Lax still sends the cookie on a cross-site top-level GET, so a malicious page can force sign-out. Impact is limited to session denial, but the mechanism is concrete.

The antiforgery bypass is real: the GET handler invokes the POST action in-process, so a bare top-level GET signs out any authenticated user and Lax still ships the cookie. But the only capability gained is forced logout, a session-availability nuisance with no data exposure, privilege escalation or tenant crossing. Classic logout-CSRF; LOW matches the claim.

**Reachability evidence:** src/Identity.API/Quickstart/Account/AccountController.cs:146


### [LOW] Expected webhook token is logged in cleartext on every unauthenticated request  (f018)
`src/WebhookClient/Endpoints/WebhookEndpoints.cs:35` | sensitive-data-exposure | claimed LOW (alignment +0) | confidence 7.7
**Owner:** top committer: Steve Sanderson (1 of 1 recent commit); no CODEOWNERS entry
**Verdict:** exploitable; votes TP 3 / FP 0 / CV 0

**Preconditions (3):**
- Read access to the WebhookClient log sink
- Log aggregation or OTLP export enabled
- ValidateToken actually effective and the token non-default

**Threat-model match:** none

**Why:** WebhookEndpoints.cs:35 logs tokenToValidate (the configured secret from line 14) and the caller token at Information before the check at line 37, on every anonymous request. It runs for accepted and rejected requests, and ServiceDefaults formats and OTLP-exports logs with no redaction. Severity is LOW because log access is required, but the cleartext-secret data flow is real.

The log statement runs at Information on every request and can ship the expected token off-box, so the disclosure is real and unmitigated. Monetizing it requires telemetry access, export configured and validation actually enforced, while the token is a low-privilege shared secret already committed in appsettings. Three-plus preconditions and no PII/admin/RCE impact keep it at LOW.

**Reachability evidence:** src/WebhookClient/Program.cs:29


## Dropped

| id | title | file:line | why dropped |
|---|---|---|---|
| f006 | Internet-facing mobile BFF catch-all routes forward unauthenticated requests to anonymous Catalog write endpoints | `src/eShop.AppHost/Extensions.cs:142` | duplicate of f001 |
| f012 | OIDC confidential-client secret `secret` is hardcoded for webapp and webhooksclient | `src/WebApp/Extensions/Extensions.cs:78` | duplicate of f020 |
| f023 | Cross-user basket deletion: OrderStarted deletes the basket of any event-supplied UserId, and the publisher takes it from the request body | `src/Basket.API/IntegrationEvents/EventHandling/OrderStartedIntegrationEventHandler.cs:14` | duplicate of f009 |
| f043 | OIDC confidential-client secret (`secret`) embedded in the shipped app and stored in plaintext Preferences | `src/ClientApp/Services/Settings/SettingsService.cs:15` | duplicate of f020 |
| f002 | CVV, card number and full PII are issued in id_tokens/userinfo to every client | `src/Identity.API/Services/ProfileService.cs:23` | intentional_behavior; rule 3 |
| f011 | Identity DB seeder re-creates demo users alice/bob with password Pass123$ and the login page advertises it | `src/Identity.API/UsersSeed.cs:33` | intentional_behavior; rule 3 |
| f015 | Anonymous POST /webhook-received injects arbitrary data into a global store rendered to every visitor | `src/WebhookClient/Endpoints/WebhookEndpoints.cs:31` | intentional_behavior, not_actionable; rule 3 |
| f017 | NuGet vulnerability audit warnings globally suppressed | `Directory.Build.props:11` | not_actionable; rule 13 |
| f019 | Create/Update bind the full CatalogItem entity, allowing overposting of Id, PictureFileName, Price and stock fields | `src/Catalog.API/Apis/CatalogApi.cs:415` | intentional_behavior; rule 3 |
| f024 | Webhook token validation reads the wrong configuration key, so ValidateToken is silently ignored | `src/WebhookClient/Endpoints/WebhookEndpoints.cs:13` | misread_code, not_actionable; rule 13 |
| f027 | CI actions referenced by mutable tags instead of commit SHAs | `.github/workflows/pr-validation.yml:23` | not_actionable; rule 13 |
| f029 | webapp confidential client disables PKCE while its client secret is public | `src/Identity.API/Configuration/Config.cs:90` | already_handled, implausible_trigger; rule 13 |
| f030 | Chatbot exposes a PII function tool and renders model-chosen image URLs, enabling prompt-injection exfiltration | `src/WebApp/Components/Chatbot/ChatState.cs:97` | already_handled, intentional_behavior; rule 6 |
| f031 | returnUrl filtering in /user/login is bypassable with protocol-relative URLs | `src/WebApp/Components/Pages/User/LogIn.razor:15` | not_actionable; rule 12 |
| f032 | Forwarded-header trust enabled globally clears the trusted-proxy list, allowing X-Forwarded-For/Proto spoofing | `src/eShop.AppHost/Extensions.cs:36` | intentional_behavior, not_actionable; rule 3 |
| f033 | BFF and WebApp forward bearer tokens and login credentials over hardwired HTTP to internal services | `src/eShop.AppHost/Extensions.cs:146` | intentional_behavior, not_actionable |
| f034 | Official build pipeline extends a 1ES template from a mutable release tag | `ci.yml:18` | intentional_behavior; rule 13 |
| f036 | Production consumer contains a "throw-fake-exception" body trigger that force-fails and drops any event containing it | `src/EventBusRabbitMQ/RabbitMQEventBus.cs:163` | intentional_behavior; rule 3 |
| f037 | Database container pinned to the mutable ankane/pgvector:latest tag | `src/eShop.AppHost/AppHost.cs:13` | not_actionable; rule 13 |
| f038 | ATS fully disabled in the Mac Catalyst Release bundle and cleartext globally declared on Android | `src/ClientApp/Platforms/MacCatalyst/Info.plist:29` | intentional_behavior, not_actionable; rule 9 |
| f039 | Gateway endpoints default to plaintext HTTP and have no scheme validation; card PAN/CVV and bearer tokens are POSTed in cleartext | `src/ClientApp/ViewModels/SettingsViewModel.cs:58` | intentional_behavior; rule 3 |
| f040 | Order PII is broadcast to every user's subscription of an event type; per-user scoping is stored but not enforced | `src/Webhooks.API/Services/WebhooksRetriever.cs:7` | intentional_behavior; rule 3 |
| f041 | OIDC/JWT metadata acquisition is allowed over HTTP, enabling signing-key substitution | `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:39` | implausible_trigger; rule 13 |
| f042 | ACR build script takes a GitHub PAT as a mandatory command-line argument | `build/acr-build/queue-all.ps1:6` | intentional_behavior; rule 8 |
| f044 | Loopback-only diagnostics gate can be satisfied with a spoofed X-Forwarded-For header | `src/Identity.API/Quickstart/Diagnostics/DiagnosticsController.cs:14` | duplicate; rule 13 |
| f045 | WebhookClient /login returnUrl is passed to NavigateTo after only a UriKind.Relative parse | `src/WebhookClient/Components/Pages/LogIn.razor:9` | not_actionable; rule 12 |
| f046 | Webhook validation shared secret committed in appsettings.json | `src/WebhookClient/appsettings.json:10` | intentional_behavior, not_actionable |
| f047 | Integration events are dispatched on the unauthenticated routing key; any publisher can forge any event | `src/EventBusRabbitMQ/RabbitMQEventBus.cs:192` | already_handled, implausible_trigger; rule 13 |
| f048 | Debug HTTP handler disables TLS validation with a forgeable issuer-name check | `src/ClientApp/MauiProgram.cs:125` | intentional_behavior; rule 3 |
| f049 | Consumer ACKs messages even when processing throws, silently discarding failed or injected events | `src/EventBusRabbitMQ/RabbitMQEventBus.cs:180` | intentional_behavior; rule 3 |
| f050 | Implicit grant enabled with AllowAccessTokensViaBrowser for three swagger clients | `src/Identity.API/Configuration/Config.cs:148` | implausible_trigger, intentional_behavior, not_actionable; rule 13 |
| f051 | Exported activity accepts the unverified custom scheme maui://authcallback and the callback URL is hardcoded | `src/ClientApp/Platforms/Android/WebAuthenticationCallbackActivity.cs:6` | already_handled; rule 13 |
| f052 | Session cookie uses sliding expiration with no absolute lifetime and default Secure/SameSite policy | `src/WebApp/Extensions/Extensions.cs:71` | not_actionable; rule 13 |
| f053 | OIDC metadata fetching over plaintext is permitted for the WebApp and WebhookClient | `src/WebApp/Extensions/Extensions.cs:82` | duplicate, implausible_trigger |
| f054 | OpenAPI documents are mapped in every environment and may be reachable through the BFF | `src/eShop.ServiceDefaults/OpenApi.Extensions.cs:24` | intentional_behavior, not_actionable; rule 13 |
| f055 | Payment outcome is a fixed configuration flag with no order, amount or idempotency validation | `src/PaymentProcessor/IntegrationEvents/EventHandling/OrderStatusChangedToStockConfirmedIntegrationEventHandler.cs:21` | intentional_behavior; rule 3 |
| f056 | Deployment workflow templates pipe a remote script to bash while holding id-token: write | `.github/skills/aspire-deployment/references/github-actions-azure-csharp.yml:36` | doesnt_exist; rule 2 |
| f057 | Anonymous semantic-search text is forwarded unbounded to the external embedding provider and logged verbatim | `src/Catalog.API/Apis/CatalogApi.cs:300` | already_handled, misread_code; rule 13 |
| f058 | Hybrid Blazor client hardcodes a cleartext HTTP BFF base address in all build configurations | `src/HybridApp/MauiProgram.cs:9` | intentional_behavior, not_actionable; rule 3 |
| f059 | Same-origin product-image proxy will serve attacker-named SVG files with image/svg+xml | `src/WebApp/Program.cs:32` | implausible_trigger; rule 13 |
| f060 | AddDefaultAuthentication fails open when the Identity section is missing | `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:24` | implausible_trigger, intentional_behavior; rule 3 |
| f061 | Full card number (PAN) persisted in cleartext in ordering.paymentmethods | `src/Ordering.Infrastructure/EntityConfigurations/PaymentMethodEntityTypeConfiguration.cs:27` | already_handled, misread_code |

