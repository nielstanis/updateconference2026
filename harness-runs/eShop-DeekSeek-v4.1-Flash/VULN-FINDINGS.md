# VULN-FINDINGS — eShop (.NET reference application)

Target: `/home/niels/github/def-proj/eShop`  
Scanned: 2026-11-08T15:17:33+00:00  
Total: 61 (14 HIGH / 26 MEDIUM / 21 LOW, 7 low-confidence)  
These are static candidates, not verified vulnerabilities.

| id | severity | confidence | category | file:line | title |
|---|---|---|---|---|---|
| F-001 | HIGH | 0.9 | auth-bypass | `src/Catalog.API/Apis/CatalogApi.cs:100` | Catalog write endpoints (POST/PUT/DELETE) are completely unauthenticated and reachable through the external mobile BFF |
| F-002 | HIGH | 0.9 | sensitive-data-exposure | `src/Identity.API/Services/ProfileService.cs:23` | CVV, card number and full PII are issued in id_tokens/userinfo to every client |
| F-003 | HIGH | 0.9 | hardcoded-secret | `src/Identity.API/tempkey.jwk:1` | RSA token-signing private key committed to the repository and used as the live signing credential |
| F-004 | HIGH | 0.9 | auth-bypass | `src/Ordering.API/Apis/OrdersApi.cs:51` | Any authenticated customer can ship any order |
| F-005 | HIGH | 0.9 | idor | `src/Ordering.API/Application/Queries/OrderQueries.cs:6` | GET /api/orders/{orderId} returns any order without an ownership check |
| F-006 | HIGH | 0.9 | authorization-gap | `src/eShop.AppHost/Extensions.cs:142` | Internet-facing mobile BFF catch-all routes forward unauthenticated requests to anonymous Catalog write endpoints |
| F-007 | HIGH | 0.9 | auth-bypass | `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:49` | JWT bearer disables audience validation, so any token from the IdP is accepted by every API |
| F-008 | MEDIUM | 0.9 | idor | `src/Ordering.API/Apis/OrdersApi.cs:22` | Any authenticated user can cancel any other user's order |
| F-009 | MEDIUM | 0.9 | auth-bypass | `src/Ordering.API/Apis/OrdersApi.cs:141` | CreateOrder trusts body-supplied UserId instead of the JWT sub claim |
| F-010 | MEDIUM | 0.9 | business-logic | `src/Ordering.API/Extensions/BasketItemExtensions.cs:20` | Order item prices and quantities are accepted from the client request, allowing arbitrary order totals |
| F-011 | HIGH | 0.8 | hardcoded-secret | `src/Identity.API/UsersSeed.cs:33` | Identity DB seeder re-creates demo users alice/bob with password Pass123$ and the login page advertises it |
| F-012 | MEDIUM | 0.8 | hardcoded-secret | `src/WebApp/Extensions/Extensions.cs:78` | OIDC confidential-client secret `secret` is hardcoded for webapp and webhooksclient |
| F-013 | MEDIUM | 0.8 | sensitive-data-exposure | `src/WebhookClient/Components/Pages/AddWebhook.razor:30` | Unauthenticated /add-webhook page renders the configured webhook validation token into the HTML |
| F-014 | MEDIUM | 0.8 | sensitive-data-exposure | `src/WebhookClient/Components/Pages/Home/ReceivedMessages.razor:13` | Received-webhook token column is rendered to unauthenticated visitors |
| F-015 | MEDIUM | 0.8 | auth-bypass | `src/WebhookClient/Endpoints/WebhookEndpoints.cs:31` | Anonymous POST /webhook-received injects arbitrary data into a global store rendered to every visitor |
| F-016 | MEDIUM | 0.8 | sensitive-data-in-logs | `src/Webhooks.API/Services/GrantUrlTesterService.cs:17` | Webhook signing token written to logs in cleartext at Information level |
| F-017 | LOW | 0.8 | insecure-default | `Directory.Build.props:11` | NuGet vulnerability audit warnings globally suppressed |
| F-018 | LOW | 0.8 | sensitive-data-exposure | `src/WebhookClient/Endpoints/WebhookEndpoints.cs:35` | Expected webhook token is logged in cleartext on every unauthenticated request |
| F-019 | HIGH | 0.7 | mass-assignment | `src/Catalog.API/Apis/CatalogApi.cs:415` | Create/Update bind the full CatalogItem entity, allowing overposting of Id, PictureFileName, Price and stock fields |
| F-020 | HIGH | 0.7 | hardcoded-secret | `src/Identity.API/Configuration/Config.cs:52` | All confidential OIDC clients share the literal client secret "secret", including the public MAUI client |
| F-021 | HIGH | 0.7 | ssrf | `src/Webhooks.API/Services/GrantUrlTesterService.cs:21` | Authenticated user can force server-side OPTIONS/POST requests to arbitrary hosts |
| F-022 | HIGH | 0.7 | ssrf | `src/Webhooks.API/Services/WebhooksSender.cs:32` | Persistent blind SSRF: stored DestUrl is POSTed without re-validation and redirects are followed |
| F-023 | MEDIUM | 0.7 | idor | `src/Basket.API/IntegrationEvents/EventHandling/OrderStartedIntegrationEventHandler.cs:14` | Cross-user basket deletion: OrderStarted deletes the basket of any event-supplied UserId, and the publisher takes it from the request body |
| F-024 | MEDIUM | 0.7 | security-misconfiguration | `src/WebhookClient/Endpoints/WebhookEndpoints.cs:13` | Webhook token validation reads the wrong configuration key, so ValidateToken is silently ignored |
| F-025 | LOW | 0.7 | csrf | `src/Identity.API/Quickstart/Account/AccountController.cs:152` | GET /Account/Logout signs the user out without a prompt, enabling logout CSRF |
| F-026 | HIGH | 0.6 | sensitive-data-in-logs | `src/Ordering.API/Apis/OrdersApi.cs:134` | Full PAN and CVV are written to logs on order creation, and CVV is logged by every MediatR behavior |
| F-027 | MEDIUM | 0.6 | ci-supply-chain | `.github/workflows/pr-validation.yml:23` | CI actions referenced by mutable tags instead of commit SHAs |
| F-028 | MEDIUM | 0.6 | token-exposure | `src/ClientApp/Services/Identity/IdentityService.cs:47` | Logout failure leaves access/refresh tokens in SecureStorage; post-logout redirect is unregistered |
| F-029 | MEDIUM | 0.6 | auth-bypass | `src/Identity.API/Configuration/Config.cs:90` | webapp confidential client disables PKCE while its client secret is public |
| F-030 | MEDIUM | 0.6 | prompt-injection | `src/WebApp/Components/Chatbot/ChatState.cs:97` | Chatbot exposes a PII function tool and renders model-chosen image URLs, enabling prompt-injection exfiltration |
| F-031 | MEDIUM | 0.6 | open-redirect | `src/WebApp/Components/Pages/User/LogIn.razor:15` | returnUrl filtering in /user/login is bypassable with protocol-relative URLs |
| F-032 | MEDIUM | 0.6 | auth-bypass | `src/eShop.AppHost/Extensions.cs:36` | Forwarded-header trust enabled globally clears the trusted-proxy list, allowing X-Forwarded-For/Proto spoofing |
| F-033 | MEDIUM | 0.6 | improper-tls | `src/eShop.AppHost/Extensions.cs:146` | BFF and WebApp forward bearer tokens and login credentials over hardwired HTTP to internal services |
| F-034 | LOW | 0.6 | ci-supply-chain | `ci.yml:18` | Official build pipeline extends a 1ES template from a mutable release tag |
| F-035 | LOW | 0.6 | information-disclosure | `src/EventBusRabbitMQ/RabbitMQEventBus.cs:161` | Full raw integration-event bodies (buyer name, identity GUID) are written to span tags and logs |
| F-036 | LOW | 0.6 | business-logic | `src/EventBusRabbitMQ/RabbitMQEventBus.cs:163` | Production consumer contains a "throw-fake-exception" body trigger that force-fails and drops any event containing it |
| F-037 | LOW | 0.6 | ci-supply-chain | `src/eShop.AppHost/AppHost.cs:13` | Database container pinned to the mutable ankane/pgvector:latest tag |
| F-038 | MEDIUM | 0.5 | improper-transport-config | `src/ClientApp/Platforms/MacCatalyst/Info.plist:29` | ATS fully disabled in the Mac Catalyst Release bundle and cleartext globally declared on Android |
| F-039 | MEDIUM | 0.5 | cleartext-transport | `src/ClientApp/ViewModels/SettingsViewModel.cs:58` | Gateway endpoints default to plaintext HTTP and have no scheme validation; card PAN/CVV and bearer tokens are POSTed in cleartext |
| F-040 | MEDIUM | 0.5 | idor | `src/Webhooks.API/Services/WebhooksRetriever.cs:7` | Order PII is broadcast to every user's subscription of an event type; per-user scoping is stored but not enforced |
| F-041 | MEDIUM | 0.5 | improper-tls | `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:39` | OIDC/JWT metadata acquisition is allowed over HTTP, enabling signing-key substitution |
| F-042 | LOW | 0.5 | credential-exposure | `build/acr-build/queue-all.ps1:6` | ACR build script takes a GitHub PAT as a mandatory command-line argument |
| F-043 | LOW | 0.5 | hardcoded-secret | `src/ClientApp/Services/Settings/SettingsService.cs:15` | OIDC confidential-client secret (`secret`) embedded in the shipped app and stored in plaintext Preferences |
| F-044 | LOW | 0.5 | auth-bypass | `src/Identity.API/Quickstart/Diagnostics/DiagnosticsController.cs:14` | Loopback-only diagnostics gate can be satisfied with a spoofed X-Forwarded-For header |
| F-045 | LOW | 0.5 | open-redirect | `src/WebhookClient/Components/Pages/LogIn.razor:9` | WebhookClient /login returnUrl is passed to NavigateTo after only a UriKind.Relative parse |
| F-046 | LOW | 0.5 | hardcoded-secret | `src/WebhookClient/appsettings.json:10` | Webhook validation shared secret committed in appsettings.json |
| F-047 | HIGH | 0.4 | event-forgery | `src/EventBusRabbitMQ/RabbitMQEventBus.cs:192` | Integration events are dispatched on the unauthenticated routing key; any publisher can forge any event |
| F-048 | MEDIUM | 0.4 | improper-cert-validation | `src/ClientApp/MauiProgram.cs:125` | Debug HTTP handler disables TLS validation with a forgeable issuer-name check |
| F-049 | MEDIUM | 0.4 | business-logic | `src/EventBusRabbitMQ/RabbitMQEventBus.cs:180` | Consumer ACKs messages even when processing throws, silently discarding failed or injected events |
| F-050 | MEDIUM | 0.4 | weak-crypto | `src/Identity.API/Configuration/Config.cs:148` | Implicit grant enabled with AllowAccessTokensViaBrowser for three swagger clients |
| F-051 | LOW | 0.4 | oidc-redirect-hijack | `src/ClientApp/Platforms/Android/WebAuthenticationCallbackActivity.cs:6` | Exported activity accepts the unverified custom scheme maui://authcallback and the callback URL is hardcoded |
| F-052 | LOW | 0.4 | session-management | `src/WebApp/Extensions/Extensions.cs:71` | Session cookie uses sliding expiration with no absolute lifetime and default Secure/SameSite policy |
| F-053 | LOW | 0.4 | mitm | `src/WebApp/Extensions/Extensions.cs:82` | OIDC metadata fetching over plaintext is permitted for the WebApp and WebhookClient |
| F-054 | LOW | 0.4 | info-disclosure | `src/eShop.ServiceDefaults/OpenApi.Extensions.cs:24` | OpenAPI documents are mapped in every environment and may be reachable through the BFF |
| F-055 | MEDIUM | 0.3 | business-logic | `src/PaymentProcessor/IntegrationEvents/EventHandling/OrderStatusChangedToStockConfirmedIntegrationEventHandler.cs:21` | Payment outcome is a fixed configuration flag with no order, amount or idempotency validation |
| F-056 | LOW | 0.3 | ci-supply-chain | `.github/skills/aspire-deployment/references/github-actions-azure-csharp.yml:36` | Deployment workflow templates pipe a remote script to bash while holding id-token: write |
| F-057 | LOW | 0.3 | unbounded-input | `src/Catalog.API/Apis/CatalogApi.cs:300` | Anonymous semantic-search text is forwarded unbounded to the external embedding provider and logged verbatim |
| F-058 | LOW | 0.3 | cleartext-transport | `src/HybridApp/MauiProgram.cs:9` | Hybrid Blazor client hardcodes a cleartext HTTP BFF base address in all build configurations |
| F-059 | LOW | 0.3 | xss | `src/WebApp/Program.cs:32` | Same-origin product-image proxy will serve attacker-named SVG files with image/svg+xml |
| F-060 | LOW | 0.3 | auth-bypass | `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:24` | AddDefaultAuthentication fails open when the Identity section is missing |
| F-061 | MEDIUM | 0.2 | sensitive-data-storage | `src/Ordering.Infrastructure/EntityConfigurations/PaymentMethodEntityTypeConfiguration.cs:27` | Full card number (PAN) persisted in cleartext in ordering.paymentmethods |

### F-001 — Catalog write endpoints (POST/PUT/DELETE) are completely unauthenticated and reachable through the external mobile BFF

- **Severity:** HIGH  
- **Confidence:** 0.9 (Catalog registers no authentication and maps writes unprotected; the external BFF catch-all forwards them; anonymous writes confirmed.)  
- **Category:** auth-bypass  
- **Location:** `src/Catalog.API/Apis/CatalogApi.cs:100`

**Description.** Catalog.API never registers authentication/authorization and maps PUT (100, 105), POST (110) and DELETE (114) without RequireAuthorization. AppHost/Extensions.cs:142 exposes the catalog cluster through the external mobile-bff catch-all /api/catalog/{*any}, so internet clients reach the writes.

**Exploit scenario.** curl -X DELETE https://<bff>/api/catalog/items/1?api-version=1.0 wipes items; PUT rewrites price/stock and publishes a price-change event; POST creates arbitrary rows — no credential required.

**Recommendation.** Require authenticated, authorized callers for all mutations, enable UseAuthentication/UseAuthorization, and restrict the BFF to GET.

### F-002 — CVV, card number and full PII are issued in id_tokens/userinfo to every client

- **Severity:** HIGH  
- **Confidence:** 0.9 (ProfileService assigns every claim regardless of RequestedClaimTypes, and AlwaysIncludeUserClaimsInIdToken makes the CVV/PAN/PII over-disclosure concrete.)  
- **Category:** sensitive-data-exposure  
- **Location:** `src/Identity.API/Services/ProfileService.cs:23`

**Description.** GetProfileDataAsync ignores requested claim types/scopes and sets IssuedClaims to every claim from GetClaimsFromUser: card_number (71), card_holder (74), card_security_number (77), card_expiration (80), full address (82-95), email (101), phone (110). All clients set AlwaysIncludeUserClaimsInIdToken=true, so even the low-privilege webhooksclient receives PAN/CVV/address in its ID token and userinfo. Card/CVV are also persisted in identitydb.

**Exploit scenario.** Any holder of a user token — a malicious client, a leaked token, a refresh token redeemed with the public secret, or the webhooks client — calls /connect/userinfo and obtains the user's CVV, PAN, expiry, address, email and phone.

**Recommendation.** Honor RequestedClaimTypes, emit card/address claims only for an explicit scope, never emit CVV in any token, drop AlwaysIncludeUserClaimsInIdToken where unnecessary, and stop storing CVV.

### F-003 — RSA token-signing private key committed to the repository and used as the live signing credential

- **Severity:** HIGH  
- **Confidence:** 0.9 (tempkey.jwk is git-tracked with full RSA private params, copied to output, and is the live non-rotating issuer key; only caveat is sample-repo context.)  
- **Category:** hardcoded-secret  
- **Location:** `src/Identity.API/tempkey.jwk:1`

**Description.** tempkey.jwk is a full RSA private JWK (D/P/Q/DP/DQ/QI present) tracked in git and copied to build output via Identity.API.csproj:50. Program.cs:37 calls AddDeveloperSigningCredential() with no explicit key, so Duende loads tempkey.jwk as the issuer signing key; Program.cs:29 sets KeyManagement.Enabled=false, so the key never rotates. Anyone with repo or published-artifact access can mint tokens signed with the issuer key. APIs validate against the issuer JWKS with ValidateAudience=false (AuthenticationExtensions.cs:33-49), so forged tokens are accepted. Duplicate of F-10-01.

**Exploit scenario.** Extract D/P/Q from tempkey.jwk, mint an RS256 JWT with kid F7383A0ED7CD960EF473FD2851803938 and iss=<identity host>, sub=alice, scope=orders basket webhooks, then call Basket/Ordering/Webhooks APIs — accepted as alice with no credentials.

**Recommendation.** Remove tempkey.jwk from the repo and published output, purge it from git history, rotate the key, load signing material from a secret store, enable KeyManagement, and gate developer credentials to Development.

### F-004 — Any authenticated customer can ship any order

- **Severity:** HIGH  
- **Confidence:** 0.9 (Ship is gated only by group authentication, no role/policy exists, and any body-supplied order id is shipped; confirmed.)  
- **Category:** auth-bypass  
- **Location:** `src/Ordering.API/Apis/OrdersApi.cs:51`

**Description.** PUT /api/orders/ship (11, 51-78) is gated only by group-level RequireAuthorization; there are no roles or policies and no admin role exists. ShipOrderCommandHandler loads the order by the body-supplied OrderNumber and calls SetShippedStatus, whose own comment says it is an administrator action. No ownership check.

**Exploit scenario.** A customer enumerates order ids and marks a victim's Paid order Shipped; the transition is irreversible through normal flow, so the victim cannot cancel while goods were never dispatched.

**Recommendation.** Require an admin/staff policy on ship and never accept the order id without verifying the caller's authority.

### F-005 — GET /api/orders/{orderId} returns any order without an ownership check

- **Severity:** HIGH  
- **Confidence:** 0.9 (OrderQueries filters only on id and the endpoint never uses IIdentityService; confirmed IDOR.)  
- **Category:** idor  
- **Location:** `src/Ordering.API/Application/Queries/OrderQueries.cs:6`

**Description.** OrderQueries.GetOrderAsync(int id) (6-35) queries by id with no caller predicate; OrdersApi.cs:80-91 passes the route value through, and IIdentityService is never consulted. Order ids come from a HiLo sequence and are sequential. The projection includes street/city/state/zip/country, items, prices and status.

**Exploit scenario.** Any authenticated user iterates GET /api/orders/{1..N} and harvests other customers' shipping addresses, purchase history and order state.

**Recommendation.** Filter by o.Buyer.IdentityGuid == caller sub or enforce an order-owner resource authorization policy.

### F-006 — Internet-facing mobile BFF catch-all routes forward unauthenticated requests to anonymous Catalog write endpoints

- **Severity:** HIGH  
- **Confidence:** 0.9 (Catalog has no auth and the external BFF catch-all forwards writes; anonymous internet writes are real.)  
- **Category:** authorization-gap  
- **Location:** `src/eShop.AppHost/Extensions.cs:142`

**Description.** The external YARP ingress has no authentication or route authorization; the catch-all /api/catalog/{*any} (142) and the read routes (97-139) have no method restriction. Catalog.API registers POST/PUT/DELETE with no auth, so internet clients reach writes through the BFF with only an api-version query value.

**Exploit scenario.** curl -X POST https://<bff>/api/catalog/items?api-version=2.0 -d '{...}' creates an item; DELETE removes one; no token required, giving internet write access to price, stock and PictureFileName.

**Recommendation.** Add WithMatchMethod(GET/HEAD) to catalog routes, remove/whitelist the catch-all, require a JWT at the proxy for non-public paths, and never expose Catalog.API anonymously.

### F-007 — JWT bearer disables audience validation, so any token from the IdP is accepted by every API

- **Severity:** HIGH  
- **Confidence:** 0.9 (ValidateAudience=false while APIs use bare RequireAuthorization is a clear cross-audience token acceptance pattern.)  
- **Category:** auth-bypass  
- **Location:** `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:49`

**Description.** AddDefaultAuthentication sets options.Audience but disables the check with ValidateAudience=false (49); endpoints use bare RequireAuthorization(). Signature, lifetime and issuer are validated, but a token minted for audience webhooks or an ID token for webapp/maui is accepted by Ordering. Duplicate of F-10-03.

**Exploit scenario.** An attacker obtains a low-privilege token (webhooksclient or a mobile ID token) and replays it against /api/orders, reading or modifying other users' orders.

**Recommendation.** Set ValidateAudience=true or enforce per-API scope policies, and restrict ValidTypes to access tokens.

### F-008 — Any authenticated user can cancel any other user's order

- **Severity:** MEDIUM  
- **Confidence:** 0.9 (Cancel accepts only an order number and never compares the caller identity; confirmed.)  
- **Category:** idor  
- **Location:** `src/Ordering.API/Apis/OrdersApi.cs:22`

**Description.** PUT /api/orders/cancel (22-49) takes only the order number from the body and requires just authentication. CancelOrderCommandHandler (19-28) loads the order and calls SetCancelledStatus without comparing it to the caller's sub; the validator checks only non-zero.

**Exploit scenario.** An attacker iterates ids and cancels every order in a cancellable state, denying purchases and corrupting inventory/payment records at scale.

**Recommendation.** Resolve the caller via IIdentityService and reject unless the order belongs to them; return 404 for non-owned ids.

### F-009 — CreateOrder trusts body-supplied UserId instead of the JWT sub claim

- **Severity:** MEDIUM  
- **Confidence:** 0.9 (CreateOrder builds the command from request.UserId without consulting IIdentityService; body-supplied identity is authoritative.)  
- **Category:** auth-bypass  
- **Location:** `src/Ordering.API/Apis/OrdersApi.cs:141`

**Description.** CreateOrderRequest carries UserId/UserName/Buyer from the JSON body (171-185); CreateOrderAsync builds CreateOrderCommand from request.UserId (141) without consulting IIdentityService. The value becomes the Order buyer id, buyer lookup/creation and OrderStartedIntegrationEvent(UserId), which Basket.API uses to delete /basket/{UserId}.

**Exploit scenario.** (a) Accountability bypass with a fabricated GUID; (b) supply a victim's GUID to create an order in their name and delete their basket via the OrderStarted event; (c) spoof the buyer name shown to staff.

**Recommendation.** Ignore client-supplied identity, resolve sub/name server-side, and remove UserId/UserName/Buyer from the public contract.

### F-010 — Order item prices and quantities are accepted from the client request, allowing arbitrary order totals

- **Severity:** MEDIUM  
- **Confidence:** 0.9 (UnitPrice and Quantity are copied from the request and persisted with no catalog/basket re-fetch; confirmed.)  
- **Category:** business-logic  
- **Location:** `src/Ordering.API/Extensions/BasketItemExtensions.cs:20`

**Description.** BasketItemExtensions.ToOrderItemDTO copies UnitPrice and Units verbatim from the request body (13-23); CreateOrderCommandHandler passes them into AddOrderItem without re-fetching catalog or basket prices. The validator checks only that items are non-empty, so a unit price of 0.01 or 0 is accepted.

**Exploit scenario.** POST an order with unitPrice 0.01 for a product; the order is persisted with that total and flows through stock/payment/refund logic. Quantity and display names are equally arbitrary.

**Recommendation.** Load authoritative prices/quantities server-side from the caller's basket or Catalog and validate the submitted items against them.

### F-011 — Identity DB seeder re-creates demo users alice/bob with password Pass123$ and the login page advertises it

- **Severity:** HIGH  
- **Confidence:** 0.8 (Seeder creates alice/bob with Pass123$ on every startup and the login page prints the hint; directly exploitable.)  
- **Category:** hardcoded-secret  
- **Location:** `src/Identity.API/UsersSeed.cs:33`

**Description.** UsersSeed.cs:33/78 create alice and bob with Pass123$ on every startup via AddMigration (Program.cs:12); deleting the rows does not remove the credential because the next boot recreates them. Views/Account/Login.cshtml:46 renders the credential hint to anonymous visitors. The seed also contains card PAN/CVV and address fields. Duplicates: F-01-06, F-10-02.

**Exploit scenario.** An unauthenticated visitor reads the login-page hint, signs in as alice/Pass123$, and obtains an SSO session plus tokens containing alice's card, address and order data.

**Recommendation.** Remove the hardcoded password and hint, seed only in Development from configuration/secret storage, force per-deployment passwords, and drop card/PII from seed data.

### F-012 — OIDC confidential-client secret `secret` is hardcoded for webapp and webhooksclient

- **Severity:** MEDIUM  
- **Confidence:** 0.8 (WebApp and WebhookClient hardcode ClientSecret=secret matching the server registration; concrete hardcoded credential.)  
- **Category:** hardcoded-secret  
- **Location:** `src/WebApp/Extensions/Extensions.cs:78`

**Description.** WebApp hardcodes ClientId=webapp and ClientSecret=secret (77-78); WebhookClient does the same (53-54). The server registers new Secret("secret".Sha256()) for webapp/webhooksclient/maui, and webapp has RequirePkce=false, so the public secret is the only client-authentication control.

**Exploit scenario.** Anyone with an authorization code or refresh token for webapp can redeem it at /connect/token using the public secret; confidential-client separation provides no protection.

**Recommendation.** Load client secrets from a secret store, use distinct secrets, rotate, and enable RequirePkce on webapp.

### F-013 — Unauthenticated /add-webhook page renders the configured webhook validation token into the HTML

- **Severity:** MEDIUM  
- **Confidence:** 0.8 (No [Authorize] on the page and the token is copied into a bound input rendered to anonymous visitors; confirmed.)  
- **Category:** sensitive-data-exposure  
- **Location:** `src/WebhookClient/Components/Pages/AddWebhook.razor:30`

**Description.** The page has no [Authorize]; OnInitialized copies WebhookClientOptions.Token into the token field (28-31), which is bound to an input (14) and emitted in the prerendered HTML. That token is the shared secret checked on /check and /webhook-received.

**Exploit scenario.** curl https://<webhookclient>/add-webhook returns the token input value with no cookies; the token then passes X-eshop-whtoken validation for forged webhooks.

**Recommendation.** Add [Authorize], stop pre-filling the secret into a DOM input, and never render the token.

### F-014 — Received-webhook token column is rendered to unauthenticated visitors

- **Severity:** MEDIUM  
- **Confidence:** 0.8 (Token column is outside the AuthorizeView and renders the captured webhook secret to unauthenticated visitors; confirmed.)  
- **Category:** sensitive-data-exposure  
- **Location:** `src/WebhookClient/Components/Pages/Home/ReceivedMessages.razor:13`

**Description.** Home.razor wraps only RegisteredHooks in AuthorizeView; ReceivedMessages renders for everyone and includes a Token column (13). The token is the X-eshop-whtoken value captured from deliveries and equals the shared secret for UI-created subscriptions.

**Exploit scenario.** An unauthenticated visitor polls / until a webhook arrives and reads the token column, then posts forged /webhook-received records that pass validation.

**Recommendation.** Remove or mask the token column and move ReceivedMessages inside the authenticated view.

### F-015 — Anonymous POST /webhook-received injects arbitrary data into a global store rendered to every visitor

- **Severity:** MEDIUM  
- **Confidence:** 0.8 (Anonymous POST with root ValidateToken unset stores attacker data rendered to all visitors; confirmed.)  
- **Category:** auth-bypass  
- **Location:** `src/WebhookClient/Endpoints/WebhookEndpoints.cs:31`

**Description.** MapPost("/webhook-received") (31-53) has no RequireAuthorization or antiforgery; the JSON body is deserialized into WebhookData and stored in the singleton HooksRepository (46). Token validation is skipped when root ValidateToken is false, which is the default. Records are rendered on the anonymous home page.

**Exploit scenario.** POST a forged OrderPaid payload with any X-eshop-whtoken; the record is pushed to every open ReceivedMessages grid, forging paid-order events for operators.

**Recommendation.** Require operator authorization, enable token validation by default and fail closed, and use HMAC over the body.

### F-016 — Webhook signing token written to logs in cleartext at Information level

- **Severity:** MEDIUM  
- **Confidence:** 0.8 (Token and expected token are logged verbatim at Information and exported via OTLP; confirmed.)  
- **Category:** sensitive-data-in-logs  
- **Location:** `src/Webhooks.API/Services/GrantUrlTesterService.cs:17`

**Description.** Line 17 logs the caller token verbatim; line 25 logs expected and received tokens. The level is Information, so it runs in normal operation, and ServiceDefaults exports formatted logs to OTLP.

**Exploit scenario.** Anyone with log/dashboard/OTLP access greps for the message and obtains tenants' X-eshop-whtoken values, then forges webhook deliveries or poisons receiver queues.

**Recommendation.** Remove token values from log templates; log only a boolean or truncated hash, and redact the header in telemetry.

### F-017 — NuGet vulnerability audit warnings globally suppressed

- **Severity:** LOW  
- **Confidence:** 0.8 (NU1901-NU1904 suppression with warnings-as-errors is exactly as described and disables audit solution-wide.)  
- **Category:** insecure-default  
- **Location:** `Directory.Build.props:11`

**Description.** NoWarn includes NU1901;NU1902;NU1903;NU1904 with TreatWarningsAsErrors=true, disabling restore-time audit for all direct and transitive dependencies.

**Exploit scenario.** A vulnerable package version is introduced and the build stays green because the audit warning is suppressed, shipping the CVE to production.

**Recommendation.** Remove the suppressions or narrow them to reviewed packages so new advisories fail the build.

### F-018 — Expected webhook token is logged in cleartext on every unauthenticated request

- **Severity:** LOW  
- **Confidence:** 0.8 (Expected token is logged at Information on every request, including rejections, with OTLP export; confirmed.)  
- **Category:** sensitive-data-exposure  
- **Location:** `src/WebhookClient/Endpoints/WebhookEndpoints.cs:35`

**Description.** Line 35 logs the caller token and the expected secret at Information level before validation, including for rejected requests. The logs are exported via OTLP.

**Exploit scenario.** Anyone with log access learns the shared webhook secret without touching the app, then forges deliveries that pass X-eshop-whtoken validation.

**Recommendation.** Remove the expected-token argument and log only a boolean outcome with constant-time comparison.

### F-019 — Create/Update bind the full CatalogItem entity, allowing overposting of Id, PictureFileName, Price and stock fields

- **Severity:** HIGH  
- **Confidence:** 0.7 (Overposting via entity binding is confirmed, though it is largely a sub-case of the anonymous write surface.)  
- **Category:** mass-assignment  
- **Location:** `src/Catalog.API/Apis/CatalogApi.cs:415`

**Description.** CreateItem (415-437) blindly copies Id, brand/type, Description, PictureFileName, Price and stock thresholds. UpdateItem (373-412) calls CurrentValues.SetValues(productToUpdate) (390), copying every scalar including Id, Price and PictureFileName, and line 392 overwrites Embedding with null when AI is disabled. The V1 Id null check at 364 is dead.

**Exploit scenario.** POST sets price -999.99 and stock 2147483647; PUT reprices an item to one cent, publishes the fabricated price change, and wipes its embedding so it disappears from semantic search.

**Recommendation.** Introduce request DTOs with client-owned fields only, never bind Id/PictureFileName/OnReorder, validate price/stock bounds, and preserve Embédding when no generator is configured.

### F-020 — All confidential OIDC clients share the literal client secret "secret", including the public MAUI client

- **Severity:** HIGH  
- **Confidence:** 0.7 (Identical literal secret for all three clients and embedded in the MAUI app is real; the exact code-interception chain is somewhat speculative.)  
- **Category:** hardcoded-secret  
- **Location:** `src/Identity.API/Configuration/Config.cs:52`

**Description.** maui (Config.cs:52), webapp (82) and webhooksclient (118) all use new Secret("secret".Sha256()); the MAUI app also embeds DefaultClientSecret="secret" (SettingsService.cs:19). Client authentication therefore adds no security. The maui client uses custom scheme maui://authcallback with AllowAccessTokensViaBrowser=true (71). Duplicate of F-10-05.

**Exploit scenario.** A malicious app registers maui://authcallback, starts its own PKCE flow, receives the code via the victim's SSO session, and redeems it at /connect/token with client_secret=secret, obtaining the victim's tokens and card/address claims.

**Recommendation.** Issue unique high-entropy secrets per client from a secret store, make the native client public (no secret) with mandatory PKCE and verified redirect URIs, and rotate the current values.

### F-021 — Authenticated user can force server-side OPTIONS/POST requests to arbitrary hosts

- **Severity:** HIGH  
- **Confidence:** 0.7 (No allowlist or private-range checks and the same-origin check compares two attacker URLs; the OPTIONS SSRF primitive is real.)  
- **Category:** ssrf  
- **Location:** `src/Webhooks.API/Services/GrantUrlTesterService.cs:21`

**Description.** Subscription creation passes caller-controlled Url/GrantUrl to TestGrantUrl (WebHooksApi.cs:41). Validation is only Uri.IsWellFormedUriString plus CheckSameOrigin comparing the two attacker-supplied URLs. There is no allowlist, private-range block, scheme restriction or DNS pinning; the server sends OPTIONS with the caller token (13-21). Service discovery is enabled, so Aspire names resolve to internal services; 201 vs 400 leaks whether an internal host answered.

**Exploit scenario.** Register a webhook with Url=GrantUrl=http://169.254.169.254/latest/meta-data/... and an empty token; if OPTIONS returns 2xx the metadata URL is stored, then DNS rebinding or a 307 redirect makes delivery POST to internal services or metadata.

**Recommendation.** Allowlist schemes/hosts, reject private/loopback/link-local/metadata ranges after DNS resolution, disable redirects and re-validate, pin DNS, and disable service discovery for user URLs.

### F-022 — Persistent blind SSRF: stored DestUrl is POSTed without re-validation and redirects are followed

- **Severity:** HIGH  
- **Confidence:** 0.7 (Stored DestUrl is POSTed without re-validation and redirects are followed; genuine persistent SSRF.)  
- **Category:** ssrf  
- **Location:** `src/Webhooks.API/Services/WebhooksSender.cs:32`

**Description.** The persisted DestUrl is used directly in new Uri(subs.DestUrl) and SendAsync (15-32), with no re-validation at send time and default redirect following. SendAll fans order payloads (buyer name, order id, items) to every subscription of the type.

**Exploit scenario.** Register a benign destination, later repoint its DNS or return a 307 to an internal URL; when any order is paid, webhooks-api POSTs order data to the attacker-chosen internal address from inside the trusted network.

**Recommendation.** Re-validate at send time with a hardened egress policy, disable auto-redirects, pin DNS, and sign payloads with per-subscription secrets.

### F-023 — Cross-user basket deletion: OrderStarted deletes the basket of any event-supplied UserId, and the publisher takes it from the request body

- **Severity:** MEDIUM  
- **Confidence:** 0.7 (Basket deletion chain from body-supplied UserId is verified and HTTP-reachable, though partly a duplicate of the CreateOrder identity issue.)  
- **Category:** idor  
- **Location:** `src/Basket.API/IntegrationEvents/EventHandling/OrderStartedIntegrationEventHandler.cs:14`

**Description.** The handler deletes /basket/{event.UserId} (14) without verifying event authenticity or ownership. The sole publisher builds the event from CreateOrderRequest.UserId (OrdersApi.cs:141), which is attacker-supplied. Victim GUIDs leak through webhook payloads and span tags.

**Exploit scenario.** Register a webhook for OrderShipped to collect BuyerIdentityGuid values; POST /api/orders with a minimal body whose UserId is the victim's GUID; Basket.API deletes the victim's basket and the order is created in their name.

**Recommendation.** Derive buyer identity from the token in Ordering.API, and only delete a basket after validating a signed event bound to an order.

### F-024 — Webhook token validation reads the wrong configuration key, so ValidateToken is silently ignored

- **Severity:** MEDIUM  
- **Confidence:** 0.7 (Options are bound from WebhookClientOptions but the endpoint reads root ValidateToken, so the documented flag is ignored; confirmed bug.)  
- **Category:** security-misconfiguration  
- **Location:** `src/WebhookClient/Endpoints/WebhookEndpoints.cs:13`

**Description.** WebhookClientOptions declares ValidateToken and is bound from configuration, but WebhookEndpoints.cs:13 reads configuration["ValidateToken"] at the root. Setting WebhookClientOptions__ValidateToken=true still leaves validateToken false, so every request is accepted.

**Exploit scenario.** An operator enables validation via the documented options key; an attacker still posts to /webhook-received without the header and the record is stored.

**Recommendation.** Read the flag from IOptions<WebhookClientOptions>, fail startup when missing, and default to requiring validation.

### F-025 — GET /Account/Logout signs the user out without a prompt, enabling logout CSRF

- **Severity:** LOW  
- **Confidence:** 0.7 (ShowLogoutPrompt=false makes the GET handler sign out directly, bypassing the antiforgery POST; real logout CSRF with limited impact.)  
- **Category:** csrf  
- **Location:** `src/Identity.API/Quickstart/Account/AccountController.cs:152`

**Description.** AccountOptions.ShowLogoutPrompt=false means the GET handler (146-160) always calls Logout(vm) directly, which calls SignOutAsync (175) and bypasses the antiforgery-protected POST. The comment at 291-293 documents that the prompt exists to prevent cross-site forced logout.

**Exploit scenario.** A malicious page navigates the victim to /Account/Logout; the SameSite=Lax cookie is sent on the top-level GET and the session is silently terminated, disrupting checkout or forcing repeated re-authentication.

**Recommendation.** Restore ShowLogoutPrompt=true or require antiforgery-protected POST for all sign-out paths.

### F-026 — Full PAN and CVV are written to logs on order creation, and CVV is logged by every MediatR behavior

- **Severity:** HIGH  
- **Confidence:** 0.6 (Raw CreateOrderRequest logging is real on the missing-x-requestid path, but the claimed CVV leakage from {@Command} is overstated because MEL ToString yields the type name.)  
- **Category:** sensitive-data-in-logs  
- **Location:** `src/Ordering.API/Apis/OrdersApi.cs:134`

**Description.** The empty-x-requestid path (132-136) logs the raw CreateOrderRequest including full CardNumber and CardSecurityNumber before validation. Lines 148-153 log the command; LoggingBehavior.cs:9, TransactionBehavior.cs:41/59, ValidatorBehavior.cs:30 and IdentifiedCommandHandler.cs:79-95 log {@Command}; CreateOrderCommandHandler.cs:47 logs {@Order} with address PII. Only the PAN is masked; the CVV is never removed.

**Exploit scenario.** Any checkout (especially one omitting x-requestid) persists full PAN and CVV in application logs; log/SIEM readers, support staff or a logging compromise obtain card-not-present credentials.

**Recommendation.** Remove card data from loggable objects or add destructuring redaction, delete the raw-request log, and log only order/request ids.

### F-027 — CI actions referenced by mutable tags instead of commit SHAs

- **Severity:** MEDIUM  
- **Confidence:** 0.6 (Mutable action tags are confirmed; standard pinning gap requiring upstream compromise.)  
- **Category:** ci-supply-chain  
- **Location:** `.github/workflows/pr-validation.yml:23`

**Description.** Workflows use actions/checkout@v4, setup-dotnet@v3/v4, setup-node@v4 and upload-artifact@v4, plus an unpinned npm i -g markdownlint-cli. A moved tag changes the code executed in CI, which runs builds/tests and even the AppHost with the job GITHUB_TOKEN.

**Exploit scenario.** An attacker re-points a major tag after compromising the action repo; the next main-branch run executes malicious code with the job token and can tamper with artifacts.

**Recommendation.** Pin every uses: to a full commit SHA and pin the npm tool version.

### F-028 — Logout failure leaves access/refresh tokens in SecureStorage; post-logout redirect is unregistered

- **Severity:** MEDIUM  
- **Confidence:** 0.6 (SignOutAsync leaves tokens on failure, the redirect URI mismatches, and the result is ignored; stale session confirmed though auto-login is overstated.)  
- **Category:** token-exposure  
- **Location:** `src/ClientApp/Services/Identity/IdentityService.cs:47`

**Description.** SignOutAsync clears SecureStorage only on success (45-57); errors return false while tokens remain. PostLogoutRedirectUri is maui://authcallback (16, 142) but IdentityServer registers maui://authcallback/Account/Redirecting (Config.cs:57), so end-session fails. The view model ignores the false result and the app auto-restores the session on next launch.

**Exploit scenario.** A user logs out on a shared device, the session silently survives, and the next launch auto-authenticates as them; the refresh token is never revoked.

**Recommendation.** Clear SecureStorage unconditionally in finally, surface logout failure, register the exact post-logout URI, and revoke the refresh token.

### F-029 — webapp confidential client disables PKCE while its client secret is public

- **Severity:** MEDIUM  
- **Confidence:** 0.6 (Public secret plus RequirePkce=false is a genuine missing control, but exploitation depends on an authorization-code leak.)  
- **Category:** auth-bypass  
- **Location:** `src/Identity.API/Configuration/Config.cs:90`

**Description.** webapp uses GrantTypes.Code with RequirePkce=false (Config.cs:90) and the source-committed secret (82). Any observed authorization code can be exchanged by anyone, with no verifier, using the published secret; offline access is enabled and consent is not required.

**Exploit scenario.** Attacker obtains a ?code= value from a proxy log, browser history or Referer, then POSTs /connect/token with client_id=webapp, client_secret=secret and the code — receiving the victim's access and refresh tokens.

**Recommendation.** Enable RequirePkce=true for every code client and rotate to unique secrets stored outside source.

### F-030 — Chatbot exposes a PII function tool and renders model-chosen image URLs, enabling prompt-injection exfiltration

- **Severity:** MEDIUM  
- **Confidence:** 0.6 (PII tool and unvalidated image MarkupString are confirmed; exploitation depends on probabilistic prompt injection through catalog text.)  
- **Category:** prompt-injection  
- **Location:** `src/WebApp/Components/Chatbot/ChatState.cs:97`

**Description.** ChatState registers GetUserInfo (43), which serializes name, address, email and phone into the LLM conversation (96-115); SearchCatalog feeds catalog text into the same context. Assistant output is rendered through MarkupString, and the image regex accepts any scheme and unvalidated host (MessageProcessor.cs:24,33). There is no tool-argument or image-host allowlist.

**Exploit scenario.** An attacker stores a product description instructing the model to call GetUserInfo and emit an image URL encoding the JSON; a victim who searches that product sends their PII to the attacker's host.

**Recommendation.** Do not expose address/email/phone to the model, delimit untrusted text, restrict images to fixed https hosts, and render assistant text as encoded text.

### F-031 — returnUrl filtering in /user/login is bypassable with protocol-relative URLs

- **Severity:** MEDIUM  
- **Confidence:** 0.6 (Protocol-relative URLs pass the relative-URI check and NavigateTo leaves origin; credible post-auth open redirect.)  
- **Category:** open-redirect  
- **Location:** `src/WebApp/Components/Pages/User/LogIn.razor:15`

**Description.** ReturnUrl is rejected only when the parsed Uri is absolute (13-15); //evil.example and /\evil.example parse as relative, pass the check and reach Nav.NavigateTo, which resolves them cross-origin. The value survives the OIDC round trip.

**Exploit scenario.** Send a victim /user/login?returnUrl=%2F%2Fevil.example%2Flogin; after authenticating they are bounced to an attacker clone that harvests credentials or MFA.

**Recommendation.** Require a rooted single-slash path, reject // and /\, or compare the resolved authority to BaseUri.

### F-032 — Forwarded-header trust enabled globally clears the trusted-proxy list, allowing X-Forwarded-For/Proto spoofing

- **Severity:** MEDIUM  
- **Confidence:** 0.6 (Global forwarded-header enablement clears known proxies; real spoofing vector but mostly self-claims and IsHttps impact.)  
- **Category:** auth-bypass  
- **Location:** `src/eShop.AppHost/Extensions.cs:36`

**Description.** AddForwardedHeaders sets ASPNETCORE_FORWARDEDHEADERS_ENABLED=true on every DotnetProjectResource (30-38). In .NET 10 this clears KnownIPNetworks/KnownProxies, so any client reaching a service directly can dictate RemoteIpAddress and Request.IsHttps — poisoning the diagnostics loopback check and audit logs. Duplicate of F-10-13.

**Exploit scenario.** A logged-in user sends GET /Diagnostics with X-Forwarded-For: 127.0.0.1 and receives the loopback-only view; X-Forwarded-Proto: https makes cleartext requests appear secure.

**Recommendation.** Enable forwarded headers only where a proxy exists and configure KnownProxies/KnownIPNetworks explicitly instead of clearing them.

### F-033 — BFF and WebApp forward bearer tokens and login credentials over hardwired HTTP to internal services

- **Severity:** MEDIUM  
- **Confidence:** 0.6 (BFF ordering/identity hops use http and clients attach bearer tokens, but it depends on the trusted internal network boundary.)  
- **Category:** improper-tls  
- **Location:** `src/eShop.AppHost/Extensions.cs:146`

**Description.** BFF backends use GetEndpoint("http") for ordering (146) and identity (150), and catalog (95). The proxy copies Authorization headers, so mobile bearer tokens and the whole OIDC exchange traverse the internal network in cleartext. WebApp/WebhookClient gRPC clients also use http with AddAuthToken(), and the mobile client hardcodes http://10.0.2.2:11632.

**Exploit scenario.** An attacker on the shared container or local network captures a bearer token from the cleartext /api/orders or /api/catalog hop and replays it against Ordering.API.

**Recommendation.** Use https endpoint references for every backend, enforce TLS/mTLS internally, redirect HTTP to HTTPS on BFF/WebhookClient, and remove hardcoded http base addresses.

### F-034 — Official build pipeline extends a 1ES template from a mutable release tag

- **Severity:** LOW  
- **Confidence:** 0.6 (Mutable template ref is confirmed; retagging requires access to a Microsoft-owned repo.)  
- **Category:** ci-supply-chain  
- **Location:** `ci.yml:18`

**Description.** ci.yml pulls the template with ref: refs/tags/release (18), which defines the entire build (pool, SDL, steps). Re-pointing the tag changes the code executed by the official pipeline in the internal 1ES pool with no repo change.

**Exploit scenario.** An attacker with retag access to the template repo adds a step; the next eShop build executes it inside the internal pool with pipeline service connections.

**Recommendation.** Reference the template by commit SHA or an immutable protected branch.

### F-035 — Full raw integration-event bodies (buyer name, identity GUID) are written to span tags and logs

- **Severity:** LOW  
- **Confidence:** 0.6 (Line 161 tags every consumed body verbatim and events carry buyer PII; severity depends on telemetry access controls.)  
- **Category:** information-disclosure  
- **Location:** `src/EventBusRabbitMQ/RabbitMQEventBus.cs:161`

**Description.** Line 161 tags every consumed message with the full broker body; line 172 logs the raw body on failure. Shipped events carry BuyerName and BuyerIdentityGuid; handlers also log object graphs. The data flows to OTel and console logs.

**Exploit scenario.** Anyone with telemetry access harvests buyer names and identity GUIDs for all orders; the GUIDs are reusable as the victim sub in the cross-user basket deletion chain.

**Recommendation.** Log only event id/type/routing key, add PII redaction, and restrict telemetry endpoints.

### F-036 — Production consumer contains a "throw-fake-exception" body trigger that force-fails and drops any event containing it

- **Severity:** LOW  
- **Confidence:** 0.6 (The throw-on-marker is real production code and BuyerName reaches consumers, but impact is dropping the buyer's own notification.)  
- **Category:** business-logic  
- **Location:** `src/EventBusRabbitMQ/RabbitMQEventBus.cs:163`

**Description.** Lines 163-166 throw whenever the raw body contains that string; combined with ACK-on-exception the message is silently discarded. BuyerName is user-controlled in shipped events, so a buyer can embed the marker in their name and suppress their own shipment event.

**Exploit scenario.** A buyer sets their name to include throw-fake-exception; when the shipped event is published, Webhooks and WebApp consumers throw, log the full body and drop the notification.

**Recommendation.** Remove the test hook or gate it behind Development, and stop ACKing exceptions.

### F-037 — Database container pinned to the mutable ankane/pgvector:latest tag

- **Severity:** LOW  
- **Confidence:** 0.6 (Mutable latest tag is confirmed, but it is a local/CI dev container with limited production exposure.)  
- **Category:** ci-supply-chain  
- **Location:** `src/eShop.AppHost/AppHost.cs:13`

**Description.** The Postgres resource for all four databases uses WithImageTag("latest") (13-14). The tag is mutable and not digest-pinned; the Playwright CI job and developers run this AppHost with real data volumes attached.

**Exploit scenario.** If the image account is compromised or the tag is retagged, the next run starts a backdoored container with the databases attached, able to tamper with data or attack the host network.

**Recommendation.** Pin the image by digest or a specific version tag and mirror it into a controlled registry.

### F-038 — ATS fully disabled in the Mac Catalyst Release bundle and cleartext globally declared on Android

- **Severity:** MEDIUM  
- **Confidence:** 0.5 (ATS disabled and cleartext/backup enabled are confirmed, but pure missing-hardening until combined with the HTTP endpoint finding.)  
- **Category:** improper-transport-config  
- **Location:** `src/ClientApp/Platforms/MacCatalyst/Info.plist:29`

**Description.** MacCatalyst Info.plist sets NSAllowsArbitraryLoads=true (27-31) for all configurations; AndroidManifest sets usesCleartextTraffic=true and allowBackup=true; iOS sets NSAllowsLocalNetworking. These remove the platform guard against the HTTP endpoints in F-09-04.

**Exploit scenario.** A Release Catalyst or iOS build silently loads an HTTP URL, letting a same-network attacker read tokens and card data the OS would otherwise block.

**Recommendation.** Remove NSAllowsArbitraryLoads, scope exceptions to localhost and Debug, disable cleartext and backups in Release.

### F-039 — Gateway endpoints default to plaintext HTTP and have no scheme validation; card PAN/CVV and bearer tokens are POSTed in cleartext

- **Severity:** MEDIUM  
- **Confidence:** 0.5 (HTTP defaults and unvalidated setters are confirmed, but the exploit requires the user to retarget to a LAN IP.)  
- **Category:** cleartext-transport  
- **Location:** `src/ClientApp/ViewModels/SettingsViewModel.cs:58`

**Description.** Defaults are http://{host}:11632 and http://{host}:5221 (55-68); setters store arbitrary strings (129-179). Checkout builds the order from card claims (CheckoutViewModel.cs:58-90) and POSTs it with a bearer token (OrderService.cs:28-40). iOS permits local cleartext, Mac Catalyst disables ATS, Android sets usesCleartextTraffic=true.

**Exploit scenario.** A user points the app at a LAN IP over shared Wi-Fi; an attacker sniffs the order POST and obtains full card data plus the bearer token, and can rewrite catalog prices.

**Recommendation.** Reject non-HTTPS endpoints except an explicit debug host, default to https, and remove cleartext allowances outside Debug.

### F-040 — Order PII is broadcast to every user's subscription of an event type; per-user scoping is stored but not enforced

- **Severity:** MEDIUM  
- **Confidence:** 0.5 (The UserId predicate is genuinely absent, but broadcasting same-type events may be intended semantics.)  
- **Category:** idor  
- **Location:** `src/Webhooks.API/Services/WebhooksRetriever.cs:7`

**Description.** GetSubscriptionsOfType returns all subscriptions matching the type with no UserId predicate (line 7); both event handlers pass the full set to SendAll. Subscriptions are stored per user but delivery ignores the owner, so user A receives events about user B.

**Exploit scenario.** An attacker registers for OrderShipped and receives every customer's BuyerName and OrderId, and can subscribe to OrderPaid to learn other buyers' SKUs and quantities.

**Recommendation.** Scope delivery to the affected user's subscriptions or remove/redact buyer PII from broadcast payloads.

### F-041 — OIDC/JWT metadata acquisition is allowed over HTTP, enabling signing-key substitution

- **Severity:** MEDIUM  
- **Confidence:** 0.5 (RequireHttpsMetadata=false is unconditional, but key substitution only matters when an http authority is actually used.)  
- **Category:** improper-tls  
- **Location:** `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:39`

**Description.** RequireHttpsMetadata=false is set unconditionally in the JWT bearer handler (39) and both OIDC clients (WebApp Extensions.cs:82, WebhookClient Extensions.cs:58). With an http:// authority the discovery document and JWKS are fetched in cleartext; an on-path attacker can substitute keys. The AppHost uses http when ESHOP_USE_HTTP_ENDPOINTS=1 or when Identity__Url points at an internal HTTP address. Duplicate: F-10-04.

**Exploit scenario.** On a deployment with Identity__Url=http://identity, a network attacker replaces the JWKS with their own key and mints tokens issued by that authority; APIs accept them as any user.

**Recommendation.** Remove RequireHttpsMetadata=false (gate to Development), require https authorities, and pin/validate metadata.

### F-042 — ACR build script takes a GitHub PAT as a mandatory command-line argument

- **Severity:** LOW  
- **Confidence:** 0.5 (Mandatory PAT in argv is confirmed, but it is a local legacy operator script with no remote path.)  
- **Category:** credential-exposure  
- **Location:** `build/acr-build/queue-all.ps1:6`

**Description.** queue-all.ps1 declares a mandatory $patToken (6) and passes it to az acr build-task create --git-access-token (32). The PAT is visible in process listings, history and transcripts, and is inherited by the az child process.

**Exploit scenario.** A local user or process reads the az/pwsh command line during a run and recovers the repository PAT, then clones/pushes to the repo or creates build tasks.

**Recommendation.** Read the PAT from an environment variable or secure prompt, avoid argv, and use a short-lived least-privilege token.

### F-043 — OIDC confidential-client secret (`secret`) embedded in the shipped app and stored in plaintext Preferences

- **Severity:** LOW  
- **Confidence:** 0.5 (Hardcoded secret in a public native client with PKCE is real but low impact in the demo stack.)  
- **Category:** hardcoded-secret  
- **Location:** `src/ClientApp/Services/Settings/SettingsService.cs:15`

**Description.** DefaultClientSecret="secret" (15) is returned and used as OidcClientOptions.ClientSecret (IdentityService.cs:139); IdentityServer enforces it. It is persisted via Preferences (plaintext), and Android allows backup.

**Exploit scenario.** Anyone with the APK or an adb backup extracts maui/secret and reuses it against the IdP (token-endpoint abuse; PKCE limits direct token minting).

**Recommendation.** Configure the native client as public (no secret, PKCE required) and remove the secret from the app and Preferences.

### F-044 — Loopback-only diagnostics gate can be satisfied with a spoofed X-Forwarded-For header

- **Severity:** LOW  
- **Confidence:** 0.5 (Loopback gate is as described, but exploitation needs global forwarded-header trust and direct Identity reachability; impact is the caller's own claims.)  
- **Category:** auth-bypass  
- **Location:** `src/Identity.API/Quickstart/Diagnostics/DiagnosticsController.cs:14`

**Description.** DiagnosticsController compares Connection.RemoteIpAddress to loopback (13-17) but the AppHost enables ASPNETCORE_FORWARDEDHEADERS_ENABLED for every service with the known-proxy list cleared, so X-Forwarded-For rewrites the address. An authenticated remote caller sending X-Forwarded-For: 127.0.0.1 receives the diagnostics view of their own claims/properties instead of 404.

**Exploit scenario.** A user with any valid cookie sends GET /Diagnostics with X-Forwarded-For: 127.0.0.1 and receives session claims and cookie properties that the loopback check was meant to keep local.

**Recommendation.** Configure ForwardedHeadersOptions with an explicit KnownProxies/KnownNetworks allowlist (or remove the endpoint outside Development) and gate diagnostics on authorization rather than IP.

### F-045 — WebhookClient /login returnUrl is passed to NavigateTo after only a UriKind.Relative parse

- **Severity:** LOW  
- **Confidence:** 0.5 (Same mechanism is real and the login page is reachable, but impact is lower and absolute URLs throw.)  
- **Category:** open-redirect  
- **Location:** `src/WebhookClient/Components/Pages/LogIn.razor:9`

**Description.** new Uri(ReturnUrl ?? "", UriKind.Relative) accepts protocol-relative strings (9-10), which NavigateTo resolves cross-origin; absolute URLs throw and end at /Error.

**Exploit scenario.** An operator follows /login?returnUrl=%2F%2Fevil.example after signing in and lands on an attacker-cloned page.

**Recommendation.** Validate a rooted path (StartsWith("/") and not "//" or "/\\") and reject absolute URIs explicitly.

### F-046 — Webhook validation shared secret committed in appsettings.json

- **Severity:** LOW  
- **Confidence:** 0.5 (Committed GUID is confirmed as the validation token, but it only matters when validation is enabled, which is off and misconfigured by default.)  
- **Category:** hardcoded-secret  
- **Location:** `src/WebhookClient/appsettings.json:10`

**Description.** WebhookClientOptions:Token is the fixed GUID 6168DB8D-DC58-4094-AF24-483278923590, used to authenticate incoming deliveries; it ships in default config and is identical for every deployment.

**Exploit scenario.** Read the GUID from the repo and POST a forged payload with X-eshop-whtoken: <GUID>; if validation is enabled it is accepted as genuine (by default validation is off).

**Recommendation.** Move the token to per-deployment secret storage or generate it per subscription, default validation to true, and use payload HMAC.

### F-047 — Integration events are dispatched on the unauthenticated routing key; any publisher can forge any event

- **Severity:** HIGH  
- **Confidence:** 0.4 (Dispatch is routing-key-only with no publisher identity, but exploitation presupposes broker write access; architectural trust weakness.)  
- **Category:** event-forgery  
- **Location:** `src/EventBusRabbitMQ/RabbitMQEventBus.cs:192`

**Description.** OnMessageReceived takes the event name from the routing key and dispatches to handlers (192-207) with no signature, publisher identity, vhost separation or replay protection. All services share one exchange and AMQP credentials over plaintext. Consumers trust payloads: OrderStarted deletes /basket/{UserId}, stock/payment events advance order state, PaymentProcessor emits success for any OrderId.

**Exploit scenario.** With broker access, publish OrderStatusChangedToStockConfirmedIntegrationEvent {"OrderId":N} and PaymentProcessor emits success, Ordering.API marks the order Paid; publish OrderStarted {"UserId":victim} to delete a victim's basket; replay at will.

**Recommendation.** Use per-service credentials/vhosts and TLS, sign messages with per-publisher keys and verify before dispatch, and add replay protection plus handler-side invariant checks.

### F-048 — Debug HTTP handler disables TLS validation with a forgeable issuer-name check

- **Severity:** MEDIUM  
- **Confidence:** 0.4 (Spoofable issuer check is real but entirely #if DEBUG and returns null in Release; debug-only artifact.)  
- **Category:** improper-cert-validation  
- **Location:** `src/ClientApp/MauiProgram.cs:125`

**Description.** The #if DEBUG handler is injected into RequestProvider and the OIDC backchannel (78-91, 146-149). On Android it accepts any certificate whose issuer is CN=localhost (125-133), which is attacker-chosen; on iOS/Mac Catalyst it trusts any https://localhost URL (138). Compiled out in Release.

**Exploit scenario.** With a Debug build, an attacker on the same network DNS/ARP-spoofs the host and presents a self-signed CN=localhost cert, capturing the authorization code, refresh token and bearer tokens.

**Recommendation.** Remove the callback or pin a specific developer CA fingerprint behind a non-distributable build flag, and never apply it to the OIDC backchannel.

### F-049 — Consumer ACKs messages even when processing throws, silently discarding failed or injected events

- **Severity:** MEDIUM  
- **Confidence:** 0.4 (Unconditional ACK after exception is confirmed, but it is a reliability issue the code labels a simplification and requires broker access.)  
- **Category:** business-logic  
- **Location:** `src/EventBusRabbitMQ/RabbitMQEventBus.cs:180`

**Description.** ProcessEvent failures are caught (170-175) and the message is unconditionally ACKed (180); there is no DLQ or retry. Handler and deserialization exceptions cause permanent silent loss and erase evidence of injected events.

**Exploit scenario.** Publish a body that throws during dispatch; it is logged and ACKed, never retried or dead-lettered. Repeating for a target order suppresses the expected state transition.

**Recommendation.** Only ACK after successful handling; nack to a DLX on shape failures and a bounded retry queue for transient failures, and alert on DLQ growth.

### F-050 — Implicit grant enabled with AllowAccessTokensViaBrowser for three swagger clients

- **Severity:** MEDIUM  
- **Confidence:** 0.4 (Implicit grant with browser tokens is confirmed, but this is largely missing-hardening on Swagger-UI clients requiring an additional compromise.)  
- **Category:** weak-crypto  
- **Location:** `src/Identity.API/Configuration/Config.cs:148`

**Description.** basketswaggerui (148), orderingswaggerui (163) and webhooksswaggerui (178) use GrantTypes.Implicit with AllowAccessTokensViaBrowser=true, returning access tokens in the URL fragment where they are exposed to history, scripts and injected content.

**Exploit scenario.** A user authenticates to a Swagger UI; the token lands in the fragment. Script access to that origin, a malicious extension or history access yields the token and API access as the victim.

**Recommendation.** Migrate these clients to code + PKCE (AllowAccessTokensViaBrowser=false) or disable them outside Development.

### F-051 — Exported activity accepts the unverified custom scheme maui://authcallback and the callback URL is hardcoded

- **Severity:** LOW  
- **Confidence:** 0.4 (Custom-scheme hijack is real but PKCE defeats code redemption; at most broken/influenced login.)  
- **Category:** oidc-redirect-hijack  
- **Location:** `src/ClientApp/Platforms/Android/WebAuthenticationCallbackActivity.cs:6`

**Description.** The redirect uses a private-use scheme registered by an exported activity (6-10), so any app can register the same filter. MauiAuthenticationBrowser reconstructs the result from the literal maui://authcallback rather than the configured CallbackUri (13-20). PKCE is enforced server-side, limiting impact.

**Exploit scenario.** A malicious app registers maui://authcallback and intercepts the authorization response, breaking or influencing login (code redemption fails without the verifier).

**Recommendation.** Use HTTPS App Links/Universal Links or loopback, and derive/validate the returned URL from the configured redirect URI.

### F-052 — Session cookie uses sliding expiration with no absolute lifetime and default Secure/SameSite policy

- **Severity:** LOW  
- **Confidence:** 0.4 (Sliding cookie with no absolute lifetime and SaveTokens is a weak default, but largely missing-hardening.)  
- **Category:** session-management  
- **Location:** `src/WebApp/Extensions/Extensions.cs:71`

**Description.** The cookie handler sets only ExpireTimeSpan (71); SlidingExpiration defaults true with no absolute limit, so any request renews the 60-minute session. SecurePolicy stays SameAsRequest, SameSite Lax, and SaveTokens=true stores access/refresh tokens in the ticket. WebhookClient has the same sliding configuration.

**Exploit scenario.** A captured auth cookie can be replayed periodically to keep the session and contained tokens alive indefinitely, and lacks Secure if any request is served over HTTP.

**Recommendation.** Disable sliding expiration or add an absolute lifetime, set SecurePolicy=Always, set SameSite explicitly, and avoid SaveTokens where unnecessary.

### F-053 — OIDC metadata fetching over plaintext is permitted for the WebApp and WebhookClient

- **Severity:** LOW  
- **Confidence:** 0.4 (RequireHttpsMetadata=false is confirmed, but it requires an http authority plus an on-path attacker and duplicates an existing finding.)  
- **Category:** mitm  
- **Location:** `src/WebApp/Extensions/Extensions.cs:82`

**Description.** Both OIDC handlers set RequireHttpsMetadata=false (WebApp 82, WebhookClient 58) with SaveTokens=true; no environment guard limits it, and WebhookClient has no HTTPS redirection.

**Exploit scenario.** An attacker on the internal network or an operator using an http://identity authority can substitute discovery/JWKS and mint accepted tokens, or downgrade the code exchange.

**Recommendation.** Remove RequireHttpsMetadata=false or gate it to Development, require HTTPS authorities, and add HTTPS redirection to WebhookClient.

### F-054 — OpenAPI documents are mapped in every environment and may be reachable through the BFF

- **Severity:** LOW  
- **Confidence:** 0.4 (MapOpenApi outside the dev guard is verified, but schema disclosure is low impact and BFF dot-segment reachability is unproven.)  
- **Category:** info-disclosure  
- **Location:** `src/eShop.ServiceDefaults/OpenApi.Extensions.cs:24`

**Description.** MapOpenApi() is called whenever the OpenApi section exists (19-24), outside the IsDevelopment guard that only wraps Scalar UI (26-42). Catalog, Ordering and Webhooks all ship the section, so /openapi/{document}.json is unauthenticated in production. BFF dot-segment canonicalisation may allow reaching it.

**Exploit scenario.** An unauthenticated request to /api/catalog/../openapi/v1.json through the BFF yields the full schema, revealing write routes and parameter shapes.

**Recommendation.** Map OpenAPI only inside IsDevelopment or protect it with authorization, and reject dot segments in proxy routes.

### F-055 — Payment outcome is a fixed configuration flag with no order, amount or idempotency validation

- **Severity:** MEDIUM  
- **Confidence:** 0.3 (No order/amount/idempotency checks is real, but it is explicitly documented as a payment simulation and needs broker access.)  
- **Category:** business-logic  
- **Location:** `src/PaymentProcessor/IntegrationEvents/EventHandling/OrderStatusChangedToStockConfirmedIntegrationEventHandler.cs:21`

**Description.** The handler switches only on PaymentSucceeded (21, default true) and publishes success/failure for the supplied OrderId (23/27/32). It never checks order existence, state, buyer, amount or prior payment; no instrument is involved.

**Exploit scenario.** With broker access, publish a stock-confirmed event for order N; PaymentProcessor emits success regardless of stock or payment, and Ordering.API marks the order Paid. Replays emit repeated success events.

**Recommendation.** Authenticate the event, load and validate the order/amount/state server-side, and use an idempotency key per order; keep the simulation flag behind an explicit demo mode.

### F-056 — Deployment workflow templates pipe a remote script to bash while holding id-token: write

- **Severity:** LOW  
- **Confidence:** 0.3 (It is a documentation reference template, not an active workflow, and its actions are SHA-pinned; risky only if copied.)  
- **Category:** ci-supply-chain  
- **Location:** `.github/skills/aspire-deployment/references/github-actions-azure-csharp.yml:36`

**Description.** The reference workflows use curl -sSL https://aspire.dev/install.sh | bash (36) and grant permissions: id-token: write with Azure OIDC login. The unpinned script runs in an OIDC-enabled job and can exchange a token for the federated Azure identity.

**Exploit scenario.** A compromised or spoofed aspire.dev serves a modified installer that requests an OIDC token and exchanges it for Azure credentials, then deploys or exfiltrates resources.

**Recommendation.** Install the CLI from a pinned checksum-verified release or pinned dotnet tool, never pipe network content to a shell, and scope id-token: write to the login job.

### F-057 — Anonymous semantic-search text is forwarded unbounded to the external embedding provider and logged verbatim

- **Severity:** LOW  
- **Confidence:** 0.3 (Text length is bounded by Kestrel and the harm is unthrottled paid calls plus Trace/Debug logging; mostly volumetric/log-injection.)  
- **Category:** unbounded-input  
- **Location:** `src/Catalog.API/Apis/CatalogApi.cs:300`

**Description.** The semantic-relevance endpoints accept text with no max length (287) and pass it to CatalogAI.GetEmbeddingAsync (300), which calls the configured external provider (CatalogAI.cs:61). There is no rate limit or quota, and the text is logged at Trace/Debug (CatalogAI.cs:64-67, CatalogApi.cs:323).

**Exploit scenario.** Thousands of anonymous requests with 8 KB texts drive paid embedding calls with no quota and can inject forged newline-delimited log entries into the OTel pipeline.

**Recommendation.** Cap text length, require auth or per-IP rate limiting, and log a truncated/hashed query with newline sanitization.

### F-058 — Hybrid Blazor client hardcodes a cleartext HTTP BFF base address in all build configurations

- **Severity:** LOW  
- **Confidence:** 0.3 (Hardcoded emulator HTTP address with no credentials sent; impact limited to forged catalog data on the developer host.)  
- **Category:** cleartext-transport  
- **Location:** `src/HybridApp/MauiProgram.cs:9`

**Description.** MobileBffHost is http://10.0.2.2:11632 or http://localhost:11632 and is used for all catalog data and image URLs; no token is sent. Platform configs permit cleartext.

**Exploit scenario.** On the emulator host, any process binding that address can serve forged catalog JSON/images, controlling product names, descriptions and prices shown to the user.

**Recommendation.** Serve the BFF over HTTPS, use an https base address, and remove release cleartext allowances.

### F-059 — Same-origin product-image proxy will serve attacker-named SVG files with image/svg+xml

- **Severity:** LOW  
- **Confidence:** 0.3 (Precondition is not currently satisfiable: Pics/ holds only webp and there is no upload path; mostly missing-hardening.)  
- **Category:** xss  
- **Location:** `src/WebApp/Program.cs:32`

**Description.** MapForwarder exposes the catalog picture endpoint under the storefront origin; the backend maps .svg to image/svg+xml (CatalogApi.cs:455-466) and PictureFileName is writable via the anonymous catalog API. Today Pics/ holds only .webp, so exploitation needs an SVG placed there.

**Exploit scenario.** Get an SVG with script into Pics, set an item's PictureFileName to it, and lure an authenticated shopper to /product-images/{id}; the script runs in the storefront origin and can make authenticated calls.

**Recommendation.** Serve a strict MIME allowlist (no SVG), add nosniff/Content-Disposition, or use a separate image origin.

### F-060 — AddDefaultAuthentication fails open when the Identity section is missing

- **Severity:** LOW  
- **Confidence:** 0.3 (Early return is real but requires a misconfigured deployment; pre-existing appsettings define Identity, so low practical reachability.)  
- **Category:** auth-bypass  
- **Location:** `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:24`

**Description.** When the Identity configuration section is absent, AddDefaultAuthentication returns before AddAuthentication/AddAuthorization (24-28) instead of throwing. Services that call RequireAuthorization can then run without authorization middleware, serving protected endpoints anonymously.

**Exploit scenario.** A deployment or trimmed image omitting the Identity section starts successfully with auth disabled; /api/orders and /api/webhooks accept unauthenticated reads and writes.

**Recommendation.** Throw at startup when Identity is absent for services requiring authorization, or register auth unconditionally.

### F-061 — Full card number (PAN) persisted in cleartext in ordering.paymentmethods

- **Severity:** MEDIUM  
- **Confidence:** 0.2 (Contradicted by the code: the PAN is masked before the command is built and the security number has no EF mapping.)  
- **Category:** sensitive-data-storage  
- **Location:** `src/Ordering.Infrastructure/EntityConfigurations/PaymentMethodEntityTypeConfiguration.cs:27`

**Description.** PaymentMethod._cardNumber is mapped as CardNumber with no encryption/converter (27-31), and Buyer.VerifyOrAddPaymentMethod stores whatever CreateOrderRequest.CardNumber contained for every checkout. The API's masking does not protect the database copy.

**Exploit scenario.** A database read (backup leak, co-located SQL access, over-broad reporting credentials, insider) yields full PANs and cardholder names for all customers.

**Recommendation.** Do not persist PANs; store a processor token plus card type/last-4/expiry, or encrypt the column with a KMS-backed protector.

