# Triage Report

**25 in -> 0 duplicates, 2 false positives, 23 confirmed (6 high / 9 med / 8 low), 1 need manual test**. Verified against source at 913acea; no application was run.

**Confidence review:** 3 raised (f001, f012, f013), 10 unchanged, 10 downgraded, 2 suppressed vs the scan's claimed severity.

Context: interactive; environment = Internet-facing (BFF-exposed): the Aspire mobile-bff, WebApp and Identity.API are externally reachable; Catalog.API, Ordering.API, Basket.API and Webhooks.API are reached through the BFF catch-all routes and must be judged as untrusted HTTP callers. Catalog writes have no authentication at all.

Scoring: Derived HIGH/MEDIUM/LOW from preconditions and access level (default); 3-vote verification, precision on ties.

Threat model applied: Customer order/PII breach: reading or altering other shoppers' orders, addresses and identities; Token/identity takeover: forging, replaying, or harvesting CVV/PAN from issued claims; Unauthenticated data tampering: anyone rewriting catalog prices, stock or content without logging in; SSRF into internal network: server-side requests to internal services or cloud metadata; Compliance-scoped data exposure (PCI card data in tokens, storage or logs); Supply-chain compromise: vulnerable dependency or build configuration ships a compromised service.

Verification: Each finding re-derived from source (fresh read, code-first, adversarial default) before severity was adjusted; false-positive entries carry an explicit refute reason and the exclusion rule that applied.

## Act on these

### [HIGH] Repository-committed RSA private signing key (tempkey.jwk) is the active token-signing credential  (f001)

`src/Identity.API/Program.cs:37` | hardcoded-secret | claimed HIGH (alignment +1) | confidence 9.0/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (4):**
- Attacker obtains the committed private JWK (public in git, copied to output by Identity.API.csproj:50)
- The deployed Identity.API runs AddDeveloperSigningCredential() with KeyManagement.Enabled=false, so its JWKS matches that key
- The attacker knows the issuer URL string each consumer compares against Identity:Url
- Consumer APIs keep ValidateAudience=false (AuthenticationExtensions.cs:49)

**Access level:** unauthenticated_remote

**Threat-model match:** Token/identity takeover: forging, replaying, or harvesting CVV/PAN from issued claims; also enables Customer order/PII breach: reading or altering other shoppers' orders, addresses and identities and SSRF into internal network: server-side requests to internal services or cloud metadata (a forged webhooks token reaches the grant-URL tester)

**Why:** Program.cs:29 sets KeyManagement.Enabled=false and :37 calls AddDeveloperSigningCredential(); tempkey.jwk is git-tracked (verified with git ls-files) and carries full RSA private material (d, p, q) that is copied to the build output. Every API validates against this instance. No rotation, no environment guard.

**Reachability evidence:** src/Identity.API/Program.cs:37, src/Identity.API/tempkey.jwk:1, src/Identity.API/Identity.API.csproj:50

### [HIGH] Catalog.API writes are unauthenticated by construction: the service has no authentication/authorization middleware  (f003)

`src/Catalog.API/Program.cs:29` | auth-bypass | claimed HIGH (alignment +0) | confidence 9.0/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (2):**
- Attacker can reach Catalog write paths (through the anonymous BFF /api/catalog/{*any} catch-all, or any internal foothold)
- A valid item id or a well-formed CatalogItem body

**Access level:** unauthenticated_remote

**Threat-model match:** Unauthenticated data tampering: anyone rewriting catalog prices, stock or content without logging in

**Why:** Catalog.API Program.cs (:1-29) never calls AddDefaultAuthentication, UseAuthentication or UseAuthorization, and the mutating routes (CatalogApi.cs:100,105,110,114) carry no RequireAuthorization, so the service cannot authenticate a caller at all. Reachable without a token through the externally exposed mobile BFF catch-all (/api/catalog/{*any}, AppHost Extensions.cs:142). Full price, stock and content integrity loss, and forged ProductPriceChanged events fan out to carts and webhook subscribers.

**Reachability evidence:** src/Catalog.API/Program.cs:29, src/Catalog.API/Apis/CatalogApi.cs:110, src/eShop.AppHost/Extensions.cs:142

### [HIGH] IDOR: GET /api/orders/{orderId} returns any buyer's order to any authenticated user  (f004)

`src/Ordering.API/Apis/OrdersApi.cs:80` | auth-bypass | claimed HIGH (alignment +0) | confidence 9.0/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (3):**
- Attacker holds any valid Ordering token (the default webapp/maui scope set includes 'orders')
- Request sent as GET /api/orders/{id}?api-version=1.0 (directly or via the public BFF /api/orders/{*any})
- Order ids are a dense HiLo sequence, so enumeration is trivial

**Access level:** authenticated

**Threat-model match:** Customer order/PII breach: reading or altering other shoppers' orders, addresses and identities

**Why:** GetOrderAsync (:80-91) passes the route orderId straight to OrderQueries.GetOrderAsync, which filters only o.Id == id (OrderQueries.cs:6-35) and returns street, city, state, zip, country, items and total. The sibling GetOrdersByUserAsync (:93-99) does scope by sub, which shows this is a gap. Every self-registered shopper can harvest every order by looping ids until 404.

**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:80, src/Ordering.API/Application/Queries/OrderQueries.cs:10

### [HIGH] PUT /api/orders/cancel and /api/orders/ship are callable by any authenticated shopper on any order  (f006)

`src/Ordering.API/Apis/OrdersApi.cs:22` | auth-bypass | claimed HIGH (alignment +0) | confidence 8.5/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (2):**
- Attacker holds a valid Ordering token (no role or scope beyond 'orders' is required)
- Attacker enumerates an order id and supplies it as orderNumber in the body

**Access level:** authenticated

**Threat-model match:** Customer order/PII breach: reading or altering other shoppers' orders, addresses and identities (integrity: cancelling or shipping another buyer's order)

**Why:** Program.cs:21-22 gates both routes with a bare RequireAuthorization(); there is no role model anywhere in Identity (no role claims are issued), so the 'administrator executes ship' comment in ShipOrderCommandHandler cannot be enforced. Neither endpoint nor handler compares Buyer.IdentityGuid with the caller. Any shopper can cancel or ship any order and fires OrderStatusChangedTo* events to webhook subscribers. A minor gap (no admin model) limits the fix but not the exploit.

**Reachability evidence:** src/Ordering.API/Program.cs:21, src/Ordering.API/Apis/OrdersApi.cs:22

### [HIGH] Externally exposed mobile BFF forwards /api/catalog/{*any} and /api/orders/{*any} without method or route restriction  (f012)

`src/eShop.AppHost/Extensions.cs:146` | auth-bypass | claimed MEDIUM (alignment +1) | confidence 8.0/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (2):**
- The mobile BFF is deployed with external HTTP endpoints (AppHost.cs:63)
- For catalog impact, no additional precondition: Catalog has no auth (F-003)

**Access level:** unauthenticated_remote

**Threat-model match:** Unauthenticated data tampering: anyone rewriting catalog prices, stock or content without logging in via the anonymous catalog catch-all; Customer order/PII breach: reading or altering other shoppers' orders, addresses and identities amplification for any holder of an orders token

**Why:** ConfigureMobileBffRoutes adds /api/catalog/{*any} (:142) and /api/orders/{*any} (:146) with only an api-version query match, no method restriction and no proxy authentication. Because Catalog.API has no auth at all, the catch-all makes unauthenticated catalog writes internet-reachable through the BFF. Raised from MEDIUM to HIGH: without this route the anonymous catalog write defect (F-003) is internal-only, so the BFF is what turns it into an unauthenticated remote issue. The catalog half merges with F-003's impact; the route restriction is a separate fix.

**Reachability evidence:** src/eShop.AppHost/Extensions.cs:142, src/eShop.AppHost/Extensions.cs:146, src/eShop.AppHost/AppHost.cs:63

### [HIGH] Full order entity, including card number, CVV and buyer address, is logged at Information level  (f013)

`src/Ordering.API/Application/Commands/CreateOrderCommandHandler.cs:50` | sensitive-data-in-logs | claimed MEDIUM (alignment +1) | confidence 8.0/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (1):**
- Attacker can read Ordering logs or the OTLP backend (log access is a real precondition, not assumed in a deployed system with shared collectors)

**Access level:** authenticated

**Threat-model match:** Compliance-scoped data exposure (PCI card data in tokens, storage or logs)

**Why:** CreateOrderCommandHandler.cs:47 logs {@Order} of the aggregate that carries CardNumber and CardSecurityNumber; LoggingBehavior.cs:9 and TransactionBehavior.cs:41 log {@Command} for every command, and OrdersApi.cs:134 logs the whole request on the invalid-request path. Default log level is Information (appsettings.json). The CVV is in the serialised object graph even though it is not persisted (see f016). Raised from MEDIUM to HIGH: log aggregation plus OTLP export means card data leaves the process boundary, which is the PCI-scoped exposure the threat model rates as high, and it is triggerable by any shopper's checkout.

**Reachability evidence:** src/Ordering.API/Application/Commands/CreateOrderCommandHandler.cs:47, src/Ordering.API/Application/Behaviors/LoggingBehavior.cs:9

### [MEDIUM] JWT validation sets ValidateAudience=false, so a token minted for one API is accepted by every API  (f002)

`src/eShop.ServiceDefaults/AuthenticationExtensions.cs:49` | auth-bypass | claimed HIGH (alignment -1) | confidence 8.5/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (4):**
- Attacker holds any valid Identity-issued token (any self-registered shopper)
- A client whose AllowedScopes do not include the target API is available (WebhooksClient has only 'webhooks'; all three Swagger implicit clients are single-scope)
- Target API uses AddDefaultAuthentication (Ordering, Webhooks, Basket)
- One of the target APIs is reachable with that token (Ordering via the BFF /api/orders catch-all; Webhooks internally or via the BFF)

**Access level:** authenticated

**Threat-model match:** Token/identity takeover: forging, replaying, or harvesting CVV/PAN from issued claims (cross-service privilege escalation); enables Customer order/PII breach: reading or altering other shoppers' orders, addresses and identities once a webhooks-only token reaches Ordering

**Why:** AuthenticationExtensions.cs:49 disables audience validation unconditionally, outside the DEBUG block, while :38 sets a per-service Audience that then goes unused. Every client in Config.cs is granted 'orders', 'basket' and 'webhooks' except WebhooksClient (webhooks only, Config.cs:139) and the three Swagger implicit clients (basket/orders/webhooks respectively). A webhooks-only token therefore reaches Ordering, whose routes check nothing but a valid token. Downgraded from HIGH to MEDIUM: the attacker must already hold a legitimate token from the same issuer, so this is lateral privilege, not initial access.

**Reachability evidence:** src/eShop.ServiceDefaults/AuthenticationExtensions.cs:49, src/Identity.API/Configuration/Config.cs:139, src/Ordering.API/Program.cs:21

### [MEDIUM] POST /api/orders trusts client-supplied UserId/UserName, letting any authenticated user act as another buyer  (f005)

`src/Ordering.API/Apis/OrdersApi.cs:118` | auth-bypass | claimed HIGH (alignment -1) | confidence 8.5/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (3):**
- Attacker holds a valid Ordering token (default shopper scope set is sufficient)
- Attacker knows or can guess the victim's sub claim (string GUID, exposed to the client itself and reused across APIs)
- The victim's identity need not be re-authenticated: the sub claim is never compared

**Access level:** authenticated

**Threat-model match:** Customer order/PII breach: reading or altering other shoppers' orders, addresses and identities

**Why:** CreateOrderRequest.UserId (:171-185) is forwarded into CreateOrderCommand (:141) and used by CreateOrderCommandHandler as new Order(message.UserId, ...) (:40) and OrderStartedIntegrationEvent(message.UserId) (:32); the buyer handler finds or creates a Buyer keyed on it. Downgraded from HIGH to MEDIUM because the attacker must know the victim's sub GUID; the impact (orders attributed to the victim, the victim's basket cleared) is real but requires that extra step.

**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:141, src/Ordering.API/Application/Commands/CreateOrderCommandHandler.cs:32

### [MEDIUM] Profile service copies stored card number, CVV, expiry and address into issued tokens and userinfo claims  (f008)

`src/Identity.API/Services/ProfileService.cs:74` | sensitive-data-exposure | claimed HIGH (alignment -1) | confidence 8.0/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (2):**
- Attacker obtains an ID token or userinfo response for any user (browser storage, network capture on an HTTP hop, logs, or normal API use)
- The offending claims are emitted because the requesting client asks for the profile scope, which every in-tree client does

**Access level:** authenticated

**Threat-model match:** Compliance-scoped data exposure (PCI card data in tokens, storage or logs)

**Why:** ProfileService adds card_number (:70), card_holder (:74), card_security_number (:78), card_expiration (:82) and address_* (:86-98) unconditionally. webapp sets AlwaysIncludeUserClaimsInIdToken=true (Config.cs:87), so PAN and CVV ride inside the ID token that the storefront and MAUI app retain. Downgraded from HIGH to MEDIUM because the values are the demo profile (seeded), and there is no path-by-path proof of a leak to a third party from this code alone; it is a compliance defect and a real amplifier for F-001.

**Reachability evidence:** src/Identity.API/Services/ProfileService.cs:70, src/Identity.API/Configuration/Config.cs:87

### [MEDIUM] Order unit prices are taken from the client, so a shopper can buy at attacker-chosen prices  (f007)

`src/Ordering.API/Apis/OrdersApi.cs:141` | business-logic | claimed HIGH (alignment -1) | confidence 7.5/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (2):**
- Attacker holds a valid Ordering token
- Ordering.API is reachable (BFF or direct) and does not re-read prices from Catalog at order time

**Access level:** authenticated

**Threat-model match:** Unauthenticated data tampering: anyone rewriting catalog prices, stock or content without logging in (price/payment integrity reached from a checkout, not from the catalog endpoint)

**Why:** CreateOrderRequest.Items is a list of `BasketItem` with client-supplied UnitPrice and Quantity (OrdersApi.cs:171-185); CreateOrderCommandHandler passes unitPrice into Order.AddOrderItem (:43) and OrderItem.GetTotal multiplies it (Order.cs:185). The validator checks only that the item list is non-empty. This is one half of the flow correctly identified, but the claim that Discount also flows through is wrong: BasketItemExtensions.ToOrderItemDTO never copies Discount, so discount is always 0. Downgraded from HIGH to MEDIUM because the storefront normally sends the price its own cart computed and the impact is bounded to orders the attacker places (the discount path is not exploitable as claimed).

**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:141, src/Ordering.API/Extensions/BasketItemExtensions.cs:13, src/Ordering.Domain/AggregatesModel/OrderAggregate/Order.cs:185

### [MEDIUM] Webhook grant-URL check compares the two caller-supplied URLs against each other (SSRF to internal hosts)  (f011)

`src/Webhooks.API/Services/GrantUrlTesterService.cs:7` | ssrf | claimed MEDIUM (alignment +0) | confidence 7.5/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (3):**
- Attacker holds a webhooks-scoped token (or any token, per F-002)
- Webhooks.API is reachable (internally or via the BFF /identity-adjacent path)
- Target host resolves from the Webhooks.API pod (e.g. 169.254.169.254, catalog-api, ordering-api)

**Access level:** authenticated

**Threat-model match:** SSRF into internal network: server-side requests to internal services or cloud metadata

**Why:** CheckSameOrigin(urlHook, url) compares two attacker-controlled values, then HttpRequestMessage(OPTIONS, url) is sent (:14, :21) with no allowlist or private-range block. Corroborated by Fennec (CWE-918, sha256:0b301fec/c38aa7cb). Requires a webhooks token, which every in-tree client can obtain (Config.cs:66). Impact is blind SSRF (response body not returned) but a later webhook delivery POSTs order data to DestUrl, so it is a data-exfiltration primitive as well.

**Reachability evidence:** src/Webhooks.API/Services/GrantUrlTesterService.cs:7, src/Webhooks.API/Services/GrantUrlTesterService.cs:21

### [MEDIUM] webapp authorization-code client runs with RequirePkce=false and AllowOfflineAccess=true  (f014)

`src/Identity.API/Configuration/Config.cs:89` | insecure-configuration | claimed MEDIUM (alignment +0) | confidence 7.5/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (2):**
- Attacker can intercept or obtain an authorization code from the webapp redirect (log, browser history, referrer, shared machine)
- The attacker also holds the shared client secret (F-009)

**Access level:** authenticated

**Threat-model match:** Token/identity takeover: forging, replaying, or harvesting CVV/PAN from issued claims

**Why:** Config.cs:89 sets RequirePkce=false for webapp, AllowOfflineAccess=true (:90) and a long-lived refresh path; the WebApp client also sets SaveTokens=true and GetClaimsFromUserInfoEndpoint. This is a genuine defence-in-depth regression, but it is only exploitable together with a code interception. Kept at MEDIUM; the fix is a one-line change and should be done regardless.

**Reachability evidence:** src/Identity.API/Configuration/Config.cs:89, src/Identity.API/Configuration/Config.cs:90

### [MEDIUM] All confidential OIDC clients share the literal client secret "secret"  (f009)

`src/Identity.API/Configuration/Config.cs:82` | hardcoded-secret | claimed HIGH (alignment -1) | confidence 7.0/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (2):**
- Attacker reads the repo or the MAUI app config (both ship the secret)
- Attacker also captures a valid authorization code from the webapp flow (no PKCE, Config.cs:89) or already holds the MAUI client's stored credentials

**Access level:** authenticated

**Threat-model match:** Token/identity takeover: forging, replaying, or harvesting CVV/PAN from issued claims

**Why:** Config.cs registers new Secret("secret".Sha256()) for webapp (:82), maui (:52) and webhooksclient (:118); the MAUI app ships ClientSecret=secret in its defaults, and webapp sets RequirePkce=false. The secret alone is not sufficient for webapp: a code exchange still needs an intercepted code, and identityserver does not expose a client-credentials grant here. It is fully sufficient on its own only for the MAUI custom-scheme flow. Downgraded to MEDIUM because the primary precondition is code interception; it becomes a HIGH as soon as one code leak occurs.

**Reachability evidence:** src/Identity.API/Configuration/Config.cs:82, src/Identity.API/Configuration/Config.cs:89, src/WebApp/Extensions/Extensions.cs:78

### [MEDIUM] Login cancel branch redirects to model.ReturnUrl without a local-URL check (open redirect on the IdP)  (f015)

`src/Identity.API/Quickstart/Account/AccountController.cs:84` | open-redirect | claimed MEDIUM (alignment +0) | confidence 7.0/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (3):**
- Attacker can drive a victim to POST /Account/Login with a crafted ReturnUrl and a valid antiforgery token (a same-site scripted or crafted-form scenario)
- A live authorization request exists for the ReturnUrl (so GetAuthorizationContextAsync returns non-null)
- A victim clicks through to the redirect

**Access level:** authenticated

**Threat-model match:** Token/identity takeover: forging, replaying, or harvesting CVV/PAN from issued claims

**Why:** The cancel branch redirects to Redirect(model.ReturnUrl) at :84 without Url.IsLocalUrl; the success path at :115 does check. Fennec flagged :84 and :111. The UI's Login button posts button=login, so an attacker must forge the button field, and the branch also calls DenyAuthorizationAsync. Because the 'trust model.ReturnUrl' comment is only valid while the context is live, the bug is a genuine missing check. Merged Fennec's two flows into one finding; kept at MEDIUM because it needs a crafted POST, not a simple link.

**Reachability evidence:** src/Identity.API/Quickstart/Account/AccountController.cs:84, src/Identity.API/Quickstart/Account/AccountController.cs:111

### [MEDIUM] Webhook delivery broadcasts every user's subscriptions, so any shopper can subscribe to all order events  (f017)

`src/Webhooks.API/Services/WebhooksRetriever.cs:7` | idor | claimed MEDIUM (alignment +0) | confidence 7.0/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (2):**
- Attacker holds a webhooks token (obtainable from every in-tree client, incl. the storefront's bundled scopes and F-002)
- Attacker registers a subscription with their own DestUrl

**Access level:** authenticated

**Threat-model match:** Customer order/PII breach: reading or altering other shoppers' orders, addresses and identities (partial: order id, status, buyer name, item and price data)

**Why:** WebhooksRetriever.GetSubscriptionsOfType selects by Type only and ignores the UserId column that CRUD enforces (WebHooksApi.cs:16,27,72); WebhooksSender then POSTs the order event to every DestUrl. A shopper who can register one subscription receives every buyer's order events. Kept at MEDIUM (broadcast leak, but the receiver must be attacker-hosted and the scope is not classified as admin-only in any policy).

**Reachability evidence:** src/Webhooks.API/Services/WebhooksRetriever.cs:7, src/Webhooks.API/Services/WebhooksSender.cs:17

## Hardening / low priority

### [LOW] Consent POST redirects to result.RedirectUri copied verbatim from model.ReturnUrl  (f016)

`src/Identity.API/Quickstart/Consent/ConsentController.cs:63` | open-redirect | claimed MEDIUM (alignment -1) | confidence 6.0/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (2):**
- Attacker controls a client registered to the IdP (self-registered or leaked registration) and its returnUrl
- The victim must log in and accept consent for that client

**Access level:** authenticated

**Threat-model match:** Token/identity takeover: forging, replaying, or harvesting CVV/PAN from issued claims

**Why:** ConsentController.ProcessConsent sets result.RedirectUri = model.ReturnUrl (:138) after the context check, then Redirect(result.RedirectUri) at :63. The context must be live, and it originates from an attacker-registered client, so the redirect boat is reached by the attacker's own client rather than a victim's. Fennec sha256:440a1f97. Downgraded from MEDIUM to LOW: the exploit's impact is that the attacker's own client gets consent, which it could obtain directly.

**Reachability evidence:** src/Identity.API/Quickstart/Consent/ConsentController.cs:63, src/Identity.API/Quickstart/Consent/ConsentController.cs:138

### [LOW] Demo receiver accepts any unauthenticated POST: token validation off by default and compared non-constant-time  (f019)

`src/WebhookClient/Endpoints/WebhookEndpoints.cs:16` | auth-bypass | claimed MEDIUM (alignment -1) | confidence 6.0/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (2):**
- WebhookClient is reachable by the attacker (it is a local/Aspire demo host, not an external endpoint in AppHost)
- The attacker can POST arbitrary JSON

**Access level:** unauthenticated_remote

**Threat-model match:** Unauthenticated data tampering: anyone rewriting catalog prices, stock or content without logging in

**Why:** ValidateToken defaults to false because bool.TryParse of a missing key yields false (:16), and comparison is tokenToValidate == token via a string implicit comparison (non-constant-time). The appsettings In-tree token is committed. However the WebhookClient is a developer/demo receiver with no external endpoint in AppHost and the hacked payload in Json2 rendered into a Blazor UI. Downgraded to LOW because of the limited exposure; still a real defence-in-depth fail-open fix.

**Reachability evidence:** src/WebhookClient/Endpoints/WebhookEndpoints.cs:16, src/WebhookClient/Endpoints/WebhookEndpoints.cs:31

### [LOW] Webhook bearer token logged in cleartext at Information level  (f022)

`src/Webhooks.API/Services/GrantUrlTesterService.cs:17` | sensitive-data-in-logs | claimed LOW (alignment +0) | confidence 6.0/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (1):**
- Attacker can read Webhooks.API logs / OTLP backend

**Access level:** authenticated

**Threat-model match:** Token/identity takeover: forging, replaying, or harvesting CVV/PAN from issued claims (token replay as X-eshop-whtoken)

**Why:** LogInformation(:17) interpolates the subscriber token (and :23 logs received vs expected) at the default Information level with no redaction. The token is replayable in the delivery header. Kept at LOW: it requires log access, but it is a straightforward credential leak and should ship in the same log-redaction fix as F-013.

**Reachability evidence:** src/Webhooks.API/Services/GrantUrlTesterService.cs:17, src/Webhooks.API/Services/GrantUrlTesterService.cs:23

### [LOW] Identity auth cookie has no explicit Secure/HttpOnly and relies on a global SameSite=Lax  (f010)

`src/Identity.API/Program.cs:50` | insecure-configuration | claimed MEDIUM (alignment -1) | confidence 5.5/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (2):**
- Attacker can observe or downgrade a request on an HTTP hop between the browser and Identity (AppHost can run HTTP launch profiles)
- No HTTPS redirect on Identity; only MinimumSameSitePolicy is set

**Access level:** authenticated

**Threat-model match:** Token/identity takeover: forging, replaying, or harvesting CVV/PAN from issued claims

**Why:** Program.cs:50 sets only MinimumSameSitePolicy=SameSiteMode.Lax; there is no UseHttpsRedirection and no ConfigureApplicationCookie. ASP.NET Identity's defaults do set HttpOnly=true and Secure=SameAsRequest, so the missing pieces are 'Secure outside HTTPS' and 'no HSTS/redirect'. Downgraded from MEDIUM to LOW: the flags the finding claims are missing are largely defaulted correctly, and the real risk is the HTTP hop already tracked as threat-model T14.

**Reachability evidence:** src/Identity.API/Program.cs:50

### [LOW] NuGet vulnerability auditing suppressed repo-wide (NU1901-NU1904) while TreatWarningsAsErrors is on  (f023)

`Directory.Build.props:11` | insecure-configuration | claimed LOW (alignment +0) | confidence 5.0/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (1):**
- A vulnerable transitive package is introduced and remains unnoticed until manual review

**Access level:** unauthenticated_remote

**Threat-model match:** Supply-chain compromise

**Why:** Directory.Build.props:11 suppresses NU1901-NU1904 while TreatWarningsAsErrors is true, so audit findings are invisible. Fennec confirmed MessagePack 2.5.302 / CVE-2026-92707 in test projects (not runtime), and ankane/pgvector:latest is a floating tag. Kept at LOW: no exploitable vulnerable package is reachable from src today, but the suppression disables the control that would tell you tomorrow.

**Reachability evidence:** Directory.Build.props:11

### [LOW] Chatbot markdown image syntax becomes a live image element, enabling tracking and a narrow attribute-injection window  (f020)

`src/WebApp/Components/Chatbot/MessageProcessor.cs:18` | xss | claimed MEDIUM (alignment -1) | confidence 4.5/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (2):**
- An attacker can influence model output reaching AllowImages (catalog product text or a prompt-injection) and the user interacts with the page
- The WebApp chatbot is enabled and the user is signed in

**Access level:** authenticated

**Threat-model match:** Bypass of client-side output encoding / privacy (tracking beacon), narrow

**Why:** AllowImages re-expands &lt;/&gt; (:18) then emits an img tag with HTML-encoded title/src (:24) inside a MarkupString rendered by Chatbot.razor:46. The encoding prevents attribute-breaking injection: any double quote in the model text becomes &quot; before it is placed in the attribute. So the 'narrow attribute-injection window' is not demonstrable from source, and what remains is a model-controlled image beacon (IP/time leak). Downgraded from MEDIUM to LOW and the XSS claim removed. This is a defence-in-depth item, not script injection.

**Reachability evidence:** src/WebApp/Components/Chatbot/MessageProcessor.cs:18, src/WebApp/Components/Chatbot/Chatbot.razor:46

### [LOW] Basket Redis key concatenates the raw sub claim into a shared, unsegmented namespace  (f021)

`src/Basket.API/Repositories/RedisBasketRepository.cs:16` | improper-input-validation | claimed LOW (alignment +0) | confidence 3.5/10

**Verdict:** exploitable, votes 3 TP / 0 FP / 0 CV

**Preconditions (1):**
- A non-GUID or attacker-influenced sub claim is accepted by the issuer (none in-tree; forgery would need F-001)

**Access level:** adjacent_network

**Threat-model match:** Basket confidentiality/integrity

**Why:** GetBasketKey(userId) appends the raw sub (:16) with no validation, but every caller takes userId from the sub claim (MapToCustomerBasket uses the derived userId, and GetUserIdentity reads the claim) rather than from the request payload, so a client cannot choose the key today. The structural problem (shared Redis, no namespace per service) is real and matches threat-model T24/T25. Confirmed as a minor hardening item, not a live bypass.

**Reachability evidence:** src/Basket.API/Repositories/RedisBasketRepository.cs:16, src/Basket.API/Grpc/BasketService.cs:93

## Needs manual test

### [LOW] CVV is accepted from the request and persisted in the ordering database rather than discarded  (f018)

`src/Ordering.API/Application/Commands/CreateOrderCommandHandler.cs:40` | sensitive-data-exposure | claimed MEDIUM (alignment -2) | confidence 3.0/10

**Verdict:** needs_manual_test, votes 2 TP / 1 FP / 0 CV

**Access level:** authenticated

**Threat-model match:** Compliance-scoped data exposure (PCI card data in tokens, storage or logs)

**Why:** This finding is wrong on its central claim: the CVV is accepted and travels the whole order pipeline, but PaymentMethodEntityTypeConfiguration.cs never maps the `SecurityNumber` property at all, and the EF migration for `paymentmethods` (20230925222426_Initial.cs:91-103) has no security-number column, so no CVV is persisted. Verified against both the configuration and the generated migration. The surviving, real part is that the CVV is captured, validated (Length(3), CreateOrderCommandValidator:14) and carried in the domain object, so it is unavoidably present in the {@Order} log (F-013). That part is a duplicate of F-013's logging exposure, so this entry is downgraded to LOW and its only actionable content is 'stop accepting CVV at all / rely on tokenisation'.

**Reachability evidence:** src/Ordering.Infrastructure/EntityConfigurations/PaymentMethodEntityTypeConfiguration.cs:1, src/Ordering.Domain/AggregatesModel/BuyerAggregate/PaymentMethod.cs:8

## Suppressed

### [LOW] Unauthenticated /product-images/{id} forwarder passes the raw route value into a templated upstream path  (f024)

`src/WebApp/Program.cs:32` | ssrf | claimed LOW (alignment +0) | confidence 0.0/10

**Verdict:** false_positive (exclusion rule 13)

**Threat-model match:** SSRF into internal network: server-side requests to internal services or cloud metadata

**Why:** The forwarder has no int constraint, but the upstream target route is itself id-constrained (CatalogApi.cs:47 maps items/{id:int}/pic), so a non-int value simply fails to match upstream. YARP normalises the forwarded path, and the catalog picture handler is confined to the Pics provider root, which is covered by the existing regression test GetCatalogItemPicDoesNotServeFilesOutsidePics (CatalogApiTests.cs:236-268). No demonstrated evasion; this is a hygiene note, not a finding.

**Refute reasons:** already_handled, implausible_trigger

**Reachability evidence:** src/WebApp/Program.cs:32, src/Catalog.API/Apis/CatalogApi.cs:47, tests/Catalog.FunctionalTests/CatalogApiTests.cs:237

### [LOW] Demo account credentials (bob / Pass123$) injected as workflow env  (f025)

`.github/workflows/playwright.yml:37` | hardcoded-secret | claimed LOW (alignment +0) | confidence 0.0/10

**Verdict:** false_positive (exclusion rule 13)

**Threat-model match:** Token/identity takeover: forging, replaying, or harvesting CVV/PAN from issued claims

**Why:** The credentials are the seeded demo users committed in UsersSeed.cs and printed on the login page; the workflow only repeats them to drive a demo E2E run. There is no additional secret to disclose, and fixing the demo creds is threat-model T2's job, not this workflow's. Suppressed as non-actionable for this codebase.

**Refute reasons:** not_actionable, already_handled

**Reachability evidence:** .github/workflows/playwright.yml:37

## Notes for the fixer

1. **Two findings changed verdict on re-read.** F-018's central claim (CVV persisted) is false: `PaymentMethodEntityTypeConfiguration` never maps `_securityNumber` and the EF migration has no such column. The CVV is still accepted and logged, so its real exposure is F-013. F-020's XSS claim does not hold either: `HtmlEncoder.Encode` runs on the attribute values, so the encoded-quote breakout is not demonstrable; what remains is a model-controlled image beacon.
2. **Three severities were raised.** F-012 (BFF catch-all) is the control that turns the anonymous catalog write defect into an internet-reachable issue, so it is HIGH. F-013 (card data in logs) is a PCI-scoped egress. F-002 is not raised, because it needs a valid same-issuer token; it was downgraded.
3. **The fastest wins.** F-002 (`ValidateAudience=true` per service) and F-014 (`RequirePkce=true`) are each a one-line change. F-003+F-012 need an admin policy plus BFF route restrictions. F-004/F-006/F-005/F-007 are ownership and identity checks on the Ordering endpoints.
4. **Same-root-cause clusters.** F-008 and F-018 (card fields in the profile and order models) share one fix: stop capturing card data outside the payment provider. F-013 and F-022 share the redaction layer. F-001 and F-009 share secret management.
5. **Not fixable in code today.** F-006's 'admin only ship' cannot be enforced because Identity issues no role claims; adding a role model is a prerequisite.

## Out of scope of this triage

Threat-model items with no source-level finding (T3, T4, T16, T20, T21, T23, T26, T27, T29) were not voted on. They are infrastructure, deployment and supply-chain observations and should go to a separate control review. T2 (seeded demo accounts) is partially represented by F-025, which was suppressed as non-actionable in this repo.

**Mode note.** Source-only verification with three independent passes (code-first re-derivation, adversarial refutation, threat-model fit). No application was run and no request was sent.