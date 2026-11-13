# Candidate Patches

> **Static review only.** These diffs were authored and reviewed by independent agents reading source. They were NOT compiled, run, or re-attacked. Read each diff yourself before applying — see `docs/patching.md#reviewing-generated-patches` for what to look for.

**Input:** ./TRIAGE.json · **Repo:** /home/niels/github/def-proj/eShop · 19 findings → 19 diffs

---
## bug_02: [HIGH] RSA token-signing private key committed to the repository and used as the live signing credential  (f003)

`src/Identity.API/tempkey.jwk:1` · hardcoded-secret · owner: top committer: Aditya Mandaleeka (1 of 1 recent commit); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 7/10
**Diff:** `PATCHES/bug_bug_02/patch.diff` (8 hunks, 98 lines)

**Rationale:** The committed full RSA private JWK is loaded unconditionally via AddDeveloperSigningCredential while key management is disabled. The diff deletes tempkey.jwk, drops its Content Include from Identity.API.csproj, gitignores the name, and replaces the loader with a development-only in-memory credential (persistKey:false) plus a non-development AddSigningCredential(LoadPkcs12FromFile(...)) path that fails closed when config is missing.
**Variants checked:** Only one signing-credential call site and only one .jwk file in the tree; AppHost passes no signing material; ServiceDefaults validation needed no change for this root cause.
**Bypass considered:** A Development deployment now gets a fresh unknown in-memory key, so the old committed kid no longer validates; non-Development without configured certificate throws at startup. Residual: rotate and purge the key from history and published artifacts.

---

## bug_06: [HIGH] JWT bearer disables audience validation, so any token from the IdP is accepted by every API  (f007)

`src/eShop.ServiceDefaults/AuthenticationExtensions.cs:49` · auth-bypass · owner: top committer: Michael Stonis (1 of 1 recent commit); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 7/10
**Diff:** `PATCHES/bug_bug_06/patch.diff` (2 hunks, 46 lines)

**Rationale:** AddDefaultAuthentication sets the per-service Audience then disables ValidateAudience, so tokens minted for another API or client ID tokens are accepted. The diff flips ValidateAudience to true, making the already-configured audience authoritative.
**Variants checked:** Audience values in Basket/Ordering/Webhooks appsettings match the IdP API resources; WebApp requests both orders and basket, so its token still works; no service forwards a token across APIs.
**Bypass considered:** ID tokens (aud = client id) and tokens for a different API are now rejected; a missing audience fails closed because ValidateAudience defaults to requiring one.

---

## bug_04: [HIGH] Received-webhook token column is rendered to unauthenticated visitors  (f014)

`src/WebhookClient/Components/Pages/Home/ReceivedMessages.razor:13` · sensitive-data-exposure · owner: top committer: Steve Sanderson (1 of 1 recent commit); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 7/10
**Diff:** `PATCHES/bug_bug_04/patch.diff` (5 hunks, 163 lines)

**Rationale:** ReceivedMessages renders hook.Token and Home.razor:22 invokes it outside the AuthorizeView on the anonymous / route. The diff wraps the component body in AuthorizeView/NotAuthorized and applies the same gate to the AddWebhook form that pre-fills the same secret.
**Variants checked:** ReceivedMessages fixed; RegisteredHooks already behind AuthorizeView; AddWebhook same-secret exposure gated; endpoints do not render the token.
**Bypass considered:** A page-level [Authorize] would be inert because Routes.razor uses RouteView with no fallback policy, so the guard is an explicit AuthorizeView inside the component.
> **Out-of-scope hunks:** src/WebhookClient/Components/Pages/AddWebhook.razor:1-2,12-30, tests/Application.UnitTests/WebhookClientTests.cs:1-8,102-162

---

## bug_08: [MEDIUM] GET /api/orders/{orderId} returns any order without an ownership check  (f005)

`src/Ordering.API/Application/Queries/OrderQueries.cs:6` · idor · owner: top committer: Srushti (1 of 1 recent commit); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_bug_08/patch.diff` (6 hunks, 81 lines)

**Rationale:** The query filters only on order id and returns the full shipping address and items. The diff adds userId to GetOrderAsync and filters on Buyer.IdentityGuid, threading the authenticated identity from the endpoint; foreign ids collapse to the existing NotFound path.
**Variants checked:** GetOrderAsync fixed; GetOrdersFromUserAsync already scoped; GetCardTypes has no owner; cancel/ship are separate findings.
**Bypass considered:** A null or empty sub matches no buyer and returns 404; Buyer is a mapped navigation so the predicate is evaluated in SQL, and the endpoint group is already authenticated.

---

## bug_07: [MEDIUM] Any authenticated user can cancel any other user's order  (f008)

`src/Ordering.API/Apis/OrdersApi.cs:22` · idor · owner: top committer: Rob Conery (1 of 1 recent commit); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_bug_07/patch.diff` (7 hunks, 102 lines)

**Rationale:** Cancel loads the order by the body-supplied number and cancels it without comparing the caller's sub. The diff adds an ownership gate in CancelOrderAsync using IIdentityService and a new OrderBelongsToUserAsync predicate on Buyer.IdentityGuid, returning a uniform 404 before the command is dispatched. The shared handler is deliberately untouched because the payment-failure broker path also cancels orders with no user context.
**Variants checked:** Cancel fixed; GetOrderAsync and ShipOrderAsync are separate findings; the broker-driven cancel path stays functional; the new predicate mirrors GetOrdersFromUserAsync.
**Bypass considered:** Spoofing buyer fields is impossible because the command carries only OrderNumber and identity comes from the sub claim; replaying an x-requestid does not re-dispatch.

---

## bug_11: [MEDIUM] CreateOrder trusts body-supplied UserId instead of the JWT sub claim  (f009)

`src/Ordering.API/Apis/OrdersApi.cs:141` · auth-bypass · owner: top committer: Rob Conery (1 of 1 recent commit); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 6/10
**Diff:** `PATCHES/bug_bug_11/patch.diff` (6 hunks, 118 lines)

**Rationale:** CreateOrder builds the command from body-supplied UserId/UserName while IIdentityService is unused, and the value drives the buyer identity and basket-clearing event. The diff derives userId/userName from the authenticated principal, rejects a missing subject, and removes UserId/UserName/Buyer from CreateOrderRequest; the handler prefers the principal.
**Variants checked:** Create endpoint fixed; draft endpoint never writes identity; basket and webhooks already use the sub claim.
**Bypass considered:** Sending victim userId/userName/buyer fields is ignored because the properties no longer exist on the server DTO and the command is built from claims; a token without sub is rejected 400. Residual in-process callers with no HttpContext fall back to the command value.

---

## bug_10: [MEDIUM] Order item prices and quantities are accepted from the client request, allowing arbitrary order totals  (f010)

`src/Ordering.API/Extensions/BasketItemExtensions.cs:20` · business-logic · owner: top committer: Aditya Mandaleeka (1 of 1 recent commit); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 7/10
**Diff:** `PATCHES/bug_bug_10/patch.diff` (12 hunks, 256 lines)

**Rationale:** Client unit prices flow straight into the persisted order and total. The diff adds ICatalogPriceService/CatalogPriceService to fetch authoritative prices, has CreateOrderCommandHandler resolve them before clearing the basket, fail closed on unknown products or invalid units, and persist catalog prices instead of item.UnitPrice; AppHost adds a catalog reference.
**Variants checked:** Create and draft paths checked; the draft path remains a preview; cancel/ship carry no prices; the handler is the persistence choke point.
**Bypass considered:** Duplicate ids collapse to one catalog price per product and unknown products are rejected before any order row or basket-clearing event is written. Residual: Units is still client-chosen but can only raise the total, and stock validation bounds it.

---

## bug_14: [MEDIUM] Persistent blind SSRF: stored DestUrl is POSTed without re-validation and redirects are followed  (f022)

`src/Webhooks.API/Services/WebhooksSender.cs:32` · ssrf · owner: top committer: Aditya Mandaleeka (1 of 1 recent commit); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 7/10
**Diff:** `PATCHES/bug_bug_14/patch.diff` (6 hunks, 240 lines)

**Rationale:** Stored DestUrl is POSTed with no delivery-time validation while the default client follows redirects. The diff adds a shared validator, validates before dispatch, registers a named client with AllowAutoRedirect=false, UseProxy=false and a ConnectCallback that re-resolves and only connects to public addresses, and applies the same client to the grant tester.
**Variants checked:** Sender and grant tester both use the safe client; other clients use fixed internal base addresses.
**Bypass considered:** Redirect and proxy pivots are closed; DNS rebinding is closed because ConnectCallback connects to the specific validated IP. Residual: a public IP that the platform NATs inward, or IPv4-translated IPv6 forms not matched by the ::/96 test.

---

## bug_16: [MEDIUM] Logout failure leaves access/refresh tokens in SecureStorage; post-logout redirect is unregistered  (f028)

`src/ClientApp/Services/Identity/IdentityService.cs:47` · token-exposure · owner: top committer: Michael Stonis (4 of 4 recent commits); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 7/10
**Diff:** `PATCHES/bug_bug_16/patch.diff` (7 hunks, 136 lines)

**Rationale:** SignOutAsync returns on LogoutAsync error before the only token wipe, the post-logout URI mismatches the registered value, and the caller ignores the result. The diff clears the token in a finally block, converts provider errors into a false result, appends /Account/Redirecting to the post-logout URI, and surfaces a failure alert.
**Variants checked:** Sign-in, refresh, mock service and the profile caller checked; the browser callback activity has no path restriction so the extra path is still delivered.
**Bypass considered:** All provider outcomes (error, cancel, missing endpoint, exception) now reach the finally and clear the token. Residual: if the keystore write itself throws, the token remains; a dedicated remove path with retry is a follow-up.

---

## bug_15: [MEDIUM] Full raw integration-event bodies (buyer name, identity GUID) are written to span tags and logs  (f035)

`src/EventBusRabbitMQ/RabbitMQEventBus.cs:161` · information-disclosure · owner: top committer: iem365-michael (1 of 1 recent commit); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_bug_15/patch.diff` (1 hunks, 28 lines)

**Rationale:** Line 161 tags every consumed body and line 172 logs it on failure; events carry BuyerName and BuyerIdentityGuid. The diff replaces the body tag with the byte size, removes the body from the warning log, and stops embedding it in the fake-exception message, while leaving decode and dispatch unchanged.
**Variants checked:** ProcessEvent already logs only the event name; DeserializeMessage does not log; the remaining body sinks were the tag, the exception text and the warning.
**Bypass considered:** Exception text still flows into span exception tags, but the self-generated exception no longer contains the body; a JsonException leaks position, not content.

---

## bug_19: [LOW] Expected webhook token is logged in cleartext on every unauthenticated request  (f018)

`src/WebhookClient/Endpoints/WebhookEndpoints.cs:35` · sensitive-data-exposure · owner: top committer: Steve Sanderson (1 of 1 recent commit); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_bug_19/patch.diff` (3 hunks, 80 lines)

**Rationale:** The Information-level log writes both the caller token and the configured expected secret before the check, on every anonymous request. The diff removes both secret arguments and logs only whether validation is enabled, leaving the comparison untouched.
**Variants checked:** No other copy of the leaking message exists; other webhook log sites carry no secret.
**Bypass considered:** Deleting the arguments means the values never enter ILogger state, so no provider or exporter can recover them. The separate grant-tester log leak is its own finding.

---

## bug_18: [LOW] GET /Account/Logout signs the user out without a prompt, enabling logout CSRF  (f025)

`src/Identity.API/Quickstart/Account/AccountController.cs:152` · csrf · owner: top committer: Aditya Mandaleeka (1 of 1 recent commit); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 6/10
**Diff:** `PATCHES/bug_bug_18/patch.diff` (4 hunks, 48 lines)

**Rationale:** ShowLogoutPrompt=false makes the anonymous GET handler call the POST logout action in-process, bypassing antiforgery. The diff restores the prompt default and only auto-signs-out when the user is authenticated, a logoutId was supplied, and the prompt was suppressed.
**Variants checked:** Other GET handlers are read-only or begin external auth; all state-changing POSTs keep antiforgery.
**Bypass considered:** A bare cross-site GET now renders the prompt and the follow-up POST needs an antiforgery token. Residual: a valid RP-initiated logoutId with ShowSignoutPrompt=false still auto-signs-out by design.

---

## bug_01: [HIGH] Catalog write endpoints (POST/PUT/DELETE) are completely unauthenticated and reachable through the external mobile BFF  (f001)

`src/Catalog.API/Apis/CatalogApi.cs:100` · auth-bypass · owner: top committer: Mike Kistler (3 of 3 recent commits); no CODEOWNERS entry
**Status:** static_review_only · review REJECT · style 6/10
**Diff:** `PATCHES/bug_bug_01/patch.diff` (10 hunks, 198 lines)

**Rationale:** Root cause is Catalog.API never calling AddDefaultAuthentication (Program.cs) and mapping the four write endpoints without RequireAuthorization (CatalogApi.cs:100,105,110,114); the BFF merely exposes it. The diff registers AddDefaultAuthentication, adds the required Identity:Audience plus Identity__Url from AppHost, attaches RequireAuthorization to exactly the PUT/POST/DELETE endpoints, and relaxes two OpenAPI GetRequiredSection("Scopes") calls so the service can boot without a per-API Scopes map. Reads stay anonymous.
**Variants checked:** All four catalog write mappings fixed; Ordering/Webhooks groups already gated; Basket gRPC out of this surface; BFF route left as a forwarder because the resource now returns 401.
**Bypass considered:** Anonymous PUT/POST/DELETE via the BFF now hits authorization middleware before model binding and returns 401; only a valid low-privilege JWT remains (audience validation is a separate finding).

> **Rejected by reviewer:** Core fix is correct and well-scoped, but both ServiceDefaults hunks are off the call path and delete a fail-fast config check for all services; adding a Scopes section to Catalog appsettings would keep the guard. The test shim also authenticates by default, so the new test only checks endpoint metadata.
> **Out-of-scope hunks:** src/eShop.ServiceDefaults/OpenApi.Extensions.cs:55, src/eShop.ServiceDefaults/OpenApiOptionsExtensions.cs:170

---

## bug_03: [HIGH] Any authenticated customer can ship any order  (f004)

`src/Ordering.API/Apis/OrdersApi.cs:51` · auth-bypass · owner: top committer: Rob Conery (1 of 1 recent commit); no CODEOWNERS entry
**Status:** static_review_only · review REJECT · style 6/10
**Diff:** `PATCHES/bug_bug_03/patch.diff` (4 hunks, 78 lines)

**Rationale:** Ship is gated only by bare authentication and the handler ships whichever order number the body supplies, despite being documented as an administrator action. The diff registers an AdminOnly policy requiring the admin role and adds RequireAuthorization("AdminOnly") to the ship endpoint.
**Variants checked:** Ship fixed; cancel and by-id read have different root causes left to their own fixes; no other admin-only operation exists in the group; Webhooks handlers filter by caller id.
**Bypass considered:** Authorization evaluates validated JWT claims before model binding, so body order numbers cannot influence it; a forged role claim is blocked by issuer/signature validation.

> **Rejected by reviewer:** Right layer, but nothing issues the admin role: ProfileService emits no role claim and UsersSeed assigns no roles, so RequireRole("admin") would 403 every caller and permanently disable shipping. The test only passes because AutoAuthorizeMiddleware defaults every request to admin.

---

## bug_05: [HIGH] Unauthenticated /add-webhook page renders the configured webhook validation token into the HTML  (f013)

`src/WebhookClient/Components/Pages/AddWebhook.razor:30` · sensitive-data-exposure · owner: top committer: Steve Sanderson (1 of 1 recent commit); no CODEOWNERS entry
**Status:** static_review_only · review REJECT · style 7/10
**Diff:** `PATCHES/bug_bug_05/patch.diff` (3 hunks, 45 lines)

**Rationale:** OnInitialized copies WebhookClientOptions.Token into a field bound to an input, so it is emitted during prerender to anonymous visitors. The diff removes that assignment and resolves the token server-side inside RegisterAsync, keeping it out of component state and the DOM.
**Variants checked:** AddWebhook fixed; RegisteredHooks and ReceivedMessages are separate render sites; endpoints use the token server-side only.
**Bypass considered:** Even if the page were reachable, the configured token is no longer held in a bound field or rendered, so the HTML cannot disclose it.

> **Rejected by reviewer:** The token-removal hunks are correct root-cause fixes, but the patch also adds [Authorize], an unrelated policy change that is inert anyway because Routes.razor uses RouteView instead of AuthorizeRouteView. Drop that hunk or ship it with the router change.
> **Out-of-scope hunks:** src/WebhookClient/Components/Pages/AddWebhook.razor:2, src/WebhookClient/Components/Pages/AddWebhook.razor:8

---

## bug_12: [MEDIUM] Webhook signing token written to logs in cleartext at Information level  (f016)

`src/Webhooks.API/Services/GrantUrlTesterService.cs:17` · sensitive-data-in-logs · owner: top committer: Aditya Mandaleeka (1 of 1 recent commit); no CODEOWNERS entry
**Status:** static_review_only · review REJECT · style 5/10
**Diff:** `PATCHES/bug_bug_12/patch.diff` (2 hunks, 20 lines)

**Rationale:** Both Information-level messages log the caller and expected webhook tokens verbatim. The diff replaces the token values with booleans for supplied/received/matched.
**Variants checked:** WebhooksSender logs only destination and type; API handlers do not log the token; validation messages carry no values.
**Bypass considered:** The receiver's own proxy or non-default header-recording instrumentation can still log the X-eshop-whtoken header; that is receiver-side and outside this file.

> **Rejected by reviewer:** Hunk 1 fixes the leak, but hunk 2 still logs {TokenReceived}, which is the receiver's echo of the same shared secret, so the credential remains in logs on the success path and user-controlled header content still reaches the logger. Log only the TokenMatched boolean and fix the IsNullOrEmpty/IsNullOrWhiteSpace mismatch.

---

## bug_17: [MEDIUM] All confidential OIDC clients share the literal client secret "secret", including the public MAUI client  (f020)

`src/Identity.API/Configuration/Config.cs:52` · hardcoded-secret · owner: top committer: Michael Stonis (1 of 1 recent commit); no CODEOWNERS entry
**Status:** static_review_only · review REJECT · style 7/10
**Diff:** `PATCHES/bug_bug_17/patch.diff` (13 hunks, 129 lines)

**Rationale:** All three clients register the same literal secret and the MAUI binary ships it, with webapp also disabling PKCE. The diff loads per-client secrets from ClientSecrets:{clientId} with fail-closed lookup, makes MAUI a public client (no secret, PKCE retained), enables PKCE for webapp, and reads the relying-party secrets from configuration.
**Variants checked:** Server and both relying parties plus the MAUI default changed; swagger clients are intentionally public; no other committed client-secret literals found.
**Bypass considered:** MAUI remains a public client whose client_id and custom scheme are known; PKCE stops code interception but not a malicious app starting its own flow. Distinct secrets rely on operational config.

> **Rejected by reviewer:** Secret removal is root-cause, but the patch adds required ClientSecrets/ClientSecret keys without supplying them in appsettings or AppHost, so Identity.API and both relying parties throw at startup; the unit fixture hides it with dummy values. It also mixes in webapp PKCE changes that belong to a separate finding.
> **Out-of-scope hunks:** src/Identity.API/Configuration/Config.cs:90, src/WebApp/Extensions/Extensions.cs:81

---

## bug_13: [MEDIUM] Authenticated user can force server-side requests to arbitrary hosts  (f021)

`src/Webhooks.API/Services/GrantUrlTesterService.cs:21` · ssrf · owner: top committer: Aditya Mandaleeka (1 of 1 recent commit); no CODEOWNERS entry
**Status:** static_review_only · review REJECT · style 8/10
**Diff:** `PATCHES/bug_bug_13/patch.diff` (7 hunks, 229 lines)

**Rationale:** The grant tester fetches a caller-supplied URL after only a format check and a same-origin comparison of two attacker URLs. The diff adds a WebhookUrlValidator policy (http/https only, no userinfo, block loopback/private/link-local/metadata/numeric hosts/single-label names), applies it at validation and at both egress points, and disables auto-redirects on a named client.
**Variants checked:** Grant tester, sender, and request validation all use the validator; other outbound clients use fixed base addresses.
**Bypass considered:** Validation is pre-DNS, so a dotted attacker hostname resolving to an internal address still reaches the sink; closing that needs resolve-time pinning. Redirect pivots are blocked.

> **Rejected by reviewer:** The allowlist and redirect suppression are the right layer, but IsAllowed accepts any dotted hostname without resolving it, so a name pointing at 169.254.169.254 still reaches SendAsync; IsPublicAddress only applies to literals. Move validation to resolution/connect time with a pinned ConnectCallback, and keep the sibling sender hunks separate.
> **Out-of-scope hunks:** src/Webhooks.API/Services/WebhooksSender.cs:7, src/Webhooks.API/Services/WebhooksSender.cs:15-20

---

## bug_09: [MEDIUM] Full PAN and CVV are written to logs on order creation  (f026)

`src/Ordering.API/Apis/OrdersApi.cs:134` · sensitive-data-in-logs · owner: top committer: Rob Conery (1 of 1 recent commit); no CODEOWNERS entry
**Status:** static_review_only · review REJECT · style 6/10
**Diff:** `PATCHES/bug_bug_09/patch.diff` (4 hunks, 78 lines)

**Rationale:** Line 134 logs the raw CreateOrderRequest record, whose synthesized ToString prints PAN and CVV before masking. The diff logs only UserId and adds ToString overrides that mask the PAN and CVV on CreateOrderRequest and CreateOrderCommand.
**Variants checked:** The warning sink and command log sites checked; other order commands carry no card data; MediatR behaviors log the command object.
**Bypass considered:** Serilog-style object destructuring ignores ToString and would still print CardSecurityNumber; there is no such sink in the repo today, so the masking is defense-in-depth rather than a complete guarantee.

> **Rejected by reviewer:** The line-134 change is the correct root-cause fix, but the patch also modifies the unrelated CreateOrderCommand class and relies on ToString masking, which serializer sinks bypass; the CVV still enters the command unmasked and is logged via {@Command}. The test asserts ToString rather than the rendered template.
> **Out-of-scope hunks:** src/Ordering.API/Application/Commands/CreateOrderCommand.cs:84-93

---


## Skipped

None: every finding had a source location and produced a diff.
