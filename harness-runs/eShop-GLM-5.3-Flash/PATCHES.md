# Candidate Patches

> **Static review only.** These diffs were authored and reviewed by
> independent agents reading source. They were NOT compiled, run, or
> re-attacked. Read each diff yourself before applying — see
> `docs/patching.md#reviewing-generated-patches` for what to look for.

**Input:** ./TRIAGE.json · **Repo:** /home/niels/github/def-proj/eShop · 23 findings → 23 diffs (23 ACCEPT / 0 REJECT)

---
## bug_01: [HIGH] PUT /api/orders/cancel cancels any user's order - no buyer scoping (IDOR)  (f001)

`src/Ordering.API/Application/Commands/CancelOrderCommandHandler.cs:21` · idor · owner: no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Ordering.API/
**Status:** static_review_only · review ACCEPT · style 9/10
**Diff:** `PATCHES/bug_01/patch.diff` (ownership check via IBuyerRepository.FindAsync + IIdentityService, fails closed; test: foreign buyer cannot cancel)

**Rationale:** Root cause is the unscoped PK load + unconditional SetCancelledStatus in the handler; fix belongs in the handler because internal domain-event flows need the repository unscoped.
**Variants checked:** SetAwaitingValidation/SetStockConfirmed/SetPaid/SetStockRejected/Ship handlers (separate findings); domain-event callers intentionally unscoped.
**Bypass considered:** Foreign cancel, null sub, null BuyerId, idempotent replay — all fail closed.
**Test:** tests/Ordering.UnitTests/Application/CancelOrderCommandHandlerTest.cs

---

## bug_02: [HIGH] GET /api/orders/{orderId} returns any order without buyer scoping (IDOR)  (f002)

`src/Ordering.API/Application/Queries/OrderQueries.cs:8` · idor · owner: no CODEOWNERS entry; top committer: Erin McLaughlin / Srushti; component: Ordering.API/
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_02/patch.diff` (GetOrderAsync(int id, string userId) with o.Buyer.IdentityGuid == userId predicate; fail-closed 404 on missing sub)

**Rationale:** Threads the JWT subject into the query, mirroring GetOrdersFromUserAsync's existing scoping pattern.
**Variants checked:** GetOrdersFromUserAsync already scoped; GetCardTypesAsync static; command-side OrderRepository.GetAsync flows untouched (cancel/ship are separate findings).
**Bypass considered:** Foreign id enumeration, empty sub, non-integer ids — all fail closed; identity comes only from the principal.
**Test:** Get_order_scopes_query_to_caller_identity in tests/Ordering.UnitTests/Application/OrdersWebApiTest.cs

---

## bug_03: [HIGH] All catalog item mutation endpoints (create/update/delete) are anonymous  (f003)

`src/Catalog.API/Apis/CatalogApi.cs:100` · auth-bypass · owner: no CODEOWNERS entry; top committer: Mike Kistler; component: Catalog.API/
**Status:** static_review_only · review ACCEPT · style 6/10
**Diff:** `PATCHES/bug_03/patch.diff` (AddDefaultAuthentication wiring + RequireAuthorization on all four mutation routes + Identity:Audience config + AppHost Identity__Url + functional tests)

**Rationale:** Catalog.API is the only API service with zero auth wiring; the fix mirrors the fleet pattern (Extensions.cs:10/:12/:5) at the same DI slot and gates exactly the four mutating routes, leaving reads anonymous for the storefront.
**Variants checked:** Exactly 4 mutation mappings repo-wide; no other missing AddDefaultAuthentication; read routes deliberately anonymous.
**Bypass considered:** YARP-relayed mutations now 401; version hopping finds no unprotected variant; event-bus stock mutations are separate findings.
**Test:** UpdateCatalogItemWithoutTokenIsRejected (401 without token; 200 anonymous read) in tests/Catalog.FunctionalTests/CatalogApiTests.cs
> ⚠️ **Apply-time amendment:** the fixture references `AutoAuthorizeStartupFilter`, which the diff uses but does not define in tests/Catalog.FunctionalTests — copy the ~10-line private class from tests/Ordering.FunctionalTests/OrderingApiFixture.cs:66-76 before compiling. (Reviewer-flagged.)

---

## bug_04: [HIGH] ProfileService ignores RequestedClaimTypes and emits payment-card data (incl. CVV) into every token  (f005)

`src/Identity.API/Services/ProfileService.cs:22` · sensitive-data-exposure · owner: no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Identity.API/
**Status:** static_review_only · review ACCEPT · style 9/10
**Diff:** `PATCHES/bug_04/patch.diff` (deletes the four card-claim emissions at their sole source; honors RequestedClaimTypes per the Duende contract)

**Rationale:** GetClaimsFromUser is the only producer of card_* claims; no API consumes them from tokens. MAUI checkout autofill degrades to nulls (functional follow-up, zero security impact).
**Variants checked:** Single IProfileService implementation; sole consumers via ClientApp userinfo (covered by source removal); Config.cs flags untouched (moot once the source is empty).
**Bypass considered:** userinfo, requested-claim filtering, AlwaysIncludeUserClaimsInIdToken, reissue — none can emit card claims post-fix; rotate outstanding tokens at deploy.
**Test:** tests/Application.UnitTests/ProfileServiceTests.cs (no card_* claims under unrestricted profile; filter returns exact intersection)

---

## bug_05: [HIGH] Committed RSA private key is the IdentityServer token-signing key  (f007)

`src/Identity.API/tempkey.jwk:1` · hardcoded-secret · owner: no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Identity.API/
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_05/patch.diff` (removes KeyManagement.Enabled=false + AddDeveloperSigningCredential, the csproj Content include shipping the key, and gitignores tempkey*.jwk/rsa)

**Rationale:** Removes the load path for the committed key rather than the binary file; Duende automatic key management becomes the only credential source.
**Variants checked:** Single AddDeveloperSigningCredential/KeyManagement occurrence; no Dockerfiles — publish output covered by the csproj change.
**Bypass considered:** Stale checkouts/images still containing tempkey.jwk no longer load it. **Operator actions outside the diff:** git rm --cached + history purge, treat kid F7383A0E… as compromised and rotate, register a durable ISigningKeyStore/certificate before production.
**Test:** Omitted — key-material loading has no testable branch; verify via JWKS key-id absence at deploy.

---
## bug_06: [HIGH] Client-supplied UserId/UserName copied verbatim into order and Buyer aggregates  (f008)

`src/Ordering.API/Apis/OrdersApi.cs:141` · auth-bypass · owner: no CODEOWNERS entry; top committer: Rob Conery / David Fowler; component: Ordering.API/
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_06/patch.diff` (CreateOrderCommandHandler derives UserId/UserName from the injected IIdentityService with a fail-closed guard)

**Rationale:** Fix sits exactly at the sink where body identity was consumed; sourced from the same trusted mechanism as the read path (OrdersApi.cs:95). CreateOrderRequest DTO shape preserved.
**Variants checked:** CreateOrderDraftCommandHandler never reads BuyerId (pure price draft); downstream event handlers now receive identity-derived values; IdentifiedCommandHandler UserId use is log-only.
**Bypass considered:** Any casing/encoding of body identity never reaches the aggregate or events; unauthenticated requests rejected by the guard.
**Test:** Handle_creates_order_for_identity_service_user_not_body_user in tests/Ordering.UnitTests/Application/NewOrderCommandHandlerTest.cs

---

## bug_07: [HIGH] Credit-card CVV and, in one path, the full unmasked PAN written to logs  (f009)

`src/Ordering.API/Application/Behaviors/LoggingBehavior.cs:9` · sensitive-data-exposure · owner: no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Ordering.API/
**Status:** static_review_only · review ACCEPT · style 9/10
**Diff:** `PATCHES/bug_07/patch.diff` (missing-x-requestid branch logs only the request type name; CardSecurityNumber fully masked at the command boundary next to the existing PAN masking)

**Rationale:** Masks at the API boundary — strictly stronger than redacting at LoggingBehavior — and closes the raw-record dump at OrdersApi.cs:134 that contradicted the code's own comment. Validator Length(3) semantics unchanged by length-preserving masking.
**Variants checked:** All {@Command} sinks safe once masked at construction; domain layer only stores the CVV; draft endpoint carries no card fields.
**Bypass considered:** All card-value variations, malformed CVV, missing-header paths yield only masked data in every reachable sink.
**Test:** Create_order_masks_card_data_in_command in tests/Ordering.UnitTests/Application/OrdersWebApiTest.cs (asserts masked PAN + CVV on the mediated command)

---

## bug_08: [HIGH] Full payment-card data logged destructured by the mediator pipeline  (f010)

`src/Ordering.API/Application/Behaviors/TransactionBehavior.cs:41` · sensitive-data-in-logs · owner: no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Ordering.API/
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_08/patch.diff` (CreateOrderCommand.ToString() override emitting only the UserId — every {@Command} sink renders safely regardless of formatter)

**Rationale:** Fixes the leak's source (the object's own text rendering), covering all 15 {@Command} sites in one move, matching the hazard acknowledged at OrdersApi.cs:126-130. f009's raw-request sink deliberately untouched.
**Variants checked:** CreateOrderCommand is the only payment-data-carrying command; Cancel/Ship/draft commands carry OrderNumber/items only.
**Bypass considered:** Reflection-serializing formatters (JSON console) would bypass ToString — noted, out of minimal scope.
**Test:** Create_Order_Command_ToString_Check_No_Card_Data in tests/Ordering.UnitTests/Application/CreateOrderCommandTest.cs

---

## bug_09: [HIGH] PUT /api/orders/ship lets any authenticated user ship any order  (f012)

`src/Ordering.API/Application/Commands/ShipOrderCommandHandler.cs:21` · auth-bypass · owner: no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Ordering.API/
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_09/patch.diff` (named "admin" policy in Program.cs + .RequireAuthorization("admin") on only the /ship mapping; two existing tests updated to 403, new fail-closed test)

**Rationale:** FAIL-CLOSED by design: no token in the solution currently carries an admin role claim (Identity.API's ProfileService emits no role claim; Ordering.API has no role store), so every ship request is 403 until an operator maps real admins. /cancel deliberately untouched (separate finding).
**Variants checked:** Only two RequireAuthorization sites repo-wide; all seven route mappings reviewed.
**Bypass considered:** Non-admin JWT + any OrderNumber dies in the authorization middleware before the handler; only deliberately minted admin-claim tokens ship orders (the intended grant path).
**Test:** ShipOrderRequiresAdminRole in tests/Ordering.FunctionalTests/OrderingApiTests.cs

---

## bug_10: [HIGH] Order items persist client-supplied UnitPrice/Discount/Units with no price verification  (f014)

`src/Ordering.API/Application/Commands/CreateOrderCommandHandler.cs:44` · business-logic · owner: no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Ordering.API/
**Status:** static_review_only · review ACCEPT · style 9/10
**Diff:** `PATCHES/bug_10/patch.diff` (OrderItem constructor invariants: throw on unitPrice <= 0 and discount < 0; mirrored FluentValidation rule for clean 400s; four regression tests)

**Rationale:** Adds the missing aggregate invariants at the DDD layer, covering both the create and draft handlers via the shared constructor. KNOWN LIMITATION (stated in the patch): blocks negative/zero/garbage prices but not underpricing — true price authority requires a Catalog lookup, which Ordering.API cannot wire without a new gRPC client (recommended follow-up).
**Variants checked:** Only two production OrderItem construction sites, both through the fixed constructor; no catalog/grpc client exists in Ordering.API.
**Bypass considered:** Negative price, zero price, negative discount blocked at two layers; underpricing (0.01 vs 500) still passes — honestly noted.
**Test:** tests/Ordering.UnitTests/Domain/OrderAggregateTest.cs (zero/negative price, negative discount, aggregate path)

---
## bug_11: [MEDIUM] LLM output rendered as raw HTML with unrestricted <img src>  (f015)

`src/WebApp/Components/Chatbot/MessageProcessor.cs:24` · xss-content-injection · owner: no CODEOWNERS entry; top committer: Stephen Toub; component: WebApp/
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_11/patch.diff` (IsAllowedImageUrl gate: only relative /product-images/... URLs render as <img>; everything else downgraded to HTML-escaped inert text)

**Rationale:** Allowlist gate at the exact sink; the allowed branch is byte-identical to the old line 24 so legit product images keep rendering. CSP img-src 'self' recommended defense-in-depth, out of scope.
**Variants checked:** Only MarkupString sink in src/; sole caller Chatbot.razor:46; all other <img> uses are static assets or provider-generated relative URLs.
**Bypass considered:** Absolute/protocol-relative/data:/traversal/self-origin-authority tricks and plain links all render inert; residual is same-origin /product-images/ without traversal only.
**Test:** Omitted — no WebApp test project exists; planned assertions documented in the patch.

---

## bug_12: [MEDIUM] DestUrl posted at send time with no re-validation - SSRF  (f017)

`src/Webhooks.API/Apis/WebHooksApi.cs:41` · ssrf · owner: no CODEOWNERS entry; top committer: Aditya Mandaleeka / Chris Martinez; component: Webhooks.API/
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_12/patch.diff` (send-time guard in WebhooksSender: scheme allowlist, fail-closed DNS resolution, IP-range denial incl. loopback/link-local/metadata/RFC1918/CGNAT/ULA, IPv4-mapped normalization; named HttpClient with AllowAutoRedirect=false)

**Rationale:** Validates at the actual egress point — the single funnel for all three event-handler send paths. RESIDUAL: resolver-level check retains a DNS-rebinding TOCTOU window (full fix needs connection pinning).
**Variants checked:** Two outbound HTTP sites in Webhooks.API — sender (fixed) and grant probe (f038); one guard covers all send paths.
**Bypass considered:** Private IPs, metadata, IPv6 forms, decimal literals, non-http schemes, redirect pivots all rejected.
**Test:** SenderSkipsDeliveryToDisallowedDestinations (zero requests for private/metadata/loopback/ftp) in tests/Application.UnitTests/WebhookTests.cs

---

## bug_13: [MEDIUM] All confidential clients share hardcoded client secret 'secret'  (f018)

`src/Identity.API/Configuration/Config.cs:82` · hardcoded-secret · owner: no CODEOWNERS entry; top committer: Michael Stonis; component: Identity.API/
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_13/patch.diff` (config-sourced per-client secrets via fail-fast helper; RequirePkce=true on webapp/webhooksclient + UsePkce=true on both senders; AppHost Aspire secret parameters; test fixture updated)

**Rationale:** Fail-fast configuration replaces the committed credential; MAUI deliberately left as-is (public client, secret ships in the binary) with an in-code note.
**Variants checked:** Only Config.cs:52/82/118 use .Sha256 secrets; two server-side senders updated; webhook 'Token = secret' in functional tests is unrelated.
**Bypass considered:** Old shared secret no longer authenticates webapp/webhooksclient; PKCE enforced on the previously exempt path; missing config fails closed naming the key.
**Test:** Existing IdentityConfigurationTests fixture updated with dummy keys (required by fail-fast); no new test — config wiring only.

---

## bug_14: [MEDIUM] Failed idempotency-keyed commands marked processed with fabricated success  (f019)

`src/Ordering.Infrastructure/Idempotency/RequestManager.cs:21` · business-logic · owner: no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Ordering.Infrastructure/
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_14/patch.diff` (removes catch { return default; } in IdentifiedCommandHandler so inner-command failures propagate and TransactionBehavior rolls back the marker atomically)

**Rationale:** The swallow was the defect; removal restores transactional atomicity — retries re-execute instead of receiving fabricated success. Duplicate-detection and RequestManager untouched.
**Variants checked:** Only mediator swallow in src; other catches rethrow; event-publish failure handling is a separate concern.
**Bypass considered:** Same-key retry after failure re-executes; fresh-key retry surfaces a genuine 500; cross-user poisoning dropped (unguessable GUIDs, hardening note).
**Test:** Handler_throws_when_inner_command_fails in tests/Ordering.UnitTests/Application/IdentifiedCommandHandlerTest.cs

---

## bug_15: [HIGH] Webhook receiver token validation disabled by default + config-key mismatch  (f021)

`src/WebhookClient/Endpoints/WebhookEndpoints.cs:13` · auth-bypass · owner: no CODEOWNERS entry; top committer: Steve Sanderson; component: WebhookClient/
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_15/patch.diff` (section-bound IOptions read replaces the fail-open root-key TryParse; ValidateToken defaults true; appsettings ships it true; fail-closed regression test)

**Rationale:** Fixes both the wrong-key lookup and the fail-open default at the cited line — the guards now actually run. Token secrecy is f029's concern; this restores the control's function.
**Variants checked:** One production read site plus tests (updated to section key); options binding confirmed; AddWebhook.razor unaffected.
**Bypass considered:** Tokenless/wrong-token posts now 400 and do not persist; the committed public token still forges valid hooks (f029).
**Test:** WebhookEndpointsRejectHooksWhenValidationIsNotConfigured in tests/Application.UnitTests/WebhookClientTests.cs

---

## bug_16: [MEDIUM] Unbounded ConcurrentQueue grows forever from unauthenticated posts  (f023)

`src/WebhookClient/Services/HooksRepository.cs:7` · unbounded-allocation · owner: no CODEOWNERS entry; top committer: Steve Sanderson; component: WebhookClient/
**Status:** static_review_only · review ACCEPT · style 9/10
**Diff:** `PATCHES/bug_16/patch.diff` (AddNew trims to MaxEntries=1000; endpoint 413s payloads > 64KB before AddNew; retention-cap regression test)

**Rationale:** Root cause is unbounded retention; the two caps bound memory at cap × max-accepted-payload. GetAll/enumeration unchanged (snapshot-safe).
**Variants checked:** Only growable in-process store in WebhookClient; subscriptions dictionary is subscriber-bounded and drained.
**Bypass considered:** Flood path bounded regardless of post rate; concurrency transiently self-corrects at cap.
**Test:** HooksRepositoryCapsRetainedHooksAtMaxEntries in tests/Application.UnitTests/WebhookClientTests.cs

---
## bug_17: [MEDIUM] JWT audience validation globally disabled in shared library  (f024)

`src/eShop.ServiceDefaults/AuthenticationExtensions.cs:49` · auth-bypass · owner: no CODEOWNERS entry; top committer: Michael Stonis; component: eShop.ServiceDefaults/
**Status:** static_review_only · review ACCEPT · style 9/10
**Diff:** `PATCHES/bug_17/patch.diff` (single-line deletion of ValidateAudience = false)

**Rationale:** Restores the JwtBearer default so the per-service Identity:Audience (orders/basket/webhooks) becomes effective; aud-arrays are validated by intersection, so the WebApp-relayed multi-audience token still works by design while single-audience swagger tokens no longer cross services. Matches the maintainer's unmerged "Re-enable audience validation" commit.
**Variants checked:** ValidateAudience appears exactly once in source; no custom AudienceValidator.
**Bypass considered:** Basket-audience token replay at Ordering.API now 401; residual: multi-audience user tokens pass all three services by design.
**Test:** Omitted — no ServiceDefaults test project exists.

---

## bug_18: [MEDIUM] Seed users alice/bob created unconditionally, password on the login page  (f027)

`src/Identity.API/UsersSeed.cs:33` · hardcoded-secret · owner: no CODEOWNERS entry; top committer: toyzoz / Rob Conery; component: Identity.API/
**Status:** static_review_only · review ACCEPT · style 9/10
**Diff:** `PATCHES/bug_18/patch.diff` (IWebHostEnvironment injected into UsersSeed; SeedAsync early-returns unless IsDevelopment; Login.cshtml hint replaced with a neutral prompt)

**Rationale:** Root-cause gate on the unconditional seeder (migrations still run) plus defense-in-depth hint removal. OPERATIONAL NOTE: DBs previously seeded in non-dev still contain the accounts — rotate/delete at deploy. e2e unaffected (AppHost launch profiles set Development; Playwright uses env-var credentials).
**Variants checked:** Three hardcoded-credential hits in Identity.API, all covered; no other IDbSeeder implementations.
**Bypass considered:** Only the exact Development environment name seeds; hint removed for all environments; ci.yml does not run Playwright.
**Test:** Omitted — Identity.API has no test project; verified by inspection.

---

## bug_19: [MEDIUM] Subscription token logged at Information during grant probing  (f030)

`src/Webhooks.API/Services/GrantUrlTesterService.cs:25` · sensitive-data-in-logs · owner: no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Webhooks.API/
**Status:** static_review_only · review ACCEPT · style 9/10
**Diff:** `PATCHES/bug_19/patch.diff` (both token logs lowered to Debug behind IsEnabled guards; values replaced by MaskToken — '<absent>' or '<present sha256=XXXXXXXX>')

**Rationale:** The plaintext secret is removed from the only two leaking statements at the right level, with diagnosability preserved by a non-invertible prefix; the grant decision still compares real values. WebhookClient's own token log is a separate finding.
**Variants checked:** GrantUrlTesterService.cs:17/:25 are the only token-bearing logs in Webhooks.API; WebhooksSender already omits the token at Debug.
**Bypass considered:** Grant-URL servers can no longer recover a victim's expected token from Information logs.
**Test:** Omitted — functional tests stub IGrantUrlTesterService; verify via git grep post-apply.

---

## bug_20: [LOW] Raw event message bodies in telemetry spans and error logs  (f032)

`src/EventBusRabbitMQ/RabbitMQEventBus.cs:161` · sensitive-data-in-logs · owner: no CODEOWNERS entry; top committer: Martin Costello; component: EventBusRabbitMQ/
**Status:** static_review_only · review ACCEPT · style 9/10
**Diff:** `PATCHES/bug_20/patch.diff` (span tag → messaging.message.body.size; fake-exception message de-correlated from the body; error log prints the event name only)

**Rationale:** Root-cause removal of the payload from every sink it reached (span tag, exception message via ActivityExtensions, log template); routing-key identity already on the span preserves correlation.
**Variants checked:** All SetTag sites reviewed (others use routing keys); body still used functionally for the trigger check and deserialization.
**Bypass considered:** No consumer-controlled content reaches any sink in this file; framework JsonException text via ex noted as out of scope.
**Test:** Omitted — no EventBusRabbitMQ test project exists.

---

## bug_21: [MEDIUM] GetUserInfo dumps full PII into LLM context  (f037)

`src/WebApp/Components/Chatbot/ChatState.cs:100` · sensitive-data-exposure · owner: no CODEOWNERS entry; top committer: Stephen Toub / Eric Erhardt; component: WebApp/
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_21/patch.diff` (GetUserInfo serializes only the display-name claim; [Description] updated)

**Rationale:** Data minimization at the tool boundary — the eight address/email/phone fields are deleted before entering model context, so injection steering (via f015's render sink) cannot exfiltrate data that is not present. Tool-call invisibility and third-party egress are inherent to the LLM integration (only fully mitigated by not sending PII at all).
**Variants checked:** GetCartContents returns product data keyed to the caller; SearchCatalog/AddToCart return no claims; no other claim readers enter LLM context.
**Bypass considered:** Repeated tool calls yield only the name; other tools never touch _user.Claims.
**Test:** Omitted — no WebApp test project exists.

---

## bug_22: [MEDIUM] Grant-time OPTIONS probe is an internal network scanner  (f038)

`src/Webhooks.API/Services/GrantUrlTesterService.cs:14` · ssrf · owner: no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Webhooks.API/
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_22/patch.diff` (fail-closed public-host gate before any outbound probe: absolute http/https, DNS resolution, reject-if-any-non-public across IPv4 private/loopback/link-local/CGNAT/docs/reserved and IPv6 ::/112, ::ffff:0:0/96, NAT64, fe80::/10, fec0::/10, fc00::/7, ff00::/8, Teredo, documentation, 6to4)

**Rationale:** Egress validation before the sink — root cause rather than symptom masking; helpers confined to the same class. WebhooksSender untouched (f017).
**Variants checked:** Two direct HttpClient uses in Webhooks.API — probe (fixed) and sender (f017); WebhooksRetriever DB-only.
**Bypass considered:** DNS rebinding TOCTOU vs SendAsync's own resolution remains (needs connection pinning); redirects gain no liveness oracle (outcome is a boolean against the token echo).
**Test:** Omitted — no Webhooks.API unit-test project; functional tests stub the service; suggested range-helper assertions documented in the patch.

---

## bug_23: [LOW] Order-status handlers log buyer name and identity GUID  (f054)

`src/WebApp/Services/OrderStatus/IntegrationEvents/EventHandling/OrderStatusChangedToCancelledIntegrationEventHandler.cs:12` · pii-in-logs · owner: no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: WebApp/
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_23/patch.diff` (identical one-line change in all six handlers: {@IntegrationEvent} → @event.GetType().Name)

**Rationale:** Root-cause fix at the exact emission site — no event property reaches the logger anymore; correlation via @event.Id preserved; the notification call is untouched.
**Variants checked:** Grep confirms exactly six identical log sites, the only destructured-object log calls in src/WebApp.
**Bypass considered:** No PII reaches the logger; BuyerIdentityGuid still flows to NotifyOrderStatusChangedAsync (its intended purpose, not a log write).
**Test:** Omitted — recommend a FakeLogger unit test asserting no Buyer* keys when build capability is available.

---
## Skipped

| id | title | why skipped |
|---|---|---|
| (none) | — | all 23 true positives had a source location and produced a diff |
