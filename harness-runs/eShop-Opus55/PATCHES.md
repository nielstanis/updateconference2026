# Candidate Patches

> **Static review only.** These diffs were authored and reviewed by
> independent agents reading source. They were NOT compiled, run, or
> re-attacked. Read each diff yourself before applying — see
> `docs/patching.md#reviewing-generated-patches` for what to look for.

**Input:** TRIAGE.json · **Repo:** /home/tanis/github/depj-proj/eShop · 9 findings → 9 diffs (6 accepted, 3 rejected)

**Before applying any of these:**
- **Role names now match.** bug_01 and bug_03 both require role `Admin`. bug_01 originally used `admin`; I changed it after review.
- **No role claim exists yet.** Identity.API issues no role claim today, so after bug_01 and bug_03 nobody can write to the catalog or ship orders until an admin role is issued. Both fail closed.
- **Diffs overlap.** Each diff was written against the original tree, so applying several will conflict:
  - `OrdersApi.cs`: bug_00, bug_03, bug_05, bug_07
  - `OrdersWebApiTest.cs`: bug_00, bug_05
  - `CatalogApi.cs` and `CatalogApiTests.cs`: bug_01, bug_08
  - `AppHost.cs`: bug_01, bug_04
- **Whitespace was lost.** I copied the diffs out of agent reports, and blank context lines may have lost trailing whitespace. Use `git apply --ignore-whitespace` or regenerate.
- **Two headers were fixed after review.** I corrected the line counts in the bug_00 and bug_05 hunk headers once review was done. The content is unchanged.
- **bug_02 doesn't contain the real fix.** It leaves out the deletion of the key file on purpose, so the diff carries no key material. Remove `src/Identity.API/tempkey.jwk` by hand, purge it from history, and rotate the key in every deployment that used it.

---

## bug_00: [HIGH] GET /api/orders/{orderId} returns any user's order (no ownership check)  (f001)

`src/Ordering.API/Apis/OrdersApi.cs:80` · idor · owner: component: src/Ordering.API/; no CODEOWNERS; recent committers Rob Conery, David Fowler (1/4 each)
**Status:** static_review_only · review ACCEPT · style 5/10
**Diff:** `PATCHES/bug_00/patch.diff` (6 hunks, 93 lines)

**Rationale:** Root cause OrderQueries.cs:8-10: GetOrderAsync selects by primary key only, and its sole caller OrdersApi.GetOrderAsync (OrdersApi.cs:84) never reads caller identity. IOrderQueries.GetOrderAsync now takes userId and filters o.Id == id && o.Buyer.IdentityGuid == userId (same predicate as GetOrdersFromUserAsync, OrderQueries.cs:40); OrdersApi passes IdentityService.GetUserIdentity() (sub). Non-owned orders throw KeyNotFoundException -> existing 404, so no exists-but-not-yours oracle. Null/empty userId rejected in the query to avoid EF IS NULL matching buyer-less rows. No admin bypass added. Agent ran `git apply --check` from stdin (no writes) against the read-only brief.

**Variants checked:** GetOrdersFromUserAsync already filtered; GetCardTypesAsync reference data; only production caller OrdersApi.GetOrderAsync updated plus two test mocks; cancel (f002), ship (f011), create/draft (f005) left to siblings; mobile-bff /api/orders/{*any} reaches the same handler; functional test GetStoredOrdersWithOrderId still expects 404.

**Bypass considered:** Sequential id enumeration via API or BFF now 404s; principal without sub hits the IsNullOrEmpty guard; identity comes only from the token, never request input; no other order-detail read path exists.

**Test:** tests/Ordering.UnitTests/Application/OrdersWebApiTest.cs Get_order_of_another_user_returns_not_found; two existing mocks updated for the new signature. SQL predicate not unit-tested (no EF in-memory provider in Ordering.UnitTests). Not built or run.

> **Reviewer:** The OrderQueries.cs hunk changes the lookup to FirstOrDefaultAsync(o => o.Id == id && o.Buyer.IdentityGuid == userId) and OrdersApi.cs:84 passes IdentityService.GetUserIdentity(), closing the IDOR at the data layer with the same ownership predicate GetOrdersFromUserAsync uses; empty identity fails closed and no new input is trusted. Style 5 because the OrdersApi.cs hunk header was off by one (-80,6 should be -80,7 +80,8) and the OrderQueries.cs blank context line lacked the source's trailing whitespace. Orchestrator corrected both mechanical issues in PATCHES/bug_00/patch.diff after review; content unchanged. The new unit test mocks the query layer, so the EF filter itself is not exercised.

---

## bug_01: [HIGH] Catalog create/update/delete endpoints have no authentication and are reachable from the internet via mobile-bff  (f003)

`src/Catalog.API/Apis/CatalogApi.cs:100` · auth-bypass · owner: component: src/Catalog.API/; no CODEOWNERS; top committer Mike Kistler (3/11)
**Status:** static_review_only · review ACCEPT · style 7/10
**Diff:** `PATCHES/bug_01/patch.diff` (9 hunks, 197 lines)

**Rationale:** Root cause: CatalogApi.cs:100-117 maps the four catalog write routes with no authorization metadata, and Catalog.API Extensions.AddApplicationServices never calls AddDefaultAuthentication (unlike Basket/Ordering/Webhooks), so the service has no auth at all. The patch adds AddDefaultAuthentication, puts .RequireAuthorization(policy => policy.RequireRole("Admin")) on PUT v1, PUT v2, POST and DELETE (plain RequireAuthorization is insufficient because any self-registered user can get a token), and passes Identity__Url/Audience/Scopes to catalog-api via the AppHost rather than appsettings (to avoid breaking build-time OpenAPI generation). GET routes stay anonymous. Fails closed if Identity config is missing (auth-tagged endpoints 500). No admin role claim is issued by Identity.API today, so catalog writes are effectively disabled until an operator provisions one. Restricting mobile-bff catalog routes to GET and narrowing SetValues to a DTO are left as follow-ups. Role name aligned to "Admin" (same as bug_03) by the orchestrator after review.

**Variants checked:** Only four write routes exist in Catalog.API (all covered); GETs intentionally anonymous; Ordering/Webhooks already group-protected (gaps are f001/f002/f011); Basket already authenticated; mobile-bff catalog routes only proxy; overlaps with f031 (CreateItem Id) and f006 (pricing) noted.

**Bypass considered:** Anonymous write via catalog-api or mobile-bff catch-all now 401; authenticated non-admin now 403; api-version switching does not help since each versioned route carries the policy; missing Identity config makes auth-tagged endpoints fail; forged JWTs fail signature/issuer validation, contingent on f004 being fixed.

**Test:** tests/Catalog.FunctionalTests/CatalogApiTests.cs CatalogItemWriteEndpointsRequireAdminRole (401 anonymous, 403 customer, v1 and v2). CatalogApiFixture adds dummy Identity config and a test-only startup filter signing requests in from an X-Test-Role header; CreateHttpClient defaults to role Admin. Conflicts with bug_08 (f031), which edits the same test file and CreateHttpClient callers. Not built or run.

> **Reviewer:** CatalogApi.cs adds RequireAuthorization(RequireRole("Admin")) to all four write routes and Extensions.cs adds the AddDefaultAuthentication registration they need, fixing the root cause (no auth in Catalog.API at all). AppHost Identity__* wiring is required; the X-Test-Role middleware is test-only. Owners should know Identity.API issues no Admin role and defines no catalog scope, so writes fail closed for everyone once deployed, and shared ValidateAudience=false leaves the role check as the only guard.

---

## bug_03: [MEDIUM] PUT /api/orders/ship (admin action) is open to any authenticated user for any order  (f011)

`src/Ordering.API/Apis/OrdersApi.cs:12` · privilege-escalation · owner: component: src/Ordering.API/; no CODEOWNERS; recent committers Rob Conery, David Fowler (1/4 each)
**Status:** static_review_only · review ACCEPT · style 6/10
**Diff:** `PATCHES/bug_03/patch.diff` (4 hunks, 66 lines)

**Rationale:** Root cause OrdersApi.cs:12: the ship route inherits only the policy-less group RequireAuthorization (Program.cs:21-22). Adds an endpoint-level .RequireAuthorization(policy => policy.RequireRole("Admin")), combined with the group policy, so non-admins get 403 before the handler runs. DEPLOYMENT CAVEAT: Identity.API ProfileService issues no role claim and no seeded user has a role, so after this patch nobody can ship via the API until the IdP issues role=Admin to operator accounts (fails closed); the IdP-side change is left as a follow-up. The agent ran `git apply --check` (no writes) despite the read-only brief.

**Variants checked:** Only /ship is an admin action; cancel/get/create are siblings f002/f001/f005; SetShippedStatus is reached only via this endpoint; mobile-bff /api/orders/{*any} forwards to the same endpoint; ValidateAudience=false is cross-service and out of scope.

**Bypass considered:** BFF path hits the same gated endpoint; replayed IdentifiedCommand still passes authorization first; other-audience tokens still need a role=Admin claim the IdP does not issue; the x-test-role header is read only by the test-only AutoAuthorizeMiddleware.

**Test:** tests/Ordering.FunctionalTests/OrderingApiTests.cs ShipWithoutAdminRoleIsForbidden (expects 403); AutoAuthorizeMiddleware adds a role claim from an x-test-role header so the two existing ship tests still exercise handler logic. Not built or run.

> **Reviewer:** The OrdersApi.cs hunk adds RequireAuthorization(policy => policy.RequireRole("Admin")) to /ship, fixing the vertical privilege escalation at the route; the test-only x-test-role middleware never runs in production and the new 403 test covers the fix. Style docked for the inline policy and hard-coded "Admin" string, and because Identity.API issues no role claim the endpoint refuses everyone until role issuance is added.

---

## bug_04: [MEDIUM] Order item prices and product names are taken from the client request  (f006)

`src/Ordering.API/Extensions/BasketItemExtensions.cs:20` · business-logic · owner: component: src/Ordering.API/; no CODEOWNERS; top committer Aditya Mandaleeka (1/1)
**Status:** static_review_only · review ACCEPT · style 7/10
**Diff:** `PATCHES/bug_04/patch.diff` (8 hunks, 187 lines)

**Rationale:** Root cause CreateOrderCommandHandler.cs:44, the only place a persisted Order gets its items, passes client item.ProductName/UnitPrice into Order.AddOrderItem (values originate in CreateOrderRequest.Items via ToOrderItemDTO, which only maps). Adds ICatalogService/CatalogService, a typed HttpClient calling Catalog.API's existing read-only GET api/catalog/items/by?ids=... (the endpoint WebApp already uses for basket pricing), and the handler resolves every ProductId before doing anything else, building each OrderItem from catalog Name and Price; unknown ProductIds throw OrderingDomainException. Registered with base address https+http://catalog-api; AppHost adds .WithReference(catalogApi) to ordering-api. Fails closed: catalog unreachable or unknown product means no order is persisted (IdentifiedCommandHandler returns false; API response unchanged). Assumes api-version query param is honoured by Catalog.API. PictureUrl remains client-supplied (display-only).

**Variants checked:** CreateOrderCommandHandler fixed; CreateOrderDraftCommandHandler has the same pattern but builds an unsaved draft returned to the same caller (not fixed); only two AddOrderItem callers; mapping helpers unchanged; Discount never populated from client input; textual merge conflict expected with f005 (same handler/endpoint area); uses only the read-only items/by endpoint so f003's write auth does not affect it.

**Bypass considered:** Forged UnitPrice/ProductName ignored; non-existent ProductId now rejected; duplicate ProductIds priced from catalog then merged; units <= 0 still rejected by OrderItem; catalog failure rejects the order rather than falling back.

**Test:** tests/Ordering.UnitTests/Application/NewOrderCommandHandlerTest.cs Handle_uses_catalog_price_and_name_instead_of_client_supplied_values (captures the Order passed to IOrderRepository.Add); existing test and FakeOrderRequestWithBuyer helper updated. Not compiled or run; hunk counts checked by hand.

> **Reviewer:** The handler hunk replaces item.ProductName/item.UnitPrice with catalogItem.Name/Price looked up by ProductId from catalog-api, removing trust in the client price that BasketItemExtensions.cs:20 feeds via CreateOrderCommand.cs:70; unknown products throw rather than fall back. CatalogService, DI and AppHost hunks are required wiring; the new test checks a forged 0.01 becomes the catalog's 100. Residuals: PictureUrl still client-controlled; order creation now depends on catalog-api availability; a dropped trailing space on a context line may need --ignore-whitespace.

---

## bug_06: [MEDIUM] Indirect prompt injection via catalog content plus GetUserInfo tool plus auto-rendered images exfiltrates user PII with zero clicks  (f012)

`src/WebApp/Components/Chatbot/MessageProcessor.cs:24` · prompt-injection · owner: component: src/WebApp/; no CODEOWNERS; committers Stephen Toub, Aditya Mandaleeka (1/2 each)
**Status:** static_review_only · review ACCEPT · style 7/10
**Diff:** `PATCHES/bug_06/patch.diff` (4 hunks, 54 lines)

**Rationale:** Root cause MessageProcessor.cs:24: AllowImages turns every model-emitted markdown link/image into a raw <img src> with no URL check, rendered as MarkupString at Chatbot.razor:46, enabling zero-click exfiltration. Adds an anchored allowlist (IsProductImageUrl) accepting only the app's own same-origin shape product-images/{int} with optional ?api-version=N.N (ProductImageUrlProvider.cs:8, ChatState.cs:125); anything else is emitted as HTML-encoded literal text. GetUserInfo narrowing, untrusted-tool-output marking and CSP img-src 'self' are left as defense-in-depth; the sink fix alone breaks the chain.

**Variants checked:** Only MarkupString sink in WebApp/WebAppComponents is Chatbot.razor:46 via AllowImages (fixed). Other <img src> sites (CatalogListItem.razor:10, ItemPage.razor:22/79, CartPage.razor:43) use server-built ProductImages.GetProductImageUrl(id) (no fix). ChatState.SearchCatalog/GetUserInfo left unchanged. Injection vector overlaps f003.

**Bypass considered:** Absolute/protocol-relative URLs fail the ^/?product-images/ anchor; path tricks fail \d+$; extra query params fail the api-version-only anchored query; encoded/whitespace variants fail and render as text. Residual: model can still print PII as visible text, which is not exfiltration.

**Test:** tests/Application.UnitTests/MessageProcessorTests.cs plus a ProjectReference to src/WebApp/WebApp.csproj (no WebApp test project exists). Unbuilt; possible Program type collision with other referenced web projects is unverified.

> **Reviewer:** Line 24 of MessageProcessor.cs previously emitted <img src> for any URL in model output, enabling exfiltration via image requests; the first hunk now emits <img> only when the anchored IsProductImageUrl regex matches, which fits the product-images/{id}?api-version=2.0 URLs from ProductImageUrlProvider.cs:8 and ChatState.cs:125, and HTML-encodes everything else. No new surface; csproj and test hunks are in scope, though the test covers only the reject case and rejected links now render as visible encoded markdown.

---

## bug_07: [LOW] PUT /api/orders/cancel cancels any user's order  (f002)

`src/Ordering.API/Application/Commands/CancelOrderCommandHandler.cs:21` · idor · owner: component: src/Ordering.API/; no CODEOWNERS; top committer Aditya Mandaleeka (1/1)
**Status:** static_review_only · review ACCEPT · style 7/10
**Diff:** `PATCHES/bug_07/patch.diff` (5 hunks, 86 lines)

**Rationale:** Root cause CancelOrderCommandHandler.cs:21-27 loads by client OrderNumber and cancels with no ownership check, and CancelOrderCommand carries no caller identity. Because the handler is also used by the internal OrderPaymentFailedIntegrationEventHandler (no HttpContext), identity is placed on the command: CancelOrderCommand gains optional UserId; OrdersApi.CancelOrderAsync always overwrites it with the token sub (403 if missing); the handler resolves the Buyer via IBuyerRepository.FindAsync(UserId) and returns false unless order.BuyerId == buyer.Id (BuyerId because GetAsync does not load the Buyer navigation). A false result reuses the existing 500 'Cancel order failed' response, so no existence oracle. The internal payment-failed path keeps UserId null and still cancels.

**Variants checked:** Ship (f011) left to sibling; integration-event-only Set*Status handlers need no change; OrderPaymentFailedIntegrationEventHandler works with UserId null; GET (f001) and create (f005) are siblings; IdentifiedCommandHandler only forwards; ClientApp DTO compatible; existing OrdersWebApiTest mocks return "" for userId; functional tests' AutoAuthorizeMiddleware adds sub.

**Bypass considered:** Body userId (null or another user) is overwritten from the token; missing sub returns 403 before dispatch (prevents impersonating the internal null path); empty sub finds no buyer; accounts with no Buyer row fail; orders with null BuyerId fail closed (owner also cannot cancel in that short window).

**Test:** tests/Ordering.UnitTests/Application/CancelOrderCommandHandlerTest.cs Handle_does_not_cancel_order_owned_by_another_buyer. Not built or run.

> **Reviewer:** The handler hunk resolves the caller's Buyer via IBuyerRepository.FindAsync and refuses the cancel when Order.BuyerId differs, fixing the root cause at CancelOrderCommandHandler.cs:25-31; the endpoint sets UserId from the token sub with `command with { UserId = userId }`, discarding any client value. Design weakness: a null UserId skips the check (fail-open by design for OrderPaymentFailedIntegrationEventHandler), so any future HTTP path that builds CancelOrderCommand without UserId would bypass it. OrdersApi hunk header is one line off but applies with offset.

---

## bug_02: [HIGH] IdentityServer RSA signing private key is committed to git and shipped in build output  (f004)

`src/Identity.API/tempkey.jwk:1` · hardcoded-secret · owner: component: src/Identity.API/; no CODEOWNERS; added by Aditya Mandaleeka (1/1, initial commit fc61f90)
**Status:** static_review_only · review REJECT · style 6/10
**Diff:** `PATCHES/bug_02/patch.diff` (5 hunks, 72 lines)

**Rationale:** Root cause: src/Identity.API/tempkey.jwk is a git-tracked RSA private key (added fc61f90), Identity.API.csproj:50 copies it into every build/publish output, and Program.cs:29/:37 disable Duende key management and call AddDeveloperSigningCredential() unconditionally, which loads that file. The diff (1) removes the csproj Content item, (2) gitignores tempkey.jwk so a regenerated dev key cannot be recommitted, (3) restricts AddDeveloperSigningCredential to Development and enables Duende automatic key management elsewhere. NOT in the diff (secret contents deliberately not emitted): git rm src/Identity.API/tempkey.jwk; purge from history (git filter-repo/BFG), force-push, invalidate clones/forks; treat the key as compromised and rotate it in every deployment/image that ran with it, rebuild and redeploy. Ops: Duende automatic key management in production needs a Duende license plus shared key/Data Protection storage for multiple replicas; a Key Vault-backed AddSigningCredential is the alternative. Note: the agent ran `git apply --check` (no writes) despite the read-only brief; eShop working tree confirmed unmodified.

**Variants checked:** Repo-wide grep for tempkey, AddDeveloperSigningCredential, KeyManagement, AddSigningCredential: only Identity.API Program.cs:29/37 and Identity.API.csproj:50 in code. tempkey.jwk is the only tracked key-material file. Consuming APIs' validation hardening (audience) is separate. f001/f002/f005 depend on token integrity restored here.

**Bypass considered:** ASPNETCORE_ENVIRONMENT=Development still uses a developer credential, but a fresh random per-instance key, not forgeable. Keys from git history or already-published images remain valid until history purge plus rotation. Re-committing a regenerated dev key is blocked by the .gitignore entry.

**Test:** tests/Application.UnitTests/IdentityConfigurationTests.cs SigningKeyIsNotCopiedToBuildOutput (Application.UnitTests references Identity.API, so the Content item flowed the key into its output). Needs a clean build for the after-check because PreserveNewest leaves stale copies. The Development/non-Development signing switch is untested.

> **Rejected by reviewer:** src/Identity.API/tempkey.jwk is tracked and the diff never deletes it; the .gitignore entry has no effect on a tracked file, and in Development AddDeveloperSigningCredential() still loads the committed key from the project directory, contradicting the new 'never committed' comment. The csproj hunk only stops copying to build output, and the new test checks that symptom rather than the key's presence. Non-Development key management change is the right direction (licensing and shared key storage caveats). Orchestrator note: the missing deletion is a consequence of the patch brief forbidding secret contents as removed lines; the author's rationale (not shown to the reviewer) requires git rm, history purge and key rotation. The comment wording 'never committed' should be fixed.

---

## bug_05: [MEDIUM] CreateOrder trusts body-supplied UserId/UserName instead of the JWT subject  (f005)

`src/Ordering.API/Apis/OrdersApi.cs:141` · auth-bypass · owner: component: src/Ordering.API/; no CODEOWNERS; recent committers Rob Conery, David Fowler (1/4 each)
**Status:** static_review_only · review REJECT · style 4/10
**Diff:** `PATCHES/bug_05/patch.diff` (2 hunks, 55 lines)

**Rationale:** Root cause OrdersApi.cs:141: CreateOrderAsync passes client-controlled CreateOrderRequest.UserId/UserName into CreateOrderCommand, which drives OrderStartedIntegrationEvent (basket deletion), the Order aggregate and the Buyer/payment-method upsert. The endpoint now takes identity from the validated JWT via services.IdentityService (sub and User.Identity.Name) and rejects requests lacking either with 400 before any command is sent. The CreateOrderRequest record is unchanged for wire compatibility; body identity fields are ignored. Buyer.Name for new buyers now comes from the token Name claim (cosmetic). The log line at L126-130 still prints request.UserId (log text only).

**Variants checked:** CreateOrderDraftAsync takes BuyerId from body but the draft handler never reads it; GetOrdersByUserAsync already uses IdentityService; get/cancel/ship are siblings f001/f002/f011; CreateOrderCommand is constructed only at OrdersApi.cs:141 in src; handler's unused IIdentityService left as-is; pricing is sibling f006; Basket.API already derives userId from sub.

**Bypass considered:** Victim UserId/UserName/Buyer in the body are ignored; missing sub/name claims yield 400 before Mediator.Send; replayed x-requestid only hits the caller's own idempotency path; POST /api/orders is the only route that issues CreateOrderCommand.

**Test:** tests/Ordering.UnitTests/Application/OrdersWebApiTest.cs Create_order_uses_token_identity_not_request_body (captures the sent IdentifiedCommand and asserts token identity). Not compiled or run.

> **Rejected by reviewer:** The OrdersApi.cs hunk fixes the root cause by replacing client-controlled request.UserId/UserName at line 141 with token identity from IdentityService (matching GetOrdersByUserAsync at line 95) and fails closed with 400 when identity is missing. Rejected only because the test hunk header declared +179,30 while the body has 27 new-side lines, so the diff was malformed; the reviewer said correcting it to +179,27 would make this an ACCEPT. Orchestrator corrected the header in PATCHES/bug_05/patch.diff after review; content unchanged.

---

## bug_08: [LOW] CreateItem accepts a client-supplied primary key, allowing sequence collisions that block item creation  (f031)

`src/Catalog.API/Apis/CatalogApi.cs:421` · business-logic · owner: component: src/Catalog.API/; no CODEOWNERS; top committer Mike Kistler (3/11)
**Status:** static_review_only · review REJECT · style 6/10
**Diff:** `PATCHES/bug_08/patch.diff` (5 hunks, 87 lines)

**Rationale:** Root cause CatalogApi.cs:421 (CreateItem) copies Id = product.Id from the body; on a Postgres identity-by-default column the explicit Id does not advance the sequence. The fix removes that assignment so EF lets Postgres assign the Id; Location already reflects item.Id. Companion change: CatalogContextSeed.cs seeds explicit ids, so SeedAsync now ends with a constant setval(pg_get_serial_sequence('"Catalog"','Id'), MAX(Id)+1, false), run outside the if(!Any()) block so existing databases (including attacker-claimed ids) are repaired on startup; idempotent. UpdateItem (v2 PUT /items/{id}) now returns 400 when the body Id differs from the route id instead of a 500 from EF. Anonymous creation itself is f003.

**Variants checked:** CreateItem fixed; UpdateItem/UpdateItemV1 mismatch rejected (V1 consistent by construction); CatalogContextSeed.SeedAsync sequence repaired; no other body-to-PK copy in src; CatalogBrand/CatalogType use generated ids; overlap with f003 (auth) noted; if f003 adds auth these functional tests will need its auth setup.

**Bypass considered:** Any client Id is ignored; pre-claimed ids are skipped by the startup setval; mismatched v2 PUT returns 400 before SetValues and PUT never inserts.

**Test:** tests/Catalog.FunctionalTests/CatalogApiTests.cs CreateCatalogItemIgnoresClientSuppliedId (v1 and v2); AddCatalogItem and GetCatalogItemPicDoesNotServeFilesOutsidePics updated to read the id from Location. Hunk line numbers computed by hand; not built or run.

> **Rejected by reviewer:** The CreateItem hunk removes Id = product.Id at line 421 (root-cause fix) and the seed setval hunk is a necessary follow-on because the seeder inserts explicit ids into an IdentityByDefault column; the constant raw SQL adds no input surface. The UpdateItem hunk (-375,7) adds a body/route id check to a different function on the v2 PUT route, which already fails with a 500 when EF refuses the key change, so it is scope creep and should be a separate change. Without it the reviewer would ACCEPT at about 7.
> **Out-of-scope hunks:** src/Catalog.API/Apis/CatalogApi.cs:375

---

## Skipped

None. Every confirmed finding produced a diff.
