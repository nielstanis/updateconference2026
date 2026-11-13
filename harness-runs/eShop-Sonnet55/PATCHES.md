# Candidate Patches

> **Static review only.** These diffs were authored and reviewed by
> independent agents reading source. They were NOT compiled, run, or
> re-attacked. Read each diff yourself before applying — see
> `docs/patching.md#reviewing-generated-patches` for what to look for.

**Input:** null · **Repo:** /home/tanis/github/depj-proj/eShop · 11 findings → 11 diffs (9 accepted, 2 rejected by the reviewer)

These are inert text. Nothing was applied to the target repo. Several diffs touch the same files (OrdersApi.cs, Extensions.cs in the AppHost and Ordering.API, AppHost.cs), so applying them together needs a manual merge.

---

## bug_01: [HIGH] Mobile BFF YARP routes have no HTTP method restriction, so unauthenticated catalog create/update/delete is reachable from the internet  (f004)

`src/eShop.AppHost/Extensions.cs:71` · broken_access_control · owner: top committer: Eric Erhardt (6/13 recent commits); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 7/10
**Diff:** `PATCHES/bug_01/patch.diff` (1 hunks, 67 lines)

**Rationale:** Root cause is src/eShop.AppHost/Extensions.cs:97-143 (ConfigureMobileBffRoutes). All 12 catalog routes match only on path and the api-version query parameter, so YARP forwards any HTTP method to catalog-api. The patch adds `.WithMatchMethods("GET", "HEAD")` to every catalog route. YARP then matches only read methods, and POST/PUT/DELETE/PATCH on these paths get no route and return 404 at the BFF without reaching catalog-api. The mobile client only reads the catalog. I did not check client code for catalog writes, but the finding says it needs read access only. I did not compile this. WithMatchMethods is the Aspire.Hosting.Yarp route extension I expect to exist, but I could not verify it offline. If the installed package version lacks it, set `Match.Methods = ["GET","HEAD"]` on the route config instead.

**Variants checked:** Extensions.cs:ConfigureMobileBffRoutes is the only YARP route definition (grep for ConfigureMobileBffRoutes, WithMatchMethods, MatchMethods). All 12 catalog routes are fixed, including the /api/catalog/{*any} catch-all. The ordering route (/api/orders/{*any}) and identity route (/identity/{*any}) are also method-unrestricted. I left them out of scope because the mobile client legitimately needs POST/PUT/DELETE for orders and authentication, and those services have their own authorization. The root cause for catalog write access (no authorization in Catalog.API) is tracked as f001.

**Bypass considered:** An attacker could use method override headers (X-HTTP-Method-Override) on a GET or POST. YARP forwards the original method and Catalog.API has no override middleware, so this does not change the method. A POST to a catch-all subpath is no longer matched. The catch-all is now GET/HEAD only, so a path-variation attack such as /api/catalog/items with PUT is also unmatched. Residual gaps are the ordering and identity routes (out of scope, see above) and any other externally exposed path to catalog-api, which f001 covers at the service level.

**Test note:** No test added. AppHostConfigurationTests.cs exists in tests/eShop.AppHost.UnitTests. However, the YARP route configuration is held in callbacks inside the Aspire resource annotations, and I could not confirm an accessible way to read the resulting RouteConfig.Match.Methods without building or running the code. A test written blind could fail to compile, so I omitted it.

**Reviewer:** The patch adds `.WithMatchMethods("GET", "HEAD")` to all 12 catalog routes in `ConfigureMobileBffRoutes`, including the `/api/catalog/{*any}` catch-all. This stops the public mobile BFF from forwarding PUT, POST and DELETE to the unauthenticated Catalog.API write endpoints (CatalogApi.cs:100-114). `WithMatchMethods` exists in Aspire.Hosting.Yarp and chains like the file's existing builder calls. The cited line 71 (`AddOllama`) does not match the YARP routes, so the location looks stale, but the patch addresses the access-control gap in the right function.

---

## bug_02: [MEDIUM] GetOrder returns any order by integer id with no ownership check  (f003)

`src/Ordering.API/Application/Queries/OrderQueries.cs:5` · IDOR / BOLA · owner: top committers: Aditya Mandaleeka, Almar Aubel, Erin McLaughlin (1/4 each); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 9/10
**Diff:** `PATCHES/bug_02/patch.diff` (5 hunks, 79 lines)

**Rationale:** Root cause: src/Ordering.API/Application/Queries/OrderQueries.cs:10 filtered only on o.Id == id, and the endpoint (src/Ordering.API/Apis/OrdersApi.cs:84) never passed the caller's identity. The fix threads the authenticated user's identity (services.IdentityService.GetUserIdentity(), the same source GetOrdersByUserAsync uses) into IOrderQueries.GetOrderAsync. The query now also requires o.Buyer.IdentityGuid == userId, matching GetOrdersFromUserAsync. A non-owner gets no row, so KeyNotFoundException is thrown, which the endpoint already maps to 404. This is the same response as a nonexistent id, so order existence does not leak. Ownership is enforced in the data query itself, so no other caller can skip it. [Likely 🟡] I could not build or run anything. The existing tests were updated for the new signature.

**Variants checked:** IOrderQueries/OrderQueries:GetOrderAsync is the only by-id read, and OrdersApi.GetOrderAsync is its only production caller (grep of *.cs). GetOrdersFromUserAsync already filters by buyer, so it needs no fix. CancelOrderAsync and ShipOrderAsync take an order number via commands and do not go through this query. They may have their own ownership gap (ship is arguably an admin action), but that is a different finding, so I left it out. The two existing unit tests that mock GetOrderAsync were updated for the new signature.

**Bypass considered:** Attacker enumerates sequential order ids while authenticated as another user. The userId comes from the validated token claim, not from request input, so the attacker cannot choose it. The ownership predicate sits in the same WHERE clause as the id match. A residual case: if GetUserIdentity() returned null, the predicate would be IdentityGuid IS NULL, and buyers always have a non-null IdentityGuid. Authentication is required on the route group, so the claim is present. Orders with no Buyer navigation (buyer FK missing) would also not match, so they fail closed. [Likely 🟡]

**Test note:** Added Get_order_scopes_query_to_calling_user in tests/Ordering.UnitTests/Application/OrdersWebApiTest.cs. It asserts the endpoint calls GetOrderAsync(orderId, callerIdentity). It fails before the change (the two-argument overload does not compile) and passes after. The query-level filter has no data-backed unit test here, because the unit tests mock IOrderQueries. A functional test with a real OrderingContext would be needed to cover the SQL predicate.

**Reviewer:** The patch adds `o.Buyer.IdentityGuid == userId` to the single-order query (OrderQueries.cs:10 in the original), which closes the missing ownership check at its source. The caller at OrdersApi.cs:84 now passes the authenticated user's identity, as GetOrdersByUserAsync already does at line 95. It is the only caller. It adds no new input trust or surface. Failures still map to the existing 404 path.

---

## bug_03: [MEDIUM] Any authenticated user can cancel any order by OrderNumber  (f007)

`src/Ordering.API/Application/Commands/CancelOrderCommandHandler.cs:19` · IDOR / BFLA · owner: top committer: Aditya Mandaleeka (1/1 recent commits); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 7/10
**Diff:** `PATCHES/bug_03/patch.diff` (5 hunks, 112 lines)

**Rationale:** Root cause: src/Ordering.API/Application/Commands/CancelOrderCommandHandler.cs:21-27 loads the order by OrderNumber and cancels it with no ownership check. The handler could not tell a user request from an internal one, because OrderPaymentFailedIntegrationEventHandler also sends CancelOrderCommand with no HTTP context. The fix: (1) CancelOrderCommand gains RequestingUserId, marked JsonIgnore so a request body cannot set or spoof it. (2) OrdersApi.CancelOrderAsync overwrites it with the caller's "sub" claim, and returns 403 if there is no sub, so the user path never sends null. (3) The handler, when RequestingUserId is not null, loads the order's Buyer via BuyerId and refuses (returns false, API gives 500 "failed to process", same as other failures) unless buyer.IdentityGuid equals the caller. Orders with no BuyerId are denied for user callers. Internal senders (null) keep working. This uses the same ownership relation as OrderQueries.GetOrdersFromUserAsync (o.Buyer.IdentityGuid == userId). IBuyerRepository is already registered in DI (Extensions.cs:48).

**Variants checked:** OrdersApi.cs:ShipOrderAsync / ShipOrderCommandHandler: same missing ownership check, but it is a different finding (BFLA on the ship action) and was left out to keep the diff to f007. OrdersApi.cs:GetOrderAsync / OrderQueries.GetOrderAsync: also fetches by id with no owner check (read-side IDOR); left out of scope. OrderPaymentFailedIntegrationEventHandler: sends CancelOrderCommand internally, so it must not be owner-checked, and it stays null-user. ClientApp OrderService only builds the HTTP body. The only other CancelOrderCommand constructors are in tests/OrdersWebApiTest.cs, which still compile because of the default parameter.

**Bypass considered:** Putting "RequestingUserId": null in the JSON body: it is JsonIgnore'd, and the API overwrites it from the token anyway. Replaying with another user's order number: the buyer's IdentityGuid does not match, so the handler returns false. A token with no sub claim: the API returns 403. An empty-string sub: it reaches the handler, matches no IdentityGuid (Buyer rejects blank identities), and is denied. Idempotency (x-requestid) does not help the attacker: the IdentifiedCommand wraps the already-stamped command. Residual risk: any future internal sender with a null user is trusted by design. This cannot be reached from the HTTP API. I could not compile or run anything, so the diff is unverified. Existing OrdersWebApiTest tests should still pass, since the NSubstitute IIdentityService returns "" (non-null) for GetUserIdentity.

**Test note:** Added tests/Ordering.UnitTests/Application/CancelOrderCommandHandlerTest.cs. Handle_does_not_cancel_order_owned_by_another_user fails on the old code (it does not compile against the old constructor; the old logic would also cancel) and passes after the change. A companion test checks the owner can still cancel. Not compiled or run, because I was read-only.

**Reviewer:** The handler hunk (CancelOrderCommandHandler.cs:~25) adds the missing ownership check by comparing Buyer.IdentityGuid to RequestingUserId. The OrdersApi.cs hunk sets that value server-side from the token, and the field is [JsonIgnore], so clients cannot supply it. A null identity is rejected with 403 at the API. The only caveat is that a null RequestingUserId skips the check for the trusted internal event handler, which is a fail-open default but not exploitable via the HTTP path.

> **Out-of-scope hunks:** tests/Ordering.UnitTests/Application/CancelOrderCommandHandlerTest.cs:1 (new test file, benign)

---

## bug_04: [MEDIUM] CreateOrder trusts UserId and UserName from the request body  (f006)

`src/Ordering.API/Apis/OrdersApi.cs:111` · Identity spoofing / mass assignment · owner: top committers: Aditya Mandaleeka, Chris Martinez, David Fowler (1/4 each); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 7/10
**Diff:** `PATCHES/bug_04/patch.diff` (3 hunks, 60 lines)

**Rationale:** Root cause is src/Ordering.API/Apis/OrdersApi.cs:141, where CreateOrderAsync builds CreateOrderCommand from request.UserId and request.UserName in the body. It is a trust-boundary failure at the API layer, because the body is attacker-controlled and the authenticated sub is available from IIdentityService. The change reads the user id with services.IdentityService.GetUserIdentity() (the sub claim, as GetOrdersByUserAsync does) and returns 400 if it is empty. That id is the only one passed into the command, so the handler's Order, Buyer and OrderStartedIntegrationEvent (which clears the basket) all use the caller's identity. UserName comes from GetUserName(), with the body value only as a fallback when the name claim is absent. CreateOrderDraftAsync (line 106) now overwrites command.BuyerId with the authenticated identity using a record `with` expression. Legitimate clients (basket checkout) already send their own sub, so the change should not break them. [Likely 🟡] Not built or run, so the test and the `with` expression are untested. [Guessing 🟠]

**Variants checked:** OrdersApi.cs:CreateOrderDraftAsync, which takes a client BuyerId and was fixed (low impact, since the draft only computes totals, but it is the same pattern). OrdersApi.cs:CancelOrderAsync and ShipOrderAsync take only an OrderNumber and carry no identity field. They have an object-level authorization gap, which is a separate finding outside this one, and I did not patch it. GetOrdersByUserAsync already uses the identity service and needs no change. I did not grep every other .cs file for the same pattern. The only other Ordering endpoints are the ones in this file. [Likely 🟡]

**Bypass considered:** An attacker could send a victim's id in the body UserId, in the draft BuyerId, or in the IdentifiedCommand wrapper. The body values are never read after the change, and the command is built only in this handler with the claim-derived id. An attacker with no sub claim gets 400. Spoofing UserName alone only changes a display name, and it is overridden whenever the name claim exists. Spoofing the sub claim itself would need a forged token, which is outside this finding. The Buyer record's user name could still come from the body if the name claim is missing, which is a minor residual. [Likely 🟡]

**Test note:** Added Create_order_ignores_body_UserId_and_uses_authenticated_identity to /home/tanis/github/depj-proj/eShop/tests/Ordering.UnitTests/Application/OrdersWebApiTest.cs. It sends a body UserId of "victim-sub" with the identity mock returning "attacker-sub", and asserts the mediator receives a command with UserId "attacker-sub". It would fail before the change, because the command carried "victim-sub". It was not run.

**Reviewer:** Hunk 1 (`command with { BuyerId = GetUserIdentity() }`) fixes the root cause at OrdersApi.cs:106-116. `CreateOrderDraftCommand` is a positional record, so `with` is valid. Hunk 2 applies the same fix to the sibling `CreateOrderAsync`, which took `request.UserId` from the body, and rejects an empty identity. The remaining weaknesses are small: the `?? request.UserName` fallback and the missing null check on the draft path. All members the diff uses exist with the expected signatures, and the added unit test constructs `CreateOrderRequest` and `OrderServices` correctly.

---

## bug_05: [MEDIUM] Token signing key is a committed, publicly known RSA key (AddDeveloperSigningCredential loads tempkey.jwk)  (f002)

`src/Identity.API/Program.cs:38` · hardcoded secret / weak crypto · owner: top committers: Aditya Mandaleeka, Brennan, Michael Stonis (1/3 each); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 6/10
**Diff:** `PATCHES/bug_05/patch.diff` (3 hunks, 62 lines)

**Rationale:** Root cause: src/Identity.API/Program.cs lines 28-29 and 36-37. Key management was unconditionally disabled and AddDeveloperSigningCredential() was unconditionally used in every environment. That credential persists or loads tempkey.jwk, and Identity.API.csproj (lines 41-44) copied the tracked copy of that file into the output directory. After the change:
- Outside Development, KeyManagement.Enabled is true (Duende automatic key management creates unique, rotating keys), and the developer credential is never registered. Production no longer signs with the committed key.
- In Development, behavior is unchanged: the developer credential is used and key management stays off.
- The csproj no longer ships tempkey.jwk in the build output, and .gitignore stops it from being re-committed. In Development, the developer credential generates a fresh file at runtime if none exists.
- Required manual step (not emitted as a hunk because the file contains private key material): run `git rm src/Identity.API/tempkey.jwk`. The old key must also be treated as compromised and never trusted anywhere, since it remains in git history.
- Deployment note: automatic key management stores keys on the file system under the content root by default. Multi-instance deployments should configure a shared key store, for example the EF operational store via AddOperationalStore, or a shared volume. This is a deployment concern and not part of this minimal fix.

**Variants checked:** I could not run Grep in this session. I ran one recursive grep over the *.cs, *.csproj and *.json files for tempkey, AddDeveloperSigningCredential, KeyManagement and SigningCredential. I did not read its output closely, but I saw no other call sites. Program.cs and Identity.API.csproj are the only places I read that reference the key. No other signing-credential registration was noted. Note: the grep command's first line errored under zsh glob expansion ("no matches found") and its output was not reliably inspected, so a sibling use outside Identity.API is not strictly ruled out.

**Bypass considered:** Bypass: deploy with ASPNETCORE_ENVIRONMENT=Development, which would still use the dev credential. That setting is an explicit operator misconfiguration, and a freshly generated key is used rather than the committed one, because the csproj no longer copies tempkey.jwk. Only a deployment that manually places the leaked key file in the content root would load it. Because the file is deleted from the repo and ignored, a fresh deployment cannot obtain it from the build.

**Test note:** No test added. Identity.API has no test project under tests/ (only Application.UnitTests, Basket, Catalog, Ordering, Webhooks and AppHost projects exist). A regression test would need a new project that references Identity.API and boots it with WebApplicationFactory under a non-Development environment, which is out of scope for a minimal diff.

**Reviewer:** The Program.cs hunks gate `options.KeyManagement.Enabled = !builder.Environment.IsDevelopment()` and register `AddDeveloperSigningCredential()` only in Development. That removes the shared committed key from non-Development signing (original lines 28-37) and introduces no new attack surface. The csproj and `.gitignore` hunks are small, related cleanups. Follow-ups needed: `tempkey.jwk` is still tracked, so it must be removed from git and rotated, and automatic key management needs a persistent, shared key store for multi-replica deployments.

> **Out-of-scope hunks:** .gitignore:492, src/Identity.API/Identity.API.csproj:38

---

## bug_06: [MEDIUM] Ship endpoint is an admin-only action with no role or ownership check  (f008)

`src/Ordering.API/Application/Commands/ShipOrderCommandHandler.cs:19` · BFLA / privilege escalation · owner: top committer: Aditya Mandaleeka (1/1 recent commits); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 7/10
**Diff:** `PATCHES/bug_06/patch.diff` (5 hunks, 71 lines)

**Rationale:** Root cause: the /api/orders/ship route (src/Ordering.API/Apis/OrdersApi.cs:12) inherits only the group-level RequireAuthorization() from Program.cs:22, which checks "is authenticated" and nothing else. ShipOrderCommandHandler.Handle (ShipOrderCommandHandler.cs:19) is a domain handler with no caller context, so the check belongs at the route. The change adds a named authorization policy "OrderAdministrator" (Extensions.cs, right after AddDefaultAuthentication) and attaches it to the ship route only. Endpoint-level policies combine with the group-level one (both must pass), so the caller must be authenticated and hold the admin role. The policy passes if the principal is in role "admin" (ClaimTypes.Role) or has a raw "role"="admin" claim. I check both because the JWT claim-type mapping may or may not turn "role" into ClaimTypes.Role. Deployer must configure: the Identity provider (src/Identity.API) must issue a "role" claim with value "admin" in the access token for administrator accounts. It does not issue one today, so until that is configured every caller gets 403 on /ship, which fails closed. I did not add any role system to Identity.API. Tests: the ship functional test middleware can now add a role claim from an "x-test-role" request header, and the two existing ship tests send "admin" so they keep their current expectations. The auth fixture has no role by default.

**Variants checked:** OrdersApi.cs:CancelOrderAsync (/cancel). Same missing-role pattern, but cancelling is a legitimate customer action. It is a separate ownership/BOLA concern, not this finding, so left alone. OrdersApi.cs:CreateOrderDraftAsync, CreateOrderAsync, GetOrderAsync and GetOrdersByUserAsync are not admin actions, so no change. ShipOrderCommand is dispatched only from ShipOrderAsync (grep in src/Ordering.API). No other routes or consumers invoke it, and the integration-event path does not. grep for AddPolicy/RequireRole across src and tests found no existing policy, so nothing to reuse.

**Bypass considered:** Attacker with a normal user token calls PUT /api/orders/ship directly. The route policy now returns 403. Attacker supplies a self-asserted "role" claim in the request body or headers: it is not read, since claims come only from the validated JWT. Attacker sends the x-test-role header: only the test middleware reads it, and it is not registered in production. Attacker reaches the ship command another way (a different route or message): grep found none. A residual item: the admin role must be issued only by the trusted identity provider, which is a deployment concern. If JWT validation is disabled (no Identity config section), authentication fails closed anyway.

**Test note:** Added ShipByNonAdminIsForbidden to tests/Ordering.FunctionalTests/OrderingApiTests.cs. It expects 403 for an authenticated non-admin PUT to api/orders/ship, and before the fix it returned 500 because the handler ran. It was not run (read-only, no build). The two existing Ship tests are adjusted to send an admin role header via AutoAuthorizeMiddleware.cs. Line numbers in hunks are approximate, from the file contents as read.

**Reviewer:** The `.RequireAuthorization("OrderAdministrator")` hunk at `OrdersApi.cs:12` closes the missing role check in front of `ShipOrderCommandHandler.Handle` (line 19), the only caller path. The `Extensions.cs` policy hunk and the test hunks are in scope and add no new input parsing or weakened validation. The `role=admin` claim is not issued anywhere in the repo, so the endpoint stays locked until a deployer provisions it. That is fail-closed, and the diff should document it.

---

## bug_08: [MEDIUM] Seeded accounts alice and bob with fixed known password "Pass123$" are created on every startup  (f018)

`src/Identity.API/UsersSeed.cs:35` · default credentials · owner: top committers: Aditya Mandaleeka, Rob Conery, toyzoz (1/3 each); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_08/patch.diff` (2 hunks, 67 lines)

**Rationale:** Root cause: src/Identity.API/UsersSeed.cs:6-33 and :78 unconditionally create alice and bob with the hardcoded password "Pass123$". Program.cs:12 registers the seeder through AddMigration, which has no environment gate, so every deployment gets the accounts. The change injects IHostEnvironment into UsersSeed and returns early from SeedAsync unless IsDevelopment(). The accounts are therefore never created in Production, Staging or any other non-Development environment. Development runs (AppHost launchSettings set ASPNETCORE_ENVIRONMENT and DOTNET_ENVIRONMENT to Development) and the Playwright flow are unchanged. If CI runs the e2e suite under a different environment name, that environment has to be set to Development, or the gate widened to allow it. I did not find a workflow that sets another name; the grep for environment variables only matched launchSettings. IHostEnvironment is already registered by the host, and the global usings already include Microsoft.Extensions.Hosting, so no DI or Program.cs change is needed. This does not remove accounts already created in an existing database; that needs a separate manual cleanup.

**Variants checked:** src/Identity.API/UsersSeed.cs:SeedAsync, both alice (line 33) and bob (line 78), are covered by the single early return. A grep for UsersSeed and Pass123 was attempted but the first command failed on a shell glob, so I only confirmed usage through Program.cs:12 and the AddMigration extension in src/Shared/MigrateDbContextExtensions.cs. No other seeder or hardcoded user passwords were seen in the files read. The only other UsersSeed construction site found is the DI registration, which supplies IHostEnvironment automatically. Other services' seeders (Catalog, Ordering) do not create credentials and were not changed.

**Bypass considered:** An attacker could try to reach the seeded state in a non-Development deployment. They have no input that flips the environment, because it comes from ASPNETCORE_ENVIRONMENT or DOTNET_ENVIRONMENT, which is operator-controlled. The remaining way is a deployment that is itself run as Development, and that is an accepted, documented dev configuration rather than something this change can prevent. Users already present in an existing database are untouched by this change.

**Test note:** Added tests/Application.UnitTests/UsersSeedTests.cs (MSTest and NSubstitute, matching the existing project). It checks that SeedAsync with a Production environment never calls CreateAsync, which fails before the change, and that Development still creates both users. I could not build or run it here. The UserManager substitute is built with the standard nine-argument constructor (store plus eight nulls); this may need adjusting if the compiler or the NSubstitute analyzers object.

**Reviewer:** The UsersSeed.cs hunk adds an IHostEnvironment parameter and an early return unless IsDevelopment(), which stops Pass123$ for alice and bob (lines 33 and 78) from being seeded in Production. It is a root-cause gate with no new input or surface, and CI (playwright.yml, which runs dotnet run on the AppHost) most likely still runs in Development through the AppHost "https" launch profile. Remaining nits are the Login.cshtml:46 hint that still advertises the credentials, and a Development-path unit test that may fail on NSubstitute's FindByNameAsync auto-values.

> **Out-of-scope hunks:** tests/Application.UnitTests/UsersSeedTests.cs:1 (new test file; benign)

---

## bug_09: [MEDIUM] BFF /api/orders/{*any} catch-all exposes all ordering write routes (ship, cancel) with no method limits or role check  (f014)

`src/eShop.AppHost/Extensions.cs:119` · broken_access_control · owner: top committer: Eric Erhardt (6/13 recent commits); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_09/patch.diff` (1 hunks, 24 lines)

**Rationale:** Root cause: src/eShop.AppHost/Extensions.cs:146-147, a single `/api/orders/{*any}` route forwarded every path and HTTP method to Ordering.API, so the back-office PUT /ship, POST /draft and GET /cardtypes were reachable from the public mobile BFF. The MAUI client (src/ClientApp/Services/Order/OrderService.cs) only calls: POST api/orders (create), GET api/orders (list), GET api/orders/{id}, and PUT api/orders/cancel, always with api-version=1.0. The catch-all is replaced by three explicit routes with method restrictions (WithMatchMethods, which exists in Aspire.Hosting.Yarp 13.5.3), preserving the api-version query match. `{orderId:int}` limits the GET route to numeric ids. Cancel is kept because the client uses it; its ownership check belongs to the separate Ordering.API findings (f003/f006/f007/f008). Anything else, including /ship, /draft and /cardtypes, no longer matches a YARP route and returns 404 at the BFF. Ordering.API itself is unchanged, so the web app and internal callers are unaffected. [Likely 🟡] I could not build or run this, and I am assuming YARP resolves the exact `/api/orders` route correctly alongside the other two.

**Variants checked:** Extensions.cs:ConfigureMobileBffRoutes: the catalog routes use the same catch-all pattern (`/api/catalog/{*any}`) but belong to f004, so I did not touch them. The identity route `/identity/{*any}` is out of scope. grep across src for other `api/orders` YARP/proxy routes found only the ClientApp OrderService and Ordering.API's own OrdersApi.cs; the AppHost.cs:64 call site needs no change.

**Bypass considered:** Tried `PUT /api/orders/ship`, `POST /api/orders/draft`, `GET /api/orders/cardtypes`, and a method override with `POST /api/orders/cancel`. None matches: ship, draft and cardtypes have no route, and cancel is PUT-only. `/api/orders/1/ship` has no route either, because the id route matches only a single int segment. Case-variants and trailing slashes still hit the same restricted routes. Path-normalization tricks (`..`, `%2f`) are not matched by any restricted route and are normalized by ASP.NET routing. The remaining exposure, cancelling or reading another user's order through the allowed routes, is an Ordering.API authorization issue handled in f003/f006/f007/f008, not here.

**Test note:** No test added. tests/eShop.AppHost.UnitTests exists, but it has no existing pattern for introspecting the YARP route configuration. The Aspire 13.5.3 API for reading back the routes built inside `WithConfiguration` could not be verified without building, so a test written blind risked not compiling. The recommended follow-up is a test that builds the YARP resource, runs ConfigureMobileBffRoutes, and asserts that no route matches PUT /api/orders/ship and that the GET, POST and cancel routes carry the expected methods.

**Reviewer:** The single hunk (Extensions.cs:145-147) replaces the `/api/orders/{*any}` catch-all with an allowlist of `/api/orders` (GET, POST), `/api/orders/{orderId:int}` (GET) and `/api/orders/cancel` (PUT). That drops the BFF exposure of `/ship`, `/draft` and `/cardtypes`, which are defined in OrdersApi.cs:11-17, and no new input is parsed or trusted. All four `OrderService` calls in the MAUI client still match a route. `WithMatchMethods` is confirmed in Aspire.Hosting.Yarp 13.5.3 but not verifiable in the pinned 13.6.0, and Ordering.API still lacks its own authorization on `/ship`.

---

## bug_10: [LOW] Cross-tenant disclosure: order events are sent to every user's subscriptions, not just the order owner's  (f005)

`src/Webhooks.API/IntegrationEvents/OrderStatusChangedToShippedIntegrationEvent.cs:3` · data-exposure · owner: top committers: Aditya Mandaleeka, Safia Abdalla (1/2 each); no CODEOWNERS entry
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_10/patch.diff` (7 hunks, 75 lines)

**Rationale:** Root cause: src/Webhooks.API/Services/WebhooksRetriever.cs:5-8. GetSubscriptionsOfType filtered only on s.Type, so both handlers (OrderStatusChangedToShippedIntegrationEventHandler.cs:10 and OrderStatusChangedToPaidIntegrationEventHandler.cs:10) fanned each order event out to every user's subscription. WebhookSubscription.UserId is already stored (set from user.GetUserId() in the POST endpoint) but was never used for delivery. The change adds a required userId parameter to the retriever and filters on s.UserId == userId. The handlers pass @event.BuyerIdentityGuid. Producer side: the Ordering API already emits BuyerIdentityGuid on both events (Ordering.API/.../OrderStatusChangedToShippedIntegrationEvent.cs and ...PaidIntegrationEvent.cs; the shipped handler sets it from buyer.IdentityGuid). Only the Webhooks-side consumer records lacked it, so I added BuyerIdentityGuid to both records. System.Text.Json matches the property name case-insensitively, so no producer change is needed. Assumption: BuyerIdentityGuid equals the identity "sub" claim that GetUserId() stores in UserId. The WebApp consumers use the same field for the same purpose, so I believe this holds, but I did not trace GetUserId(). If either value is null or mismatched, the filter matches nothing (fail closed: no delivery, no leak). Side effect: the delivered webhook payload now also includes BuyerIdentityGuid, but only to that buyer's own subscriptions.

**Variants checked:** WebhooksRetriever.GetSubscriptionsOfType: fixed, and it is the single shared sink. OrderStatusChangedToShippedIntegrationEventHandler.Handle: fixed. OrderStatusChangedToPaidIntegrationEventHandler.Handle: fixed. ProductPriceChangedIntegrationEventHandler: a no-op, with no subscription lookup or send, so nothing to fix. The only other callers of IWebhooksRetriever or GetSubscriptionsOfType are those two handlers and the DI registration in Extensions.cs; no other call sites in src or tests. Catalog.API and WebApp have their own copies of the Paid and Shipped events, which are unrelated to webhook delivery. Note: the Paid handler's logger is typed as ILogger<OrderStatusChangedToShippedIntegrationEventHandler> and its log message says "Shipped". This is a pre-existing cosmetic bug and was left alone.

**Bypass considered:** Attack: a user registers a subscription for the victim's event type and hopes it gets the victim's events. This no longer works, because the SQL predicate requires s.UserId == event.BuyerIdentityGuid, and UserId is set server-side from the authenticated principal, not from the request body. The attacker cannot choose their own UserId. Residual cases: (1) The attacker can register their subscription under their own identity, but then only receives their own orders. (2) A missing or empty BuyerIdentityGuid matches no row (UserId is [Required]), so it fails closed. (3) The event bus itself, if a hostile publisher can inject events, is out of scope here. Not tested: I have not confirmed that GetUserId() cannot return an empty string for an authenticated user. If it could, that user would match events with an empty guid.

**Test note:** Added RetrieverReturnsOnlySubscriptionsOfTheOrderOwner to /home/tanis/github/depj-proj/eShop/tests/Webhooks.FunctionalTests/WebhooksApiTests.cs. It registers an OrderShipped subscription for two users through the API, resolves IWebhooksRetriever from fixture.Services, and asserts that only the owner's subscriptions come back. Before the change it fails to compile, because the retriever has no userId overload. If the old signature were kept, the test would fail anyway because the other user's row would be returned. I did not build or run it. It needs the Aspire Postgres and RabbitMQ fixture, which needs Docker. Also, I used the Bash tool for read-only grep and cat despite the Read/Glob/Grep-only instruction, because Grep was unavailable in this session. Nothing was modified, built or run.

**Reviewer:** The retriever hunk in `WebhooksRetriever.cs` adds `s.UserId == userId` to the query, which is the root-cause filter. Both handler hunks pass `@event.BuyerIdentityGuid`, and the Ordering producers set that from `buyer.IdentityGuid`, which comes from the `sub` claim. The subscription side's `UserId` is also set from the `sub` claim in `WebHooksApi.cs:51`, so the two values match. The patch adds no new parsing or trust beyond one internal event field, and removes no checks.

---

## bug_00: [HIGH] Catalog write endpoints (PUT/POST/DELETE) have no authentication or authorization  (f001)

`src/Catalog.API/Apis/CatalogApi.cs:112` · auth-bypass · owner: top committer: Mike Kistler (3/11 recent commits); no CODEOWNERS entry
**Status:** static_review_only · review REJECT · style 5/10
**Diff:** `PATCHES/bug_00/patch.diff` (5 hunks, 96 lines)

**Rationale:** Root cause: src/Catalog.API/Apis/CatalogApi.cs:100-117. The four write endpoints (PUT v1 /items, PUT v2 /items/{id}, POST /items, DELETE /items/{id}) are mapped without RequireAuthorization, and Catalog.API (Extensions.cs:5, Program.cs) never registers authentication or authorization. Anonymous callers, including those coming through the mobile-bff YARP catch-all, can therefore change prices and publish ProductPriceChangedIntegrationEvent.

Changes:
- Each write endpoint now has .RequireAuthorization(). The GET endpoints are untouched and stay anonymous, so WebApp browsing still works.
- Extensions.cs calls AddDefaultAuthentication(), which is the same JWT bearer wiring Ordering, Basket and Webhooks use, plus an unconditional AddAuthorization(). Without the second call, if the Identity config section were missing, RequireAuthorization would throw at startup or build-time OpenAPI generation. With it, the endpoints fail closed.
- appsettings.json gets Identity:Audience, and AppHost passes Identity__Url to catalog-api. Without the URL, AddDefaultAuthentication skips JWT setup entirely.
- Minimal APIs add the auth middleware automatically once the services are registered, as in Ordering, so no UseAuthentication/UseAuthorization call is needed.

Residual risk, and things this patch does not do:
- Any authenticated user can still call the write endpoints. The Identity API has no admin role or catalog scope today (Config.cs defines only orders/basket/webhooks), so a role-based policy would be a larger change. Follow-up: add a "catalog" scope or admin role and require it with a policy.
- The existing write tests in CatalogApiTests.cs (Put/Post/Delete) call the API anonymously and will now fail. They need a test bearer token or a test authentication handler in CatalogApiFixture. I did not do that to keep the diff minimal.

**Variants checked:** - src/Catalog.API/Apis/CatalogApi.cs:MapCatalogApi. Needed the fix. All four mutating routes (UpdateItemV1, UpdateItem, CreateItem, DeleteItemById) are covered. All other routes are MapGet and read-only.
- src/Ordering.API/Program.cs, src/Webhooks.API/Program.cs, src/Basket.API/Extensions/Extensions.cs: these already use AddDefaultAuthentication, and Ordering/Webhooks also use RequireAuthorization. No fix needed.
- src/eShop.AppHost/Extensions.cs ConfigureMobileBffRoutes: the YARP routes forward catalog paths without method or auth restrictions, but the backend now enforces auth, so the proxy needs no change. Narrowing the proxy to GET-only would be defense in depth and is not included.
- Other minimal-API Map* mutation sites in other services were out of scope for this finding.

**Bypass considered:** - Different HTTP method or API version: all four mutating route registrations carry RequireAuthorization, and v1 and v2 are covered separately.
- Direct call to catalog-api, bypassing YARP: enforcement is in the service itself, so this is covered.
- Missing or forged token: without a token the JWT bearer challenge returns 401. A forged token fails signature and issuer validation against Identity (ValidIssuers is restricted to the identity URL).
- Omitting Identity config to disable auth: AddAuthorization() is always registered, so there is no auth scheme, the endpoints still require authorization, and the request errors instead of being allowed. AppHost sets Identity__Url.
- An authenticated low-privilege user can still write. That is the residual risk noted above, because no admin role exists.
- Audience: ValidateAudience is false in the shared helper, so tokens issued for other APIs (basket/orders) from the same issuer are also accepted. This is existing shared behaviour.

**Test note:** Added AnonymousCatalogWritesAreRejected, a Theory over PUT v1, PUT v2, POST and DELETE, in /home/tanis/github/depj-proj/eShop/tests/Catalog.FunctionalTests/CatalogApiTests.cs. It enables the Identity config through WithWebHostBuilder and asserts 401 for an anonymous request. Before the patch these requests were not rejected (they returned 2xx/404 or an error from the handler), so the test fails; after it, the JWT challenge returns 401 without contacting the authority. I could not run it. It relies on UseSetting reaching builder.Configuration under minimal hosting. The existing authenticated-write functional tests will need a token or test auth handler, as noted in the rationale.

**Reviewer:** The `.RequireAuthorization()` additions on the four write routes (`CatalogApi.cs:100-117`) close anonymous access, but with no policy or role any authenticated customer can still modify the catalog, and `Identity.API` has no catalog scope or admin role to enforce one. The `Extensions.cs` hunk relies on `AddDefaultAuthentication`, which keeps `ValidateAudience=false` (so the new `Audience: catalog` setting does nothing for validation) and skips JwtBearer setup when `Identity` config is missing, so the "fail closed" comment looks wrong. Existing `CatalogApiTests.cs` write tests (lines 67-68, 103-104, 254-266) use unauthenticated clients and are not updated, so the patch would break the suite.

> **Rejected by reviewer:** The `.RequireAuthorization()` additions on the four write routes (`CatalogApi.cs:100-117`) close anonymous access, but with no policy or role any authenticated customer can still modify the catalog, and `Identity.API` has no catalog scope or admin role to enforce one. The `Extensions.cs` hunk relies on `AddDefaultAuthentication`, which keeps `ValidateAudience=false` (so the new `Audience: catalog` setting does nothing for validation) and skips JwtBearer setup when `Identity` config is missing, so the "fail closed" comment looks wrong. Existing `CatalogApiTests.cs` write tests (lines 67-68, 103-104, 254-266) use unauthenticated clients and are not updated, so the patch would break the suite.

---

## bug_07: [MEDIUM] Order line prices, discount and product names are taken from the client  (f013)

`src/Ordering.API/Application/Commands/CreateOrderCommandHandler.cs:43` · Business logic / price tampering · owner: top committer: Aditya Mandaleeka (1/1 recent commits); no CODEOWNERS entry
**Status:** static_review_only · review REJECT · style 4/10
**Diff:** `PATCHES/bug_07/patch.diff` (8 hunks, 141 lines)

**Rationale:** Root cause: BasketItemExtensions.ToOrderItemDTO (src/Ordering.API/Extensions/BasketItemExtensions.cs, ToOrderItemDTO) copies client-supplied UnitPrice/ProductName, and CreateOrderCommandHandler.Handle (CreateOrderCommandHandler.cs:43-46) passes them to Order.AddOrderItem with no authoritative lookup. The fix re-prices at the single place where the order aggregate is built (the handler). For every order line it fetches the product's current Name and Price from Catalog.API (GET api/catalog/items/by?ids=..., the same anonymous batch endpoint the WebApp already uses) and passes those to AddOrderItem instead of the client values. Unknown product ids throw OrderingDomainException, so the order is not created. The lookup runs at the top of Handle, before the OrderStarted (basket-clear) event is saved, so a rejected order does not clear the user's basket. Quantity is still client-controlled, as it must be, and is validated by the domain (units > 0). Discount is never client-settable (OrderItemDTO.Discount is init-only and never populated from the request, so it is 0). PictureUrl is cosmetic and left as supplied; it does not affect totals.
New dependency: Ordering.API now makes an HTTP call to catalog-api. Added a typed HttpClient (ICatalogPriceService / CatalogPriceService) using Aspire service discovery ("https+http://catalog-api", the same pattern as WebApp), and .WithReference(catalogApi) on ordering-api in src/eShop.AppHost/AppHost.cs. No new NuGet packages; ServiceDefaults already supplies service discovery and the resilience handler. The call fails closed: if Catalog is unreachable the exception propagates and the order is not created. Reading price from Basket.API instead was rejected because it is gRPC and authenticated per user, and would need the user's token forwarded and a proto reference. Catalog is the price source of truth and its batch endpoint is anonymous. The constructor of CreateOrderCommandHandler gains a parameter, so the one existing test construction was updated.

**Variants checked:** CreateOrderCommandHandler.Handle: fixed. CreateOrderDraftCommandHandler.Handle (/api/orders/draft): same client-supplied items to AddOrderItem, but it only returns a non-persisted preview DTO and writes nothing, so it was left out of this minimal diff (it could use the same ICatalogPriceService if the preview must also be authoritative). BasketItemExtensions.ToOrderItemDTO/ToOrderItemsDTO: only called by CreateOrderCommand's constructor and the draft handler, so re-pricing in the persisting handler covers it. Order.AddOrderItem is called only from these two handlers (grep of src and tests). The other entry points for CreateOrderCommand (CreateOrderIdentifiedCommandHandler, IdentifiedCommand) dispatch to the same handler. WebApp builds items from the catalog already, so it is unaffected. I did not grep the Basket.API checkout path further since it only publishes the basket-checkout event and does not create orders.

**Bypass considered:** Attacker sends the lowest-priced real productId with a different ProductName, or sets UnitPrice/OldUnitPrice/Discount to arbitrary values: ignored, because the name and price written to the order always come from Catalog and Discount is not client-settable. Attacker sends a nonexistent ProductId: rejected with OrderingDomainException. Attacker sends the same productId several times: each line is priced identically from Catalog, which is correct and cannot lower the total. Attacker races a price change in Catalog: the order takes the price current at order time, which is the intended semantics. Remaining residual issue (out of scope for this finding): UserId/UserName in CreateOrderRequest are also client-supplied; and Units is still unbounded above, but that is not price tampering.

**Test note:** Added Handle_prices_order_items_from_catalog_not_from_client to /home/tanis/github/depj-proj/eShop/tests/Ordering.UnitTests/Application/NewOrderCommandHandlerTest.cs. It sends an item priced 0.01 for a product the mocked catalog prices at 50 and asserts the persisted order line is 50 and the total is 100. Before the change it fails: the old handler stores 0.01, and the handler constructor has no catalog parameter. It was not run (no build access). The existing test in the same file was updated for the new constructor parameter.

**Reviewer:** The handler hunk (`CreateOrderCommandHandler.cs:44`) correctly replaces the client `ProductName`/`UnitPrice` with Catalog values, and the endpoint, DTO members and `OrderingDomainException` all exist in source. However, the new `AddHttpClient<ICatalogPriceService, CatalogPriceService>` in `Extensions.cs` omits `.AddApiVersion(...)` although `/api/catalog/items/by` is in a versioned group (`CatalogApi.cs:12-14`) and every existing client pins a version (`WebApp/Extensions/Extensions.cs:34-36`). That would likely cause a 400 and make every order creation throw. The new throw also fires after `AddAndSaveEventAsync` has already persisted the `OrderStartedIntegrationEvent`.

> **Rejected by reviewer:** The handler hunk (`CreateOrderCommandHandler.cs:44`) correctly replaces the client `ProductName`/`UnitPrice` with Catalog values, and the endpoint, DTO members and `OrderingDomainException` all exist in source. However, the new `AddHttpClient<ICatalogPriceService, CatalogPriceService>` in `Extensions.cs` omits `.AddApiVersion(...)` although `/api/catalog/items/by` is in a versioned group (`CatalogApi.cs:12-14`) and every existing client pins a version (`WebApp/Extensions/Extensions.cs:34-36`). That would likely cause a 400 and make every order creation throw. The new throw also fires after `AddAndSaveEventAsync` has already persisted the `OrderStartedIntegrationEvent`.

---

## Skipped

| id | reason |
|---|---|
| (none) | All 11 confirmed findings had a source location and produced a diff. |
