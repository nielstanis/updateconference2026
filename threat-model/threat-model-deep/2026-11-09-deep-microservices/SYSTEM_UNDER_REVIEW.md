# SYSTEM_UNDER_REVIEW

Bundle: eShop reference application ("AdventureWorks"), source revision `913acea` (HEAD at session start, taken from the caller-attached session context, not independently verified); working tree `not_checked`: Git inspection was skipped because the protected Git prefix could not be used (`--no-lazy-fetch` is rejected by the installed git). This run's own output is under `threat-model/2026-11-09-deep-microservices/`.
Run: mode `deep`; `REVIEW_SCOPE: security`; `METHODS: []` (none requested; "without methods" default); `PRIVACY_PROFILES: []`. Library: Grim Prompter at revision `2a94457c` (library `LIBRARY_ROOT` label: `grim-prompter`; project root label: `eShop`). Selected architecture prompts: `deep/microservices/00..05` (primary). Architecture selected by the architecture selector (see `selection.json`).
Purpose: Design-level security threat model of the eShop reference application as a sample/template that developers copy, and as it would behave if deployed as shown (Aspire AppHost + Azure Container Apps deployment described in README). Primary architecture: `microservices`.
Scope: Aspire AppHost topology; Identity.API (Duende IdentityServer + ASP.NET Identity); Catalog.API; Basket.API (gRPC + Redis); Ordering.API (+ Ordering.Domain/Infrastructure); OrderProcessor; PaymentProcessor; Webhooks.API; WebhookClient; WebApp (Blazor Server + chatbot); mobile-bff YARP gateway; RabbitMQ event bus + integration event log; ServiceDefaults auth/health; PostgreSQL/Redis/RabbitMQ resources; MAUI ClientApp/HybridApp client-side identity and endpoint config (bounded); CI workflows (bounded).
Out of scope: `tests/`, `e2e/`, `node_modules`, EF `Migrations/` bodies, `bin/obj`, `.github/skills/**` (agent skill docs), Azure/Foundry/Ollama provider internals, MAUI platform folders, wwwroot static assets, runtime behavior of any deployed instance. No execution, build, test or network use occurred.

## Evidence

E1 — configuration observation (topology)
Locator: src/eShop.AppHost/AppHost.cs:1-105. AppHost declares Redis, RabbitMQ (`eventbus`, persistent container lifetime), Postgres (`ankane/pgvector:latest`, persistent) with four databases (catalogdb, identitydb, orderingdb, webhooksdb) on ONE Postgres server; projects identity-api, basket-api, catalog-api, ordering-api, order-processor, payment-processor, webhooks-api, webhooksclient, webapp; YARP `mobile-bff`; Azure Container App environment `aca`. A single `eventbus` RabbitMQ reference is passed to basket, catalog, ordering, order-processor, payment-processor, webhooks-api and webapp.

E2 — configuration observation (external exposure)
Locator: src/eShop.AppHost/AppHost.cs:25-28, 62-64, 71-73. `WithExternalHttpEndpoints()` is applied to identity-api, mobile-bff and webapp only. basket, catalog, ordering, webhooks-api, webhooksclient, order-processor and payment-processor have no external-endpoint call in the AppHost (webhooksclient is referenced from identity config as an HTTP callback target). Whether ACA ingress matches this in deployment is not observed.

E3 — configuration observation (mobile BFF routes)
Locator: src/eShop.AppHost/Extensions.cs:88-152. The mobile-bff YARP resource routes `/api/catalog/{*any}` (catch-all, api-version 1.0|1|2.0 query match) to catalog-api, `/api/orders/{*any}` (api-version 1.0|1) to ordering-api, `/identity/{*any}` to identity-api, plus explicit `/catalog-api/api/catalog/...` read routes. Because the catalog catch-all matches any method and path under `/api/catalog/`, it is reachable from the externally exposed BFF for non-GET verbs too; per-route HTTP method restriction is not set in the configuration read here.

E4 — implementation observation (Catalog write endpoints have no authentication)
Locator: src/Catalog.API/Apis/CatalogApi.cs:13-19, 97-117, 359-453; src/Catalog.API/Program.cs:1-29; src/Catalog.API/Extensions/Extensions.cs:1-62. `PUT /api/catalog/items`, `PUT /items/{id}`, `POST /items`, `DELETE /items/{id}` are mapped with no `RequireAuthorization()` and a text search of Catalog.API's Program/Extensions/Apis found no `AddDefaultAuthentication`, `RequireAuthorization` or `Authorize`. Update uses `CurrentValues.SetValues(productToUpdate)` from the request body (all mapped properties including Price and PictureFileName), recomputes the embedding, and publishes `ProductPriceChangedIntegrationEvent` when Price changes (CatalogApi.cs:390-399). CreateItem accepts client-supplied `Id` and `PictureFileName` (415-430).

E5 — implementation observation (catalog picture file read)
Locator: src/Catalog.API/Apis/CatalogApi.cs:251-272; src/Catalog.API/Program.cs:5-8. The picture endpoint resolves `item.PictureFileName` through a `PhysicalFileProvider` rooted at `ContentRoot/Pics` and streams the file. PictureFileName is client-writable via E4. Most recent commit message in session context ("Confine catalog picture reads to Pics (#1061)") indicates a recent fix for path confinement; the provider-level confinement was not independently tested.

E6 — implementation observation (shared JWT validation)
Locator: src/eShop.ServiceDefaults/AuthenticationExtensions.cs:22-52. If the `Identity` config section is absent, authentication is not registered at all (24-28). Otherwise JwtBearer with `RequireHttpsMetadata = false` (39), `ValidateAudience = false` (49) despite setting `Audience` (40), `ValidIssuers` = [identityUrl] (plus an Android emulator issuer under `#if DEBUG`, 42-44). No scope or role policy is defined (`AddAuthorization()` default only, 52).

E7 — implementation observation (Ordering authentication and per-order authorization)
Locator: src/Ordering.API/Program.cs:19-22; src/Ordering.API/Apis/OrdersApi.cs:7-185; src/Ordering.API/Application/Queries/OrderQueries.cs:6-35; src/Ordering.API/Infrastructure/Services/IdentityService.cs:5-9. All order routes require an authenticated caller (group `.RequireAuthorization()`), but: `GET api/orders/{orderId}` returns any order by id with no owner filter (OrderQueries.cs:8-10); `PUT /cancel` and `PUT /ship` act on `OrderNumber` from the body with no owner check and no admin role/scope check (OrdersApi.cs:22-78; handler comment says "administrator executes ship"); `POST /` takes `UserId`, `UserName`, address and card data from the request body rather than the token `sub` (OrdersApi.cs:118-185; identity service is available but not used there); `POST /draft` builds a draft from a client `BuyerId`. Only `GET /` uses the token subject (93-98).

E8 — implementation observation (order payment data)
Locator: src/Ordering.API/Apis/OrdersApi.cs:124-144; src/Ordering.Domain/AggregatesModel/OrderAggregate/Order.cs:52-64, 171-175; src/Ordering.Infrastructure/EntityConfigurations/PaymentMethodEntityTypeConfiguration.cs:29; src/Ordering.Domain/Events/OrderStartedDomainEvent.cs:12-13. The API masks the card number (keeps last 4) before building the command (OrdersApi.cs:140), but passes `CardSecurityNumber`, holder name and expiration through the command, domain event and into the Order/PaymentMethod aggregate; a CardNumber column exists. Whether the security number is persisted was not traced in this read (see G6). Logging of the command object is guarded in the create handler only by a comment (OrdersApi.cs:126-130), while the `IdentifiedCommand` log at 148-153 uses `{@Command}` and `CreateOrderCommandHandler` logs `{@Order}` (CreateOrderCommandHandler.cs:47).

E9 — implementation observation (idempotency)
Locator: src/Ordering.API/Application/Commands/IdentifiedCommandHandler.cs:39-104; src/Ordering.Infrastructure/Idempotency/RequestManager.cs (listed, not read). Duplicate `x-requestid` returns a canned success result; the request id is recorded before the inner command runs and is not removed when the inner command throws (`catch { return default; }`, 99-102), so a failed first attempt consumes the id.

E10 — implementation observation (Basket gRPC)
Locator: src/Basket.API/Program.cs:1-14; src/Basket.API/Grpc/BasketService.cs:12-69; src/Basket.API/Extensions/ServerCallContextIdentityExtensions.cs:7; src/Basket.API/Repositories/RedisBasketRepository.cs:13-48. `MapGrpcService<BasketService>()` without service-level `RequireAuthorization`; `GetBasket` is `[AllowAnonymous]` and returns an empty basket without a subject; `UpdateBasket`/`DeleteBasket` throw Unauthenticated when `sub` is empty. Basket keys are `/basket/{sub}` taken only from the token; the request message carries no buyer id. Basket is stored as JSON in Redis with no TTL set in code. If the `Identity` section is missing (E6), no authentication scheme exists and `sub` is always empty.

E11 — implementation observation (Webhooks subscription, SSRF surface)
Locator: src/Webhooks.API/Apis/WebHooksApi.cs:35-64; src/Webhooks.API/Services/GrantUrlTesterService.cs:5-45; src/Webhooks.API/Model/WebhookSubscriptionRequest.cs:10-27; src/Webhooks.API/Services/WebhooksSender.cs:5-33. Any authenticated user can register `Url` (destination) and `GrantUrl`; validation is only `Uri.IsWellFormedUriString` plus a same scheme/host/port check between the two. The service then sends an HTTP `OPTIONS` request to `GrantUrl` from the Webhooks.API network position (with the caller-chosen token in header `X-eshop-whtoken`) and requires the response to echo the token. Later, `WebhooksSender` POSTs JSON payloads to `DestUrl` for subscribers. No block-list for loopback/private/link-local addresses, no scheme restriction beyond well-formedness, no redirect policy and no timeout/size limits were observed in these files (default `IHttpClientFactory.CreateClient()`). The token is written to logs (GrantUrlTesterService.cs:17, 25).

E12 — implementation observation (Webhooks per-user scoping)
Locator: src/Webhooks.API/Apis/WebHooksApi.cs:13-33, 66-82. List/get/delete filter by `UserId == user.GetUserId()`. Webhook payload fan-out (event handlers) and `WebhooksRetriever` were not read in detail: delivery by event type to all subscribers of that type is inferred from file names only (G7).

E13 — implementation observation (WebhookClient receiver)
Locator: src/WebhookClient/Endpoints/WebhookEndpoints.cs:10-57. `/check` (OPTIONS) and `/webhook-received` are unauthenticated; token validation is controlled by configuration `ValidateToken` (parsed to false by default when absent, line 13); when validation is on, comparison is plain string equality with a configured token; both the received token and the expected token are written to logs (35). The sample configured token value appears in `src/WebhookClient/appsettings.json` [REDACTED:sample-webhook-token].

E14 — implementation observation (Identity.API client registry)
Locator: src/Identity.API/Configuration/Config.cs:40-189. In-memory clients: `maui` (code+PKCE required, secret, refresh tokens, scopes orders/basket/webhooks, 2h tokens), `webapp` (code, `RequirePkce = false` at line 90, secret, offline access), `webhooksclient` (code, secret), and three implicit-flow Swagger UI clients (`basketswaggerui`, `orderingswaggerui`, `webhooksswaggerui`; `AllowAccessTokensViaBrowser = true`, redirect URIs derived from configuration). All three confidential-client secrets are the literal sample value hashed via `"secret".Sha256()` [REDACTED:sample-client-secret] (lines 52, 82, 118). Allowed scopes for `webapp` include `webshoppingagg` and for `maui` `mobileshoppingagg`, which are not defined as ApiScopes in `GetApiScopes()` (18-26). Apis `orders`, `basket`, `webhooks` are defined (6-14). No `catalog` api resource/scope exists.

E15 — implementation observation (Identity.API host)
Locator: src/Identity.API/Program.cs:12-37. Automatic migrations and seed at startup; IdentityServer with `KeyManagement.Enabled = false` and `AddDeveloperSigningCredential()` (both annotated in comments as not for production); in-memory clients/resources; ASP.NET Identity user store; event raising on; 2h cookie lifetime; cookie SameSite Lax (49-50). Identity.API Quickstart controllers: `[Authorize]` on Consent, Grants, Device and Diagnostics; `[AllowAnonymous]` on Account, External, Home; `ValidateAntiForgeryToken` on posts (grep, Quickstart/*). `Url.IsLocalUrl` plus `IsValidReturnUrl` checks in login/external flows (AccountController.cs:115, ExternalController.cs:39). A `DiagnosticsController` exists (Authorize) that renders authentication result data (DiagnosticsViewModel.cs:12).

E16 — implementation observation (seeded users and credentials)
Locator: src/Identity.API/UsersSeed.cs:6-97. Users `alice` and `bob` are created at startup with the same well-known sample password [REDACTED:sample-user-password], with profile PII, card holder name, masked card number, expiration, and a card security number [REDACTED:sample-card-cvv]. The seed runs on every startup in any environment via `AddMigration<..., UsersSeed>()` (Program.cs:12). A development settings file contains a database connection string with a weak sample password [REDACTED:sample-db-password] (src/Identity.API/appsettings.Development.json:3).

E17 — implementation observation (WebApp authentication and token handling)
Locator: src/WebApp/Extensions/Extensions.cs:53-92, 12-51; src/eShop.ServiceDefaults/HttpClientExtensions.cs:11-60; src/WebApp/Program.cs:11-32. Blazor Server with cookie + OIDC code flow, client id `webapp`, literal client secret [REDACTED:sample-client-secret] (line 78), `SaveTokens = true` (80), `RequireHttpsMetadata = false` (82), cookie lifetime default 60 minutes. Outbound clients to basket (gRPC), catalog (v2) and ordering attach the signed-in user's access token from the HTTP context through `HttpClientAuthorizationDelegatingHandler` (`AddAuthToken`). The WebApp forwards `/product-images/{id}` to catalog's pic endpoint (Program.cs:32). Production branch adds exception handler and HSTS (23-28).

E18 — implementation observation (AI chatbot tools)
Locator: src/WebApp/Components/Chatbot/ChatState.cs:12-96, 96-190; src/WebApp/Extensions/Extensions.cs:94-108; src/eShop.AppHost/AppHost.cs:81-92. When a chat model connection exists (Foundry opt-in via `UseFoundry`, or Ollama via an in-code `useOllama` flag set false), WebApp builds a chat client with function invocation. Model-callable tools: `GetUserInfo` (returns name, last name, street, city, state, zip, country, email, phone from the signed-in user's claims), `SearchCatalog`, `AddToCart` (calls the user's basket with the user's token), `GetCartContents`. User text and catalog item descriptions (attacker-influenceable via E4) reach the model. System prompt restricts topics but is not an enforcement boundary. Chat history lives in the server-side circuit.

E19 — implementation observation (RabbitMQ event bus)
Locator: src/EventBusRabbitMQ/RabbitMQEventBus.cs:44-100, 190-215, 250-290; src/EventBus/Extensions/EventBusBuilderExtensions.cs (listed, not read). One shared topic exchange; each service declares its own queue and binds routing keys by event type name; messages are JSON deserialized into a statically registered event type map (`_subscriptionInfo.EventTypes.TryGetValue`, 192); events carry no signature/MAC or sender identity. Broker credentials are injected by Aspire (value not read). No per-service broker user, vhost or per-queue permission is visible in the code read.

E20 — implementation observation (event-driven order saga and payment simulation)
Locator: src/PaymentProcessor/IntegrationEvents/EventHandling/OrderStatusChangedToStockConfirmedIntegrationEventHandler.cs:1-37; src/PaymentProcessor/PaymentOptions.cs; src/OrderProcessor/Services/GracePeriodManagerService.cs:43-60; src/OrderProcessor/Extensions/Extensions.cs:15-19; src/Basket.API/IntegrationEvents/EventHandling/OrderStartedIntegrationEventHandler.cs:1-17. Payment is simulated: the handler publishes `OrderPaymentSucceeded` or `Failed` solely from the `PaymentOptions.PaymentSucceeded` setting, with no gateway call; any bus publisher of an `OrderStatusChangedToStockConfirmed`, `OrderPaymentSucceeded`, `GracePeriodConfirmed` or `OrderStartedIntegrationEvent` (basket delete by UserId) is trusted by the consumers. OrderProcessor polls Postgres (order DB) on a 30s check, 1 minute grace period (appsettings) and publishes `GracePeriodConfirmed`.

E21 — implementation observation (health and diagnostics endpoints)
Locator: src/eShop.ServiceDefaults/Extensions.cs:99-125. `/health` and `/alive` are mapped only when the environment is Development (comment warns of security implications); OTLP exporter is enabled only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. AppHost adds `WithHttpHealthCheck("/health")` for identity-api and ordering-api (AppHost.cs:28, 45), which depends on Development mode (observed only by configuration).

E22 — configuration observation (forwarded headers)
Locator: src/eShop.AppHost/Extensions.cs:20-45. `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` is set for every DotnetProject resource, which makes ASP.NET Core trust `X-Forwarded-*` headers from any source unless known-proxy/network restrictions are also configured (not observed).

E23 — configuration observation (secrets and defaults in settings)
Locator: src/*/appsettings*.json (reviewed list in Inspection coverage). Placeholders: Identity URL `http://localhost:5223` for webhooks; `AllowedHosts: "*"` on Ordering.API, Webhooks.API, WebApp, WebhookClient; MauiCallback `maui://authcallback`; no real secrets observed other than sample values already listed (E13, E14, E16). `PaymentOptions.PaymentSucceeded: true`.

E24 — implementation observation (MAUI client identity configuration)
Locator: src/ClientApp/Services/Settings/SettingsService.cs:15, 37-44, 81; src/ClientApp/Services/Identity/IdentityService.cs:139; src/HybridApp/MauiProgram.cs:8-9. Mobile client ships with default client id and a default client secret constant [REDACTED:sample-client-secret] in app code (a public client cannot keep a secret; the `maui` registration also requires PKCE). Access tokens stored via MAUI `SecureStorage`; endpoint settings stored in `Preferences`. HybridApp calls the mobile BFF at plain HTTP `http://10.0.2.2:11632/` / `http://localhost:11632/` (development hosts).

E25 — implementation observation (CI/CD)
Locator: .github/workflows/pr-validation.yml:1-30 (read to 30); .github/workflows/playwright.yml, markdownlint.yml, pr-validation-maui.yml (grep only). Workflows use `pull_request` and `push` to main, `actions/checkout@v4`, `actions/setup-dotnet@v3|v4`, `actions/setup-node@v4`, `actions/upload-artifact@v4`; actions are tag-pinned (not SHA-pinned); no `pull_request_target`, no explicit `permissions:` block in pr-validation.yml (markdownlint.yml has one); no secrets references found by grep. `.github/dependabot.yml` exists (not read).

E26 — documentation claim (deployment posture)
Locator: README.md:113-144. States ACA deployment deploys PostgreSQL, Redis and RabbitMQ as containers "intended for evaluation and demonstrations, not production data"; `aspire destroy` deletes the whole resource group; optional Foundry provisioning uses local Azure credentials.

E27 — implementation observation (client-writable catalog data feeds multiple consumers)
Locator: src/Catalog.API/IntegrationEvents (listed); src/Webhooks.API/Extensions/Extensions.cs:19-24; src/WebApp/Extensions/Extensions.cs:39-47. Catalog price change events are consumed by Webhooks.API (handler body is a no-op, `ProductPriceChangedIntegrationEventHandler.cs:5-8`). Order status events fan out to WebApp (Blazor notifications), Catalog (stock), Webhooks (paid/shipped) and Payment/Order processors.

## Gaps

G1 — Unknown: whether Ordering/Webhooks/Basket/Catalog are reachable from outside the ACA environment after `aspire deploy` (ingress defaults for non-`WithExternalHttpEndpoints` projects). Would be settled by the generated ACA manifests or deployment output (not inspected; no `aspire publish` run).
G2 — Unknown: whether the YARP `mobile-bff` restricts HTTP methods on `/api/catalog/{*any}` and `/api/orders/{*any}` at runtime (E3 shows no method match). Would be settled by the generated YARP config or a live request (not run).
G3 — Unknown: effective RabbitMQ/Postgres/Redis credentials, network policy and TLS in deployment (values injected by Aspire; not read). Would be settled by deployment manifests/secret store listing.
G4 — Unknown: whether `Identity` configuration is always present in every service (Catalog has none; Basket/Ordering/Webhooks rely on AppHost `Identity__Url`). Missing config silently disables authentication (E6).
G5 — Unknown: `webshoppingagg`/`mobileshoppingagg` scope consumers: scopes appear in client allow-lists but not in `GetApiScopes()`; effect on token issuance not observed.
G6 — Unknown: which card fields (number, security number) are persisted in the Ordering database; `PaymentMethodEntityTypeConfiguration` and `Order` constructors were only partially read.
G7 — Unknown: webhook fan-out logic (`WebhooksRetriever`, order paid/shipped handlers) and what payload data are sent to subscriber URLs.
G8 — Unknown: `RequestManager`, `ValidatorBehavior`, `TransactionBehavior`, `LoggingBehavior` bodies, and Ordering validators (partially unread).
G9 — Unknown: Catalog `CatalogAI` embedding/search implementation and any input limits (unread).
G10 — Unknown: HTTP security headers, CSP and CORS policy on WebApp, Identity.API (`SecurityHeadersAttribute` exists but was not read).
G11 — Unknown: contents of Identity.API Razor views (account/consent) and Blazor pages for output encoding (not read).
G12 — Unknown: runtime effect of YARP forwarded-header trust and `AllowedHosts: "*"`.
G13 — Unknown: test coverage and results (tests/ and e2e/ excluded; not run).
G14 — Unknown: working-tree cleanliness and Git history (Git not used).

## Inspection coverage

Discovery scope: `find` over `src/`, `.github/`, root config files for `.cs/.csproj/.json/.yml/.md/.razor/.proto/.props/.slnx` excluding bin/obj/Migrations/tests/e2e/node_modules; listing is a name listing with a head limit applied in the first listing command (400 lines) and a second listing of remaining source folders (250 lines), so the listing is complete for non-ClientApp/HybridApp server-side directories but ClientApp/HybridApp/Identity views were deliberately not exhaustively enumerated. Source revision `913acea` (from session context). Evidence is freshly read in this run unless labeled.

Files inspected (full read unless "partial"):
- README.md (full)
- src/eShop.AppHost/AppHost.cs (full); src/eShop.AppHost/Extensions.cs (full)
- src/eShop.ServiceDefaults/AuthenticationExtensions.cs (full); HttpClientExtensions.cs (first ~60 lines; partial); Extensions.cs (grep + lines 108-125; partial)
- src/Ordering.API/Program.cs (full), Extensions/Extensions.cs (full), Apis/OrdersApi.cs (full), Apis/OrderServices.cs (full), Infrastructure/Services/IdentityService.cs (full), Application/Queries/OrderQueries.cs (full), Application/Commands/CreateOrderCommandHandler.cs, ShipOrderCommandHandler.cs, CancelOrderCommandHandler.cs, IdentifiedCommandHandler.cs (full), appsettings.json (full)
- src/Ordering.Domain/AggregatesModel/OrderAggregate/Order.cs (grep + lines 130-153; partial); Ordering.Infrastructure entity configs/migrations (grep only; partial)
- src/Basket.API/Program.cs, Grpc/BasketService.cs, Extensions/Extensions.cs, Extensions/ServerCallContextIdentityExtensions.cs, Repositories/RedisBasketRepository.cs, IntegrationEvents/EventHandling/OrderStartedIntegrationEventHandler.cs, appsettings.json (full)
- src/Catalog.API/Program.cs, Extensions/Extensions.cs, appsettings.json (full); Apis/CatalogApi.cs (lines 1-125, 251-272 via grep, 359-467; partial)
- src/Webhooks.API/Program.cs, Extensions/Extensions.cs, Extensions/RouteHandlerBuilderExtensions.cs (first 37 lines), Apis/WebHooksApi.cs, Services/GrantUrlTesterService.cs, Services/WebhooksSender.cs, Model/WebhookSubscriptionRequest.cs, Model/WebhookSubscription.cs, IntegrationEvents/ProductPriceChangedIntegrationEventHandler.cs, appsettings.json (full)
- src/WebhookClient/Program.cs, Endpoints/AuthenticationEndpoints.cs, Endpoints/WebhookEndpoints.cs (full); Extensions/Extensions.cs (grep only; partial)
- src/Identity.API/Program.cs, Configuration/Config.cs, UsersSeed.cs, Services/RedirectService.cs, appsettings.json, appsettings.Development.json (full); Quickstart/** (grep only; partial)
- src/WebApp/Program.cs, Extensions/Extensions.cs (full); Components/Chatbot/ChatState.cs (full); Services/OrderingService.cs (not read despite attempt: command failed; treat as not inspected)
- src/EventBusRabbitMQ/RabbitMQEventBus.cs (grep + selected lines; partial)
- src/PaymentProcessor handler + PaymentOptions + appsettings.json (full); src/OrderProcessor appsettings.json (full), GracePeriodManagerService/Extensions (grep only; partial)
- src/ClientApp/Services/Settings/SettingsService.cs, Identity/IdentityService.cs (grep only; partial); src/HybridApp/MauiProgram.cs, Services/CatalogService.cs (grep only; partial)
- appsettings.json for WebApp, WebhookClient, AppHost (full)
- .github/workflows/pr-validation.yml (first 30 lines; partial); other workflows (grep only; partial)

Files or areas not inspected: Identity.API Razor views, controller bodies beyond grep, SecurityHeadersAttribute; Ordering validators/behaviors/RequestManager/OrderRepository/BuyerRepository; Catalog CatalogAI/CatalogContextSeed; Webhooks WebhooksRetriever and paid/shipped handlers; WebApp Blazor pages and `BasketService`/`OrderStatusNotificationService`; EventBus abstractions and IntegrationEventLogEF; MAUI ClientApp views/viewmodels (bounded to settings/identity grep); `tests/`, `e2e/` (out of scope); `package.json`, `package-lock.json`, `Directory.Packages.props` dependency manifests (listed, not read; so dependency vulnerability review not performed); `.github/dependabot.yml`; `.devcenter`, `es-metadata.yml`, `ci.yml` (root; listed, not read). Exclusions labeled separately above under "Out of scope".

Unmapped trust boundaries:
- UB1: suspected crossing between mobile-bff and ordering/catalog at deployment time (ACA ingress, YARP method handling); evidence basis E2/E3; missing trace: generated manifests/YARP effective config.
- UB2: suspected crossing between services and RabbitMQ broker credentials/ACLs; evidence basis E1/E19; missing trace: broker user/vhost configuration.
- UB3: suspected crossing between WebApp and the AI model provider (Foundry/Ollama); evidence basis E18; missing trace: provider-side data handling and network path.
- UB4: suspected crossing between Webhooks.API and arbitrary customer URLs (egress network policy); evidence basis E11; missing trace: ACA egress/network rules.

Redactions: [REDACTED:sample-client-secret] ×3 sources (Config.cs 52/82/118 via hash call, WebApp Extensions.cs:78, WebhookClient Extensions.cs:54, ClientApp SettingsService.cs:15): the literal sample "secret" value; [REDACTED:sample-user-password] (UsersSeed.cs); [REDACTED:sample-card-cvv] (UsersSeed.cs, two seeded security numbers); [REDACTED:sample-webhook-token] (WebhookClient/appsettings.json); [REDACTED:sample-db-password] (Identity.API/appsettings.Development.json). All are documented sample/placeholder values for local development; still redacted per the runbook.
