# Threat Model: eShop (AdventureWorks reference shop)

## 1. System context

eShop is Microsoft's reference e-commerce application for .NET 10, built as about a dozen C# services and orchestrated by .NET Aspire 13.6. Customers browse a catalog, keep a basket, sign in through an OIDC identity provider (Duende IdentityServer 7.3.2 over ASP.NET Core Identity), and place orders. Orders are processed asynchronously through integration events on RabbitMQ, with an EF Core outbox. Payment is simulated by `PaymentProcessor`, which replies with an event. Optional features are an LLM chatbot in the Blazor storefront that can call tools (read the user's profile, search the catalog, add to the cart), semantic catalog search over pgvector embeddings, and a webhooks subsystem that POSTs order events to URLs that subscribers register. The roughly 550 source files live under `src/`, with ASP.NET Core minimal APIs, a gRPC basket service, Blazor Server front ends, a YARP backend-for-frontend (`mobile-bff`), and .NET MAUI mobile and hybrid clients.

Aspire runs three containers: one Postgres server (`ankane/pgvector:latest`) holding catalogdb, identitydb, orderingdb and webhooksdb; Redis for baskets; and RabbitMQ. Only `identity-api`, `webapp` and `mobile-bff` get external endpoints. Every other service is reachable only on the internal Aspire or Azure Container Apps network, except through whatever the BFF forwards. People run it locally with `aspire run`, or deploy it to Azure Container Apps with `aspire deploy`. The README says the deployment is "intended for evaluation and demonstrations, not production data". In practice the code is widely copied as a starting template, so this model treats every default as something that may reach production unchanged.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| Payment card data | Card number, CVV, expiry and holder name. Stored in clear text on `ApplicationUser` in identitydb, emitted as OIDC claims (`card_number`, `card_security_number`) by `ProfileService`, sent in full in `CreateOrderRequest`, with the CVV carried through `CreateOrderCommand` and `OrderStartedDomainEvent` | critical |
| Token signing key | IdentityServer signing key from `AddDeveloperSigningCredential()` (on-disk `tempkey.jwk`), with automatic key management disabled. Whoever holds it can mint tokens for every API | critical |
| User credentials | ASP.NET Identity password hashes, security stamps and reset tokens in identitydb. Seeded users `alice` and `bob` | high |
| OIDC client secrets | Client secrets for `webapp`, `webhooksclient` and `maui`, all the literal `"secret"` and hard-coded on both sides | high |
| Session tokens | Access, refresh and ID tokens and auth cookies. `SaveTokens=true` stores tokens in the WebApp and WebhookClient cookies | high |
| Customer PII | Name, address, email and phone in identitydb, order shipping addresses in orderingdb, OIDC profile claims, and data sent to the chatbot LLM | high |
| Order records | Orders, line items, prices, status history and the outbox in orderingdb. Status changes are driven by bus events | high |
| Infrastructure credentials | Postgres superuser, Redis and RabbitMQ credentials (Aspire parameters), and Azure deployment identity | high |
| Build & deploy pipeline | GitHub Actions and ADO 1ES pipelines, NuGet, npm and libman dependencies, container images | high |
| Host filesystem | Files readable by the Catalog.API process (appsettings, keys, OS files) | high |
| Catalog data | Items, prices, descriptions, picture references and embeddings in catalogdb. Price changes fan out to baskets | medium |
| Basket data | Per-user baskets in Redis under `/basket/{sub}` | medium |
| Webhook subscriptions | Subscriber URLs, grant URLs and shared tokens in webhooksdb, plus the order events delivered to them | medium |
| AI provider access | Azure OpenAI/Foundry chat and embedding deployments, billed per call | medium |
| Service availability | Storefront, checkout, IdP (a single point of failure for every API), Postgres, Redis and RabbitMQ, all run as single instances | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| Catalog write API | `POST /api/catalog/items`, `PUT /items`, `PUT /items/{id}`, `DELETE /items/{id}` take a whole `CatalogItem` (price, description, `PictureFileName`, stock). Catalog.API never calls `AddDefaultAuthentication` and has no `RequireAuthorization` (`src/Catalog.API/Apis/CatalogApi.cs:100-117`). A price update publishes `ProductPriceChangedIntegrationEvent` | unauth internet → mobile-bff → Catalog.API → catalogdb, event bus | Catalog data, Basket data, Customer PII, Service availability |
| Catalog read & picture API | Public catalog queries and `GET /items/{id}/pic`, which serves `PictureFileName` through a `PhysicalFileProvider` rooted at `Pics` (`CatalogApi.cs:251-273`) | unauth internet → Catalog.API → local filesystem | Catalog data, Host filesystem |
| Catalog semantic search | `GET /items/withsemanticrelevance` sends user text to the embedding provider, then runs a pgvector query. Anonymous | unauth internet → Catalog.API → external AI provider | AI provider access, Service availability |
| mobile-bff proxy | Externally exposed YARP. The catch-all `/api/catalog/{*any}` and `/api/orders/{*any}` routes match on the `api-version` query only, not on HTTP method. `/identity/{*any}` reaches the IdP over its `http` endpoint (`src/eShop.AppHost/Extensions.cs:88-153`) | internet → internal service network | Catalog data, Order records, Session tokens |
| Ordering API | `/api/orders`: create (`UserId`, `UserName`, `UnitPrice`, `Discount` and the full card data come from the request body), cancel and ship by `OrderNumber`, get by id, list, draft. Requires authentication but has no ownership or role checks. Idempotency comes from the global `x-requestid` | authenticated user → Ordering.API → orderingdb, event bus | Order records, Customer PII, Payment card data, Basket data |
| Basket gRPC API | `GetBasket` (`[AllowAnonymous]`), `UpdateBasket`, `DeleteBasket`, keyed on the JWT `sub` | WebApp, mobile → Basket.API → Redis | Basket data |
| Webhooks API | Subscription CRUD scoped by `sub`. Sends a server-side `OPTIONS` to the user-supplied `GrantUrl` and later POSTs order events to the user-supplied `Url`. Delivery picks subscribers by event type only (`WebhooksRetriever.cs`) | internal caller (no external endpoint in the AppHost, no mobile-bff route) → Webhooks.API → arbitrary outbound URL | Webhook subscriptions, Order records, Infrastructure credentials |
| WebhookClient receiver | `OPTIONS /check` and `POST /webhook-received`. The token check only runs when `ValidateToken=true`, uses a plain `==` comparison, and the token is hard-coded in `appsettings.json` | internet or Webhooks.API → WebhookClient | Webhook subscriptions |
| Identity.API login & OIDC | Duende quickstart login, consent, external login and `/connect/*` endpoints. Clients are configured in memory in `Config.cs`: shared secret `"secret"`, `webapp` with `RequirePkce=false`, three Implicit-grant Swagger clients, and a `maui` client with a secret embedded in the app | unauth internet → IdP → identitydb | User credentials, Session tokens, OIDC client secrets, Payment card data, Customer PII, Token signing key |
| JWT bearer validation | `AddDefaultAuthentication` in ServiceDefaults: `ValidateAudience=false`, `RequireHttpsMetadata=false`, an extra DEBUG issuer `https://10.0.2.2:5243`, and it silently returns without auth when the `Identity` config section is missing (`AuthenticationExtensions.cs:24-49`) | caller token → Basket, Ordering, Webhooks APIs | Session tokens, Order records, Basket data, Webhook subscriptions |
| WebApp storefront | Blazor Server app with the OIDC client `webapp`. Forwards the user's access token to downstream APIs. Cookies are SameSite=Lax | browser → WebApp → backend APIs | Session tokens, Customer PII, Basket data, Order records |
| WebApp chatbot | LLM with the tools `GetUserInfo` (name, address, email, phone), `SearchCatalog`, `AddToCart` and `GetCartContents`. `MessageProcessor.AllowImages` turns markdown images in model output into `<img src>` for any URL. Anonymous users can chat | browser + catalog content → LLM → user PII, basket | Customer PII, Basket data, AI provider access |
| RabbitMQ event bus | Integration events (order started, stock confirmed, payment succeeded or failed, price changed, status changed) carry no message authentication. Seven services share one set of broker credentials. Failed messages are acked and dropped | service → broker → every consumer | Order records, Basket data, Catalog data, Webhook subscriptions |
| Postgres & Redis stores | One Postgres server, with the `postgres` superuser used by every service across four databases. Redis basket store. Dev fallbacks hard-code `Password=yourWeak(!)Password` | service network → data stores | User credentials, Payment card data, Customer PII, Order records, Basket data, Infrastructure credentials |
| Forwarded headers | `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` on every .NET project, with no `KnownProxies` or `KnownNetworks` set. `AllowedHosts: "*"` | any client → request scheme, host, IP seen by the app | Session tokens, Service availability |
| MAUI mobile clients | ClientApp and HybridApp: client secret stored in Preferences, HTTP base URLs, a DEBUG handler that accepts any `CN=localhost`-issued certificate, and Android cleartext allowed to 10.0.2.2 | device, network → mobile-bff, IdP | Session tokens, OIDC client secrets, Payment card data |
| Logging & telemetry | Structured logs (`{@Command}`, `{@IntegrationEvent}`), OpenTelemetry with formatted messages, scopes and experimental AI prompt and response capture, exported to OTLP or the Aspire dashboard | app → log and trace sinks | Payment card data, Customer PII, Webhook subscriptions, Session tokens |
| Dependency supply chain | NuGet (single nuget.org source, central package management, no lock file, NU1901-NU1904 audit warnings suppressed, preview Aspire packages), npm (`package-lock.json` with sha1 integrity resolved from internal feeds), libman from cdnjs without SRI, `ankane/pgvector:latest` image | third-party registry → build and runtime | Build & deploy pipeline, every runtime asset |
| CI pipelines | GitHub Actions on `pull_request` and push (actions pinned by tag, no `permissions:` block on three workflows, seed credentials in YAML, Playwright traces uploaded). ADO 1ES template at a mutable `refs/tags/release`. ACR script that takes a GitHub PAT on the command line | contributor or upstream template → CI runner, repo token | Build & deploy pipeline |
| AppHost deployment config | Aspire AppHost: chooses external endpoints, the `ESHOP_USE_HTTP_ENDPOINTS` plaintext switch, AI provisioning, secrets held in user-secrets and Aspire parameters outside the tree, and the persistent containers | operator, deployment → Azure Container Apps | Infrastructure credentials, Token signing key, Service availability, AI provider access |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T2 | Anyone who can read the eShop repository forges access tokens for any user and any API, because the IdentityServer signing private key is committed to git and copied into every build | remote_unauth | Identity.API login & OIDC, AppHost deployment config | Token signing key, Session tokens, Order records | critical | almost_certain | unmitigated | none (`src/Identity.API/tempkey.jwk` is tracked and copied to output by `Identity.API.csproj:50`; `AddDeveloperSigningCredential()` loads it; key management disabled at `Program.cs:29`) | fc61f90, VULN-FINDINGS F-004 (TRIAGE f004, confirmed 3-0) |
| T1 | Payment card numbers and CVVs leak to anyone who can read logs, traces, identitydb or ID tokens, because card data is logged in clear text, stored unencrypted and issued as OIDC claims | insider | Ordering API, Logging & telemetry, Identity.API login & OIDC, MAUI mobile clients | Payment card data | critical | likely | partially_mitigated | PAN masked to the last 4 digits before `CreateOrderCommand`; CVV not persisted in orderingdb | |
| T3 | Compromised or vulnerable third-party package, image or CDN asset runs code inside the build or the running services | supply_chain | Dependency supply chain | Build & deploy pipeline, Infrastructure credentials, User credentials | critical | possible | partially_mitigated | single NuGet source with packageSourceMapping; central package management with transitive pinning; Dependabot | 56cd2c6 |
| T4 | Anonymous internet user creates, reprices, rewrites or deletes catalog items | remote_unauth | Catalog write API, mobile-bff proxy | Catalog data, Basket data, Service availability | high | almost_certain | unmitigated | none | 913acea |
| T5 | Authenticated user reads, cancels or ships other customers' orders, or places orders under another buyer's identity (which also wipes that buyer's basket) | remote_auth | Ordering API, Basket gRPC API, mobile-bff proxy | Order records, Customer PII, Basket data | high | almost_certain | unmitigated | authentication required on `/api/orders`; order list filtered by `sub` | |
| T6 | Authenticated user buys goods at a price they choose, because order line prices and discounts are taken from the request instead of the catalog | remote_auth | Ordering API | Order records, Catalog data | high | almost_certain | unmitigated | none | |
| T7 | Token issued to one client or for one API is accepted by every other API, or a misconfigured service starts with authentication silently off | remote_auth | JWT bearer validation, Basket gRPC API, Webhooks API, Ordering API | Session tokens, Order records, Basket data, Webhook subscriptions | high | likely | unmitigated | issuer and signature validated | 6b18dda |
| T9 | Attacker logs in as a default account or impersonates a confidential OIDC client by using credentials published in the source | remote_unauth | Identity.API login & OIDC, WebApp storefront, MAUI mobile clients | User credentials, OIDC client secrets, Session tokens | high | likely | partially_mitigated | redirect URIs pinned per client; login lockout on failure | |
| T10 | Anyone who can publish to the message broker marks orders as paid, confirms stock or deletes baskets by injecting integration events | insider | RabbitMQ event bus | Order records, Basket data, Catalog data | high | possible | partially_mitigated | broker reachable only on the internal network; event types limited to a registered set | |
| T11 | Compromise of any one service gives read and write access to every database and the shared broker, because they all use the same superuser and shared credentials | insider | Postgres & Redis stores, AppHost deployment config | User credentials, Payment card data, Customer PII, Order records, Infrastructure credentials | high | possible | unmitigated | Aspire-generated passwords; data stores not externally exposed | |
| T12 | Network attacker intercepts or alters IdP, metadata or mobile traffic because of plaintext endpoints and relaxed certificate checks | adjacent_network | MAUI mobile clients, JWT bearer validation, AppHost deployment config | Session tokens, OIDC client secrets, Payment card data | high | rare | partially_mitigated | TLS bypass and extra issuer are `#if DEBUG` only; HTTPS profile by default | 909ee34 |
| T13 | Malicious contribution or upstream template change uses CI to tamper with builds or steal repository tokens | supply_chain | CI pipelines | Build & deploy pipeline | high | rare | partially_mitigated | `pull_request` (not `pull_request_target`); no repo secrets referenced; markdownlint uses `contents: read` | |
| T14 | Attacker reads arbitrary files on the catalog host through attacker-controlled picture paths | remote_unauth | Catalog read & picture API | Host filesystem, Infrastructure credentials | high | rare | mitigated | `PhysicalFileProvider` rooted at `Pics` rejects `..` and absolute paths; regression test | 913acea |
| T8 | A user who can reach Webhooks.API makes it send requests to internal services or cloud metadata endpoints (SSRF) | remote_auth | Webhooks API | Infrastructure credentials, Service availability | high | rare | partially_mitigated | webhooks-api and webhooksclient have no external endpoints in the AppHost and mobile-bff has no route to them; GrantUrl same-origin check only compares two caller-chosen URLs; no private-address denylist | |
| T16 | Injected catalog text or chat input steers the chatbot into sending the user's profile to an attacker URL or changing their cart | remote_unauth | WebApp chatbot, Catalog write API | Customer PII, Basket data | medium | likely | partially_mitigated | message text HTML-encoded; AddToCart needs an authenticated user | |
| T17 | Anonymous traffic exhausts paid AI quota or service capacity, and poison or failing events are acked and silently lost | remote_unauth | Catalog semantic search, Catalog read & picture API, RabbitMQ event bus | AI provider access, Service availability, Order records | medium | likely | unmitigated | standard resilience handler on outbound HttpClients only; no inbound rate limiting; catalog `PageSize` uncapped | |
| T18 | Catalog changes and order state transitions happen with no attributable actor, so abuse can't be traced or reversed | remote_unauth | Catalog write API, Ordering API | Catalog data, Order records | medium | likely | unmitigated | request and command logging without user identity on catalog | |
| T19 | Client-supplied X-Forwarded-* headers spoof scheme, host or client IP, which affects redirect URLs, IP-based checks and logs | remote_unauth | Forwarded headers | Session tokens, Service availability | medium | possible | unmitigated | none | |
| T20 | Credential stuffing or password spraying takes over customer accounts at the IdP | remote_unauth | Identity.API login & OIDC | User credentials, Customer PII, Payment card data | medium | possible | partially_mitigated | `lockoutOnFailure: true`; antiforgery on the login form | |
| T15 | A user who can reach Webhooks.API subscribes and receives every customer's paid and shipped order events | remote_auth | Webhooks API | Order records, Webhook subscriptions | medium | rare | partially_mitigated | webhooks-api is not externally exposed in the AppHost and mobile-bff has no route to it; delivery still filters by event type only (`WebhooksRetriever.cs:7`) | |
| T21 | Attacker sends forged webhook deliveries to WebhookClient, which records them as genuine | remote_unauth | WebhookClient receiver | Webhook subscriptions | low | likely | unmitigated | optional shared-token check | |

## 5. Deprioritized

| threat | reason |
|---|---|
| SQL injection against catalog, ordering or identity databases | All data access is EF Core LINQ. No `FromSqlRaw`, `ExecuteSqlRaw`, `SqlQuery` or Dapper calls outside migrations |
| Type-confusion or gadget deserialization on the event bus | Consumers resolve types from a registered `EventTypes` dictionary (no `Type.GetType`) and use System.Text.Json. The forged-event risk is covered by T10 |
| Stored XSS through catalog text or chatbot output | Blazor and Razor encode output. `AllowImages` HTML-encodes both the text and the `img` attributes. The residual risk is image-URL exfiltration (T16), not script execution |
| Open redirect in the IdP login and consent flow | Controllers use the standard Duende `GetAuthorizationContextAsync`, `IsLocalUrl` and `IsValidReturnUrl` checks. `RedirectService` is registered but no caller was found (see section 6) |
| Unauthenticated Ollama or OpenWebUI exposure | `useOllama = false` is hard-coded in `AppHost.cs`. Revisit if it is switched on |
| Memory-corruption RCE in input parsers | Managed .NET code with no native format parsers in the tree |
| Timing attack on webhook token comparison | Low-value secret that is also sent in clear text to the subscriber. Superseded by T21 |
| Repudiation of basket changes | Baskets are user-scoped, low value and short-lived. Not worth audit cost |

## 6. Open questions

- **Deployment intent.** Is this checkout deployed anywhere with real users or real card data, or is it only a demo? Several high rows (T1, T9) drop sharply if it never leaves a laptop. T2 does not: any deployment built from this tree signs with the published key.
- **Catalog administration.** Who is supposed to edit the catalog? Is there an intended admin role or back office, or is anonymous write an accepted demo shortcut?
- **Order prices.** Is the client-supplied `UnitPrice` deliberate (trusting the basket) or an oversight? Does any downstream step re-price before payment?
- **Ship and cancel.** Is `PUT /api/orders/ship` meant to be a staff-only action? Is there a role claim that should gate it?
- **Audience validation.** Why was branch `6b18dda` ("Re-enable audience validation") never merged? Is there a known client that breaks when audience validation is on?
- **Webhook exposure.** Is webhooks-api or webhooksclient ever exposed in a real deployment (ingress rule, extra BFF route, public app calling it)? The AppHost keeps both internal, which is why T8 and T15 are scored `rare`. If either is exposed, T8 goes back to `likely` and T15 to `almost_certain`.
- **Webhook egress.** In Azure Container Apps, can Webhooks.API reach the managed-identity or IMDS endpoint and other internal apps? Is there an egress firewall or NSG upstream?
- **Card data.** Is collecting and storing the CVV in identitydb and in token claims intentional sample behavior? Should the model assume a PCI scope?
- **Signing key in deployment.** Has any deployment ever run with the committed `tempkey.jwk`? If so, rotate the key there and treat every token it issued as forgeable.
- **Seed data.** Are the seeded `alice` and `bob` accounts created in every environment, or only in Development?
- **Log and trace sinks.** Where do OTLP logs and traces go outside local development, and who can read them? Does that sink count as a PCI system?
- **Broker and database isolation.** Do deployed environments keep one Postgres superuser and one RabbitMQ user for every service?
- **Forwarded headers.** Is there always a trusted ingress (ACA envoy) in front of every service that strips client-supplied X-Forwarded-* headers?
- **Mobile builds.** Are DEBUG builds of the MAUI apps ever distributed, for example to internal testers?
- **RedirectService.** Is `Identity.API/Services/RedirectService.cs` dead code, or is it reachable from a view?
- **Risk appetite.** Is denial of service (AI cost exhaustion, catalog deletion) acceptable for this use case?

## 7. Provenance

- mode: bootstrap
- date: 2026-11-09
- target: /home/tanis/github/depj-proj/eShop (git@github.com:dotnet/eShop.git) @ 913acea
- inputs: git-log mined (all branches); no --vulns file; GitHub advisory fetch skipped (gh CLI not installed)
- owner: unset
- updated: 2026-11-10. T2, T8 and T15 rescored from /vuln-scan and /triage results (TRIAGE.json: f004 confirmed 3-0; f007 and f008 dropped 3-0 because webhooks-api is not externally reachable).

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Set a default-deny `FallbackPolicy` (authenticated user) in every API and require an admin role on catalog writes; restrict BFF routes by HTTP method | T4, T16, T18 | yes | S |
| Derive buyer identity only from the token `sub`, enforce ownership on order read and cancel, require a staff role for ship, and scope `x-requestid` per user | T5 | yes | M |
| Re-price every order line from the catalog server-side and ignore client `UnitPrice` and `Discount` | T6 | yes | S |
| Validate audience, require HTTPS metadata, and fail closed at startup when the `Identity` config section is missing | T7, T12 | yes | S |
| Stop collecting or forwarding CVVs, drop card claims from `ProfileService`, encrypt or tokenize stored PANs, and add a log redaction policy (Microsoft.Extensions.Compliance.Redaction) for card and PII fields | T1 | yes | M |
| Delete the committed `tempkey.jwk`, purge it from git history, rotate the key in every deployment that used it, then load the signing key from Key Vault (or Duende automatic key management with persisted, protected keys) and keep `AddDeveloperSigningCredential` to Development | T2 | yes | M |
| Move client secrets out of source and into per-environment secrets, require PKCE on every code client, drop the Implicit-grant Swagger clients, and seed demo users only in Development | T9 | yes | S |
| Route webhook egress through an allowlisting resolver that denies private, loopback and link-local ranges and requires https | T8 | partial | M |
| Filter webhook delivery to the order owner's subscriptions | T15 | yes | S |
| Give each service its own broker and database principal with least privilege (per-exchange publish rights, per-database owners) | T10, T11 | partial | M |
| Lock dependencies (`RestorePackagesWithLockFile`, digest-pinned images, SRI on libman assets), re-enable NU1901-NU1904 as errors, and drop preview packages from release builds | T3 | partial | M |
| Pin GitHub Actions by SHA, add `permissions: contents: read` to every workflow, and reference the ADO template by commit | T13 | partial | S |
| Treat LLM output as untrusted: render images only from the catalog's own host and confirm tool actions that change state | T16 | partial | S |
| Add ASP.NET Core rate limiting on anonymous endpoints (semantic search especially), cap `PageSize`, and dead-letter failed events instead of acking them | T17 | partial | S |
| Configure `KnownProxies`/`KnownNetworks` (or disable forwarded headers where no proxy exists) and set explicit `AllowedHosts` | T19 | yes | S |
| Make WebhookClient token validation mandatory with a constant-time comparison and a per-deployment secret | T21 | yes | S |
| Add MFA support and per-IP and per-account throttling on the IdP login | T20 | partial | M |
| Build release mobile apps HTTPS-only, with debug certificate bypasses compiled out and secrets kept in SecureStorage | T12 | partial | S |
