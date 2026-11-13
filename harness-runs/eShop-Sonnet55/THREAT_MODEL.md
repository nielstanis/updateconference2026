# Threat Model: dotnet/eShop (AdventureWorks reference e-commerce app)

## 1. System context

eShop is Microsoft's reference .NET e-commerce application. It runs on .NET 10 and is orchestrated by .NET Aspire 13.6.0. It is a set of services: identity-api (Duende IdentityServer 7.3.2 with ASP.NET Identity), basket-api (gRPC over Redis), catalog-api (Postgres with pgvector, optional AI embeddings), ordering-api, order-processor, payment-processor, webhooks-api, a Blazor webapp, a webhook receiver client, a YARP "mobile-bff" gateway, and MAUI client apps. Services talk over HTTP and gRPC and exchange integration events through a shared RabbitMQ broker. About 500 C# files.

The README calls it an evaluation and demo sample, and the Azure Container Apps deployment is documented as "not production data". Even so, `es-metadata.yml` marks it production, and developers copy its patterns. Treat it as a reference implementation whose defaults will be reused. Only identity-api, mobile-bff and webapp have external endpoints in the AppHost. Every other service is internal, so many threats below depend on an attacker first reaching the internal network or compromising one service. The repo has no SECURITY.md.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| User accounts and credentials | ASP.NET Identity users and password hashes in identitydb | critical |
| IdentityServer signing key | Key that signs every token; a developer key is committed as `Identity.API/tempkey.jwk` | critical |
| OIDC client secrets | Shared secret "secret" for webapp, webhooksclient and maui | high |
| Access tokens and claims | JWTs that authorize Orders, Basket and Webhooks APIs; user claims carry card fields | critical |
| Payment card data | PAN, CVV, holder, expiry on the Identity user, in claims, in checkout requests, and PAN in the paymentmethods table | critical |
| Buyer PII and shipping addresses | Name, address, phone, order history | high |
| Orders and order state | Status flow Submitted to Shipped or Cancelled, prices and items | high |
| Payment status integrity | Paid/failed outcomes carried by integration events; the processor is a stub | high |
| Baskets | Per-user baskets in Redis | medium |
| Catalog data integrity | Items, prices, stock, descriptions and embeddings | medium |
| Catalog picture files and host filesystem | Pics directory and anything else readable by the catalog process | medium |
| Webhook subscriptions and tokens | User-supplied destination URLs and shared tokens | high |
| Integration events | RabbitMQ messages that drive order, payment, stock and webhook state | high |
| Databases and DB credentials | Four Postgres databases behind one superuser identity | high |
| AI configuration and prompts | Foundry or OpenAI keys, chat history, user info passed to the model | medium |
| Service availability | Login, catalog, checkout, event consumers | medium |
| Host process integrity | The .NET service processes and their containers | high |
| Build and CI integrity | NuGet and npm dependencies, GitHub Actions, container images | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| Catalog.API HTTP API | `/api/catalog/*` GET and POST/PUT/DELETE items, search; no authentication anywhere in the project | internet or internal client → catalog service | Catalog data integrity, Integration events, Webhook subscriptions and tokens, AI configuration and prompts |
| Catalog picture endpoint | `GET /api/catalog/items/{id}/pic`, reads a DB-supplied file name through a PhysicalFileProvider | DB-controlled string → filesystem | Catalog picture files and host filesystem |
| Ordering.API HTTP API | Create, read, ship, cancel orders; group-level RequireAuthorization only | authenticated user → order data | Orders and order state, Buyer PII and shipping addresses, Payment card data |
| Webhooks.API registration API | `/api/webhooks` create, list, delete subscriptions with a user-supplied URL | authenticated user → webhooks DB and outbound HTTP | Webhook subscriptions and tokens, Host process integrity |
| Webhook delivery and grant check | WebhooksSender POSTs to stored URLs; GrantUrlTesterService sends OPTIONS to a registrant URL | service → arbitrary URL | Host process integrity, Webhook subscriptions and tokens |
| Basket.API gRPC | GetBasket (AllowAnonymous), UpdateBasket, DeleteBasket over Redis; manual identity check | WebApp or client → basket service | Baskets |
| mobile-bff YARP proxy | External proxy to catalog, ordering and the full identity app with no gateway auth | internet → internal services | Catalog data integrity, Orders and order state, User accounts and credentials |
| WebhookClient receiver endpoints | `OPTIONS /check`, `POST /webhook-received`, shared-token check | anonymous network → receiver | Webhook subscriptions and tokens, Service availability |
| Identity.API OIDC and login | Login UI, `/connect/*`, client registrations, seed users, developer signing key | internet → identity provider | User accounts and credentials, IdentityServer signing key, OIDC client secrets, Access tokens and claims |
| JWT bearer validation | Shared `AddDefaultAuthentication` in ServiceDefaults (no audience check, no scope policy) | token → every API | Access tokens and claims, Orders and order state, Baskets, Webhook subscriptions and tokens |
| RabbitMQ event bus | Shared broker; consumers deserialize events by type name; no message signing | broker access → every service | Integration events, Orders and order state, Payment status integrity |
| WebApp Blazor UI and OIDC client | Blazor pages, OIDC code flow with hardcoded secret and no PKCE, returnUrl handling | browser → web app | Access tokens and claims, Payment card data, Buyer PII and shipping addresses |
| WebApp AI chatbot | Chat with tool calls (SearchCatalog, AddToCart, GetUserInfo) and markdown image rendering | user prompt and catalog text → LLM → rendered output | AI configuration and prompts, Baskets, Buyer PII and shipping addresses |
| Catalog semantic search and embeddings | Search text and item text sent to Ollama or OpenAI/Foundry; vectors stored in pgvector | user text → third-party model | AI configuration and prompts, Service availability |
| MAUI client apps | ClientApp and HybridApp, custom `maui://authcallback` scheme, tokens in SecureStorage | device → identity and BFF | Access tokens and claims |
| Aspire AppHost deployment config | One Postgres superuser for four DBs, shared RabbitMQ creds, `ankane/pgvector:latest`, unrestricted forwarded headers, HTTP toggle | deployment config → every service | Databases and DB credentials, Integration events, Host process integrity |
| CI workflows and build pipeline | GitHub Actions on version tags, no `permissions:` blocks, e2e job runs the whole AppHost, legacy PAT scripts | PR code and third-party actions → runner and repo token | Build and CI integrity |
| NuGet and npm dependencies | Central package management, NU1901–NU1904 suppressed, no lock files, npm lock points at an internal feed | public registries → build | Build and CI integrity, Host process integrity |
| Application logging | Webhook tokens, CVV and holder name via `{@Command}`, IdentityServer events | service → log sinks and Aspire dashboard | Payment card data, Webhook subscriptions and tokens, Buyer PII and shipping addresses |
| Repo-embedded agent skills | `.github/skills/**` instruction files read by AI tooling | repo content → AI agent | Build and CI integrity |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Attacker forges tokens accepted by every API by using the committed developer signing key | remote_unauth | Identity.API OIDC and login; JWT bearer validation | IdentityServer signing key, Access tokens and claims, User accounts and credentials | critical | likely | unmitigated | none (code is marked "TODO not for production") | |
| T2 | Card number, CVV, holder and expiry are exposed because they are stored on the Identity user, issued as token claims, sent through checkout and logged | remote_auth | Identity.API OIDC and login; Ordering.API HTTP API; Application logging | Payment card data, Access tokens and claims | critical | likely | partially_mitigated | PAN masked in the order log line and before the Orders DB write; CVV not persisted in Ordering | 0ace928 |
| T3 | One compromised service reads or rewrites every database and every event, because all share one Postgres superuser and one broker credential | adjacent_network | Aspire AppHost deployment config; RabbitMQ event bus | Databases and DB credentials, Integration events, User accounts and credentials | critical | possible | unmitigated | none | |
| T4 | A token issued to any client or scope is accepted by every API, because audience validation is off and no scope policies exist | remote_auth | JWT bearer validation | Access tokens and claims, Orders and order state, Baskets, Webhook subscriptions and tokens | high | almost_certain | unmitigated | issuer check only; the fix `6b18dda` exists only on an unmerged branch | 6b18dda (unmerged) |
| T5 | Any authenticated user reads, ships or cancels any order and can create orders as another user | remote_auth | Ordering.API HTTP API | Orders and order state, Buyer PII and shipping addresses | high | almost_certain | unmitigated | group-level RequireAuthorization only | 50dd0d4 |
| T6 | Attacker logs in with known default credentials (alice and bob with `Pass123$`) seeded on every startup | remote_unauth | Identity.API OIDC and login | User accounts and credentials, Payment card data, Buyer PII and shipping addresses | high | almost_certain | unmitigated | lockout on password sign-in | 50dd0d4 |
| T7 | Anyone who can reach catalog-api creates, edits or deletes items, changes prices, and plants text read by the chatbot and webhooks | remote_unauth | Catalog.API HTTP API; mobile-bff YARP proxy | Catalog data integrity, Integration events, Webhook subscriptions and tokens | high | likely | unmitigated | none; the API is internal in the default AppHost | |
| T8 | Server-side request forgery from webhooks-api to internal hosts and metadata endpoints through a user-supplied URL | remote_auth | Webhooks.API registration API; Webhook delivery and grant check | Host process integrity, Databases and DB credentials | high | likely | unmitigated | URL must be well-formed, and the registrant must echo the token for the grant check | |
| T9 | Attacker steals or redeems authorization codes and impersonates clients, because the webapp client has `RequirePkce=false`, all secrets are `secret`, and Swagger clients use the implicit grant | remote_unauth | Identity.API OIDC and login; WebApp Blazor UI and OIDC client; MAUI client apps | OIDC client secrets, Access tokens and claims | high | possible | unmitigated | PKCE on the maui and webhooksclient clients | |
| T10 | Network attacker reads tokens or spoofs the host, scheme and redirect URIs, because OIDC runs over HTTP and forwarded headers are trusted from anyone | adjacent_network | Aspire AppHost deployment config; Identity.API OIDC and login | Access tokens and claims, User accounts and credentials | high | possible | unmitigated | HTTPS is the default launch profile | |
| T11 | Attacker with broker access forges or replays integration events (for example `OrderPaymentSucceeded`) to mark orders paid, change stock or trigger webhooks | adjacent_network | RabbitMQ event bus | Integration events, Payment status integrity, Orders and order state | high | possible | unmitigated | broker credentials only; events are looked up by type name, so there is no gadget-style deserialization | |
| T12 | Compromised dependency, container image or CI action leads to code execution in the build or the runtime | supply_chain | CI workflows and build pipeline; NuGet and npm dependencies; Aspire AppHost deployment config | Build and CI integrity, Host process integrity | high | possible | partially_mitigated | single nuget.org feed, central package management, Dependabot for NuGet and npm | |
| T13 | Arbitrary file read through the catalog picture file name | remote_unauth | Catalog picture endpoint; Catalog.API HTTP API | Catalog picture files and host filesystem | high | rare | partially_mitigated | PhysicalFileProvider rooted at Pics, regression test; file name is still unvalidated on write | 913acea |
| T14 | Anyone submits forged webhook payloads to the receiver, because token validation is off by default and the default token is public | remote_unauth | WebhookClient receiver endpoints; Application logging | Webhook subscriptions and tokens, Service availability | medium | almost_certain | unmitigated | none; the config key read by the code does not match the key in appsettings | |
| T15 | Denial of service through missing rate limits, unbounded webhook fan-out, an unbounded payload queue, unhandled AI provider failures and silently dropped poison messages | remote_unauth | Catalog semantic search and embeddings; WebhookClient receiver endpoints; Webhook delivery and grant check; RabbitMQ event bus | Service availability | medium | likely | unmitigated | resilience handlers on service HTTP clients | |
| T16 | Prompt injection through catalog text makes the chatbot leak user data via image URLs or add items to a cart | remote_auth | WebApp AI chatbot; Catalog.API HTTP API | AI configuration and prompts, Baskets, Buyer PII and shipping addresses | medium | possible | unmitigated | text is HTML-encoded; tool set is small | |
| T17 | Open redirect or parser confusion in return-URL handling sends users to attacker sites after login | remote_unauth | WebApp Blazor UI and OIDC client; Identity.API OIDC and login | User accounts and credentials, Access tokens and claims | medium | possible | partially_mitigated | `IsLocalUrl` and IdentityServer context checks; `RedirectService` uses regex string parsing | |
| T18 | Internal or development-only features are exposed on public endpoints (full identity app through the BFF, health and OpenAPI in Development, `AllowedHosts: *`) | remote_unauth | mobile-bff YARP proxy; Aspire AppHost deployment config | User accounts and credentials, Service availability | medium | possible | unmitigated | health endpoints only in Development | |
| T19 | Actions on orders cannot be attributed, because ship and cancel record no actor and create-order trusts a body-supplied user | remote_auth | Ordering.API HTTP API; Application logging | Orders and order state | medium | possible | unmitigated | none | |
| T20 | Basket manipulation through anonymous GetBasket handling and unvalidated product ids and quantities | remote_unauth | Basket.API gRPC | Baskets | medium | possible | partially_mitigated | user id comes from the token `sub` claim only | |
| T21 | Indirect prompt injection of AI coding tools through repo-embedded skill files | supply_chain | Repo-embedded agent skills | Build and CI integrity | low | rare | unmitigated | none | |

## 5. Deprioritized

| threat | reason |
|---|---|
| Deserialization gadgets in the event bus | Events are resolved from a fixed type dictionary; no `Type.GetType`, no TypeNameHandling, no BinaryFormatter found. |
| SQL injection | No `FromSql` or `ExecuteSql*` anywhere in `src`; EF LINQ and Dapper-free paths only. |
| CORS abuse | No CORS configuration exists. |
| SignalR and file upload attacks | No hubs or upload endpoints exist. |
| Real payment processor compromise | PaymentProcessor is a stub; outcome comes from a config flag. Integrity risk is captured in T11. |
| Repudiation on login | IdentityServer success and failure events are logged; only order actions lack attribution (T19). |

## 6. Open questions

- Is any part of this deployed beyond demos? The README says the ACA deployment is evaluation only, but `es-metadata.yml` says production. This decides whether T1, T6 and T12 are findings or accepted sample behavior.
- Does `AddDeveloperSigningCredential()` actually load the committed `tempkey.jwk`, or generate a fresh key on first start? This decides whether T1 is "anyone can forge" or "anyone with the dev box can".
- Do the ID token or access token actually include the `card_*` claims? `ProfileService` adds them, but the client scopes and `GetClaimsFromUserInfoEndpoint` decide where they appear (T2).
- Are POST, PUT and DELETE catalog routes exposed by the mobile-bff? The first routes read are GET-shaped; method coverage was not verified (T7).
- Do the ship and cancel command handlers check order ownership or a role? The API layer does not; the handlers were not read (T5).
- Is `CardSecurityNumber` (CVV) retained anywhere after checkout? Ordering does not map it to a column, but the Identity user record stores it (T2).
- Are the webhooks-api and the broker reachable from workloads outside the AppHost (shared cluster, shared namespace)? This sets the real likelihood of T3, T8 and T11.
- Is there an egress policy on the webhooks-api container? None is visible in the repo (T8).
- Are the `ankane/pgvector` image and GitHub Actions pinned somewhere outside this tree? (T12)
- Is risk accepted for DoS and for the missing rate limiting on a sample app? (T15)
- Basket gRPC: with no token, does the `JwtBearer` default scheme reject the call or leave it unauthenticated? Not verified at runtime (T20).

## 7. Provenance

- mode: bootstrap
- date: 2026-11-10
- target: ~/github/depj-proj/eShop @ 913acea
- inputs: git-log mined (no CVEs, no public advisory lookup because `gh` is unavailable); no `--vulns` file
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Replace the developer signing credential with managed key storage, remove `tempkey.jwk` from git history and rotate | T1 | yes | S |
| Require authentication on all Catalog write endpoints (admin policy) and bind writes to a DTO that excludes embedding and picture fields | T7, T16 | yes | S |
| Enable audience validation and add per-API scope policies in `AddDefaultAuthentication` | T4, T5, T20 | partial | M |
| Scope orders to the token `sub`, derive the user from claims instead of the request body, and record the actor on ship and cancel | T5, T19 | yes | S |
| Gate seed users and dev clients to Development only, require PKCE, drop implicit-grant clients, and load client secrets from a secret store | T6, T9 | yes | S |
| Stop storing and issuing card data from Identity; tokenize through a payment provider and never log request objects | T2 | yes | L |
| Give each service its own Postgres role and broker credentials with per-queue ACLs | T3, T11 | partial | M |
| Block private and link-local destinations in the webhook sender, disable redirects, add timeouts, and restrict egress | T8 | yes | M |
| Enforce HTTPS metadata, set `KnownProxies` and restrict `AllowedHosts` | T10, T18 | yes | S |
| Sign integration events (for example HMAC) and add a dead-letter exchange for poison messages | T11, T15 | partial | M |
| Pin images by digest and actions by SHA, add lock files, re-enable NU1901–NU1904 warnings, and add `permissions:` blocks | T12, T21 | partial | S |
| Add rate limiting and bounded queues on public and receiver endpoints | T15 | yes | M |
| Fix the webhook receiver token config key, sign payloads, and stop logging tokens | T14 | yes | S |
| Treat catalog text as untrusted in the chatbot and drop markdown image rendering or allowlist hosts | T16 | yes | S |
| Replace the regex return-URL parsing in `RedirectService` with `IsLocalUrl` and URI parsing | T17 | yes | S |
| Validate picture file names on write and keep the PhysicalFileProvider boundary | T13 | partial | S |
