# Threat Model: eShop (AdventureWorks reference e-commerce app)

## 1. System context

eShop is Microsoft's (`dotnet/eShop`) reference e-commerce application: an
AdventureWorks storefront built on .NET 10 and orchestrated with .NET Aspire
13.6 (~540 C#/Razor source files). It decomposes into ten services: an
IdentityServer-based `identity-api` (Duende 7.3.2 + ASP.NET Identity), a
Blazor Server storefront (`webapp`) with an optional LLM shopping assistant, a
YARP `mobile-bff` reverse proxy for the MAUI/Hybrid clients, `catalog-api`
(REST + pgvector semantic search), `basket-api` (gRPC over Redis),
`ordering-api` plus `order-processor` and a stub `payment-processor`,
`webhooks-api` with a demo `webhooksclient`. Services coordinate through a
RabbitMQ integration-event bus with an EF Core outbox, and share one Postgres
server (`catalogdb`, `identitydb`, `orderingdb`, `webhooksdb`).

Its stated audience is developers learning .NET microservice patterns; the
README's Azure Container Apps section warns the containerized data tier is
"intended for evaluation and demonstrations, not production data". In
practice the code is copied as a template, so its defaults (auth wiring,
IdP config, secrets, BFF routing) propagate into real deployments.
`identity-api`, `webapp`, and `mobile-bff` are exposed externally; everything
else is internal to the Aspire/ACA environment. Optional Azure Foundry
(gpt-4.1-mini chat, text-embedding-3-small) backs the chatbot and semantic
search.

This model treats the app as if deployed as shipped (the `aspire deploy`
path to ACA), because that is how template defaults turn into incidents.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| Cardholder data | Full PAN, CVV (`SecurityNumber`), expiry and holder name stored in plaintext on `ApplicationUser`; CVV also flows through ordering commands/domain events and `PaymentMethod` | critical |
| IdP signing key & client secrets | IdentityServer RSA signing key (`tempkey.jwk`, developer credential, rotation disabled) and OAuth client secrets | critical |
| User PII | Name, postal address, email, phone on `ApplicationUser`; shipping address on orders; exposed as token claims | high |
| User credentials | ASP.NET Identity password hashes in `identitydb` | high |
| Tokens & sessions | Access/refresh/id tokens, WebApp OIDC auth cookie, MAUI tokens in SecureStorage | high |
| Order data & state integrity | Orders, items, prices, buyer; event-driven status machine (Submitted→…→Paid→Shipped) and integration-event outbox | high |
| Catalog content & price integrity | Catalog items, prices, stock, descriptions, `PictureFileName`, embeddings; price changes fan out as events | high |
| Internal network & cloud metadata | Internal service endpoints, data tier, ACA environment, cloud metadata/identity endpoints reachable from services | high |
| Build & CI integrity | Source, NuGet/npm dependencies, container images, GitHub Actions and 1ES pipelines | high |
| Webhook subscriptions & tokens | Subscriber destination URLs and shared tokens (plaintext) in `webhooksdb` | medium |
| AI credentials & spend | Azure Foundry/OpenAI connection strings and per-call cost | medium |
| Service availability | Public APIs, IdP, event bus, order-processor | medium |
| Basket contents | Per-user basket JSON in Redis keyed by `sub` | low |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| Catalog API | REST read and write (`PUT/POST/DELETE /api/catalog/items`); service registers no authentication and no endpoint calls `RequireAuthorization` | unauth network → catalog DB + event bus | Catalog content & price integrity, Order data & state integrity, Service availability |
| Catalog picture endpoint | `GET /api/catalog/items/{id}/pic` serves `PictureFileName` (DB value, writable via Catalog API) from a `PhysicalFileProvider` rooted at `Pics` | DB-stored string → filesystem read | Internal network & cloud metadata, Catalog content & price integrity |
| Semantic search (AI embeddings) | Free text → embedding API → pgvector cosine search, unauthenticated | unauth network → paid AI API + DB | AI credentials & spend, Service availability |
| Mobile BFF (YARP) | External reverse proxy; catch-all `/api/catalog/{*any}`, `/api/orders/{*any}`, `/identity/{*any}` routes match on path + api-version only (no method filter) | internet → internal services | Catalog content & price integrity, Order data & state integrity, Tokens & sessions |
| Ordering API | Bearer-JWT REST: create order (body carries `UserId`, item `UnitPrice`/`Discount`, card data), draft, get by id, cancel, ship | authenticated user → ordering DB + event bus | Order data & state integrity, User PII, Cardholder data |
| Basket gRPC API | gRPC `GetBasket` (AllowAnonymous), `UpdateBasket`, `DeleteBasket`; identity from `sub` claim; WebApp calls it over plaintext `http://basket-api` | authenticated client → Redis | Basket contents, Tokens & sessions |
| Redis basket store | Basket JSON per user, default credentials, used only by Basket.API | internal network → basket data | Basket contents |
| Webhooks API | Authenticated subscription create/delete with caller-controlled `Url`/`GrantUrl`/`Token`; server sends OPTIONS to GrantUrl and later POSTs event payloads to Url | authenticated user → server-side outbound HTTP | Internal network & cloud metadata, Order data & state integrity, Webhook subscriptions & tokens |
| WebhookClient receiver | `OPTIONS /check`, `POST /webhook-received`; token validation off unless `ValidateToken=true`; payloads stored and displayed | network caller → demo client state | Webhook subscriptions & tokens |
| RabbitMQ event bus | Shared broker, one credential for all services; routing key → allowlisted event type → System.Text.Json | service ↔ service (any publisher trusted) | Order data & state integrity, Catalog content & price integrity |
| Identity.API | IdentityServer protocol endpoints + MVC login/logout/consent/external/diagnostics; client registry with redirect URIs, grant types, secrets; `ProfileService` claim issuance | internet → IdP | User credentials, User PII, Cardholder data, Tokens & sessions |
| JWT validation | `AddDefaultAuthentication` in ServiceDefaults: issuer-only checks, `ValidateAudience=false`, `RequireHttpsMetadata=false`, silently skips auth when `Identity` config section is absent | bearer token → API authorization | Tokens & sessions, Order data & state integrity, Webhook subscriptions & tokens |
| WebApp Blazor storefront | Server-side Blazor pages (catalog, cart, checkout, orders), OIDC cookie with `SaveTokens`; builds orders server-side | browser → WebApp → backend APIs | Tokens & sessions, User PII, Order data & state integrity |
| Chatbot (LLM tools) | User text + catalog descriptions → LLM with tools `GetUserInfo`, `SearchCatalog`, `AddToCart`, `GetCartContents`; output rendered via `MarkupString` with markdown images → `<img src>` | untrusted text (user + catalog) → LLM → browser DOM | User PII, Basket contents, AI credentials & spend |
| MAUI / Hybrid clients | Native clients: cleartext allowed (Android/MacCatalyst), DEBUG TLS bypass, client secret in Preferences, implicit-ish browser token flow | device/network → backend | Tokens & sessions, User PII |
| Shared Postgres server | One `ankane/pgvector:latest` instance with four DBs, one Aspire-generated credential shared by all services | service → data tier | User credentials, Cardholder data, Order data & state integrity, Catalog content & price integrity |
| Forwarded headers | `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` on every project with no KnownProxies | client-supplied header → request scheme/host/RemoteIp | Tokens & sessions |
| Committed secrets & key material | `tempkey.jwk` (private key), client secret `"secret"`, seeded `alice`/`bob` with `Pass123$`, dev DB passwords, fixed webhook token; CredScan suppressions | repository → runtime trust | IdP signing key & client secrets, User credentials, Tokens & sessions |
| Telemetry & logs | Structured logging of commands (`{@Command}`), webhook tokens logged, OTLP export, Development environment defaults | runtime data → log/trace sinks | Cardholder data, Tokens & sessions, Webhook subscriptions & tokens |
| Supply chain | NuGet (central pinning, nuget.org only), npm lockfile, unpinned `pgvector:latest` image, Duende/ASP.NET runtime versions | third-party publisher → build/runtime | Build & CI integrity |
| CI workflows | GitHub Actions on PRs (tag-pinned actions, default token permissions, unpinned global npm install), Azure DevOps 1ES template on mutable `release` ref | contributor → CI runner | Build & CI integrity |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Attacker forges valid access/id tokens for any user and scope by signing with IdentityServer key material that ships in the repository, bypassing authentication on every API | remote_unauth | Committed secrets & key material, JWT validation, Identity.API | IdP signing key & client secrets, Tokens & sessions, Order data & state integrity, User PII | critical | almost_certain | unmitigated | none (KeyManagement disabled; `AddDeveloperSigningCredential` in all environments) | |
| T2 | Cardholder data (including CVV) is disclosed at scale because it is stored in plaintext, issued as token claims to every client, and written to logs | remote_auth | Identity.API, Ordering API, Telemetry & logs | Cardholder data, User PII | critical | likely | partially_mitigated | PAN masked to last-4 before ordering command; one `CreateOrderRequest` log line avoids full request | dotnet/eShop#993, dotnet/eShop#1010 |
| T3 | Compromise of any one service escalates to every database and to forged integration events (e.g. marking orders paid) because all services share one Postgres credential and one RabbitMQ credential | insider | Shared Postgres server, RabbitMQ event bus | User credentials, Cardholder data, Order data & state integrity, Catalog content & price integrity | critical | possible | unmitigated | data tier internal-only in ACA | |
| T4 | Malicious or vulnerable third-party code enters the build or runtime through unpinned images/tooling or lagging framework/IdP packages | supply_chain | Supply chain, CI workflows | Build & CI integrity, IdP signing key & client secrets | critical | rare | partially_mitigated | central package pinning, nuget.org-only source mapping, Dependabot | 53e0059 |
| T5 | Unauthenticated internet caller creates, modifies, re-prices or deletes catalog items (and stores arbitrary content later consumed by other components) via the unauthenticated catalog write surface exposed through the mobile BFF | remote_unauth | Catalog API, Mobile BFF (YARP) | Catalog content & price integrity, Order data & state integrity | high | almost_certain | unmitigated | none (auth silently skipped when `Identity` config absent) | 913acea |
| T6 | Authenticated user reads, cancels or ships other users' orders because order operations are not scoped to the caller (broken object-level authorization) | remote_auth | Ordering API, Mobile BFF (YARP) | Order data & state integrity, User PII | high | almost_certain | unmitigated | group-wide `RequireAuthorization()` (authentication only) | 50dd0d4 |
| T7 | Authenticated user places orders at attacker-chosen prices or on behalf of another buyer because order creation trusts client-supplied prices, discounts and user identity | remote_auth | Ordering API, Mobile BFF (YARP) | Order data & state integrity | high | almost_certain | unmitigated | units>0 and discount≤total checks only | |
| T8 | Any authenticated subscriber receives order events belonging to all other users because webhook fan-out is not scoped to the subscription owner | remote_auth | Webhooks API | Order data & state integrity, Webhook subscriptions & tokens | high | almost_certain | unmitigated | none | |
| T9 | Authenticated user makes the server issue requests to internal services or cloud metadata endpoints via caller-controlled webhook URLs (SSRF) | remote_auth | Webhooks API | Internal network & cloud metadata | high | likely | partially_mitigated | GrantUrl and Url must share an origin (attacker controls both) | dotnet/eShop#999 |
| T10 | Tokens issued for one client/API are replayed against others, or authorization codes/tokens are intercepted, because of weak token validation and OAuth client configuration (no audience check, shared static client secret, no PKCE on webapp, implicit-flow clients) | remote_auth | JWT validation, Identity.API, WebApp Blazor storefront | Tokens & sessions | high | likely | unmitigated | issuer validation; PKCE on maui client | 6b18dda, dotnet/eShop#100 |
| T11 | Attacker-planted content (catalog descriptions, user text) hijacks the shopping assistant to exfiltrate the user's PII via rendered image URLs or perform cart actions (indirect prompt injection) | remote_unauth | Chatbot (LLM tools), Catalog API, WebApp Blazor storefront | User PII, Basket contents | high | likely | partially_mitigated | message text HTML-encoded; chatbot off unless AI configured | |
| T12 | Secrets and session material leak to anyone with log/trace access because commands, webhook tokens and full request objects are logged and exported | insider | Telemetry & logs | Tokens & sessions, Webhook subscriptions & tokens, Cardholder data | high | likely | unmitigated | none | |
| T13 | Attacker takes over accounts or clients using default credentials that ship with the template (seeded users, static client secrets, default DB passwords) | remote_unauth | Committed secrets & key material, Identity.API | User credentials, Tokens & sessions, IdP signing key & client secrets | high | possible | partially_mitigated | DB passwords Aspire-generated in deploy path | |
| T14 | Network attacker intercepts or tampers with mobile client traffic and steals tokens due to cleartext permission, debug TLS bypass and client secret in Preferences | adjacent_network | MAUI / Hybrid clients | Tokens & sessions, User PII | high | possible | partially_mitigated | TLS bypass limited to DEBUG builds; tokens in SecureStorage | |
| T15 | Attacker reads arbitrary server files or serves active content (e.g. SVG) from the catalog image endpoint by controlling the stored picture path | remote_unauth | Catalog picture endpoint, Catalog API | Internal network & cloud metadata, Catalog content & price integrity | high | possible | partially_mitigated | `PhysicalFileProvider` rooted at `Pics` blocks `..`/absolute paths | 913acea |
| T16 | Unauthenticated callers exhaust service capacity or run up AI spend via unbounded pagination/array parameters and per-request embedding calls | remote_unauth | Catalog API, Semantic search (AI embeddings), Mobile BFF (YARP) | Service availability, AI credentials & spend | medium | likely | unmitigated | none (no rate limiting, no pageSize cap) | |
| T17 | Attacker injects forged webhook deliveries into subscriber endpoints because delivery authenticity rests on a static, optionally-validated, logged token | remote_unauth | WebhookClient receiver, Webhooks API | Webhook subscriptions & tokens | medium | likely | unmitigated | optional `X-eshop-whtoken` check (off by default) | |
| T18 | Privileged actions (catalog price changes, order ship/cancel, webhook registration) cannot be attributed after the fact due to no audit trail | remote_auth | Catalog API, Ordering API, Webhooks API | Catalog content & price integrity, Order data & state integrity | medium | likely | unmitigated | general application logging only | |
| T19 | Client-supplied forwarded headers spoof scheme/host/remote IP, subverting localhost-gated diagnostics, OIDC redirect/issuer construction and IP-based logging | remote_unauth | Forwarded headers, Identity.API, WebApp Blazor storefront | Tokens & sessions | medium | possible | unmitigated | none (no KnownProxies/KnownNetworks) | |
| T20 | Contributor-supplied code or a compromised third-party action abuses CI runner credentials or tokens to tamper with the repository or artifacts | supply_chain | CI workflows | Build & CI integrity | medium | rare | partially_mitigated | `pull_request` (not `_target`); no secrets referenced in workflows | |
| T21 | Adjacent attacker inside the environment reads or tampers with baskets and in-flight tokens via plaintext internal gRPC and default-credential Redis | adjacent_network | Basket gRPC API, Redis basket store | Basket contents, Tokens & sessions | medium | rare | partially_mitigated | services internal-only in ACA | |

## 5. Deprioritized

| threat | reason |
|---|---|
| SQL injection against service databases | No raw SQL outside EF migrations (`FromSqlRaw`/`ExecuteSqlRaw`/Dapper absent); EF Core LINQ parameterizes. Re-open if raw queries are introduced. |
| Remote code execution via insecure deserialization (event bus, Redis, outbox) | System.Text.Json with allowlisted event types / source-generated contexts; no `TypeNameHandling`, `BinaryFormatter` or polymorphic type resolution from message content. |
| Remote code execution via dynamic code or process spawn | No dynamic assembly load, `Process.Start` or script evaluation on external input in service code. |
| Stored/reflected XSS in Blazor pages (outside the chatbot) | Razor auto-encodes; the only `MarkupString` on untrusted data is the chatbot, covered by T11. |
| Denial of service via poison messages on the event bus | Unknown routing keys and deserialization failures are acked and dropped rather than requeued. |
| Fraudulent charges against real card networks | `PaymentProcessor` is a config-driven stub (`PaymentSucceeded`) and charges nothing; forged payment outcomes are covered by T3. |
| Repudiation of basket changes | Low-value, user-scoped data; no business decision depends on basket history. |

## 6. Open questions

- Is any deployment running this code as-is beyond demos? `es-metadata.yml` declares `isProduction: true`; does that reflect a real hosted instance (e.g. a public AdventureWorks demo) with real users?
- Is `tempkey.jwk` (via `AddDeveloperSigningCredential`) the signing key in the ACA deployment path, or is a managed key injected at publish time outside this tree?
- Who is supposed to be able to write to the catalog? Is the absence of auth on Catalog.API intentional for demo seeding, and is the mobile BFF meant to expose write methods?
- Should ship/cancel be admin- or back-office-only? Is there an intended role model for orders that the code doesn't express?
- Is storing full PAN/CVV on the user profile and emitting it as token claims a deliberate demo simplification, and is any deployment subject to PCI DSS?
- Are webhooks intended to be multi-tenant (each user sees only their own orders), or a single-operator integration feature?
- What egress controls exist in the ACA environment (NSG/firewall, managed-identity endpoint protections) that would bound T9?
- Is the chatbot (`UseFoundry`) enabled in public demos, and is there a spend cap on the Foundry deployment?
- Is the ingress in front of `webapp`/`identity-api`/`mobile-bff` a trusted proxy that strips client `X-Forwarded-*` headers?
- Is `Microsoft.AspNetCore.*` 10.0.12 (main) behind any security servicing release (open Dependabot PR #1071 bumps to 10.0.14), and is the Duende 7.3.2 → 8.x upgrade (Dependabot #1045/#1063) blocked on licensing?
- Are MAUI/Hybrid release builds published to stores, and do release builds keep cleartext traffic enabled?
- Is the risk of DoS/cost abuse acceptable for a demo deployment, or should public endpoints be rate-limited?

## 7. Provenance

- mode: bootstrap
- date: 2026-11-12
- target: /home/niels/github/UpdateConference2026/eShop (github.com/dotnet/eShop) @ 913acea
- inputs: git-log + GitHub issues/PRs mined (no --vulns file; `gh api security-advisories` returned none)
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Replace the developer signing credential with a managed, rotated key from a secret store (enable Duende key management), delete `tempkey.jwk`, and load all client secrets from the secret store | T1,T13 | yes | S |
| Make authentication fail closed (throw at startup when `Identity` config is missing), require an admin policy on every write endpoint, and restrict BFF routes to explicit method allowlists | T5,T15,T16,T11 | yes | M |
| Derive caller identity only from token claims and enforce owner/role checks in every order and webhook query/command (resource-based authorization) | T6,T7,T8 | yes | M |
| Recompute prices and discounts server-side from the catalog at order creation; never trust client-supplied amounts | T7 | yes | S |
| Stop storing or emitting CVV, tokenize PAN with a payment provider, and add a logging destructuring policy that redacts card, token and secret fields | T2,T12 | yes | M |
| Validate per-API audiences, require PKCE for all code-flow clients, and remove implicit-flow clients | T10 | yes | S |
| Route webhook delivery through an egress allowlist with resolve-then-connect validation (block private, loopback, link-local; no redirects) | T9 | yes | M |
| Sign webhook payloads with per-subscription HMAC secrets and enforce verification in receivers | T17 | yes | S |
| Give each service its own least-privilege DB user and RabbitMQ user/vhost permissions (publish/consume only its own events) | T3 | partial | M |
| Treat LLM output as untrusted: render images only from the app's own origin (CSP `img-src 'self'`) and drop PII-returning tools from the chatbot | T11 | yes | S |
| Add rate limiting and hard caps on page size and array parameters for public endpoints, and require auth for embedding-backed search | T16 | yes | S |
| Configure `KnownProxies`/`KnownNetworks` so forwarded headers are honored only from the ingress | T19 | yes | S |
| Pin container images by digest and actions by SHA, set minimal `permissions:` in every workflow, and pin global tool installs | T4,T20 | partial | S |
| Emit an append-only audit log for catalog writes, order state changes and webhook registrations | T18 | yes | M |
| Seed demo users only in Development, and disable cleartext and debug TLS overrides in release mobile builds | T13,T14 | partial | S |
| Enable TLS for internal gRPC and authentication on Redis | T21 | partial | M |
