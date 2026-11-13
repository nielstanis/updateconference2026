# Threat Model: dotnet/eShop reference e-commerce platform

## 1. System context

dotnet/eShop is Microsoft's reference .NET 10 e-commerce application: a microservices storefront (Identity.API, Catalog.API, Basket.API, Ordering.API, Webhooks.API, OrderProcessor, PaymentProcessor) orchestrated by .NET Aspire, with a Razor/Blazor web frontend (WebApp), a .NET MAUI mobile client (ClientApp) behind a YARP mobile-BFF, a WebhookClient receiver app, and a RabbitMQ event bus tying the services together. Backing stores are one pgvector Postgres container hosting all four databases (catalogdb, identitydb, orderingdb, webhooksdb), Redis for baskets, and RabbitMQ; an optional LLM (Azure Foundry or Ollama) powers catalog semantic search and a WebApp chatbot with function tools. Authentication is Duende IdentityServer at Identity.API issuing JWTs consumed by every API. It runs locally via `aspire run`, or deploys via `aspire deploy` to Azure Container Apps; the README's production path is the companion eShopOnAzure repo, and it explicitly labels the containerized backing stores "not production data".

Its ~500 source files of C# serve two audiences: people running the demo, and developers copying its patterns into real products — which makes insecure defaults (committed signing key, shared client secret `secret`, seeded users with published passwords, suppressed NuGet audit warnings) part of the product's blast radius. Analyzed at commit `913acea`.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| identitydb user store | ASP.NET Identity over Postgres (ApplicationDbContext); demo users alice/bob with published password `Pass123$` re-seeded at every startup | high |
| JWT signing key | RSA private signing credential (`tempkey.jwk`) committed to the repo, loaded by AddDeveloperSigningCredential with key management disabled | high |
| OAuth client credentials | Shared client secret `secret` (Sha256) for the webapp/maui/webhooksclient confidential clients; static WebhookClient token GUID in appsettings | high |
| Cardholder data + PII | PAN, CVV, expiration, cardholder name plus name/address/phone stored in identitydb and orderingdb; card and address fields also ride as claims in every issued token | high |
| Order records & financial integrity | Order aggregates, items, and totals; order prices and buyer identity taken from client payload; no ownership scoping on read/cancel/ship | high |
| Event bus message authenticity | RabbitMQ `eshop_event_bus` carries unsigned JSON integration events driving order lifecycle, stock, payment outcomes, and webhook dispatch | high |
| Webhook subscription data | Destination URLs + plaintext tokens in webhooksdb; tokens re-emitted in delivery headers | high |
| Catalog data integrity | Products, brands, types, prices; anonymous CRUD; forged price changes cascade into baskets and webhooks | medium |
| Redis basket store | Plaintext JSON baskets keyed `/basket/{sub}`; privacy and availability at stake | medium |
| Service availability | Single-instance Redis, RabbitMQ, Postgres (hosting all 4 DBs), OrderProcessor, PaymentProcessor; Blazor in-process sessions; per-query AI embedding spend | medium |
| Downstream-embedder security posture | Reference-app patterns and configs get copied into real deployments; committed credentials and suppressed audits propagate | high |
| Process/tenant integrity of services | Compromise of any one container reaches the shared Postgres instance and event bus; every service auto-migrates shared databases at startup | high |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| Catalog.API read/search endpoints | Anonymous browse plus pgvector semantic search generating AI embeddings from user text (outbound LLM call per query) | unauthenticated HTTP → catalog DB / AI embedding service | Catalog data integrity, Service availability |
| Catalog.API anonymous item CRUD | POST/PUT/DELETE of catalog items with no authentication wiring in Program.cs | unauthenticated HTTP → catalog DB mutation | Catalog data integrity, Webhook subscription data, Redis basket store |
| Catalog.API picture file serving | GET items/{id}/pic resolves a DB-stored PictureFileName against a PhysicalFileProvider rooted at Pics; publicly proxied via WebApp /product-images/* | unauthenticated HTTP → filesystem read via IFileProvider | Process/tenant integrity of services |
| Basket.API gRPC basket service | GetBasket ([AllowAnonymous] but sub-keyed), UpdateBasket, DeleteBasket; Redis keyed by raw `sub` claim | JWT bearer → gRPC → Redis basket store | Redis basket store |
| Ordering.API orders API | Create/draft/cancel/ship/get-by-id/list-by-user; group RequireAuthorization; buyer from `sub`; UserId/UserName/UnitPrice from request body | authenticated JWT → order pipeline / aggregate mutation | Order records & financial integrity, Cardholder data + PII |
| Identity.API OIDC provider endpoints | Login (lockout), external provider challenge/callback, consent, device flow, grants, diagnostics; in-memory client registry incl. shared secret `secret` and RequirePkce=false for webapp | unauthenticated browser → credential store / IdP authorization decisions | identitydb user store, OAuth client credentials, Cardholder data + PII |
| Identity token signing credential | tempkey.jwk committed; developer signing credential; key rotation disabled | repository read → token signing trust root (forge-tokens primitive) | JWT signing key, Order records & financial integrity, Redis basket store, Cardholder data + PII |
| WebApp Blazor Server UI | Interactive circuits (SignalR), BasketState, order-status notification registry fed by bus events; OIDC client saves tokens; token relayed over circuit in HTTP mode | browser user → server-held component state & sessions | Redis basket store, Order records & financial integrity |
| WebApp AI chatbot with function tools | IChatClient (Foundry/Ollama) plus tools GetUserInfo/SearchCatalog/AddToCart/GetCartContents guarded only by a system prompt | untrusted chat text → LLM tool execution with the signed-in user's privileges | Redis basket store, Cardholder data + PII |
| WebApp outbound clients w/ token relay | Typed HTTP/gRPC clients forwarding user bearer tokens to catalog/ordering/basket | authenticated user token forwarded cross-service | Order records & financial integrity, Redis basket store |
| Mobile BFF YARP reverse proxy | External HTTP endpoints routing /catalog-api, /api/orders, /identity to internal services, gated only on an api-version query parameter | untrusted mobile/network client → internal APIs (authorization decided by each backend) | Catalog data integrity, Order records & financial integrity, identitydb user store |
| RabbitMQ event bus ingress + handlers | Unsigned JSON events deserialized by type-name map into handlers in every service; ack-always, no dead-letter queue | internal AMQP → all service pipelines (broker access = event forgery) | Event bus message authenticity, Order records & financial integrity, Redis basket store, Webhook subscription data |
| Background processors | OrderProcessor grace-period scheduler auto-confirms orders; PaymentProcessor simulates payment outcomes from an env toggle | process env + DB contents → automatic state-transition publishing | Order records & financial integrity, Event bus message authenticity |
| Webhooks.API subscription API + sender | Authenticated users register arbitrary DestUrl (same-origin probe at grant time only); sender POSTs event JSON + token header from inside the network | authenticated user → arbitrary outbound HTTP POST from cluster (SSRF) | Webhook subscription data, Service availability, Process/tenant integrity of services |
| WebhookClient receiver endpoints | OPTIONS /check + POST /webhook-received; ValidateToken default false; token and expected token logged verbatim | unauthenticated external senders → WebhookClient data store/UI | Webhook subscription data |
| eShop.ServiceDefaults shared runtime | JWT bearer defaults (RequireHttpsMetadata=false, ValidateAudience=false at HEAD), resilience, OpenAPI defaults applied to all 8 services | shared library → fleet-wide authentication posture | Process/tenant integrity of services, Order records & financial integrity |
| Aspire AppHost + dev config fallbacks | Topology, injected connection strings, forwarded-header trust, ESHOP_USE_HTTP_ENDPOINTS mode; checked-in weak fallbacks (postgres `yourWeak(!)Password`, amqp://localhost guest/guest) | dev orchestrator / config files → production-shape topology and secrets | identitydb user store, Redis basket store, Event bus message authenticity, Process/tenant integrity of services |
| MAUI ClientApp device client | Mobile HTTP + gRPC to the BFF; local token cache; DEBUG TLS trust overrides; cleartext-traffic flag | untrusted mobile device → BFF; on-device token cache | OAuth client credentials |
| CI/CD + supply chain | GitHub Actions pull_request builds incl. full-stack e2e with demo creds; npm/NuGet feeds; curl\|sh install reference templates; legacy ACR scripts passing a PAT on the command line | pull-request source → CI runner; registries → developer machines | Downstream-embedder security posture, OAuth client credentials |
| OpenAPI/Scalar/health metadata | Anonymous OpenAPI documents, Scalar UI, and health endpoints on every service | unauthenticated HTTP → route/schema enumeration | Catalog data integrity |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Complete authentication bypass — minting arbitrary valid JWTs for any user — via the publicly committed IdentityServer signing key (tempkey.jwk) and shared client secret `secret` | remote_unauth | Identity token signing credential, Identity.API OIDC provider endpoints | JWT signing key, identitydb user store, Order records & financial integrity, Cardholder data + PII | critical | almost_certain | unmitigated | none | |
| T2 | Account and infrastructure takeover using publicly documented default credentials (demo users alice/bob `Pass123$`, postgres superuser `yourWeak(!)Password`, guest/guest RabbitMQ fallback, static webhook token) | remote_unauth | Aspire AppHost + dev config fallbacks, Identity.API OIDC provider endpoints, CI/CD + supply chain | identitydb user store, Event bus message authenticity, Webhook subscription data | critical | almost_certain | unmitigated | none | |
| T3 | Mass exposure of payment-card data (PAN, CVV) and personal information via card storage in databases and card/address claims embedded in every access token | adjacent_network | Ordering.API orders API, Identity.API OIDC provider endpoints, Aspire AppHost + dev config fallbacks | Cardholder data + PII | critical | likely | partially_mitigated | PAN masked before persistence and request-body logging dropped | 0ace928 |
| T4 | Unauthorized tampering with product data (prices, names, pictures) via unauthenticated catalog mutation endpoints, poisoning orders and downstream price-change events | remote_unauth | Catalog.API anonymous item CRUD, Mobile BFF YARP reverse proxy | Catalog data integrity, Order records & financial integrity | high | almost_certain | unmitigated | none | 50dd0d4 |
| T5 | Purchase of goods at attacker-chosen prices or under another user's identity via client-controlled UnitPrice/UserId/UserName fields in order creation | remote_auth | Ordering.API orders API | Order records & financial integrity | high | likely | unmitigated | none | |
| T6 | Reading, cancelling, or shipping other users' orders via unscoped order identifiers (broken object-level authorization) | remote_auth | Ordering.API orders API | Order records & financial integrity | high | likely | unmitigated | route-group RequireAuthorization (authentication only, no object-level checks) | 50dd0d4 |
| T7 | Server-side request forgery into the internal network — including exfiltration of webhook tokens to attacker-chosen URLs — via user-registered webhook destination URLs | remote_auth | Webhooks.API subscription API + sender | Webhook subscription data, Process/tenant integrity of services | high | likely | unmitigated | grant-time reachability probe with same-origin check (send-time unchecked) | |
| T8 | Cross-service token substitution and transport downgrade via fleet-wide JWT validation defaults (audience validation disabled at HEAD, RequireHttpsMetadata=false, auth silently disabled when the Identity config section is absent) | remote_auth | eShop.ServiceDefaults shared runtime, Basket.API gRPC basket service, Ordering.API orders API, Webhooks.API subscription API + sender | Order records & financial integrity, Redis basket store | high | likely | unmitigated | none | f4a7e56, 6b18dda |
| T9 | Interception of passwords, tokens, and card data via plaintext HTTP topology (ESHOP_USE_HTTP_ENDPOINTS) and DEBUG TLS-trust bypasses in shared auth, the Blazor WebApp circuit, and the MAUI client | adjacent_network | MAUI ClientApp device client, Aspire AppHost + dev config fallbacks, WebApp outbound clients w/ token relay, Mobile BFF YARP reverse proxy, WebApp Blazor Server UI | OAuth client credentials, Cardholder data + PII | high | possible | partially_mitigated | TLS-bypass code gated on DEBUG builds | 909ee34 |
| T10 | Authorization-code interception and token leakage via OIDC client misconfiguration (PKCE disabled for webapp, implicit Swagger clients with browser-exposed tokens, env-driven redirect targets) | remote_unauth | Identity.API OIDC provider endpoints, WebApp Blazor Server UI | OAuth client credentials, identitydb user store | high | possible | unmitigated | SameSite=Lax cookies | |
| T11 | Manipulation of order lifecycle, stock, payment outcomes, and webhook dispatch by injecting forged or replayed integration events onto the unauthenticated message bus | adjacent_network | RabbitMQ event bus ingress + handlers, Background processors | Event bus message authenticity, Order records & financial integrity | high | possible | unmitigated | none | |
| T12 | Arbitrary file read on the catalog service host via path handling of attacker-set stored file identifiers | remote_unauth | Catalog.API picture file serving, Catalog.API anonymous item CRUD | Process/tenant integrity of services | high | possible | partially_mitigated | picture reads confined to the Pics directory | 913acea |
| T13 | Backdoored reference code or vulnerable dependencies reaching downstream products via un-audited transitive packages (audit warnings suppressed), network-installed build tooling, and CI-artifact credential leakage | supply_chain | CI/CD + supply chain | Downstream-embedder security posture | high | rare | partially_mitigated | central package pinning + packageSourceMapping | |
| T14 | Unattributable catalog and order-lifecycle changes due to absent audit trails and unauthenticated mutations (repudiation) | remote_auth | Catalog.API anonymous item CRUD, Ordering.API orders API | Order records & financial integrity, Catalog data integrity | medium | likely | unmitigated | none | |
| T15 | Spoofed order-event ingestion and secret disclosure via the WebhookClient receiver's default-off token validation and Information-level token logging | remote_unauth | WebhookClient receiver endpoints | Webhook subscription data | medium | likely | unmitigated | none | |
| T16 | Storefront and order-pipeline unavailability via resource exhaustion of single-instance backing services (Redis, RabbitMQ, one Postgres for 4 DBs) and unthrottled AI-embedding-backed search | remote_unauth | Catalog.API read/search endpoints, Aspire AppHost + dev config fallbacks | Service availability | medium | likely | unmitigated | none | |
| T17 | Manipulation of the signed-in user's session (cart changes, personal-data disclosure) via indirect prompt injection into the AI shopping assistant's function tools, potentially seeded through anonymously writable catalog content | remote_unauth | WebApp AI chatbot with function tools, Catalog.API anonymous item CRUD | Redis basket store, Cardholder data + PII | medium | possible | unmitigated | system-prompt topic guardrail only | |
| T18 | Attack-surface enumeration via anonymous OpenAPI documents, Scalar UI, and health endpoints on every service | remote_unauth | OpenAPI/Scalar/health metadata | Catalog data integrity | low | almost_certain | risk_accepted | none (API documentation is the point of a reference app) | |

## 5. Deprioritized

| threat | reason |
|---|---|
| Memory corruption / RCE via native or unmanaged parsing of untrusted input | asset not present — the codebase is fully managed .NET 10; no native parsers, P/Invoke parsing, or unsafe blocks surfaced in the scan |
| SQL injection against catalog/ordering/webhooks databases | control present — all data access is EF Core parameterized LINQ; no FromSqlRaw/ExecuteSqlRaw/Dapper raw concatenation found in the tree; revisit if raw SQL appears |
| Cross-site request forgery on WebApp/WebhookClient state-changing actions | control present — antiforgery enabled globally in WebApp and used on WebhookClient logout; SameSite=Lax on identity cookies |
| Theft of the MAUI on-device token cache on a rooted/jailbroken device | actor not in threat model — assumes device-level compromise; standard mobile-platform threat outside this application's boundary |
| Malicious upstream maintainer / insider compromise of the dotnet/eShop repository itself | out of scope — addressed by GitHub platform controls and downstream pinning practices |
| Brute-force password guessing on Identity.API login | control present — ASP.NET Identity lockout enabled; residual risk dominated by published default credentials (T2) |
| Denial-of-wallet via runaway Azure OpenAI/Foundry or Ollama spend | folded into T16 (availability/resource exhaustion) |
| Spoofing X-Forwarded-* headers to defeat IP-based decisions | no IP-based authorization found in the tree (forwarded-headers middleware is enabled fleet-wide, but no consumer of client IP for authz was located); revisit if IP-bound logic is added |
| Kubernetes/Azure Container Apps platform-level attacks | out of scope — the deployment target's threat model belongs to the eShopOnAzure production repo; this model covers the application tree |
| Cross-user leak via WebApp Blazor circuit hijacking | no circuit-specific hardening gap found (standard Blazor Server threat); state services are scoped per-user; revisit if custom circuit state is added |

## 6. Open questions

- Is any deployment of this reference application internet-facing (public demo sites, `aspire deploy` to Azure Container Apps with external endpoints)? The scoring of T1, T2, T4, T15, and T18 hinges on reachability; scores assume "exposed if deployed via the in-tree path".
- Who are the intended users in practice — developers and CI only, or sales/demo staff handling real customer data? If real data enters, the card-storage design (T3) stops being a sample concern.
- Is PaymentProcessor intended to be replaced by a real payment service provider? If so, the card-capture flow feeding PAN/CVV into tokens and orderingdb becomes PCI-scoped in earnest.
- Are upstream production controls assumed (WAF, rate limiting, network segmentation, broker ACLs, managed Postgres)? The eShopOnAzure companion repo may impose them; this model credits none of them.
- Why is `ValidateAudience=false` present at HEAD (`913acea`) when commit `6b18dda` "Re-enable audience validation" exists in history? Deliberate policy or a regression on main?
- Is the committed `tempkey.jwk` + AddDeveloperSigningCredential + KeyManagement.Enabled=false arrangement a permanent design choice, or is a managed signing credential planned for any non-local deployment?
- Is the CredScan suppression of `Pass123$` and `yourWeak(!)Password` a formally signed-off risk acceptance, with the expectation that every deployment changes these values?
- What is the risk appetite for demo availability — does DoS of the storefront matter to anyone beyond CI?
- Should downstream-embedder risk (developers copying insecure defaults into production systems) weigh in prioritization, or is the model scoped strictly to this repository as deployed?

## 7. Provenance

- mode: bootstrap
- date: 2026-11-08
- target: /home/niels/github/def-proj/eShop @ 913acea
- inputs: git-log mined (no --vulns supplied); public advisories queried via gh api /repos/dotnet/eShop/security-advisories (none published)
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Move every credential out of the tree (signing key, client secrets, webhook token, DB passwords) into an env/secret store; enable IdentityServer key management and rotation; require password change on seeded accounts | T1,T2 | partial (git history retains prior material) | M |
| Default-deny authorization: RequireAuthorization on every mutating endpoint plus object-level ownership checks (buyer scoping) and principal-attributed audit logging | T4,T6,T14 | partial | M |
| Resolve order economics server-side: derive buyer identity from the JWT and verify item prices against the catalog at order time | T5 | yes | M |
| Stop storing and claiming card data: tokenize via a PSP, strip card/CVV/address claims from tokens, encrypt-at-rest as an interim | T3 | yes | L |
| Fix fleet JWT defaults: ValidateAudience=true with per-service audiences, RequireHttpsMetadata=true outside Development, fail closed when the Identity config section is missing | T8 | yes | S |
| Constrain webhook egress: deny private/link-local ranges at send time, DNS-pin resolved hosts, allowlist destinations, re-check same-origin at send | T7 | yes | M |
| Canonicalize and allowlist stored file identifiers against the storage root before any file resolution (extend the 913acea pattern) | T12 | yes | S |
| Enforce PKCE for all OIDC clients and retire implicit-flow Swagger clients with browser-exposed tokens | T10 | yes | S |
| Default the WebhookClient token validation ON and redact secrets from logs | T15 | yes | S |
| HTTPS-only topology: remove ESHOP_USE_HTTP_ENDPOINTS outside CI and delete DEBUG TLS-bypasses from release builds | T9 | yes | S |
| Authenticate the event bus (per-service broker credentials, signed envelopes) and nack-with-DLQ instead of ack-always | T11 | partial | M |
| Guard the LLM tools: human confirmation for state-changing tool calls, treat retrieved content as untrusted data, least-privilege tool scopes | T17 | partial | S |
| Add rate limiting/quotas on search and AI endpoints; harden or replicate single-instance backing services | T16 | partial | M |
| Re-enable NuGet audit warnings (remove NU1901-1904 NoWarn), pin GitHub Actions to SHAs, replace curl\|sh installer references with pinned artifacts | T13 | partial | S |
