# Stage 00: Scope and evidence (eShop, microservices)

Private review material. Companion JSON: `00-context.json` (artifact TM_CONTEXT, model `eshop-2026-11-09`, revision `r01`, parent none, status partial). This stage prepares scope and evidence. It does not model topology, list vulnerabilities or run any method. The observations below come from reading code and configuration; none is confirmed runtime behavior.

## Inspection coverage

- Evidence was collected earlier, in the evidence-collection step, at revision `913acea`. That revision comes from the session context; Git was not run, so the revision and working-tree state are unverified (G14, G-sel-git). Stage 00 re-read none of the cited project files. It read the evidence bundle and the selection files (`selection.json` partially, `selection.md` in full) as run-folder inputs.
- Carried ledger: 70 project-file entries (IN-001 to IN-070). 53 were read in full and 17 partially (line ranges or grep matches only). The bundle itself is IN-071; the selection files are IN-072 and IN-073.
- Not inspected (UN-001 to UN-013): Identity.API Razor views and controller bodies, Ordering validators, behaviors and repositories, Catalog AI code, webhook fan-out, EventBus abstractions and the integration event log, WebApp Blazor pages, MAUI views, dependency manifests, `dependabot.yml`, Git state, and the generated ACA and YARP configuration (not produced). `tests/`, `e2e/` and build output are excluded by scope.
- Discovery used name listings with head limits, so files outside those listings may exist.
- Unmapped boundaries (open topology gaps): UB1 mobile-bff and ACA ingress, UB2 broker credentials and ACLs, UB3 WebApp to model provider, UB4 Webhooks.API egress.
- Global coverage status is `partial`. File counts say nothing about analytical completeness.

## Run configuration

Mode deep, review scope security, methods none, privacy profiles none (caller decisions). Primary architecture `microservices`. `identity-federation` (boundary B-token-trust) and `agentic-ai` (boundary B-model-tools) are recommended bounded secondaries and are not run here. Architecture identities were not checked against a registry file. `COV-run-configuration` is carried unchanged from selection.

Lineage: this is a new chain (`r01`, parent null). `selection.json` is a carried sibling input, kept in attachment `ATT-selection-r00`, not a parent. No baseline comparison ran and `changes` is empty.

## Scope

In scope: Aspire AppHost topology, Identity.API, Catalog.API, Basket.API, Ordering.API with its domain and infrastructure, OrderProcessor, PaymentProcessor, Webhooks.API, WebhookClient, WebApp with the chatbot, the mobile-bff YARP gateway, the RabbitMQ event bus, ServiceDefaults authentication, the Postgres, Redis and RabbitMQ resources, and bounded MAUI client and CI workflow settings.

Out of scope: tests, e2e, `node_modules`, build output, `wwwroot`, EF migration bodies, `.github/skills/**`, Azure/Foundry/Ollama internals, MAUI platform folders, any deployed instance's runtime behavior, and dependency vulnerability review.

## Evidence carried (E1 to E27)

Twenty-seven bundle records, each with its read extent and limits in the JSON. Three further records note caller or carried decisions: `EV-caller-run-config`, `EV-caller-revision`, `EV-selection-decision`. Evidence that stage 01 should take into account as hypotheses, not findings:

| Area | What the code shows | Evidence |
| --- | --- | --- |
| Catalog writes | PUT/POST/DELETE catalog routes have no authorization; the mobile-bff catch-all `/api/catalog/{*any}` sets no method restriction; price changes publish an event | E3, E4, G2 |
| Ordering authority | Authenticated callers can get any order, cancel or ship by body `OrderNumber`; create takes `UserId` from the body | E7 |
| Token validation | Shared JwtBearer with `ValidateAudience = false`, no scope or role policy; missing `Identity` config disables authentication | E6, G4 |
| Identity client setup | Sample client secrets, `webapp` client without PKCE, implicit-flow Swagger clients, scopes not defined as ApiScopes | E14, E17, E24, G5 |
| Identity host | Developer signing credential, key management off, seeded users with a well-known sample password at every startup | E15, E16 |
| Webhooks | Caller-chosen destination and grant URL, no address restrictions seen; token written to logs on both the sender and receiver side | E11, E13 |
| Event bus | One shared exchange, unsigned JSON events, no visible per-service broker permissions; payment is simulated from a setting | E19, E20 |
| Chatbot | Model-callable tools include user claim disclosure and basket changes; catalog text reaches the model | E18, E4 |
| Edge and operations | Forwarded headers enabled for every project; health endpoints only in Development | E22, E21 |

Protective observations are kept too: Basket keys come from the token subject (E10), webhook list/get/delete are scoped to the user (E12), identity login flows use local-URL checks and anti-forgery tokens (E15), and the README says the Azure deployment is for demonstration (E26).

## Gaps

25 gaps are open. The ones that most change later conclusions:

- G1, G2, UB1: whether Catalog, Ordering and Webhooks are reachable from outside and whether the YARP routes limit methods. Settled by generated ACA and YARP configuration.
- G3, UB2: broker, Postgres and Redis credentials and network policy.
- G4, G5: whether every service has the `Identity` section, and what the undefined scopes do at token issuance.
- GAP-invariants, GAP-hop-principals, GAP-transactions: the caller supplied no ownership rules, per-hop principal descriptions or transaction and retry histories, so stage 01 cannot judge code against stated rules.
- UB3, UB4: model-provider path and webhook egress policy.
- GAP-secure-coding-pack, GAP-dependencies: no technology-specific guidance and no dependency review.

## Attachments

- `ATT-selection-r00`: selection output kept as source (boundary owners, provisional sketch, selection coverage and gaps). Not typed records in this model.
- `ATT-bundle-redaction-log`: the five placeholders in the bundle (sample client secret, user password, card security numbers, webhook token, database password) and their locations. Stage 00 opened no secret files and added no redactions.

## Handoff to stage 01

`system`, `threats`, `treatments` and `verification` carry `not_assessed` coverage records; stage 01 builds the system model from this envelope. `methods` is empty because none was requested or run.

## Checks run on this output

Parsed with duplicate-key and non-finite-number rejection; checked record ID uniqueness across evidence, coverage, gaps, inventories and attachments; checked that gap evidence references resolve to evidence records and that required fields match the stage contract. No schema validator exists in the library, so contract validity beyond these checks is not established.
