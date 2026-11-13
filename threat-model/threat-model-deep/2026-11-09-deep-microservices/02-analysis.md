# Stage 02: Microservices Threat Analysis

Model `eshop-2026-11-09`, revision `r03`, parent `r02`. Artifact type TM_ANALYSIS, status partial, depth deep. Review scope security; methods none; privacy profiles none. Architectures: microservices, identity-federation, agentic-ai. Source revision 913acea (session context, Git unverified).

Every scenario below is a reading of source code at the stated revision. Nothing was run, sent or deployed, so no scenario is a confirmed runtime finding. Confidence values describe how well the evidence supports a scenario, not how severe it is. No risk is rated because no rubric was supplied.

## Inspection coverage

Status: partial. The ledger now holds 105 processed entries (84 read in full, 21 partial) and 12 unprocessed. Stage 02 read these files itself: the Ordering consumers for GracePeriodConfirmed, StockConfirmed, PaymentSucceeded and PaymentFailed, the SetPaid and SetStockConfirmed command handlers, the Catalog consumers for AwaitingValidation and Paid (IN-095..IN-102), and the 01 model JSON as its input (IN-103). It also read more of CatalogApi.cs (picture endpoint), RouteHandlerBuilderExtensions.cs (now complete) and RabbitMQEventBus.cs (consumer loop), re-read parts of nine files already in the ledger, and listed some directories by name only (IN-105). Everything else is carried from the collection step and stage 01 without a fresh read.
Not read: Identity.API views and controller bodies, the Ordering SetAwaitingValidation and SetStockRejected handlers and repositories, CatalogAI and the Catalog event service, the order processor's selection query, WebApp pages, dependency manifests, most workflow files, tests, and any generated ACA or YARP configuration. Git was not usable, so the revision and working tree are unverified. The repository was discovered by name listings, so unlisted files may exist.

Unmapped boundaries still open: UB1 (gateway and ACA ingress), UB2 (broker credentials), UB3 (model provider path), UB4 (webhook egress), plus topology gaps G1, G2, G3, G12, UB1, UB2, UB3, UB4, G-s02-bff-method-restriction. Stage 02 opened 8 new gaps (G-s02-*), listed below. Evidence E32-E38 is fresh from this stage; E1-E31 and the other evidence records are carried.

No method ran and none was imported. The three scenario families and eight boundary checks were applied as named lenses with a null method reference.

## What this stage produced

30 threats (11 evidenced weaknesses, meaning the code behavior is observed, and 19 design hypotheses), 4 attack trees, 7 conditional attack paths, 3 new controls that record protective observations, 17 controls in all, 8 new gaps and 7 new evidence records. 18 change declarations from r02 are preserved in an attachment; the `changes` array lists what differs between r02 and r03.

## Main scenarios

These chains matter most because the code evidence is direct and each one links to others.

1. **Authenticated attacker reaches other customers' orders.** The seeded accounts (E16) give an internet client a valid token. JWT audience and scope are not checked (E6), and the Ordering API has no owner check on read, cancel or ship (E7). Create takes UserId from the body and builds the basket-delete event from it (E38, E20). Whether the gateway forwards the token and whether Ordering is reachable at all are open (G-s01-bff-auth-forwarding, G1, G2). Threats: `tm02:T-seeded-users-known-credentials`, `T-jwt-audience-scopeless-cross-api`, `T-orders-read-any-order`, `T-orders-cancel-ship-any-order`, `T-orders-create-foreign-userid`.
2. **Unauthenticated catalog writes.** Catalog has no authentication at all (E4). The mobile-bff catch-all matches any method as configured (E3), but the effective gateway and ingress are unobserved. Downstream effects are weaker than the scenario list suggests: the price-change consumer is a no-op (E27) and orders take prices from the client (E38). Threats: `T-catalog-unauth-write`, `T-catalog-price-and-event-tampering`, `T-catalog-text-poisoning-embedding`, `T-catalog-picture-filename-read`.
3. **Webhooks as a request relay and a data leak.** With an empty Token the grant handshake passes for any host that answers OPTIONS with 2xx and no header (E37), which is new in this stage. Deliveries go to all subscribers regardless of order owner (E29). Threats: `T-webhooks-ssrf-empty-token-grant`, `T-webhooks-fanout-cross-user`, `T-webhook-token-logged-and-sample-receiver-open`.
4. **Unsigned events on a shared broker.** Ordering consumers act on OrderId alone (E32); Catalog removes stock on any Paid event without checking an order or event id (E33); the consumer acknowledges every message, including failures, and a body containing a fixed string forces a failure (E34). Broker access is an assumed prerequisite. Threats: `T-bus-forged-order-lifecycle-events`, `T-bus-forged-paid-stock-and-notifications`, `T-bus-forged-orderstarted-basket-delete`, `T-bus-ack-on-failure-message-loss`.
5. **Retry that reports success for a failed order.** The request id survives a failed first attempt and the create route answers 200 whether or not the command succeeded (E9, E38). Threat: `T-orders-request-id-consumed-failure-reported-ok`.

## Threat register

Columns: type (EW evidenced weakness, DH design hypothesis), confidence, and the open gaps that would decide the scenario.

| ID | Type | Conf. | Scenario (first sentence) | Open gaps |
| --- | --- | --- | --- | --- |
| `tm02:T-catalog-unauth-write` | EW | medium | Catalog.API registers no authentication and maps PUT items, PUT items/{id}, POST items and DELETE items/{id} without RequireAuthorization. | G1, G2, UB1, G4, G-s02-bff-method-restriction |
| `tm02:T-catalog-price-and-event-tampering` | DH | low | Using the unauthenticated update route, a caller changes an item Price. | G-s01-event-handlers, GAP-invariants, G1, G2 |
| `tm02:T-catalog-text-poisoning-embedding` | DH | low | A caller who can write catalog text (tm02:T-catalog-unauth-write) sets descriptions or names. | G9, G1, G2, UB3 |
| `tm02:T-chat-indirect-injection-addtocart` | DH | low | When a chat model is configured, SearchCatalog returns catalog descriptions to the model. | UB3, G-s02-chat-output-handling, G1, G2 |
| `tm02:T-chat-claims-pii-disclosure` | DH | low | The GetUserInfo tool returns name, address, email and phone from the signed-in user's claims to the model. | UB3, G-s02-chat-output-handling |
| `tm02:T-catalog-picture-filename-read` | DH | low | PictureFileName is client-writable through the update and create routes and is passed to a PhysicalFileProvider rooted at Pics. | G-s02-pics-provider, G1, G2 |
| `tm02:T-orders-read-any-order` | EW | medium | Any caller holding a token the Ordering service accepts calls GET api/orders/{orderId} with another customer's integer id. | G-s01-bff-auth-forwarding, GAP-invariants, G1, G2, G-s02-account-provisioning |
| `tm02:T-orders-cancel-ship-any-order` | EW | medium | Any authenticated caller sends PUT cancel or PUT ship with another order's number. | GAP-invariants, G-s01-bff-auth-forwarding, G1, G2 |
| `tm02:T-orders-create-foreign-userid` | EW | medium | POST api/orders takes UserId, UserName and Buyer from the body. | GAP-invariants, G-s01-bff-auth-forwarding, G1, G2 |
| `tm02:T-orders-client-supplied-item-prices` | EW | medium | Order creation adds items using the unit price, discount and name from the request body with no catalog lookup. | GAP-invariants, G1, G2 |
| `tm02:T-orders-request-id-consumed-failure-reported-ok` | EW | medium | Order create is wrapped in an IdentifiedCommand keyed by x-requestid. | G8, GAP-transactions |
| `tm02:T-orders-state-change-unattributed` | DH | low | Cancel, ship and create log the command and request id but no calling principal, and the ClientRequest row holds no user. | G-s01-log-sinks, GAP-hop-principals |
| `tm02:T-jwt-audience-scopeless-cross-api` | EW | medium | Basket, Ordering and Webhooks share one JWT configuration with ValidateAudience false and no scope or role policy. | G4, G5 |
| `tm02:T-client-registry-secrets-no-pkce` | DH | low | The webapp, webhooksclient and one more confidential registration share one literal sample secret, and webapp does not require PKCE. | G10, G5 |
| `tm02:T-swagger-implicit-token-exposure` | DH | low | Three implicit-flow clients (basket, ordering and webhooks Swagger UI) return access tokens to the browser (AllowAccessTokensViaBrowser). | G5, G10 |
| `tm02:T-developer-signing-key` | DH | low | Identity.API runs with AddDeveloperSigningCredential and key management disabled, both commented as not for production. | G-s02-signing-key-storage, G3 |
| `tm02:T-seeded-users-known-credentials` | EW | medium | Identity.API creates users alice and bob with one sample password at every startup, in any environment, with profile data and card details. | G-s02-account-provisioning, G10 |
| `tm02:T-webhooks-ssrf-empty-token-grant` | DH | medium | An authenticated caller registers a webhook with Url and GrantUrl pointing at an internal host and port and leaves Token empty. | UB4, G1, G-s01-log-sinks |
| `tm02:T-webhooks-fanout-cross-user` | EW | medium | Webhooks.API sends every Paid and Shipped event to all subscriptions of that type with no owner filter. | G1, UB4 |
| `tm02:T-webhook-token-logged-and-sample-receiver-open` | EW | medium | The grant check logs the caller's token, the token received and the token expected, and WebhookClient logs the received and expected tokens. | G-s01-log-sinks, G1 |
| `tm02:T-bus-forged-order-lifecycle-events` | DH | medium | Any holder of the shared broker credential publishes GracePeriodConfirmed, OrderStockConfirmed and OrderPaymentSucceeded with a chosen OrderId. | UB2, G3, G-s01-event-handlers, G-s02-consumer-semantics |
| `tm02:T-bus-forged-paid-stock-and-notifications` | DH | medium | A forged OrderStatusChangedToPaid event with chosen ProductIds and Units makes Catalog remove that stock for orders that do not exist, and a replayed genuine Paid event removes stock again because no event id or order check is made. | UB2, G3, G-s02-consumer-semantics |
| `tm02:T-bus-forged-orderstarted-basket-delete` | DH | low | A forged OrderStartedIntegrationEvent naming a UserId makes Basket.API delete that user's basket. | UB2, G3 |
| `tm02:T-bus-ack-on-failure-message-loss` | EW | medium | The consumer acknowledges every message, including after an exception, with no retry or dead-letter path. | G-s01-retry-recovery, G-s02-consumer-semantics, GAP-transactions |
| `tm02:T-sensitive-data-in-logs-traces-card` | DH | low | Event bodies are written to the error log and attached to every receive span; handlers log whole events and commands; the create route logs IdentifiedCommand<CreateOrderCommand> with {@Command}, and CreateOrderCommand carries CardSecurityNumber, holder name and expiry. | G-s01-log-sinks, G-s01-card-schema |
| `tm02:T-forwarded-headers-host-trust` | DH | low | ASPNETCORE_FORWARDEDHEADERS_ENABLED is set on every project and AllowedHosts is * on several. | G12 |
| `tm02:T-ci-and-image-supply-chain` | DH | low | Workflows use tag-pinned actions (checkout v4, setup-dotnet v3/v4, setup-node v4, upload-artifact v4) and pr-validation.yml has no permissions block. | G-s02-ci-defaults, GAP-dependencies |
| `tm02:T-shared-postgres-credential-blast-radius` | DH | low | Four databases live on one Postgres server, and Aspire injects database credentials into catalog, identity, ordering, webhooks and order-processor. | G3 |
| `tm02:T-operator-control-plane-authority` | DH | low | The README says an operator deploys with local Azure credentials and that aspire destroy removes the whole resource group. | G-s01-control-owner, GAP-hop-principals |
| `tm02:T-simulated-payment-marks-orders-paid` | DH | low | PaymentProcessor turns OrderStatusChangedToStockConfirmed into OrderPaymentSucceeded from a configuration flag that is true in appsettings, with no gateway. | GAP-invariants, GAP-transactions |

Each threat record also carries its objective, actor assumptions, prerequisites, affected records, evidence and a confidence rationale stating what argues against it. Read the JSON for those fields.

## Protective counterevidence

These observations reduce or bound scenarios above. None was tested.

- `C-jwt-validation`: Resource services validate JWT issuer, signature and lifetime using the shared ServiceDefaults configuration. Limits: Implementation read only. Audience validation is disabled, no scope or role policy exists, and if the Identity section is absent authentication is not registered. Effectiveness not tested.
- `C-ordering-authn`: All order routes require an authenticated caller. Limits: Authentication only: no ownership filter on by-id read, cancel or ship; create takes the owner from the body. Not tested.
- `C-basket-sub-keying`: Basket keys derive from the token subject only and the message carries no buyer id; Update and Delete reject an empty subject. Limits: GetBasket is anonymous; depends on authentication being registered. Not tested.
- `C-webhook-owner-scope`: Webhook list, get and delete filter by the caller's UserId. Limits: Does not cover event fan-out, which has no owner predicate (E29). Not tested.
- `C-webhook-grant-handshake`: Subscription registration requires Url and GrantUrl to share scheme, host and port and the GrantUrl host to echo a token. Limits: Proves control of the host the caller named, not that the host is a safe destination; no address block-list, redirect policy or timeout seen. Not tested.
- `C-request-idempotency`: Order create runs through an IdentifiedCommand keyed by x-requestid; a repeated id returns a canned success. Limits: Id is consumed even on failure and is not bound to user or payload. Not tested.
- `C-order-state-guards`: The Order aggregate permits status changes only along the guarded paths (ship only from Paid; cancel not from Paid or Shipped). Limits: Guards are in the domain model; callers of the transitions and event handlers are partly unread. Not tested.
- `C-order-validators`: FluentValidation checks required address and card fields, card number and security number length, expiry and non-empty items on create; non-empty OrderNumber on cancel and ship. Limits: No semantic checks on ownership or price; validator pipeline wiring not read. Not tested.
- `C-card-masking`: The create route masks the card number to its last 4 before the command; the security number has no mapped database column in the entity configuration read. Limits: The security number still travels through the request, command, domain event and logging behaviors; the migration snapshot and log sinks were not read. Not tested.
- `C-transactional-publish`: Integration events are published only after the database transaction commits, using a transaction id. Limits: Outbox storage and retry were not read; commit-then-publish failure window not assessed.
- `C-maui-pkce`: The maui client registration requires PKCE and refresh tokens. Limits: The webapp registration does not require PKCE; the app also ships a secret constant. Not tested.
- `C-identity-csrf-redirect`: Identity.API posts use antiforgery tokens and login flows check return URLs with IsLocalUrl and IsValidReturnUrl. Limits: Seen by grep only; controller bodies and views unread. Not tested.
- `C-health-dev-only`: /health and /alive are mapped only in the Development environment. Limits: Deployed environment name not observed; AppHost health checks depend on it. Not tested.
- `C-webapp-hsts`: WebApp production branch adds the exception handler and HSTS. Limits: Deployed environment not observed; Identity.API and gateway headers unread (G10).
- `tm02:C-pics-provider-root`: Catalog picture reads go through a keyed PhysicalFileProvider rooted at ContentRoot/Pics, so the endpoint does not open arbitrary paths itself. Limits: Confinement depends on the provider's handling of odd names, which was not tested; the commit message about a confinement fix is a session-context claim. Not tested.
- `tm02:C-bus-unknown-type-drop`: Only routing keys in the statically registered event map are deserialized; unknown keys are logged and dropped. Limits: Limits types, not senders: any publisher can send a registered type. Not tested.
- `tm02:C-ci-no-pr-target`: Workflows run on pull_request and push, and no pull_request_target trigger was found. Limits: Only pr-validation.yml (to line 30) and grep results were read; effective token permissions unknown (G-s02-ci-defaults). Not tested.

Other protective points recorded in coverage: Basket keys come only from the token subject, so there is no direct cross-user basket read or write (scenario family h); health endpoints exist only in Development; the order aggregate rejects out-of-order transitions; the unauthenticated catalog write path is not declared as an external endpoint.

## Attack trees and paths

Trees were checked by hand against the AND/OR rules (reachability, no cycles, leaf-only satisfying sets, root satisfied). No external tool ran. Every path is conditional because at least one leaf rests on an assumption that is still open.

- `tm02:AT-order-takeover`: Goal: an attacker reads, cancels, ships or drives another customer's order. Status partial.
- `tm02:AT-catalog-mutation`: Goal: an unauthenticated caller changes catalog item data, including price and description text. Status complete.
- `tm02:AT-webhook-egress`: Goal: Webhooks.API sends an HTTP request to a host the attacker chose, including an internal one. Status partial.
- `tm02:AT-bus-forgery`: Goal: a publisher with the shared broker credential changes stock, baskets or webhook content through forged events. Status partial.
  - `tm02:AP-order-api-bff` on `tm02:AT-order-takeover`: conditional, leaves o-seed, o-bff, o-get.
  - `tm02:AP-order-api-internal-cancel` on `tm02:AT-order-takeover`: conditional, leaves o-otheraud, o-internal, o-cancel.
  - `tm02:AP-order-bus` on `tm02:AT-order-takeover`: conditional, leaves o-brokercred, o-forge.
  - `tm02:AP-catalog-bff` on `tm02:AT-catalog-mutation`: conditional, leaves c-bff, c-noauth.
  - `tm02:AP-catalog-internal` on `tm02:AT-catalog-mutation`: conditional, leaves c-internal, c-noauth.
  - `tm02:AP-webhook-ssrf` on `tm02:AT-webhook-egress`: conditional, leaves w-token, w-reach, w-register, w-opt2xx.
  - `tm02:AP-bus-paid` on `tm02:AT-bus-forgery`: conditional, leaves b-cred, b-paid.

## New gaps

- `G-s02-pics-provider` (evidence): Whether the keyed PhysicalFileProvider refuses rooted, parent-relative or otherwise odd PictureFileName values is not observed; the commit message 'Confine catalog picture reads to Pics (#1061)' is a session-context claim and Git was not used. Needed: A read of the commit diff with a safe Git invocation, or a test of the endpoint, plus the stored-name handling in CatalogApi create and update.
- `G-s02-consumer-semantics` (evidence): Consumer concurrency, prefetch and whether the 10 second Set* delay stalls other events are not read; SetAwaitingValidation and SetStockRejected handlers, RemoveStock semantics and CatalogIntegrationEventService are unread; no reconciliation for an order left in AwaitingValidation or StockConfirmed after a lost event was observed. Needed: Read of the remaining handlers, Catalog domain RemoveStock, the event service and any reconciler.
- `G-s02-ci-defaults` (evidence): Effective GITHUB_TOKEN default permissions, branch protection and what the unread workflow bodies and dependabot.yml do are not observed; pr-validation.yml was read to line 30 only. Needed: Repository settings, full workflow files and dependabot.yml.
- `G-s02-signing-key-storage` (evidence): Where the IdentityServer developer signing key is persisted, who can read that location and how several Identity.API replicas or a redeploy handle it are not observed; no key file was opened. Needed: Deployment manifest for Identity.API storage and replica count, and a statement from the caller on key handling.
- `G-s02-account-provisioning` (identity): How non-seed users are created (self-registration, admin, none), password policy and lockout are not read (Identity.API Account controller and views unread), so how an attacker obtains an authenticated session other than a seeded account is unknown. Needed: Read of the Account controller, registration views and Identity options.
- `G-s02-chat-output-handling` (evidence): How model output and tool results are rendered in the Blazor page (markup or link handling) and whether any tool call needs user confirmation is not read (WebApp pages unread, UN-005). Needed: Read of the chat components and message rendering.
- `G-s02-risk-rubric` (evidence): No risk rubric, rating inputs or business-impact statement was supplied, so no risk is rated in this stage. Needed: A caller-supplied rubric with its provenance, or caller statements of impact per asset.
- `G-s02-bff-method-restriction` (topology): Whether the generated YARP configuration accepts PUT, POST and DELETE on /api/catalog/{*any} at runtime is still unobserved; stage 02 added no new evidence. Scenario tm02:T-catalog-unauth-write depends on it for internet reach. Needed: Generated YARP configuration or a live request outside this boundary.

G-s01-event-handlers and G-s01-retry-recovery were narrowed with E32-E34 and stay open.

## Checks run and not run

Ran (own Python in isolated mode, against the JSON files in the run folder): parse with duplicate-key and non-finite-number rejection; ID syntax and uniqueness across all collections including tree nodes; reference resolution to the correct record kind for system, threat, control, tree, path, coverage, gap and change records; evidence status and purpose requirements for weaknesses and implemented controls; tree reachability, cycle and operator checks; satisfying-set evaluation per path; a comparison of r03 against r02 by stable ID confirming that every addition and modification is declared exactly once and none is declared without a delta, including nested tree nodes; preservation of r02 evidence, attachments, system collections, inventory IDs and the single run-configuration coverage record; a pattern scan for credential-like text.

Not run: any schema validator (none ships), checks of method or architecture identity against a registry, project execution, network calls, Git, tests, a chunk or byte-equality check (output is one file), and independent verification of any observation.
