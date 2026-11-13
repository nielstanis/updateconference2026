# Stage 03: Microservices Challenge And Consolidate

Model `eshop-2026-11-09`, revision `r04`, parent `r03`. Artifact type TM_REVIEWED_MODEL, status partial, depth deep. Review scope security; methods none; privacy profiles none. Architectures: microservices, identity-federation, agentic-ai. Source revision 913acea (session context; Git unverified).

Every outcome below is a reading of source code. Nothing was run, sent or deployed, so no scenario is a confirmed runtime finding. Confidence describes how well the evidence supports a scenario, not severity. No risk is rated because no rubric was supplied. Reading a file in this stage does not make a threat true or false at runtime.

## Inspection coverage

Status: partial. The ledger holds 120 processed entries (93 read in full, 27 partial) and 12 unprocessed. Stage 03 read the following itself, as fresh reads: 15 new entries (IN-106 to IN-120). They cover the stage 02 handoff and its companion, CatalogAI, the Ordering SetAwaitingValidation and SetStockRejected handlers, the OrderStockRejected consumer, the identified-command validator, the OrderProcessor selection query, the chat message renderer, parts of the OpenAPI setup, and text searches over the source tree. It also re-read, in whole or in part, about twenty files already in the ledger: AppHost, the YARP routes, ServiceDefaults authentication, the Ordering pipeline and API routes, Catalog API, Webhooks API, Identity Program and AccountController (lines 70-135), the broker consumer loop and the OrderProcessor service. Re-reads did not change those entries' extent, except CatalogApi.cs, RabbitMQEventBus.cs and GracePeriodManagerService.cs, which gained extent.

Everything else is carried from the collection step and stages 00 to 02 without a fresh read. The stage 02 JSON was parsed by script; its threat, control, gap, coverage, change, tree and evidence records were read in full, and its system records were checked for IDs and reference kinds only. Not read: Identity.API views and other controller bodies, OrderRepository and BuyerRepository, IntegrationEventLogEF and the event services, WebApp pages, CatalogContextSeed, dependency manifests, most workflow files, tests, generated ACA and YARP configuration. The repository was discovered by name listings, so unlisted files may exist.

Unmapped boundaries and topology gaps still open: G1, G2, G3, G12, UB1, UB2, UB3, UB4, G-s02-bff-method-restriction. Git state is unverified: stage 03 ran one unprotected read-only `git rev-parse` by mistake, did not use its output as evidence, and ran no protected Git form.

## What this stage did

It challenged all 30 stage 02 threats against code, kept the identities, and produced 33 threats in total (12 evidenced weaknesses, 21 design hypotheses). No threat was merged, retired or resolved. Two had confidence lowered from medium to low, five were narrowed, nine had premises or rationale revised, three gained a gap link, and eleven were kept unchanged. Three threats were added: one split out of an existing threat and two found by challenge. One gap was closed (G9), 11 were narrowed and 4 were opened. 13 observations (E39 to E51) and 16 coverage records were added. Controls, trees, paths and system records are carried unchanged because this stage has no editing contract for them.

## Threat outcomes

| Threat | Type | Confidence | Outcome |
| --- | --- | --- | --- |
| `tm02:T-catalog-unauth-write` | EW | medium | Kept. Premise strengthened: no authentication anywhere in Catalog.API and no method, policy or header handling in any gateway route. Internet reach still unobserved. |
| `tm02:T-catalog-price-and-event-tampering` | DH | low | Kept unchanged. Consumer of the price event is still the no-op handler. |
| `tm02:T-catalog-text-poisoning-embedding` | DH | low | Narrowed. Embedding steering needs an opt-in embedding generator; by default the update stores a null embedding. G9 closed. |
| `tm02:T-chat-indirect-injection-addtocart` | DH | low | Kept unchanged. |
| `tm02:T-chat-claims-pii-disclosure` | DH | low | Premise strengthened: model-supplied image URLs are fetched by the browser. Chat is off by default, so confidence stays low. |
| `tm02:T-catalog-picture-filename-read` | DH | low | Kept unchanged. Provider confinement still not observed. |
| `tm02:T-orders-read-any-order` | EW | medium | Kept. No owner check found on re-read; gateway route declared; token forwarding unobserved. |
| `tm02:T-orders-cancel-ship-any-order` | EW | medium | Kept. Failures return 500, so blocked attempts are visible; no owner or role check. Linked to two new threats. |
| `tm02:T-orders-create-foreign-userid` | EW | medium | Kept. No validator or token comparison ties the body UserId to the caller. |
| `tm02:T-orders-client-supplied-item-prices` | EW | medium | Kept unchanged. |
| `tm02:T-orders-request-id-consumed-failure-reported-ok` | EW | medium | Narrowed to create only. The rollback premise is contradicted for exceptions raised in the inner command: the request id commits with the swallowed failure. |
| `tm02:T-orders-state-change-unattributed` | DH | low | Kept unchanged. |
| `tm02:T-jwt-audience-scopeless-cross-api` | EW | medium | Kept. Identity sections are present in Basket, Ordering and Webhooks, so authentication is registered at source level. |
| `tm02:T-client-registry-secrets-no-pkce` | DH | low | Kept. Linked to the new credential rotation gap. |
| `tm02:T-swagger-implicit-token-exposure` | DH | low | Kept at low. The API reference UI that would drive the implicit clients is mapped only in Development. |
| `tm02:T-developer-signing-key` | DH | low | Kept. Linked to the new credential rotation gap. |
| `tm02:T-seeded-users-known-credentials` | EW | medium | Kept. Lockout exists at login but does not limit a correct published password; no registration path found. |
| `tm02:T-webhooks-ssrf-empty-token-grant` | DH | medium to low | Downgraded to low. No declared customer path to webhooks-api. Empty-token pass re-confirmed. |
| `tm02:T-webhooks-fanout-cross-user` | EW | medium to low | Downgraded to low for the same reach reason. Missing owner filter unchanged. |
| `tm02:T-webhook-token-logged-and-sample-receiver-open` | EW | medium | Kept unchanged. |
| `tm02:T-bus-forged-order-lifecycle-events` | DH | medium | Narrowed. A forged GracePeriodConfirmed only skips about a minute; the distinct effects are targeted cancellation and the stock-check bypass. |
| `tm02:T-bus-forged-paid-stock-and-notifications` | DH | medium | Narrowed and split. Stock effect stays; webhook content moved to a new threat. RemoveStock clamps at zero. |
| `tm02:T-bus-forged-orderstarted-basket-delete` | DH | low | Kept unchanged. |
| `tm02:T-bus-ack-on-failure-message-loss` | EW | medium | Narrowed to the later workflow steps. The first step is re-driven by the order processor. |
| `tm02:T-sensitive-data-in-logs-traces-card` | DH | low | Kept at low. One more log site found. |
| `tm02:T-forwarded-headers-host-trust` | DH | low | Kept unchanged. No new counterevidence read. |
| `tm02:T-ci-and-image-supply-chain` | DH | low | Kept unchanged. No new counterevidence read. |
| `tm02:T-shared-postgres-credential-blast-radius` | DH | low | Kept. Linked to the new credential rotation gap. No new counterevidence read. |
| `tm02:T-operator-control-plane-authority` | DH | low | Kept unchanged. No new counterevidence read. |
| `tm02:T-simulated-payment-marks-orders-paid` | DH | low | Kept unchanged. |
| `tm03:T-orders-cancel-ship-retry-reports-success` | EW | medium | New. Cancel or ship that fails reports 500, then a retry with the same request id reports 200. |
| `tm03:T-bus-forged-paid-shipped-webhook-content` | DH | low | New, split from the stock threat. |
| `tm03:T-cancel-races-payment-no-compensation` | DH | low | New. A cancel during the payment step leaves a Cancelled order with a payment outcome and no compensation in the code read. |

EW is an evidenced weakness (code behavior observed) and DH a design hypothesis. Where the table says unchanged, a protective counterexample was sought and none changed the scenario, or no new read was possible (see the counterevidence coverage records, lens `counterevidence:*`).

## Main findings from the challenge

1. **Catalog write path.** A search over all of Catalog.API found no authentication or authorization, AppHost passes it no identity URL, and no gateway route restricts method, policy or headers, including the explicit item routes. The protective counterexample the model hoped for does not exist at source level. Whether the internet can reach it is still the open question (G1, G2, UB1).
2. **Orders.** No validator, token comparison or role check was found on read, cancel, ship or create. Cancel and ship report failures as 500, which is the one visible signal. Authenticated reach through the gateway is declared but token forwarding is unobserved.
3. **Retry behavior differs by operation.** The request id is stored in the same transaction that commits, because the handler swallows the inner failure. Create then answers 200 on the first attempt. Cancel and ship answer 500 first and 200 on a retry with the same id. This split the earlier single retry threat into two.
4. **Webhooks reach.** The empty-token pass in the grant check is confirmed. No customer path to webhooks-api is declared: no external endpoint, no gateway route, no WebApp reference. Both webhook threats dropped to low for that reason.
5. **Broker events.** The order processor re-drives GracePeriodConfirmed for orders still Submitted, so a lost first step recovers. Later steps have no re-driver found. A forged payment success adds little because payment is already simulated as always successful. Repeated delivery is harmless where the aggregate guards state (grace period) and harmful where no guard exists (Catalog stock removal on Paid).
6. **Chat.** Model replies are HTML-encoded, but markdown image syntax becomes an img element with a model-supplied URL and no allow-list. That gives an exfiltration channel if a model follows injected instructions. Chat is off by default and no model was observed.

## Protective counterevidence recorded

No new control records were created because controls are carried unchanged. Protective facts are in the threat rationales and evidence: Identity sections present in three services (E47); login lockout enabled (E49); API reference UI mapped only in Development (E48); embedding generator opt-in (E43); GracePeriodConfirmed re-driver (E51); RemoveStock clamp at zero stock (E42); aggregate state guards (E31, already a control). None was tested.

## Gaps

New open gaps: `G-s03-predecessor-artifact-type` (conversion), `G-s03-tree-assumption-drift`, `G-s03-credential-rotation`, `G-s03-outbox-redelivery`. Closed: `G9`. Narrowed and still open: `G1`, `G2`, `G4`, `G8`, `G-s01-bff-auth-forwarding`, `G-s01-event-handlers`, `G-s01-retry-recovery`, `G-s02-consumer-semantics`, `G-s02-chat-output-handling`, `G-s02-account-provisioning`, `G-s02-bff-method-restriction`. Open gaps in total: 41. Gaps G2, G-s02-bff-method-restriction and UB1 describe one unknown; they were kept separate to preserve history.

## Conflicts, identity and consolidation

No conflicts: no two evidenced alternatives about one route or permission claim were found (coverage `handoff:conflicts`). The `identity_map` is empty by evaluation, not omission (coverage `handoff:identity_map`): nothing was merged, aliased or retired, and no cross-model fragment was imported. Near-duplicate pairs were checked for a counterexample and kept distinct (coverage `consolidation:identity`). One split created a new identity in the `tm03` namespace; the original keeps its ID.

## Changes against r03

The `changes` array declares 72 records of delta against r03: 36 additions and 36 modifications, each once, none retired. Parent declarations are preserved in attachment `ATT-prior-changes-eshop-2026-11-09-r03`. Inventory entries, attachments and scope are envelope data and are not declared as record changes.

## Contract problems and limits

- The stage 02 JSON declares artifact type TM_SYSTEM_MODEL although its content and companion describe TM_ANALYSIS. Stage 03 proceeded at the caller's instruction and recorded the problem in `G-s03-predecessor-artifact-type`. Continuity to a correctly labeled predecessor is not certified.
- Carried trees keep node assumptions that three stage 03 observations contradict or soften. They were not edited (`G-s03-tree-assumption-drift`).
- Four stage 02 threats (forwarded headers, CI supply chain, shared Postgres, operator authority) got no new counterevidence read. Their linked gaps name the unperformed challenge.
- No method ran or was imported. No risk was rated. Treatments and verification belong to later stages. Status stays partial.

## Checks run and not run

Ran (own Python in isolated mode, against the JSON in the run folder): parse with duplicate-key and non-finite-number rejection; ID syntax and uniqueness across all collections including tree nodes; reference resolution to the right record kind for threats, controls, gaps, coverage, trees, paths and changes; evidence rules for weaknesses, hypotheses, implemented controls and closed gaps; open threats linking no closed gap; tree reachability, cycle and operator checks and satisfying-set evaluation (trees untouched); comparison of r04 with r03 by stable ID confirming every addition and modification is declared exactly once and none is declared without a delta; preservation of carried evidence, system records, controls, trees, paths, attachments, inventory IDs and the single run-configuration coverage record; handoff coverage for empty collections; a pattern scan for credential-like text; counterevidence coverage naming every open threat.

Not run: any schema validator (none ships), registry checks of architecture or method identity, chunk or byte-equality checks (one file), project execution, network calls, protected Git, tests, and independent verification of any observation.
