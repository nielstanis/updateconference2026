# Stage 04: Treatment And Validation (microservices)

Model `eshop-2026-11-09`, revision `r05`, parent `r04`. Artifact type TM_TREATMENT_PLAN, status partial, depth deep. Review scope security; methods none; privacy profiles none. Architectures: microservices, identity-federation, agentic-ai. Source revision 913acea (session context; Git unverified).

Every treatment below is a proposal. None is implemented, accepted or approved, and no owner, date, rating or test result exists. Planned verification has not been run. The threats are readings of source code, not confirmed runtime findings.

## Inspection coverage

Status: partial. The ledger holds 122 processed entries (94 read in full, 28 partial) and 12 unprocessed. Stage 04 read no project source files. It read only the stage 03 handoff: `03-reviewed-model.json` (IN-121, partial: parsed in full by script, with threat, control, gap, dependency, change, attachment and handoff-coverage records listed and read, and other system and evidence records checked by ID and reference only) and `03-reviewed-model.md` (IN-122, read in full). All project coverage is carried from the collection step and stages 00 to 03 without a fresh read.

Omissions that bear on these treatments: Identity.API views and most controller bodies, repositories and event services, generated gateway and container platform configuration, dependency manifests, most workflow files, and tests. The repository was discovered by name listings, so unlisted files may exist. Open topology gaps: G1, G2, G3, G12, UB1, UB2, UB3, UB4, G-s02-bff-method-restriction. Git state is unverified: stage 03 ran one unprotected `git rev-parse` by mistake and did not use its output; stage 04 ran no Git.

## What this stage did

It proposed 22 treatments, 30 planned verification records, 22 requirements, 33 unrated risk records and 5 proposed decisions, opened 2 gaps, and added 7 coverage records. Threats, controls, attack trees, attack paths, evidence and system records are carried unchanged.

## Threat disposition

All 33 threats stay open. Each has at least one proposed treatment and an unrated risk record. None was resolved, retired, merged or accepted.

| Threat | Confidence | Treatments |
| --- | --- | --- |
| `tm02:T-catalog-unauth-write` | medium | catalog-write-authz, gateway-method-allowlist |
| `tm02:T-catalog-price-and-event-tampering` | low | catalog-write-authz, catalog-change-integrity |
| `tm02:T-catalog-text-poisoning-embedding` | low | catalog-write-authz, catalog-change-integrity |
| `tm02:T-chat-indirect-injection-addtocart` | low | chat-tool-minimization |
| `tm02:T-chat-claims-pii-disclosure` | low | chat-tool-minimization |
| `tm02:T-catalog-picture-filename-read` | low | gateway-method-allowlist, picture-name-confinement |
| `tm02:T-orders-read-any-order` | medium | orders-ownership |
| `tm02:T-orders-cancel-ship-any-order` | medium | orders-ownership |
| `tm02:T-orders-create-foreign-userid` | medium | orders-ownership |
| `tm02:T-orders-client-supplied-item-prices` | medium | orders-server-pricing |
| `tm02:T-orders-request-id-consumed-failure-reported-ok` | medium | idempotent-business-outcome |
| `tm02:T-orders-state-change-unattributed` | low | orders-ownership, sensitive-logging-and-attribution |
| `tm02:T-jwt-audience-scopeless-cross-api` | medium | token-audience-and-scope |
| `tm02:T-client-registry-secrets-no-pkce` | low | client-registry-hardening |
| `tm02:T-swagger-implicit-token-exposure` | low | client-registry-hardening |
| `tm02:T-developer-signing-key` | low | signing-key-and-service-credentials |
| `tm02:T-seeded-users-known-credentials` | medium | seed-user-gating |
| `tm02:T-webhooks-ssrf-empty-token-grant` | low | webhook-egress-controls |
| `tm02:T-webhooks-fanout-cross-user` | low | webhook-fanout-and-token-handling |
| `tm02:T-webhook-token-logged-and-sample-receiver-open` | medium | webhook-fanout-and-token-handling, sensitive-logging-and-attribution |
| `tm02:T-bus-forged-order-lifecycle-events` | medium | broker-identity-and-validation |
| `tm02:T-bus-forged-paid-stock-and-notifications` | medium | consumer-idempotence-and-dead-letter, broker-identity-and-validation |
| `tm02:T-bus-forged-orderstarted-basket-delete` | low | broker-identity-and-validation |
| `tm02:T-bus-ack-on-failure-message-loss` | medium | saga-reconciliation, consumer-idempotence-and-dead-letter |
| `tm02:T-sensitive-data-in-logs-traces-card` | low | sensitive-logging-and-attribution |
| `tm02:T-forwarded-headers-host-trust` | low | forwarded-header-trust |
| `tm02:T-ci-and-image-supply-chain` | low | ci-permissions-and-pins |
| `tm02:T-shared-postgres-credential-blast-radius` | low | signing-key-and-service-credentials |
| `tm02:T-operator-control-plane-authority` | low | operator-control-plane |
| `tm02:T-simulated-payment-marks-orders-paid` | low | saga-reconciliation, payment-simulation-gate |
| `tm03:T-orders-cancel-ship-retry-reports-success` | medium | idempotent-business-outcome |
| `tm03:T-bus-forged-paid-shipped-webhook-content` | low | webhook-fanout-and-token-handling, broker-identity-and-validation |
| `tm03:T-cancel-races-payment-no-compensation` | low | saga-reconciliation |

## Proposed treatments

Outcomes are architectural. Technology-specific prescriptions need a resolved secure-coding pack; none was supplied, so each dependent treatment lists an unavailable pack dependency linked to the open gap `GAP-secure-coding-pack` and its prescriptions are unverified.

### `tm04:TR-catalog-write-authz`

Threats: `tm02:T-catalog-unauth-write`, `tm02:T-catalog-price-and-event-tampering`, `tm02:T-catalog-text-poisoning-embedding`.

Require an authenticated caller holding an explicit catalog-management role or scope for create, update and delete in Catalog.API itself, with deny by default for any future write route, so the service does not rely on the gateway or network position to protect writes. Proposed only; not implemented.

Alternatives:
- Keep Catalog internal-only (no external ingress, network policy admitting only named callers) and move catalog administration into a separate admin-facing service that holds the write authority.
- Remove the write routes from Catalog.API and run catalog changes through an operator-run import job.

Tradeoffs:
- Adds an identity dependency to Catalog (it has none today) and needs a catalog administrator role to be provisioned.
- Anonymous sample tooling and any caller that writes without a token will break.
- A network-only alternative does not stop a compromised internal peer.

Verification: `tm04:VF-catalog-write-matrix`. Open gaps: G1, G2, UB1, G4, GAP-secure-coding-pack.

### `tm04:TR-gateway-method-allowlist`

Threats: `tm02:T-catalog-unauth-write`, `tm02:T-catalog-picture-filename-read`.

At the gateway, expose only the route and method set each client needs: an explicit allow-list of read methods for Catalog, deny write methods and unmatched paths, and attach no catch-all that forwards write verbs to Catalog. Treat this as a second layer, not a replacement for service-level authorization. Proposed only; not implemented.

Alternatives:
- Drop the catalog write route mapping from the mobile gateway entirely and give administrators a separate path.
- Place a web application firewall rule set in front of the gateway for method and path filtering.

Tradeoffs:
- Policy is duplicated between gateway and service and must be kept in step as the API grows.
- A gateway allow-list does not protect the direct internal route, so it does not remove the need for the Catalog treatment.

Verification: `tm04:VF-gateway-vs-direct`, `tm04:VF-edge-reach`. Open gaps: G2, UB1, G-s02-bff-method-restriction, G-s01-bff-auth-forwarding, GAP-secure-coding-pack.

### `tm04:TR-picture-name-confinement`

Threats: `tm02:T-catalog-picture-filename-read`.

Resolve picture requests from a server-side lookup (item id to stored picture) instead of caller-supplied file names, keep reads confined to the picture store root, and reject names that contain path separators or traversal sequences before they reach the file layer. Proposed only; not implemented.

Alternatives:
- Serve pictures from an object store or static host with no application file endpoint.
- Keep the current provider-rooted read and add input rejection only.

Tradeoffs:
- A lookup needs the item row on every picture read (a cost) or a cache.
- Existing clients that request by file name need a migration path.

Verification: `tm04:VF-picture-confinement`. Open gaps: G-s02-pics-provider, G1, G2, GAP-secure-coding-pack.

### `tm04:TR-catalog-change-integrity`

Threats: `tm02:T-catalog-price-and-event-tampering`, `tm02:T-catalog-text-poisoning-embedding`.

Bound and validate price, stock and text fields on write, record who changed which item and what changed in an audit event, and treat catalog text as untrusted data wherever it is consumed (embedding generation, chat context, storefront rendering). Proposed only; not implemented.

Alternatives:
- Put catalog edits behind an approval step that publishes only reviewed versions.
- Rate-limit price changes and alert on large moves without blocking them.

Tradeoffs:
- Approval workflows slow routine administration.
- Alerting needs thresholds that the business has not supplied (GAP-invariants).

Verification: `tm04:VF-catalog-audit`. Open gaps: GAP-invariants, G-s01-event-handlers, GAP-secure-coding-pack.

### `tm04:TR-orders-ownership`

Threats: `tm02:T-orders-read-any-order`, `tm02:T-orders-cancel-ship-any-order`, `tm02:T-orders-create-foreign-userid`, `tm02:T-orders-state-change-unattributed`.

In Ordering, derive the caller from the token subject, enforce per-order ownership on get, cancel and ship, restrict ship (fulfilment) to a back-office role or service principal, allow cancel only for the owner or a support role, and bind the order UserId to the token subject on the server while rejecting a conflicting body value. Return one not-found shape for foreign orders. Proposed only; not implemented.

Alternatives:
- Apply the owner predicate inside the repository query so foreign orders are unreachable from any handler.
- Make ship an internal service-to-service operation with no customer-facing route.

Tradeoffs:
- The role model for support and fulfilment is not defined (GAP-invariants, GAP-hop-principals).
- A uniform not-found hides enumeration but makes support diagnosis harder.
- Gateway token forwarding is unobserved (G-s01-bff-auth-forwarding), so the identity available to Ordering must be confirmed first.

Verification: `tm04:VF-orders-owner-vs-nonowner`, `tm04:VF-orders-userid-binding`, `tm04:VF-orders-ship-role`. Open gaps: GAP-invariants, G-s01-bff-auth-forwarding, GAP-hop-principals, GAP-secure-coding-pack.

### `tm04:TR-orders-server-pricing`

Threats: `tm02:T-orders-client-supplied-item-prices`.

Compute item prices and totals on the server from Catalog (or a server-held basket snapshot) at order creation and reject or override any client-supplied price. Proposed only; not implemented.

Alternatives:
- Sign the basket snapshot at checkout and verify the signature in Ordering.
- Accept client prices but compare to Catalog and reject on mismatch.

Tradeoffs:
- An extra Catalog call, or a snapshot that can go stale between basket and checkout.
- The intended price-change policy during checkout is not supplied (GAP-invariants).

Verification: `tm04:VF-orders-price-mismatch`. Open gaps: GAP-invariants, GAP-secure-coding-pack.

### `tm04:TR-idempotent-business-outcome`

Threats: `tm02:T-orders-request-id-consumed-failure-reported-ok`, `tm03:T-orders-cancel-ship-retry-reports-success`.

Keep one durable business outcome per transaction intent: store the request id with the user, a payload fingerprint and the final outcome, return the stored outcome (failure included) on repeat, and never answer a repeat with a canned success. Proposed only; not implemented.

Alternatives:
- Do not consume the request id on failure, so a retry re-runs the command (acceptable only where the command is safe to re-run).
- Reject repeats of an id that arrive with a different payload or user.

Tradeoffs:
- Stored outcomes add storage and a retention decision.
- Re-running on failure risks duplicate effects where downstream work is not idempotent.

Verification: `tm04:VF-idempotency-replay`. Open gaps: G8, GAP-transactions, GAP-secure-coding-pack.

### `tm04:TR-saga-reconciliation`

Threats: `tm03:T-cancel-races-payment-no-compensation`, `tm02:T-simulated-payment-marks-orders-paid`, `tm02:T-bus-ack-on-failure-message-loss`.

Give each order a durable pending state and an explicit reconciliation decision for unknown outcomes: define the compensating action (payment void or refund, stock release) when cancel and payment cross, add a re-driver for the later workflow steps, and compare bounded automatic retry with delayed manual review for each step. Proposed only; not implemented.

Alternatives:
- Reject cancel once the order reaches StockConfirmed, which removes the race at the cost of customer flexibility.
- Replace the sequential events with an orchestrated process that owns the transaction outcome.

Tradeoffs:
- Compensation logic adds code paths that need their own failure handling.
- Automatic retry improves availability but can repeat effects; delayed review keeps state safe but needs an operator procedure.
- No business invariant was supplied for the order lifecycle (GAP-invariants, GAP-transactions).

Verification: `tm04:VF-saga-cancel-payment-race`, `tm04:VF-consumer-failure-redelivery`. Open gaps: GAP-transactions, G-s02-consumer-semantics, G-s03-outbox-redelivery, G-s01-retry-recovery.

### `tm04:TR-consumer-idempotence-and-dead-letter`

Threats: `tm02:T-bus-ack-on-failure-message-loss`, `tm02:T-bus-forged-paid-stock-and-notifications`.

Consumers acknowledge only after success, route repeated failures to a dead-letter destination with an alert instead of acknowledging and dropping, and make state-changing consumers idempotent by event id (stock removal on payment must not repeat on redelivery). Proposed only; not implemented.

Alternatives:
- Keep acknowledge-on-failure but write a durable failure record that an operator replays.
- Move to a transactional inbox so each event is applied once.

Tradeoffs:
- Dead-letter handling needs an owner and a replay procedure.
- Requeueing without a limit creates poison-message loops.

Verification: `tm04:VF-stock-removal-redelivery`. Open gaps: G-s02-consumer-semantics, G-s03-outbox-redelivery, G-s01-event-handlers, GAP-secure-coding-pack.

### `tm04:TR-token-audience-and-scope`

Threats: `tm02:T-jwt-audience-scopeless-cross-api`.

Require each API to accept only tokens issued for its own audience and to enforce an operation-level scope or role, keep user tokens and client-credential tokens distinct, and reject a token minted for another API. Proposed only; not implemented.

Alternatives:
- Use per-downstream token exchange so each hop receives a token narrowed to that hop.
- Introduce one gateway-issued internal token and keep external tokens out of the internal network.

Tradeoffs:
- Scope design needs the intended operation list (GAP-hop-principals).
- Client registrations and the mobile and web clients must be updated together.
- Token exchange adds a dependency on the issuer for every hop.

Verification: `tm04:VF-jwt-cross-audience`. Open gaps: G4, G5, G-s01-token-availability, GAP-secure-coding-pack.

### `tm04:TR-client-registry-hardening`

Threats: `tm02:T-client-registry-secrets-no-pkce`, `tm02:T-swagger-implicit-token-exposure`.

Remove sample client secrets from source and supply any confidential client secret from a secret store, require PKCE for every interactive client, and remove implicit-flow Swagger clients outside development (or replace them with code flow plus PKCE). Proposed only; not implemented.

Alternatives:
- Disable the API reference clients entirely in every non-development configuration.
- Register public clients without a secret and use code flow with PKCE only.

Tradeoffs:
- Developer convenience falls and the sample experience needs a documented development path.
- The mobile client must be rebuilt without an embedded secret.

Verification: `tm04:VF-client-registry-nondev`. Open gaps: G10, G5, G-s03-credential-rotation, GAP-secure-coding-pack.

### `tm04:TR-signing-key-and-service-credentials`

Threats: `tm02:T-developer-signing-key`, `tm02:T-shared-postgres-credential-blast-radius`.

Replace the developer signing key with managed key material held in a key store with a rotation procedure, give each service its own least-privilege database credential scoped to its own database, and define rotation for the shared broker and database credentials. Proposed only; not implemented.

Alternatives:
- Use platform-managed identity for database access so no password is stored.
- Split the shared Postgres server per service domain.

Tradeoffs:
- Rotation needs a procedure and an owner (unknown).
- Per-service credentials add provisioning steps for the deployment definition.

Verification: `tm04:VF-signing-key-source`, `tm04:VF-db-credential-scope`. Open gaps: G-s02-signing-key-storage, G3, G-s03-credential-rotation, GAP-secure-coding-pack.

### `tm04:TR-seed-user-gating`

Threats: `tm02:T-seeded-users-known-credentials`.

Create seeded demonstration users only in Development, and require a first-run provisioning step or per-deployment random credentials for any other environment so no published password exists in a deployed instance. Proposed only; not implemented.

Alternatives:
- Remove seed users from the code path and ship them as a documented development script.
- Force a password change at first login for any seeded account.

Tradeoffs:
- Evaluation and demo flows lose their ready-made accounts.
- Environment detection is itself a control that must fail closed.

Verification: `tm04:VF-seed-users-nondev`. Open gaps: G-s02-account-provisioning, G10, GAP-secure-coding-pack.

### `tm04:TR-webhook-egress-controls`

Threats: `tm02:T-webhooks-ssrf-empty-token-grant`.

Validate every webhook destination at registration and at each delivery: allowed scheme only, resolve the address and refuse private, loopback, link-local and metadata ranges, re-check after resolution, apply a redirect policy, set connect and response timeouts and a response size cap, and make the empty-token handshake case fail closed. Proposed only; not implemented.

Alternatives:
- Send deliveries through an egress proxy that enforces a destination allow-list.
- Allow only receiver domains that a customer proves ownership of out of band.

Tradeoffs:
- Internal sample receivers will be refused unless an explicit development exception exists.
- Name resolution can change between check and use, so address pinning or an egress proxy is needed for strong effect.

Verification: `tm04:VF-webhook-egress-targets`. Open gaps: UB4, G1, GAP-secure-coding-pack.

### `tm04:TR-webhook-fanout-and-token-handling`

Threats: `tm02:T-webhooks-fanout-cross-user`, `tm02:T-webhook-token-logged-and-sample-receiver-open`, `tm03:T-bus-forged-paid-shipped-webhook-content`.

Scope event fan-out to the subscriptions of the order owner (the event carries the owner and the consumer filters on it), stop logging grant tokens (log presence, not value), and make the sample receiver reject an empty or missing token. Proposed only; not implemented.

Alternatives:
- Deliver through a per-owner queue so cross-owner delivery is structurally impossible.
- Remove the sample receiver from any deployed configuration.

Tradeoffs:
- Events need an owner field that older publishers may lack.
- Less logging detail makes webhook debugging slower.

Verification: `tm04:VF-webhook-fanout-owner`, `tm04:VF-webhook-token-not-logged`. Open gaps: G-s01-log-sinks, G1, UB4, UB2.

### `tm04:TR-broker-identity-and-validation`

Threats: `tm02:T-bus-forged-order-lifecycle-events`, `tm02:T-bus-forged-paid-stock-and-notifications`, `tm02:T-bus-forged-orderstarted-basket-delete`, `tm03:T-bus-forged-paid-shipped-webhook-content`.

Require authentication and per-service identities on the broker with publish and consume rights limited to each service own event types, restrict network reach to the broker, and validate events at the consumer (schema, plausibility against current state) so a registered type from the wrong sender is rejected or flagged. Proposed only; not implemented.

Alternatives:
- Sign event envelopes with a per-service key and verify at the consumer.
- Use separate queues and virtual hosts per service domain.

Tradeoffs:
- Per-service broker accounts add provisioning and rotation work.
- Signed envelopes add key distribution; plausibility checks can reject legitimate out-of-order events.

Verification: `tm04:VF-broker-publish-acl`, `tm04:VF-broker-event-validation`. Open gaps: UB2, G3, G-s03-credential-rotation, GAP-secure-coding-pack.

### `tm04:TR-chat-tool-minimization`

Threats: `tm02:T-chat-indirect-injection-addtocart`, `tm02:T-chat-claims-pii-disclosure`.

Limit chatbot tools to read-only catalog lookup plus add-to-cart behind explicit user confirmation, give the model no tool that returns identity claims or personal data (disclose only a minimal display name), and render model output without remote images unless the host is on an allow-list. Proposed only; not implemented.

Alternatives:
- Keep chat disabled in every deployed configuration until the tool set is reviewed.
- Run the model with an allow-listed tool schema and server-side argument validation.

Tradeoffs:
- Fewer tools reduce assistant usefulness.
- A confirmation step adds friction to the cart flow.
- Behavior depends on a model that was not observed (UB3).

Verification: `tm04:VF-chat-injection-cart`, `tm04:VF-chat-claims-disclosure`. Open gaps: UB3, G-s02-chat-output-handling, G10.

### `tm04:TR-sensitive-logging-and-attribution`

Threats: `tm02:T-sensitive-data-in-logs-traces-card`, `tm02:T-orders-state-change-unattributed`, `tm02:T-webhook-token-logged-and-sample-receiver-open`.

Never write card security numbers or token values to logs or traces, redact at the logging behavior and at the event model, drop sensitive fields from domain and integration events, and record state changes in an audit log attributed to the token subject. Proposed only; not implemented.

Alternatives:
- Disable request body logging in deployed configurations.
- Ship logs to a store with field-level masking and restricted access.

Tradeoffs:
- Less verbose logs reduce diagnosis detail.
- An audit log needs retention and access decisions that are not supplied.

Verification: `tm04:VF-log-redaction`. Open gaps: G-s01-log-sinks, G-s01-card-schema.

### `tm04:TR-forwarded-header-trust`

Threats: `tm02:T-forwarded-headers-host-trust`.

Accept forwarded host and protocol headers only from the known proxy or ingress addresses, and pin the public origin and issuer used for redirects and token metadata. Proposed only; not implemented.

Alternatives:
- Set a canonical public host in configuration and ignore forwarded host entirely.

Tradeoffs:
- Requires knowing the deployed proxy addresses (G12).
- A fixed host complicates multi-host deployments.

Verification: `tm04:VF-forwarded-headers`. Open gaps: G12, GAP-secure-coding-pack.

### `tm04:TR-ci-permissions-and-pins`

Threats: `tm02:T-ci-and-image-supply-chain`.

Declare an explicit least-privilege permissions block in every workflow, pin third-party actions to full commit SHAs, and pin container image references by digest. Proposed only; not implemented.

Alternatives:
- Enforce an organization-level allow-list of actions and a default read-only token.

Tradeoffs:
- Pinned references need an update process.
- Digest pinning delays security patches unless an updater is in place.

Verification: `tm04:VF-ci-permissions-pins`. Open gaps: G-s02-ci-defaults, GAP-dependencies, GAP-secure-coding-pack.

### `tm04:TR-operator-control-plane`

Threats: `tm02:T-operator-control-plane-authority`.

Separate the deployment identity from daily operator accounts with least privilege on the container platform, require approval for production deploys, and keep an audit trail of control plane actions. Proposed only; not implemented.

Alternatives:
- Deploy only from a pipeline identity and remove standing human deploy rights.

Tradeoffs:
- Slows emergency changes unless a break-glass path is defined.
- Ownership of the control plane is unknown (G-s01-control-owner).

Verification: `tm04:VF-operator-authority`. Open gaps: G-s01-control-owner, GAP-hop-principals.

### `tm04:TR-payment-simulation-gate`

Threats: `tm02:T-simulated-payment-marks-orders-paid`.

Make the simulated payment processor unusable outside development: refuse to start it in a non-development configuration, and require payment success to come from a verified provider confirmation before an order becomes Paid. Proposed only; not implemented.

Alternatives:
- Mark simulated payments as a distinct state that cannot be shipped.

Tradeoffs:
- Demo deployments lose the always-succeeds behavior unless an explicit flag is set.
- A real provider integration is out of scope of this model.

Verification: `tm04:VF-payment-simulated-nondev`. Open gaps: GAP-invariants, GAP-transactions.

## Planned verification

All 30 records are `not_run` with no result evidence. Each has separate pass, fail and inconclusive criteria in the JSON. The designs compare principals against the same operation (owner and non-owner, entitled and unentitled), compare the gateway route with the direct internal route, and use synthetic data only. A missing environment, undefined invariant or untested alternate route makes a result inconclusive, never a pass. Nothing here authorizes a run; the caller must supply an environment (G-s04-test-environment).

| Verification | Threats | Controls |
| --- | --- | --- |
| `tm04:VF-catalog-write-matrix` | catalog-unauth-write, catalog-price-and-event-tampering | none |
| `tm04:VF-gateway-vs-direct` | catalog-unauth-write | none |
| `tm04:VF-edge-reach` | catalog-unauth-write, orders-read-any-order | none |
| `tm04:VF-picture-confinement` | catalog-picture-filename-read | tm02:C-pics-provider-root |
| `tm04:VF-catalog-audit` | catalog-price-and-event-tampering, catalog-text-poisoning-embedding | none |
| `tm04:VF-orders-owner-vs-nonowner` | orders-read-any-order, orders-cancel-ship-any-order | C-ordering-authn, C-order-state-guards |
| `tm04:VF-orders-userid-binding` | orders-create-foreign-userid | C-order-validators |
| `tm04:VF-orders-ship-role` | orders-cancel-ship-any-order | none |
| `tm04:VF-orders-price-mismatch` | orders-client-supplied-item-prices | C-order-validators |
| `tm04:VF-idempotency-replay` | orders-request-id-consumed-failure-reported-ok, orders-cancel-ship-retry-reports-success | C-request-idempotency |
| `tm04:VF-saga-cancel-payment-race` | cancel-races-payment-no-compensation, simulated-payment-marks-orders-paid | none |
| `tm04:VF-consumer-failure-redelivery` | bus-ack-on-failure-message-loss | C-transactional-publish |
| `tm04:VF-stock-removal-redelivery` | bus-forged-paid-stock-and-notifications, bus-ack-on-failure-message-loss | tm02:C-bus-unknown-type-drop |
| `tm04:VF-jwt-cross-audience` | jwt-audience-scopeless-cross-api | C-jwt-validation |
| `tm04:VF-client-registry-nondev` | client-registry-secrets-no-pkce, swagger-implicit-token-exposure | C-maui-pkce |
| `tm04:VF-signing-key-source` | developer-signing-key | C-jwt-validation |
| `tm04:VF-db-credential-scope` | shared-postgres-credential-blast-radius | none |
| `tm04:VF-seed-users-nondev` | seeded-users-known-credentials | none |
| `tm04:VF-webhook-egress-targets` | webhooks-ssrf-empty-token-grant | C-webhook-grant-handshake |
| `tm04:VF-webhook-fanout-owner` | webhooks-fanout-cross-user, bus-forged-paid-shipped-webhook-content | C-webhook-owner-scope |
| `tm04:VF-webhook-token-not-logged` | webhook-token-logged-and-sample-receiver-open | none |
| `tm04:VF-broker-publish-acl` | bus-forged-order-lifecycle-events, bus-forged-paid-stock-and-notifications, bus-forged-orderstarted-basket-delete | tm02:C-bus-unknown-type-drop |
| `tm04:VF-broker-event-validation` | bus-forged-order-lifecycle-events, bus-forged-orderstarted-basket-delete | C-order-state-guards |
| `tm04:VF-chat-injection-cart` | chat-indirect-injection-addtocart | none |
| `tm04:VF-chat-claims-disclosure` | chat-claims-pii-disclosure | none |
| `tm04:VF-log-redaction` | sensitive-data-in-logs-traces-card, orders-state-change-unattributed | C-card-masking |
| `tm04:VF-forwarded-headers` | forwarded-headers-host-trust | C-webapp-hsts |
| `tm04:VF-ci-permissions-pins` | ci-and-image-supply-chain | tm02:C-ci-no-pr-target |
| `tm04:VF-operator-authority` | operator-control-plane-authority | none |
| `tm04:VF-payment-simulated-nondev` | simulated-payment-marks-orders-paid | none |

## Requirements, risks and decisions

22 requirements are proposed and not caller-approved. Risk records are all unrated with a null rubric, because no rubric or impact statement was supplied (G-s02-risk-rubric). A proposed decision carries suggested rating criteria for later caller approval (reachability, attacker privilege, affected state, evidence confidence, blast radius, on a qualitative scale the caller defines); no rating was calculated. The other proposed decisions ask the caller to choose among treatments and alternatives, resolve a secure-coding pack, confirm deployed ingress and token forwarding, and authorize a test environment. Owners and dates are null; no decision is accepted, rejected or deferred.

## Stage 03 notes

- **Predecessor label.** `02-analysis.json` still declares TM_SYSTEM_MODEL while holding TM_ANALYSIS content. It was not edited. `G-s03-predecessor-artifact-type` stays open and continuity to a correctly labeled artifact is not certified.
- **Tree assumption drift.** Attack trees, paths and controls were not edited. Treatments relate to tree goals through the threat references each tree already lists. The drifting node assumptions (lockout, webhook registration reach, stock clamp) were not revised and `G-s03-tree-assumption-drift` stays open.
- **Unprotected Git call.** Disclosed in the inspection coverage. Its output was not used and no Git ran in this stage.

## Changes against r04

The `changes` array declares 128 records of delta against r04, each once: 121 additions and 7 modifications, none retired. The modified records are seven coverage records (their reasons or status were updated because treatments, verification, requirements and risks are no longer empty, and to note stage 04 reads). The r04 declarations are preserved in attachment `ATT-prior-changes-eshop-2026-11-09-r04`. Inventory entries, attachments and scope are envelope data and are not declared as record changes.

## Contract problems and limits

- Status is partial: planned verification has not run, no pack is resolved, no rating exists, and 43 gaps remain open.
- The predecessor label defect above is unresolved.
- No method ran. Registry checks of architecture identity were unavailable.

## Checks run and not run

Ran (own Python in isolated mode against the JSON in the run folder): strict parse with duplicate-key and non-finite-number rejection; ID syntax and uniqueness across all collections, tree nodes, inventories and attachments; reference resolution to the right record kind for treatments, verification, requirements, risks, decisions, gaps and coverage; every threat covered by a treatment and a risk; treatments linking verification that addresses their threats; pack dependencies unresolved with the open technology gap; verification not_run with empty result evidence; decisions proposed with null owner and date; delta of r05 against r04 by stable ID, each addition and modification declared exactly once and none retired; carried collections, system records, attachments and inventory compared for exact preservation; one run-configuration coverage record; r04 changes preserved in the history attachment; credential-pattern scan (no credential value found; one broad base64-length pattern matched only file paths); em dash check on the JSON.

Not run: any schema validator (none ships), registry checks of architecture or method identity, chunk or byte-equality checks (one file), project execution, network calls, Git, tests, and any of the planned verification.
