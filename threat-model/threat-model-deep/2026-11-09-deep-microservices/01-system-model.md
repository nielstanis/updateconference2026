# Stage 01: Microservices System Model

Model `eshop-2026-11-09`, revision `r02`, parent `r01`. Artifact type TM_SYSTEM_MODEL, status partial, depth deep. Review scope security; methods none; privacy profiles none. Architectures: microservices, identity-federation, agentic-ai. Source revision 913acea (session context, Git unverified).

This is a system model. It lists what the code and configuration show, with gaps where they do not. It makes no threat, risk or effectiveness claim. Everything here is a reading of source at the stated revision; no deployment was observed.

## Inspection coverage

Status: partial. Scope is the eShop source at revision 913acea. The collection step (carried from r01, not re-read here) left 73 processed entries, 55 read in full and 18 partial, plus 13 unprocessed. Stage 01 added 21 entries of its own for bounded reads in Ordering (behaviors, validators, idempotency, payment and order entity configuration, PaymentMethod, Order) and Webhooks.API (retriever, paid and shipped handlers, event records), widened IN-056 and IN-068 to full reads, narrowed UN-002 and removed UN-004 (its files are now read). Totals now: 94 processed (74 read, 20 partial), 12 unprocessed.

Omissions that matter for this model: Identity.API views and controller bodies, Ordering event handlers, Catalog event handlers and CatalogAI, the order processor's selection query, WebApp pages, dependency manifests, tests, and any generated ACA or YARP configuration (UN-001..UN-013 as narrowed). Git was not usable, so revision and working-tree state are unverified. The inspection used file reads and text searches only; discovery used name listings, so unlisted files may exist.

Unmapped boundaries, all still open: UB1, UB2, UB3, UB4. They concern ACA ingress and YARP method handling (UB1), broker credentials and ACLs (UB2), the WebApp to model-provider path (UB3), and Webhooks.API egress (UB4). A further topology gap, G1, covers whether internal services are reachable from outside.

Provenance: evidence E1-E27, EV-* records, attachments and inventories were carried from r01. Evidence E28-E31 were observed fresh in this stage. Counts of files are not a measure of how much of the system was analyzed.

## What stage 01 did

Added 19 assets, 13 actors, 25 data records, 7 zones, 8 boundaries, 40 flows, 26 entry points, 9 states, 46 dependencies and 14 controls. Added evidence E28-E31 and 7 gaps. Closed G6 (card fields persisted) and G7 (webhook fan-out), narrowed G8, populated affected references on 16 other gaps. Parent r01 declared no changes, so no prior-changes attachment was needed; the 18 declarations in `changes` compare r02 with r01 by ID.

New observations from the reads:

- Card data (E28): the paymentmethods table stores card number, holder name, alias, expiration and card type. The security number is a private field with no mapped column in the entity configuration, but it travels through the request, command and domain event, and the logging behaviors log whole commands with `{@Command}` (E30). Whether it reaches a log depends on the logging provider, which was not observed.
- Webhook fan-out (E29): every subscriber of an event type receives the payload for any user's order (order id, product units, buyer name for shipped). The retriever has no owner predicate.
- Order state machine (E31): ship only from Paid, cancel not from Paid or Shipped, but cancel also succeeds from Cancelled and raises its event again. The other transitions are silent no-ops from the wrong state.
- Idempotency (E30): the request record holds id, command type and time only, with no user or payload binding.

## Zones and boundaries

| Zone | Contents |
| --- | --- |
| `Z-external` | Internet clients: browsers, MAUI apps, webhook receivers, Swagger UI users and developer tools. |
| `Z-edge` | Externally exposed hosts: webapp, mobile-bff, identity-api. |
| `Z-internal` | Hosts with no external-endpoint declaration: catalog, basket, ordering, webhooks-api, webhooksclient, order-processor, payment-processor. No network segmentation inside it was observed. |
| `Z-data` | Shared Postgres server (four databases) and Redis. |
| `Z-broker` | RabbitMQ eventbus shared by services. |
| `Z-aca-control` | Aspire AppHost, the Azure Container Apps environment and the operator who runs publish or deploy. Authority here changes routes, identities and settings, not business data. |
| `Z-model-provider` | External or local chat model provider (Foundry or Ollama). |

| Boundary | Sides | Owner architecture | Open gaps |
| --- | --- | --- | --- |
| `B-external-edge` | Z-external, Z-edge | microservices | G12 |
| `B-edge-internal` | Z-edge, Z-internal | microservices | UB1, G1 |
| `B-internal-broker` | Z-internal, Z-broker | microservices | UB2 |
| `B-internal-data` | Z-internal, Z-data | microservices | G3 |
| `B-token-trust` | A-identity-api, Z-internal | identity-federation | G4 |
| `B-model-tools` | A-webapp, A-ai-model | agentic-ai | UB3 |
| `B-webhook-egress` | A-webhooks-api, Z-external | microservices | UB4 |
| `B-operator-control` | Z-aca-control, Z-internal | null (identity gap) | G-s01-control-owner |

The operator-control boundary has a null owner because no selected architecture covers the control plane (G-s01-control-owner). Boundary ownership by identity-federation and agentic-ai does not mean those chains ran.

## Principals and authority per hop

Service names are not authenticated principals. The authority column states what each hop carries according to the code. User token forwarded by WebApp through AddAuthToken reaches Basket, Ordering and (unused) Catalog; Basket, Ordering and Webhooks validate a JWT, Catalog validates nothing, and integration events carry no identity. Ordering and Webhooks apply no scope or role policy and audience validation is off (E6).

| Flow | Hop | Authority carried |
| --- | --- | --- |
| `F-anon-webapp` | ACT-anon -> EP-webapp-ui | none |
| `F-cust-webapp` | ACT-customer -> EP-webapp-ui | customer identity via cookie; WebApp later attaches the customer's access token downstream |
| `F-cust-chat` | ACT-customer -> EP-webapp-chat | customer text; no authority beyond the circuit |
| `F-cust-identity-login` | ACT-customer -> EP-identity-ui | password credential; yields the Identity session cookie and, after the code flow, tokens |
| `F-seed-identity-login` | ACT-seed-users -> EP-identity-ui | full customer authority for alice or bob where the seed ran |
| `F-swagger-identity` | ACT-swagger-clients -> EP-identity-ui | scopes of the basket, ordering or webhooks API for the signed-in user |
| `F-webapp-identity-signin` | A-webapp -> A-identity-api | client 'webapp' registration; scopes orders, basket, webhooks plus webshoppingagg (not in the API scope list); offline access |
| `F-identity-webapp-tokens` | A-identity-api -> A-webapp | tokens signed with the developer signing credential; user subject |
| `F-anon-bff` | ACT-anon -> EP-mobile-bff-api | none at the gateway |
| `F-maui-bff` | A-maui-client -> EP-mobile-bff-api | customer bearer token on orders; public client 'maui' registration with PKCE, plus an embedded secret constant |
| `F-bff-catalog` | A-mobile-bff -> A-catalog-api | none required; any token present is not evaluated |
| `F-bff-ordering` | A-mobile-bff -> A-ordering-api | the caller's bearer token if the route forwards it; header forwarding not observed in the route configuration |
| `F-bff-identity` | A-mobile-bff -> A-identity-api | user credentials and client credentials of the caller |
| `F-webapp-basket` | A-webapp -> A-basket-api | the user's access token forwarded by AddAuthToken; the basket key comes only from the token subject |
| `F-webapp-catalog` | A-webapp -> A-catalog-api | the user's token is attached but not evaluated |
| `F-webapp-catalog-pic` | A-webapp -> A-catalog-api | none |
| `F-webapp-ordering` | A-webapp -> A-ordering-api | the user's access token forwarded by AddAuthToken; ownership rests on body fields rather than the token on create |
| `F-webapp-model` | A-webapp -> A-ai-model | WebApp's provider connection (credential not observed); user token not sent to the provider in the code read |
| `F-model-webapp-tools` | A-ai-model -> A-webapp | the signed-in user's claims and token |
| `F-pub-ordering` | A-ordering-api -> A-rabbitmq | broker credential injected by Aspire; events carry no signature or sender identity |
| `F-pub-catalog` | A-catalog-api -> A-rabbitmq | broker credential; no sender identity |
| `F-pub-orderprocessor` | A-order-processor -> A-rabbitmq | broker credential; no sender identity |
| `F-pub-payment` | A-payment-processor -> A-rabbitmq | broker credential; outcome taken from a configuration flag, not a payment gateway |
| `F-sub-payment` | A-rabbitmq -> A-payment-processor | none; no sender identity |
| `F-sub-ordering` | A-rabbitmq -> A-ordering-api | none; no sender identity |
| `F-sub-catalog` | A-rabbitmq -> A-catalog-api | none; no sender identity |
| `F-sub-basket` | A-rabbitmq -> A-basket-api | none; the event names the buyer id |
| `F-sub-webhooks` | A-rabbitmq -> A-webhooks-api | none; no sender identity |
| `F-sub-webapp` | A-rabbitmq -> A-webapp | none; no sender identity |
| `F-orderproc-postgres` | A-order-processor -> A-postgres | database credential injected by Aspire |
| `F-ordering-postgres` | A-ordering-api -> A-postgres | database credential injected by Aspire; per-service role unknown |
| `F-catalog-postgres` | A-catalog-api -> A-postgres | database credential injected by Aspire; per-service role unknown |
| `F-identity-postgres` | A-identity-api -> A-postgres | database credential injected by Aspire; per-service role unknown |
| `F-webhooks-postgres` | A-webhooks-api -> A-postgres | database credential injected by Aspire; per-service role unknown |
| `F-basket-redis` | A-basket-api -> A-redis | connection credential injected by Aspire |
| `F-customer-webhook-register` | ACT-customer -> EP-webhook-register | user bearer token; subscription stored with the token subject as UserId |
| `F-webhook-grant` | A-webhooks-api -> ACT-webhook-receiver | Webhooks.API's network position inside Z-internal; no credential attached |
| `F-webhook-deliver` | A-webhooks-api -> ACT-webhook-receiver | Webhooks.API's network position; subscriber Token handling on delivery not re-read |
| `F-operator-deploy` | ACT-operator -> EP-apphost-deploy | operator's Azure rights, which can create and destroy the resource group per README |
| `F-apphost-aca` | A-aspire-apphost -> A-aca | authority to set routes, identities, configuration and data-service credentials; business data access not shown |

Full operation, initiator and trust-decision text for each hop is in the `description` of the flow record in the JSON.

## Exposure map

Derived from entry points and the flows that reach them. Exposure is by AppHost declaration (E2) and route configuration (E3); effective ACA ingress and YARP behavior are unobserved (G1, G2, UB1).

| Entry point | Kind | Reached from | Note |
| --- | --- | --- | --- |
| `EP-webapp-ui` | ui | ACT-anon, ACT-customer | Externally exposed; page-level authorization unread (UN-005). |
| `EP-webapp-chat` | ui | ACT-customer | Untrusted text reaches a model with tools. |
| `EP-mobile-bff-api` | http-gateway | ACT-anon, A-maui-client | Externally exposed catch-all in front of unauthenticated catalog write routes (G2, UB1). |
| `EP-identity-ui` | http-route | ACT-customer, ACT-seed-users, ACT-swagger-clients | Externally exposed token issuer; controller bodies read by grep only. |
| `EP-catalog-read` | http-route | internal or event-driven | Read routes; no authentication on the service. |
| `EP-catalog-write` | http-route | internal or event-driven | State-changing routes with no authentication observed. |
| `EP-catalog-pic` | http-route | internal or event-driven | File path derives from client-writable data via EP-catalog-write. |
| `EP-orders-read` | http-route | internal or event-driven | Authenticated, not ownership-scoped on by-id read. |
| `EP-orders-state-change` | http-route | internal or event-driven | State-changing operations open to any authenticated caller. |
| `EP-orders-create` | http-route | internal or event-driven | Token subject not used for create. |
| `EP-basket-grpc` | grpc | internal or event-driven | Per-method anonymity; key from token sub. |
| `EP-webhook-register` | http-route | ACT-customer | Authenticated caller supplies URLs the server will fetch. |
| `EP-webhook-manage` | http-route | internal or event-driven | Owner-scoped by token subject. |
| `EP-webhookclient-receive` | http-route | internal or event-driven | Sample receiver endpoints. |
| `EP-bus-ordering` | message-consumer | internal or event-driven | Event-driven authority over order state; no sender identity. |
| `EP-bus-payment` | message-consumer | internal or event-driven | Trusts any bus publisher of that event. |
| `EP-bus-catalog` | message-consumer | internal or event-driven | Stock changes triggered by events; handler unread. |
| `EP-bus-basket` | message-consumer | internal or event-driven | Trusts any publisher of that event. |
| `EP-bus-webhooks` | message-consumer | internal or event-driven | Event-triggered outbound delivery. |
| `EP-bus-webapp` | message-consumer | internal or event-driven | Notification fan-out; consumer code unread (UN-005). |
| `EP-order-processor-poll` | scheduled-job | internal or event-driven | Time-driven work trigger; query body unread. |
| `EP-health` | http-route | internal or event-driven | Present only when the environment name is Development; deployed name not observed. |
| `EP-user-seed` | startup-job | internal or event-driven | Creates known accounts in any environment where it runs. |
| `EP-apphost-deploy` | operator-cli | ACT-operator | Control-plane entry, described by README only. |
| `EP-maui-app` | client-app | internal or event-driven | Client-held default client id and secret constant; plain HTTP development hosts. |
| `EP-ci-workflows` | ci-trigger | internal or event-driven | Bounded CI view. |

## Order lifecycle and idempotency

Lifecycle read from the Order aggregate: Submitted -> (grace window) -> AwaitingValidation -> StockConfirmed -> Paid -> Shipped, with Cancelled reachable from Submitted, AwaitingValidation and StockConfirmed. Payment is simulated from configuration. Transition conditions and who can request them:

| State | Description |
| --- | --- |
| `S-order-submitted` | Submitted: set by the Order constructor. A client create call with a new x-requestid reaches it; the card, address and buyer rows are created by an in-process handler. Cancel is allowed here. |
| `S-order-grace-window` | Grace window: a time condition on Submitted orders. OrderProcessor polls every 30 seconds with a 1 minute grace period and publishes GracePeriodConfirmed. Cancel through the API is not blocked during this window. The selection query body was not read. |
| `S-order-awaiting-validation` | AwaitingValidation: Submitted moves here through SetAwaitingValidationStatus, expected on GracePeriodConfirmed; Ordering's handler was not read. Stock rejection moves it to Cancelled. |
| `S-order-stock-confirmed` | StockConfirmed: reached only from AwaitingValidation. The trigger event comes from Catalog; the handler was not read. |
| `S-order-paid` | Paid: reached only from StockConfirmed when a payment result event arrives. Payment is simulated from PaymentOptions.PaymentSucceeded. |
| `S-order-shipped` | Shipped: SetShippedStatus throws unless Paid. PUT ship is available to any authenticated caller with an OrderNumber; a comment says an administrator ships. |
| `S-order-cancelled` | Cancelled: allowed from Submitted, AwaitingValidation, StockConfirmed and Cancelled; rejected from Paid and Shipped. Stock rejection also cancels from AwaitingValidation. Compensation for any held stock or payment on cancel is not shown in the code read. |
| `S-payment-simulated` | Simulated payment: Succeeded or Failed chosen only by configuration; no gateway, no pending or unknown state exists. Failure event handling in Ordering was not read. |
| `S-request-consumed` | Request id consumed: x-requestid is recorded before the inner command runs. A repeat returns a canned success; a failed first attempt also consumes the id. The record does not bind user or payload, and whether the save falls inside the command transaction was not read. |

| Transition | Condition, requester and replay |
| --- | --- |
| S-order-grace-window -> S-order-awaiting-validation | Transition permitted when status is Submitted and the grace period ends (GracePeriodConfirmed). Requested by OrderProcessor's event through the broker; any bus publisher could emit the same event type. Replay of the event is a no-op once status is no longer Submitted. |
| S-order-submitted -> S-order-grace-window | Order stays Submitted and enters the grace window until the timer fires; the client may cancel during it. |
| S-order-awaiting-validation -> S-order-stock-confirmed | Transition permitted only from AwaitingValidation when stock is confirmed. Requested by the stock confirmation event; replay from another state is silently ignored. |
| S-order-awaiting-validation -> S-order-cancelled | Stock rejection cancels the order only from AwaitingValidation. |
| S-order-stock-confirmed -> S-order-paid | Transition permitted only from StockConfirmed when a payment succeeded event arrives; the result comes from the simulated payment step. The event is correlated by the order id in its payload. |
| S-order-paid -> S-order-shipped | Transition permitted only from Paid; requested through PUT ship by any authenticated caller. A second ship call throws. |
| S-order-submitted -> S-order-cancelled | Cancel permitted from Submitted through PUT cancel by any authenticated caller on any OrderNumber; the call can be repeated. |
| S-order-stock-confirmed -> S-order-cancelled | Cancel permitted from StockConfirmed (not Paid or Shipped); whether stock is released is not shown. |

Cancellation compensation (stock release, payment reversal), lost-reply outcomes and event correlation are not shown in the code read (G-s01-event-handlers, GAP-transactions). No transaction histories were supplied.

## Dependencies

| Depends on | Dependent records |
| --- | --- |
| `A-postgres` | A-catalog-api, A-identity-api, A-ordering-api, A-webhooks-api, A-order-processor |
| `A-redis` | A-basket-api |
| `A-rabbitmq` | A-basket-api, A-catalog-api, A-ordering-api, A-order-processor, A-payment-processor, A-webhooks-api, A-webapp |
| `A-identity-api` | A-basket-api, A-ordering-api, A-webhooks-api, A-catalog-api, A-webapp |
| `A-ai-model` | A-webapp |
| `unknown` | A-catalog-api |
| `A-aca` | A-webapp, A-mobile-bff, A-identity-api, A-catalog-api, A-basket-api, A-ordering-api, A-order-processor, A-payment-processor, A-webhooks-api, A-webhookclient, A-postgres, A-redis, A-rabbitmq, A-aspire-apphost |

Four databases share one Postgres server; whether each service has its own database role is unknown (G3). One shared RabbitMQ exchange serves seven services. Recovery objectives, retry and replay controls were not found (G-s01-retry-recovery); token validation while Identity.API is down is unknown (G-s01-token-availability).

## Data and sensitivity

No caller-supplied ownership or sensitivity classification exists, so ownership below is the observed writing service.

| Data | Kind | Description |
| --- | --- | --- |
| `D-order` | resource-record | Order row in orderingdb: id, status, description, order items, buyer id, payment method id. Written by Ordering.API; read by OrderProcessor. Sensitivity: purchase history linked to a person. |
| `D-order-address` | personal-data | Owned Address value object stored with the order: street, city, state, zip, country. Taken from the request body on create. Sensitivity: personal contact data. |
| `D-payment-method` | payment-data | paymentmethods rows: CardNumber (the API masks to the last 4 before the command is built), CardHolderName, Alias, Expiration, CardTypeId. Sensitivity: payment card data. |
| `D-card-security-number` | payment-data | Card security number carried in the create request, the command, OrderStartedDomainEvent and a private PaymentMethod field. No database column is mapped in the entity configuration read. Sensitivity: card verification data. |
| `D-basket` | resource-record | Basket JSON in Redis under /basket/{sub} with no TTL set in code; product ids and quantities. Written by Basket.API only, keyed from the token subject. |
| `D-catalog-item` | resource-record | Catalog item in catalogdb: name, description, price, picture file name, stock and embedding. Written by unauthenticated PUT/POST/DELETE routes; price change publishes an event. |
| `D-stock-state` | reservation | Stock levels in catalogdb adjusted from order status events (E27 names Catalog as a consumer); reservation, release and rejection semantics were not read. |
| `D-product-picture` | file | Image files under Catalog.API Pics, served by the picture endpoint from item.PictureFileName. |
| `D-webhook-subscription` | resource-record | Subscription row in webhooksdb: Url, GrantUrl, Token, event Type, UserId. List, get and delete filter by UserId. |
| `D-webhook-payload` | outbound-message | JSON POSTed to each subscriber Url: When, Type, Payload (serialized event). Paid carries OrderId and product units; Shipped carries OrderId, OrderStatus and BuyerName. Sent to every subscriber of the type regardless of order owner. Sensitivity: order identifiers and buyer name. |
| `D-grant-token` | credential | Caller-chosen token sent as X-eshop-whtoken during the grant check and echoed back; written to logs by Webhooks.API and, with the expected token, by WebhookClient. |
| `D-access-token` | credential | Identity.API JWT access token (2 hour for maui). Resource services do not validate audience and apply no scope or role policy. WebApp stores it in its session (SaveTokens). |
| `D-refresh-token` | credential | Refresh tokens issued to webapp (offline access) and maui. |
| `D-session-cookie` | credential | WebApp authentication cookie (default 60 minute lifetime) that carries the saved tokens; Identity.API cookie 2 hours, SameSite Lax. |
| `D-client-registry` | configuration | In-memory IdentityServer clients and API resources; confidential clients share one sample secret [REDACTED:sample-client-secret]; scopes webshoppingagg and mobileshoppingagg appear in allow-lists but not in the API scope list. |
| `D-signing-key` | credential | IdentityServer developer signing credential with key management disabled. |
| `D-identity-users` | personal-data | ASP.NET Identity users in identitydb. Seeded alice and bob carry profile PII, card holder name, masked card number, expiration and a card security number [REDACTED:sample-card-cvv]. |
| `D-integration-events` | message | JSON integration events on the shared exchange (order started and status changes, stock, grace period, payment results, price changes). Unsigned; no sender identity; deserialized to a statically registered type. |
| `D-outbox` | message | Ordering integration event log used by TransactionBehavior to publish events after commit; implementation under src/IntegrationEventLogEF was not read. |
| `D-client-request` | operation-record | ClientRequest rows (Id = x-requestid, Name = command type, Time). Written before the inner command; not removed when the command throws; not bound to user or payload. |
| `D-payment-outcome` | operation-outcome | OrderPaymentSucceeded or Failed event, produced solely from PaymentOptions.PaymentSucceeded (true in appsettings). No gateway call; correlation to the order beyond the event payload is not shown. |
| `D-chat-user-text` | personal-data | User chat messages sent to the model provider when a model is configured. |
| `D-chat-history` | session-state | Chat history held in the server-side Blazor circuit. |
| `D-user-claims-pii` | personal-data | Name, last name, street, city, state, zip, country, email and phone from the user's claims, returned to the model by GetUserInfo. |
| `D-logs` | log | Application logs. Observed content: webhook grant tokens (Webhooks.API and WebhookClient), order commands through {@Command} in logging, validation and transaction behaviors. Sinks, retention and viewers not observed. |

## Controls recorded

All are status implemented from implementation observations. None was tested; limits are in each record.

| Control | Description | Limits |
| --- | --- | --- |
| `C-jwt-validation` | Resource services validate JWT issuer, signature and lifetime using the shared ServiceDefaults configuration. | Implementation read only. Audience validation is disabled, no scope or role policy exists, and if the Identity section is absent authentication is not registered. Effectiveness not tested. |
| `C-ordering-authn` | All order routes require an authenticated caller. | Authentication only: no ownership filter on by-id read, cancel or ship; create takes the owner from the body. Not tested. |
| `C-basket-sub-keying` | Basket keys derive from the token subject only and the message carries no buyer id; Update and Delete reject an empty subject. | GetBasket is anonymous; depends on authentication being registered. Not tested. |
| `C-webhook-owner-scope` | Webhook list, get and delete filter by the caller's UserId. | Does not cover event fan-out, which has no owner predicate (E29). Not tested. |
| `C-webhook-grant-handshake` | Subscription registration requires Url and GrantUrl to share scheme, host and port and the GrantUrl host to echo a token. | Proves control of the host the caller named, not that the host is a safe destination; no address block-list, redirect policy or timeout seen. Not tested. |
| `C-request-idempotency` | Order create runs through an IdentifiedCommand keyed by x-requestid; a repeated id returns a canned success. | Id is consumed even on failure and is not bound to user or payload. Not tested. |
| `C-order-state-guards` | The Order aggregate permits status changes only along the guarded paths (ship only from Paid; cancel not from Paid or Shipped). | Guards are in the domain model; callers of the transitions and event handlers are partly unread. Not tested. |
| `C-order-validators` | FluentValidation checks required address and card fields, card number and security number length, expiry and non-empty items on create; non-empty OrderNumber on cancel and ship. | No semantic checks on ownership or price; validator pipeline wiring not read. Not tested. |
| `C-card-masking` | The create route masks the card number to its last 4 before the command; the security number has no mapped database column in the entity configuration read. | The security number still travels through the request, command, domain event and logging behaviors; the migration snapshot and log sinks were not read. Not tested. |
| `C-transactional-publish` | Integration events are published only after the database transaction commits, using a transaction id. | Outbox storage and retry were not read; commit-then-publish failure window not assessed. |
| `C-maui-pkce` | The maui client registration requires PKCE and refresh tokens. | The webapp registration does not require PKCE; the app also ships a secret constant. Not tested. |
| `C-identity-csrf-redirect` | Identity.API posts use antiforgery tokens and login flows check return URLs with IsLocalUrl and IsValidReturnUrl. | Seen by grep only; controller bodies and views unread. Not tested. |
| `C-health-dev-only` | /health and /alive are mapped only in the Development environment. | Deployed environment name not observed; AppHost health checks depend on it. Not tested. |
| `C-webapp-hsts` | WebApp production branch adds the exception handler and HSTS. | Deployed environment not observed; Identity.API and gateway headers unread (G10). |

## Gaps

Closed: G6, G7. Narrowed, still open: G8. New: G-s01-event-handlers, G-s01-token-availability, G-s01-control-owner, G-s01-retry-recovery, G-s01-log-sinks, G-s01-card-schema, G-s01-bff-auth-forwarding.

| Gap | Kind | Status | Description |
| --- | --- | --- | --- |
| `G1` | topology | open | Unknown whether Ordering, Webhooks, Basket and Catalog are reachable from outside the ACA environment after aspire deploy (ingress defaults for projects without WithExternalHttpEndpoints). |
| `G2` | topology | open | Unknown whether the YARP mobile-bff restricts HTTP methods on /api/catalog/{*any} and /api/orders/{*any} at runtime; E3 shows no method match. |
| `G3` | topology | open | Unknown effective RabbitMQ, Postgres and Redis credentials, network policy and TLS in deployment (values injected by Aspire, not read). |
| `G4` | identity | open | Unknown whether the Identity configuration section is present in every service (Catalog has none; Basket, Ordering and Webhooks rely on AppHost Identity__Url). Missing configuration silently disables authentication. |
| `G5` | identity | open | Unknown consumers and issuance effect of scopes webshoppingagg and mobileshoppingagg, which appear in client allow-lists but not in GetApiScopes(). |
| `G6` | evidence | closed | Which card fields are persisted in the Ordering database. Resolved at code level in stage 01 (r02) by E28: the paymentmethods configuration maps CardHolderName, Alias, CardNumber, Expiration and CardTypeId and maps no column for the security number, which is a private field set in the constructor. Residual: the EF migrations snapshot was not read, tracked in G-s01-card-schema. |
| `G7` | evidence | closed | Webhook fan-out logic and payload content. Resolved in stage 01 (r02) by E29: WebhooksRetriever selects all subscriptions of the event type with no owner predicate; the Paid and Shipped handlers send the serialized event to each; payload fields are OrderId and product units (Paid) and OrderId, OrderStatus and BuyerName (Shipped). |
| `G8` | evidence | open | Narrowed in stage 01 (r02). Read: RequestManager, ValidatorBehavior, TransactionBehavior, LoggingBehavior and the Create, Cancel and Ship validators (E30). Still unread: IdentifiedCommandValidator, the order in which behaviors are registered, whether RequestManager's save falls inside the command transaction, OrderRepository and BuyerRepository. |
| `G9` | evidence | open | Unread Catalog CatalogAI embedding and search implementation and its input limits. |
| `G10` | evidence | open | Unknown HTTP security headers, CSP and CORS policy on WebApp and Identity.API (SecurityHeadersAttribute exists, unread). |
| `G11` | evidence | open | Identity.API Razor views and Blazor pages not read for output encoding. |
| `G12` | topology | open | Unknown runtime effect of forwarded-header trust and AllowedHosts "*". |
| `G13` | evidence | open | Test coverage and results unknown (tests/ and e2e/ excluded; nothing run). |
| `G14` | evidence | open | Working-tree cleanliness and Git history not inspected; revision 913acea comes from session context only. |
| `UB1` | topology | open | Suspected crossing between mobile-bff and ordering/catalog at deployment time (ACA ingress, YARP method handling). Selection ID G-ub1. |
| `UB2` | topology | open | Suspected crossing between services and RabbitMQ broker credentials and ACLs. Selection ID G-ub2. |
| `UB3` | topology | open | Suspected crossing between WebApp and the AI model provider (Foundry or Ollama). Selection ID G-ub3. |
| `UB4` | topology | open | Suspected crossing between Webhooks.API and arbitrary customer URLs (egress policy). Selection ID G-ub4. |
| `G-sel-availability` | coverage | open | Selection read only frontmatter and README for the library prompts. Stage 00 read the complete microservices stage 00 prompt; the identity-federation and agentic-ai prompt bodies were not read and those secondaries are not scheduled here. Architecture identities were not checked against a supplied registry file. |
| `G-sel-git` | evidence | open | Git revision verification and working-tree cleanliness were not checked (installed git rejected --no-lazy-fetch). |
| `GAP-invariants` | evidence | open | No caller-stated business invariants (resource ownership, commitment points, permitted state transitions, forbidden repeated effects) were supplied. Code behavior in E7 and E9 cannot be judged against a stated rule. |
| `GAP-hop-principals` | evidence | open | No per-hop description of the principal and operation, retained user or tenant context, downstream operations beyond a caller's ordinary scope, or the authority to change routing and identities was supplied; only code observations exist. A service name in the bundle is not an authenticated principal or an owner assignment. |
| `GAP-transactions` | evidence | open | No sample transaction histories, failure or retry descriptions, or participant states after a lost reply were supplied. Correlation between a result event and its initiating order is not shown (E20). |
| `GAP-secure-coding-pack` | technology | open | No secure-coding pack was resolved for ASP.NET Core, Duende IdentityServer, YARP or RabbitMQ.Client; technology-specific treatment advice stays unverified. |
| `GAP-dependencies` | evidence | open | Dependency manifests (Directory.Packages.props, package.json, lockfiles, nuget.config) were not read, so no dependency vulnerability review exists. |
| `G-s01-event-handlers` | evidence | open | Handler bodies for Ordering (GracePeriodConfirmed, stock confirmed or rejected, payment results), Catalog (stock on order events) and Basket/WebApp consumers, and the OrderProcessor selection query, were not read. Who can drive each order transition by publishing an event, which fields correlate a result to its order, and how stock is released on cancel are unknown. |
| `G-s01-token-availability` | evidence | open | Whether a receiving service accepts a protected operation while Identity.API metadata or keys are unavailable or stale, and what revocation freshness applies, is not observed. No requirement for token freshness was supplied. |
| `G-s01-control-owner` | identity | open | No architecture in this envelope owns the control-plane boundary (cloud-control-plane is not selected), so B-operator-control has a null owner. Which identities may change routes, workload identities, configuration and data-service credentials, and how those changes are recorded, is not supplied. |
| `G-s01-retry-recovery` | evidence | open | No retry, back-off, dead-letter, replay, capacity or recovery objective was observed for broker consumers, the order processor poll, or the database and Redis dependencies. Who may restart or replay work is not shown. Missing limits are gaps, not findings. |
| `G-s01-log-sinks` | evidence | open | Logging providers, sinks, retention and who can read logs (support and telemetry views) are not observed, so how {@Command} destructuring and webhook token logging surface sensitive fields is unknown. |
| `G-s01-card-schema` | evidence | open | The EF migrations snapshot and Buyer/BuyerRepository were not read, so the database schema is not observed even though the entity configuration maps no security-number column. |
| `G-s01-bff-auth-forwarding` | evidence | open | Whether YARP routes in mobile-bff carry an authorization policy and forward the Authorization header to ordering-api and identity-api is not shown in the configuration read; it decides whether the gateway hop keeps or loses the user's context. |

## Checks

Ran (Python 3 in isolated mode, own scripts, files in the run folder only): JSON parse with a hook rejecting duplicate keys and non-finite numbers; record ID uniqueness across the model and inventories; resolution of every reference field to the right record kind (evidence, gap, system, boundary side, flow endpoint, data, boundary); boundaries have at least two known sides and an owner in architecture_ids or null with an open gap; null endpoints carry an open gap; observed and claimed basis have matching evidence status; closed gaps carry observation evidence; controls marked implemented carry implementation observations; comparison of r02 with r01 by stable ID showing every added or modified record is declared exactly once and nothing declared lacks a delta; r01 evidence and attachments unchanged; one run-configuration coverage record.

Not run: any library schema validator (none ships), Git, build, test or live checks, a registry check of architecture IDs, and independent reading of the markdown against the JSON beyond generation from it. Inventory entries and scope are envelope data and are not part of the record-delta comparison.
