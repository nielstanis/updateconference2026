# Triage Report

75 findings in -> 12 duplicates, 40 false positives, 23 confirmed (10 high / 12 medium / 1 low), 1 needs manual test.

Context: interactive; environment = internet-facing web service (HTTP untrusted; demo accounts publicly credentialed); scoring = derived HIGH/MEDIUM/LOW from preconditions; 3-vote verification, semantic dedupe over all 75 candidates.

## Act on these

### [HIGH] Committed RSA private key is the IdentityServer token-signing key loaded in every deployment  (f007)
`src/Identity.API/tempkey.jwk:1` | hardcoded-secret | claimed HIGH (alignment +4) | confidence 0.9
**Owner:** no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Identity.API/
**Verdict:** exploitable, votes TP 3 / FP 0 / CV 0
**Preconditions (2):**
- obtain public key material (public repo / build output)
- target still signs with the committed key (default as-shipped)
**Threat-model match:** privilege escalation to admin; tenant-to-tenant data leakage; supply-chain compromise
**Why:** tempkey.jwk:1 git-tracked with full RSA private JWK; Program.cs:29 disables key management unconditionally, :37 loads the file, csproj:50 ships it to output; all bearer consumers validate against the JWKS published from this same key with ValidateAudience=false; no alternate production credential exists anywhere.
**Reachability evidence:** src/Identity.API/Program.cs:37, src/eShop.ServiceDefaults/AuthenticationExtensions.cs:33

### [HIGH] GET /api/orders/{orderId} returns any order without buyer/ownership scoping (IDOR)  (f002)
`src/Ordering.API/Application/Queries/OrderQueries.cs:8` | idor | claimed HIGH (alignment +0) | confidence 0.9
**Owner:** no CODEOWNERS entry; top committer: Erin McLaughlin / Srushti; component: Ordering.API/
**Verdict:** exploitable, votes TP 3 / FP 0 / CV 0
**Preconditions (2):**
- authenticated session (zero-knowledge)
- target orderId (sequential, enumerable)
**Threat-model match:** tenant-to-tenant data leakage
**Why:** OrderQueries.cs:8-10 FirstOrDefaultAsync(o.Id==id) with no buyer predicate returns full address PII; sole caller OrdersApi.cs:84 passes raw bound orderId; sibling list endpoint filters Buyer.IdentityGuid==userId (OrderQueries.cs:40); sequential int ids enumerable by any authenticated caller.
**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:84

### [HIGH] All catalog item mutation endpoints (create/update/delete) are anonymous with no authentication wiring anywhere in the service  (f003)
`src/Catalog.API/Apis/CatalogApi.cs:100` | auth-bypass | claimed HIGH (alignment +0) | confidence 0.9
**Owner:** no CODEOWNERS entry; top committer: Mike Kistler; component: Catalog.API/
**Verdict:** exploitable, votes TP 3 / FP 0 / CV 0
**Preconditions (1):**
- none - unauthenticated, externally reachable via mobile-bff YARP
**Threat-model match:** supply-chain compromise of downstream users (partial)
**Why:** All four mutation endpoints (CatalogApi.cs:100-117) map handlers with no RequireAuthorization; Program.cs:20-29 wires no auth middleware; Catalog.API never calls AddDefaultAuthentication while sibling APIs do; externally-exposed mobile-bff YARP forwards /catalog-api routes anonymously (AppHost/Extensions.cs:97-143); anonymous PUT reaches CurrentValues.SetValues (390) and DELETE removes rows.
**Reachability evidence:** src/Catalog.API/Apis/CatalogApi.cs:100, src/Catalog.API/Apis/CatalogApi.cs:105

### [HIGH] PUT /api/orders/ship lets any authenticated user mark any order shipped - no admin/role enforcement  (f012)
`src/Ordering.API/Application/Commands/ShipOrderCommandHandler.cs:21` | auth-bypass | claimed HIGH (alignment +0) | confidence 0.9
**Owner:** no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Ordering.API/
**Verdict:** exploitable, votes TP 3 / FP 0 / CV 0
**Preconditions (2):**
- authenticated session (zero-knowledge)
- Paid order number (sequential, enumerable)
**Threat-model match:** privilege escalation to admin
**Why:** ShipOrderAsync gates only on non-empty x-requestid Guid; sole authz is bare RequireAuthorization with zero roles/policies repo-wide; ShipOrderCommandHandler loads by number via unscoped FindAsync; SetShippedStatus guard is status-only; 'administrator executes ship order' comment documents unenforced admin intent.
**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:51, src/Ordering.API/Apis/OrdersApi.cs:70

### [HIGH] Seed users alice/bob created unconditionally with hardcoded password 'Pass123$', advertised on the login page  (f027)
`src/Identity.API/UsersSeed.cs:33` | hardcoded-secret | claimed HIGH (alignment +3) | confidence 0.8
**Owner:** no CODEOWNERS entry; top committer: toyzoz / Rob Conery; component: Identity.API/
**Verdict:** exploitable, votes TP 2 / FP 1 / CV 0
**Preconditions (1):**
- none - credentials printed on the public login page
**Threat-model match:** none
**Why:** Unconditional seeding confirmed: Program.cs:12 AddMigration<ApplicationDbContext,UsersSeed> runs SeedAsync on every boot (MigrateDbContextExtensions.cs:28,66,81) with no UseCustomizationData gate; Login.cshtml:46 prints the credentials to anonymous visitors; playwright.yml hardcodes them. Dissent: deliberate demo design (rule 3) - README declares not-for-production. Majority: concrete zero-knowledge account takeover of the demo accounts under the stated internet-facing environment.
**Reachability evidence:** src/Identity.API/Program.cs:12

### [HIGH] Unbounded in-memory ConcurrentQueue grows forever from unauthenticated webhook posts  (f023)
`src/WebhookClient/Services/HooksRepository.cs:7` | unbounded-allocation | claimed HIGH (alignment +1) | confidence 0.8
**Owner:** no CODEOWNERS entry; top committer: Steve Sanderson; component: WebhookClient/
**Verdict:** exploitable, votes TP 3 / FP 0 / CV 0
**Preconditions (1):**
- none - unauthenticated by default config
**Threat-model match:** none
**Why:** Singleton ConcurrentQueue enqueued unconditionally and never dequeued anywhere (grep zero for Dequeue/TryDequeue); writers unauthenticated by default; no body-size override (Kestrel ~30MB default); persistent unbounded state accumulation (CWE-770), not rate-limit absence - rule 1 does not apply.
**Reachability evidence:** src/WebhookClient/Endpoints/WebhookEndpoints.cs:31, src/WebhookClient/Endpoints/WebhookEndpoints.cs:46

### [HIGH] Credit-card CVV (CardSecurityNumber) and, in one path, the full unmasked PAN are written to application logs  (f009)
`src/Ordering.API/Application/Behaviors/LoggingBehavior.cs:9` | sensitive-data-exposure | claimed HIGH (alignment +0) | confidence 0.8
**Owner:** no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Ordering.API/
**Verdict:** exploitable, votes TP 3 / FP 0 / CV 0
**Preconditions (2):**
- authenticated session (zero-knowledge)
- x-requestid omitted or zero GUID
**Threat-model match:** compliance-scoped data exposure (PII/PCI)
**Why:** OrdersApi.cs:134 logs the raw CreateOrderRequest record when x-requestid is zero/missing - record ToString dumps full PAN+CVV before masking at :140, contradicting the comment at :130; reachable by any authenticated user. Caveat: the {@Command} behavior sinks may render type-name only under MEL/OTel for the non-record command class.
**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:134, src/Ordering.API/Apis/OrdersApi.cs:118

### [HIGH] ProfileService ignores RequestedClaimTypes and emits payment-card data (incl. CVV) into every token, including front-channel implicit-flow access tokens  (f005)
`src/Identity.API/Services/ProfileService.cs:22` | sensitive-data-exposure | claimed HIGH (alignment +4) | confidence 0.7
**Owner:** no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Identity.API/
**Verdict:** exploitable, votes TP 2 / FP 1 / CV 0
**Preconditions (3):**
- authenticated session (zero-knowledge)
- card data populated on the buyer
- cross-party disclosure additionally requires observation of a front-channel token artifact
**Threat-model match:** compliance-scoped data exposure (PII/PCI)
**Why:** GetProfileDataAsync (12-24) ignores RequestedClaimTypes and GetClaimsFromUser (70-80) always emits card_number/card_holder/card_security_number/card_expiration; AlwaysIncludeUserClaimsInIdToken=true on all code clients (Config.cs:72,89,125) puts CVV into front-channel id_tokens; sole registered IProfileService (Program.cs:39); only consumer reads claims via userinfo endpoint, so token exposure is not load-bearing. Dissent: intended design for MAUI checkout autofill + swagger redirect pages absent (rules 3/13).
**Reachability evidence:** src/Identity.API/Services/ProfileService.cs:22, src/Identity.API/Program.cs:39

### [HIGH] Webhook receiver token validation is disabled by default (bool.TryParse on unset config) and silently bypassed via config-key mismatch  (f021)
`src/WebhookClient/Endpoints/WebhookEndpoints.cs:13` | auth-bypass | claimed HIGH (alignment +2) | confidence 0.7
**Owner:** no CODEOWNERS entry; top committer: Steve Sanderson; component: WebhookClient/
**Verdict:** exploitable, votes TP 3 / FP 0 / CV 0
**Preconditions (1):**
- none - validation disabled by shipped default config, no auth layer on endpoints
**Threat-model match:** none
**Why:** bool.TryParse on unset root key ValidateToken defaults validation off (no shipped appsettings defines it; only a test does); guards at lines 18/37 pass for any token; typed WebhookClientOptions.ValidateToken binds from a different section and is dead code; Program.cs:29 adds no auth; endpoint externally reachable by design (AddWebhook.razor registers the public callback). Impact bounded to forged rows in the dashboard.
**Reachability evidence:** src/WebhookClient/Program.cs:29, src/WebhookClient/Endpoints/WebhookEndpoints.cs:31

### [HIGH] Full payment-card data (PAN, CVV) logged destructured by the ordering mediator pipeline  (f010)
`src/Ordering.API/Application/Behaviors/TransactionBehavior.cs:41` | sensitive-data-in-logs | claimed HIGH (alignment +1) | confidence 0.7
**Owner:** no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Ordering.API/
**Verdict:** exploitable, votes TP 2 / FP 1 / CV 0
**Preconditions (2):**
- authenticated session (zero-knowledge)
- x-requestid omitted or zero GUID
**Threat-model match:** compliance-scoped data exposure (PII/PCI)
**Why:** Majority: raw CVV flows from OrdersApi.cs:144 into CreateOrderCommand.cs:81 and every {@Command} log site serializes it on every order placement (MEL/OTel destructuring); the worse uncited sink is OrdersApi.cs:134 logging the full unmasked request record. Dissent: no Serilog in repo; {@Command} renders via ToString (type name only) and PAN is masked at :140, so nothing reaches logs (rule 13).
**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:141, src/Ordering.API/Application/Commands/IdentifiedCommandHandler.cs:87

### [MEDIUM] PUT /api/orders/cancel cancels any user's order - no buyer scoping (IDOR)  (f001)
`src/Ordering.API/Application/Commands/CancelOrderCommandHandler.cs:21` | idor | claimed MEDIUM (alignment -2) | confidence 0.9
**Owner:** no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Ordering.API/
**Verdict:** exploitable, votes TP 3 / FP 0 / CV 0
**Preconditions (3):**
- authenticated session (zero-knowledge via public demo creds)
- target order in cancellable state
- x-requestid header (public contract)
**Threat-model match:** none
**Why:** Sink verified at CancelOrderCommandHandler.cs:21 - GetAsync(OrderNumber) with no buyer scoping then unconditional SetCancelledStatus(); repo load is bare PK FindAsync (OrderRepository.cs:23) with no EF query filter; sole gate is bare RequireAuthorization (Program.cs:21-22); sibling read path scopes by user (OrdersApi.cs:95) proving ownership data available but unused here.
**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:22-41, src/Ordering.API/Apis/OrdersApi.cs:41, src/Ordering.API/Apis/OrdersApi.cs:22

### [MEDIUM] All three confidential clients share the same hardcoded client secret "secret" (SHA-256 hashed)  (f018)
`src/Identity.API/Configuration/Config.cs:82` | hardcoded-secret | claimed MEDIUM (alignment +0) | confidence 0.8
**Owner:** no CODEOWNERS entry; top committer: Michael Stonis; component: Identity.API/
**Verdict:** needs_manual_test, votes TP 2 / FP 1 / CV 0
**Preconditions (3):**
- secret knowledge (public in source)
- intercepted live authorization code (separate vector)
- PKCE-less redemption path (server permits; .NET OIDC handler defaults PKCE on)
**Threat-model match:** tenant-to-tenant data leakage (indirect)
**Why:** All three confidential clients share Secret("secret".Sha256()) (Config.cs:52/82/118) loaded live via AddInMemoryClients (Program.cs:34); clients send the same plaintext (WebApp/Extensions.cs:78, WebhookClient/Extensions.cs:54, SettingsService.cs:15); webapp RequirePkce=false. Dissent: code-only grant means the secret alone mints nothing and modern OIDC clients enable PKCE client-side, so no concrete standalone exploit (rule 13).
**Reachability evidence:** src/Identity.API/Program.cs:34

> Recommend a human build a PoC; static reasoning hit its limit.

### [MEDIUM] Idempotency key is client-controlled, unbound to user/command, and failed commands are marked processed with a fabricated success result  (f019)
`src/Ordering.Infrastructure/Idempotency/RequestManager.cs:21` | business-logic | claimed MEDIUM (alignment +0) | confidence 0.8
**Owner:** no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Ordering.Infrastructure/
**Verdict:** exploitable, votes TP 2 / FP 1 / CV 0
**Preconditions (2):**
- authenticated session (zero-knowledge)
- induced inner-command failure so the marker commits silently
**Threat-model match:** none
**Why:** Marker row inserted before inner command in the same ambient transaction; inner exception swallowed (IdentifiedCommandHandler.cs:99-102) so TransactionBehavior commits; duplicate path returns fabricated true; OrdersApi.cs:166 returns Ok unconditionally; BasketState.cs:107-108 clears the basket on the fabricated 200 while no order exists. Dissent: cross-user replay requires intercepting an unguessable client-generated GUID; cross-user angle dropped, self-affecting order-loss angle confirmed.
**Reachability evidence:** src/Ordering.API/Application/Commands/IdentifiedCommandHandler.cs:48

### [MEDIUM] JWT audience validation globally disabled in shared library - cross-audience token replay accepted by all eShop backends  (f024)
`src/eShop.ServiceDefaults/AuthenticationExtensions.cs:49` | auth-bypass | claimed MEDIUM (alignment +0) | confidence 0.8
**Owner:** no CODEOWNERS entry; top committer: Michael Stonis; component: eShop.ServiceDefaults/
**Verdict:** exploitable, votes TP 2 / FP 1 / CV 0
**Preconditions (2):**
- validly-issued JWT for any audience (zero-knowledge via swagger clients)
- direct network reachability to the internal API (bypasses the BFF)
**Threat-model match:** none
**Why:** ValidateAudience=false at HEAD in the sole JwtBearer config; fix commit 6b18dda exists only on unmerged branch adityamandaleeka-patch-1; all protected endpoints are bare RequireAuthorization so a basket-audience token replayed to Ordering.API reaches Ship/Cancel/GetOrder. Dissent: no scope/role checks anywhere so cross-audience tokens grant only the same user's own entitlements, and primary clients mint multi-audience tokens anyway (rule 13/3).
**Reachability evidence:** src/Ordering.API/Extensions/Extensions.cs:10

### [MEDIUM] Order items persist client-supplied UnitPrice/Discount/Units with no server-side price verification  (f014)
`src/Ordering.API/Application/Commands/CreateOrderCommandHandler.cs:44` | business-logic | claimed MEDIUM (alignment -1) | confidence 0.8
**Owner:** no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Ordering.API/
**Verdict:** exploitable, votes TP 3 / FP 0 / CV 0
**Preconditions (2):**
- authenticated session (zero-knowledge)
- crafted CreateOrderRequest body
**Threat-model match:** none
**Why:** CreateOrderRequest.Items (List<BasketItem> with client-settable UnitPrice) bound from body, mapped 1:1 by BasketItemExtensions.cs:20-21 with no catalog lookup; validator checks only non-emptiness; aggregate invariants pass unitPrice 0.01; GetTotal() persists the forged total; no server-side price verification anywhere in Ordering.API (grep zero). Caveat: payment is simulated, but the persisted order record is attacker-controlled.
**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:141

### [MEDIUM] Attacker-controlled DestUrl posted to at send time with no re-validation - SSRF from cluster with token/PII exfiltration (TOCTOU on grant-time check)  (f017)
`src/Webhooks.API/Apis/WebHooksApi.cs:41` | ssrf | claimed MEDIUM (alignment -2) | confidence 0.8
**Owner:** no CODEOWNERS entry; top committer: Aditya Mandaleeka / Chris Martinez; component: Webhooks.API/
**Verdict:** exploitable, votes TP 3 / FP 0 / CV 0
**Preconditions (3):**
- authenticated session (zero-knowledge)
- attacker callback satisfying the self-referential grant probe
- self-triggered order-paid/shipped event
**Threat-model match:** none
**Why:** Grant-time same-origin check compares two attacker-supplied URLs from one request; DestUrl stored unrevalidated and POSTed on a redirect-following default HttpClient with no egress/private-range check anywhere in Webhooks.API; 307/DNS-rebinding carries the POST (with custom headers preserved) into internal targets. Corrections: token sent is the attacker's own registration (no exfiltration of others' secrets) and impact is blind SSRF (response discarded) - MEDIUM more than HIGH.
**Reachability evidence:** src/Webhooks.API/Services/WebhooksSender.cs:9, src/Webhooks.API/IntegrationEvents/EventHandling/OrderStatusChangedToPaidIntegrationEventHandler.cs:16

### [MEDIUM] Order-status handlers log full integration events including buyer name and identity GUID  (f054)
`src/WebApp/Services/OrderStatus/IntegrationEvents/EventHandling/OrderStatusChangedToCancelledIntegrationEventHandler.cs:12` | pii-in-logs | claimed MEDIUM (alignment -2) | confidence 0.8
**Owner:** no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: WebApp/
**Verdict:** exploitable, votes TP 3 / FP 0 / CV 0
**Preconditions (2):**
- telemetry export enabled (Aspire default when OTEL endpoint set)
- read access to logs/OTLP backend by a party outside the PII-processing scope
**Threat-model match:** compliance-scoped data exposure (PII/PCI)
**Why:** All six handlers log the destructured event at Information level; events carry BuyerName/BuyerIdentityGuid populated from the real user's checkout name and stable sub GUID; OTel pipeline exports formatted message and structured state to OTLP with no redaction anywhere (grep zero); records' synthesized ToString prints all properties. Concrete CWE-532 over-collection - the handler only needs the GUID yet logs the name too.
**Reachability evidence:** src/WebApp/Services/OrderStatus/IntegrationEvents/EventHandling/OrderStatusChangedToCancelledIntegrationEventHandler.cs:12

### [MEDIUM] Prompt-injectable LLM output is rendered as raw HTML with unrestricted <img src> - remote content injection and PII exfiltration channel  (f015)
`src/WebApp/Components/Chatbot/MessageProcessor.cs:24` | xss-content-injection | claimed MEDIUM (alignment +2) | confidence 0.7
**Owner:** no CODEOWNERS entry; top committer: Stephen Toub; component: WebApp/
**Verdict:** exploitable, votes TP 3 / FP 0 / CV 0
**Preconditions (4):**
- anonymous catalog write (confirmed f003)
- victim chatbot query surfaces poisoned item (probabilistic)
- LLM compliance with injected instruction (probabilistic)
- victim browser fetches attacker URL
**Threat-model match:** compliance-scoped data exposure (PII/PCI)
**Why:** Sink verified: MessageProcessor.cs:24 emits a real <img> with attribute-escaped but scheme/host-unrestricted src, returned as MarkupString (line 30) and rendered at Chatbot.razor:46; no CSP in WebApp; attacker-authored catalog Description reaches model context via SearchCatalog (ChatState.cs:118-128) and GetUserInfo (96-115) supplies PII; MarkupString is the raw-HTML escape hatch so rule 14 does not exclude. Probabilistic step is model compliance, standard for indirect injection.
**Reachability evidence:** src/WebApp/Components/Chatbot/Chatbot.razor:46

### [MEDIUM] GetUserInfo dumps full PII (name, address, email, phone) into LLM context; data is invisible to the user and is held in a transcript that leaves the trust boundary  (f037)
`src/WebApp/Components/Chatbot/ChatState.cs:100` | sensitive-data-exposure | claimed MEDIUM (alignment +0) | confidence 0.7
**Owner:** no CODEOWNERS entry; top committer: Stephen Toub / Eric Erhardt; component: WebApp/
**Verdict:** exploitable, votes TP 2 / FP 1 / CV 0
**Preconditions (4):**
- chat LLM backend enabled (UseFoundry/Ollama)
- authenticated PII-bearing victim
- poisoned catalog item surfaced by the victim's search (probabilistic)
- multi-step LLM compliance (probabilistic)
**Threat-model match:** tenant-to-tenant data leakage
**Why:** GetUserInfo serializes name/address/email/phone claims into model context (ChatState.cs:100-111), tool messages hidden from the user (Chatbot.razor:42), and the whole transcript is re-sent to the configured backend every turn (ChatState.cs:78). Exfil primitive real: MessageProcessor.cs:20-24 renders any model-emitted markdown link/image as <img src> with attacker-chosen URL, and two verifiers confirmed the poisoning vector is externally reachable via the internet-facing mobile-bff catch-all /api/catalog/{*any} route (AppHost/Extensions.cs:142) into unauthenticated CreateItem. Dissent: tool data is the user's own profile in their own session, backend choice is operator config (rule 3), and multi-step LLM compliance is theoretical.
**Reachability evidence:** src/WebApp/Components/Chatbot/ChatState.cs:43, src/WebApp/Components/Chatbot/Chatbot.razor:42

### [MEDIUM] Grant-time OPTIONS probe is an internal network scanner and reachability oracle  (f038)
`src/Webhooks.API/Services/GrantUrlTesterService.cs:14` | ssrf | claimed MEDIUM (alignment +0) | confidence 0.7
**Owner:** no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Webhooks.API/
**Verdict:** exploitable, votes TP 3 / FP 0 / CV 0
**Preconditions (2):**
- authenticated session (zero-knowledge)
- well-formed attacker-supplied Url/GrantUrl URI pair
**Threat-model match:** none
**Why:** TestGrantUrl issues arbitrary OPTIONS to a fully attacker-supplied URL (GrantUrlTesterService.cs:14) with only a self-referential same-origin check (37-45); with Token="" the success condition reduces to 2xx-without-token-echo; outcome surfaced as 201 vs 400 (WebHooksApi.cs:57,61); no egress allowlist/private-range block/rate limit anywhere. Caveats: positive-detection-only oracle (4xx/5xx conflated) and /health targets only mapped in Development.
**Reachability evidence:** src/Webhooks.API/Apis/WebHooksApi.cs:41

### [MEDIUM] Client-supplied UserId/UserName are copied verbatim into the order and Buyer aggregates (order attribution forgery, cross-user basket deletion and notifications)  (f008)
`src/Ordering.API/Apis/OrdersApi.cs:141` | auth-bypass | claimed MEDIUM (alignment -1) | confidence 0.7
**Owner:** no CODEOWNERS entry; top committer: Rob Conery / David Fowler; component: Ordering.API/
**Verdict:** exploitable, votes TP 3 / FP 0 / CV 0
**Preconditions (2):**
- authenticated session (zero-knowledge)
- victim sub GUID required for targeted attribution/basket-wipe
**Threat-model match:** none
**Why:** OrdersApi.cs:141-144 copies body UserId/UserName into CreateOrderCommand; handler :32/:40 uses message.UserId verbatim with IIdentityService injected-but-unused; ValidateOrAddBuyerAggregate handler keys Buyer on attacker guid and attaches attacker card to victim Buyer (Buyer.cs:43-47); Basket.API deletes basket keyed on event UserId. Caveat: targeting a specific victim requires knowing their opaque sub GUID.
**Reachability evidence:** src/Ordering.API/Apis/OrdersApi.cs:141

### [MEDIUM] Raw event message bodies attached to telemetry spans and logged on error  (f032)
`src/EventBusRabbitMQ/RabbitMQEventBus.cs:161` | sensitive-data-in-logs | claimed MEDIUM (alignment +1) | confidence 0.6
**Owner:** no CODEOWNERS entry; top committer: Martin Costello; component: EventBusRabbitMQ/
**Verdict:** exploitable, votes TP 2 / FP 1 / CV 0
**Preconditions (2):**
- read access to observability backend / OTLP pipeline (privileged role or compromise)
- (broker publish access for the forged-content prong - internal foothold)
**Threat-model match:** compliance-scoped data exposure (PII/PCI)
**Why:** Line 161 SetTag puts the full raw body on every consumed message span and :172 logs it verbatim on error, exported via OTLP with no redaction processor; legit events carry BuyerName/BuyerIdentityGuid/UserId, so any handler failure persists order PII to observability backends. Dissent: attacker-controlled prong requires broker access (internal foothold), leaving a data-minimization hygiene issue.
**Reachability evidence:** src/EventBusRabbitMQ/RabbitMQEventBus.cs:272

### [LOW] Subscription token (sent and expected) logged at Information level during grant probing  (f030)
`src/Webhooks.API/Services/GrantUrlTesterService.cs:25` | sensitive-data-in-logs | claimed LOW (alignment -1) | confidence 0.8
**Owner:** no CODEOWNERS entry; top committer: Aditya Mandaleeka; component: Webhooks.API/
**Verdict:** mitigated, votes TP 2 / FP 1 / CV 0
**Preconditions (3):**
- local read access to Webhooks.API logs/OTLP backend
- receiver must enable ValidateToken (default off)
- token is already public in WebhookClient/appsettings.json
**Threat-model match:** none
**Why:** GrantUrlTesterService.cs:17/:25 log the sender-auth token (sent and expected) at Information level in production (appsettings.json:4), no redaction anywhere, OTLP export widens the audience; WebhooksSender.cs:27-30 deliberately omits the token at Debug level, proving the Information-level logging is an oversight. Dissent: the same token is already committed in WebhookClient config, so no marginal capability.
**Reachability evidence:** src/Webhooks.API/Apis/WebHooksApi.cs:41

## Dropped

| id | title | file:line | why dropped |
|---|---|---|---|
| f004 | IdentityServer token-signing private key committed to the re | `src/Identity.API/Program.cs:37` | duplicate of f007 |
| f006 | Login page publicly displays valid credentials for seeded ac | `src/Identity.API/Views/Account/Login.cshtml:46` | duplicate of f027 |
| f011 | Any authenticated user can cancel or ship any order by seque | `src/Ordering.API/Application/Commands/CancelOrderCommandHandler.cs:19` | duplicate of f001 |
| f013 | Client-controlled UserId in order creation drives deletion o | `src/Basket.API/IntegrationEvents/EventHandling/OrderStartedIntegrationEventHandler.cs:14` | duplicate of f008 |
| f016 | Received webhook payloads and tokens rendered to unauthentic | `src/WebhookClient/Components/Pages/Home/Home.razor:20` | FP Mechanism real (ReceivedMessages outside AuthorizeView, renders Data+Token from singleton), but the OrderPaid payload contains only OrderId/ProductId/Units - no PII - and the token shown gates only th... |
| f020 | Confidential OIDC client secret hardcoded as "secret" and ma | `src/WebApp/Extensions/Extensions.cs:78` | duplicate of f018 |
| f022 | Static webhook auth token committed to config, logged at INF | `src/WebhookClient/Endpoints/WebhookEndpoints.cs:35` | duplicate of f021 |
| f025 | OAuth callback uses an unclaimed custom scheme on an exporte | `src/ClientApp/Platforms/Android/WebAuthenticationCallbackActivity.cs:6` | FP Exported custom-scheme activity is the mandatory MAUI WebAuthenticator template; OidcClient enforces state + PKCE (verifier never leaves the app) so a captured code is unexchangeable and forged callba... |
| f026 | NSAllowsArbitraryLoads=true disables ATS entirely in the shi | `src/ClientApp/Platforms/MacCatalyst/Info.plist:29` | FP NSAllowsArbitraryLoads=true unconditional and no Release plist swap confirmed, but shipped flows keep tokens off hostile networks: defaults are mock-mode or loopback, production path is TLS, and the p... |
| f028 | AddToCart tool mutates the signed-in user's basket silently, | `src/WebApp/Components/Chatbot/ChatState.cs:137` | FP Mechanics real (auto-executed AddToCart, no confirmation, tool messages hidden), but two verifiers held the injection trigger unreachable: WebApp has no catalog-write proxy and (per their reading) cat... |
| f029 | Shared webhook authentication token hardcoded and committed  | `src/WebhookClient/appsettings.json:10` | FP Token is non-confidential by design: AddWebhook.razor pre-fills it into a public unauthenticated form, WebhooksSender echoes it to subscriber servers, and with ValidateToken unset the identical forger... |
| f031 | RequireHttpsMetadata=false in all builds for API token valid | `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:39` | FP Flag is unconditional but inert where it matters: AppHost.cs:22 defaults the https launch profile and injects the https identity endpoint into every consumer, so discovery/JWKS go over TLS; the http p... |
| f033 | Catalog decrements arbitrary product stock directly from for | `src/Catalog.API/IntegrationEvents/EventHandling/OrderStatusChangedToPaidIntegrationEventHandler.cs:13` | FP Handler mechanics accurate but every exploit path requires RabbitMQ publish access - an elevated precondition (internal foothold); the sole legitimate publisher builds events server-side from validate... |
| f034 | Ordering.API integration-event handlers transition arbitrary | `src/Ordering.API/Application/IntegrationEvents/EventHandling/OrderPaymentSucceededIntegrationEventHandler.cs:12` | FP Handlers trust payload OrderId with no origin check (verified), but the first link in the attack chain is broker publish access - an elevated precondition; with that foothold the attacker already hold... |
| f035 | Personal access token passed as command-line argument to az  | `build/acr-build/queue-all.ps1:32` | FP No secret exists in source - patToken is a mandatory runtime operator parameter (rule 8); the script is dead legacy code referencing Dockerfiles that no longer exist (zero Dockerfiles repo-wide) with ... |
| f036 | Gateway endpoints default to and are persisted as http:// wi | `src/ClientApp/ViewModels/SettingsViewModel.cs:58` | FP Endpoints are a deliberate user-editable settings surface (SettingsView.xaml:126-163); platform network-security configs restrict cleartext to 10.0.2.2/localhost; the tamperer scenario presupposes roo... |
| f039 | DEBUG Android HTTP handler accepts any self-signed cert with | `src/ClientApp/MauiProgram.cs:125` | FP #if DEBUG registration compiles out of release builds (GetKeyedService returns null, default validation restored); deliberate Microsoft-documented dev-cert pattern for loopback endpoints that never tr... |
| f040 | iOS DEBUG TrustOverrideForUrl uses unanchored prefix match " | `src/ClientApp/MauiProgram.cs:138` | FP Unanchored StartsWith confirmed but DEBUG-only, default endpoint is https://localhost:5243 (loopback, un-MITM-able), no writer of the endpoint setting exists other than the device owner's own Settings... |
| f041 | Antiforgery runs before HTTPS redirection; cookie Secure fla | `src/WebApp/Program.cs:24` | FP Ordering is real but causally irrelevant: a plaintext POST is on the wire before any server middleware runs, so reordering UseHttpsRedirection changes nothing about wire exposure; the http listener ex... |
| f042 | Webhook subscription tokens stored in plaintext in PostgreSQ | `src/Webhooks.API/Model/WebhookSubscription.cs:11` | FP Token is user-supplied at registration and echoed back to its owner via GET; it must be recoverable verbatim for the X-eshop-whtoken header so hashing is impossible; it is already logged in cleartext ... |
| f043 | OpenAPI documents served unauthenticated in all environments | `src/eShop.ServiceDefaults/OpenApi.Extensions.cs:24` | FP MapOpenApi ungated and the implicit-flow doc confirmed, but Ordering/Catalog/Webhooks APIs are internal-only (no WithExternalHttpEndpoints) and the internet-facing YARP BFF proxies only /catalog-api, ... |
| f044 | RequireHttpsMetadata=false plus http:// Authority enables MI | `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:39` | duplicate of f031 |
| f045 | Forged OrderStartedIntegrationEvent deletes any user's baske | `src/Basket.API/IntegrationEvents/EventHandling/OrderStartedIntegrationEventHandler.cs:14` | duplicate of f008 |
| f046 | Catalog "stock validation" handler confirms stock for arbitr | `src/Catalog.API/IntegrationEvents/EventHandling/OrderStatusChangedToAwaitingValidationIntegrationEventHandler.cs:27` | FP Handler is broker-only (AddSubscription); exploit requires broker publish access (elevated precondition) and with it the attacker achieves the identical end state by publishing OrderStockConfirmedInte... |
| f047 | android:allowBackup="true" backs up plaintext Preferences (O | `src/ClientApp/Platforms/Android/AndroidManifest.xml:3` | FP allowBackup=true confirmed but adds no capability: anyone with the required unlocked-device access can repoint endpoints through the app's own Settings UI (same Preferences keys); ClientSecret is the ... |
| f048 | iOS NSAllowsLocalNetworking=true permits cleartext to LAN ho | `src/ClientApp/Platforms/iOS/Info.plist:35` | FP NSAllowsLocalNetworking=true ungated but iOS defaults are loopback (traffic never leaves the device), UseMocks defaults on (zero network calls), the only writer of gateway endpoints is the local Setti... |
| f049 | Consumer swallows all handler exceptions and acknowledges ev | `src/EventBusRabbitMQ/RabbitMQEventBus.cs:170` | FP Ack-always/no-DLX confirmed but the poison-interleaving attack is mechanically invalid: RabbitMQ delivers each message independently in a fresh DI scope (lines 190-207), so a poison message only destr... |
| f050 | Missing "Identity" config section silently disables all auth | `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:24` | FP Early return confirmed but unreachable in shipped configurations: all three consumers bake an Identity section into appsettings.json, configuration layering means env vars can only add/override (never... |
| f051 | Hardcoded OIDC client secret "secret" compiled into the clie | `src/ClientApp/Services/Settings/SettingsService.cs:15` | duplicate of f018 |
| f052 | webapp confidential client disables PKCE on the authorizatio | `src/Identity.API/Configuration/Config.cs:90` | FP RequirePkce=false confirmed, but the sole webapp consumer is the ASP.NET Core OIDC handler which sends PKCE by default on .NET 8+ (never disabled in-repo), so every normal-flow code is bound to a chal... |
| f053 | PAN masking runs before validation and throws unhandled for  | `src/Ordering.API/Apis/OrdersApi.cs:140` | FP Exception before Mediator.Send so no side effects; production surfaces a sanitized 500 ProblemDetails with no disclosure; the endpoint's normal validation failures already produce the identical except... |
| f055 | OIDC confidential client secret hardcoded as "secret" with H | `src/WebhookClient/Extensions/Extensions.cs:54` | duplicate of f018 |
| f056 | Forged paid/shipped events are fanned out to all webhook sub | `src/Webhooks.API/IntegrationEvents/OrderStatusChangedToPaidIntegrationEventHandler.cs:14` | FP Fan-out mechanics verified but the only trigger is broker publish access (elevated precondition); with a foothold the attacker can already forge events at every bus consumer, so this is system-wide tr... |
| f057 | RabbitMQ and Redis are provisioned without explicit authenti | `src/eShop.AppHost/AppHost.cs:10` | FP AddRabbitMQ auto-generates random credentials when none are supplied (no guest/open); every bus-participating container already holds working broker credentials injected via WithReference, so a footho... |
| f058 | AppHost forces ASPNETCORE_FORWARDEDHEADERS_ENABLED=true on a | `src/eShop.AppHost/Extensions.cs:36` | FP The auto-injected ForwardedHeaders middleware uses the parameterless options (loopback known-proxy defaults) and applies headers only when the immediate peer is a known proxy, so an internet client's ... |
| f059 | CI actions pinned to mutable major tags; unpinned npm global | `.github/workflows/playwright.yml:22` | FP Mutable tags and unpinned npm confirmed, but no pull_request_target, zero secrets referenced by executed workflows (demo creds are plaintext, not secrets), markdownlint.yml pins permissions to content... |
| f060 | CI uploads Playwright report artifact containing authenticat | `.github/workflows/playwright.yml:39` | FP Traces do contain authenticated-session data, but the app-under-test is a fresh per-job AppHost stack on the runner (identitydb/Postgres/Redis are runner-local containers that die with the job) and th... |
| f061 | EventBus connection string falls back to amqp://localhost wi | `src/Basket.API/appsettings.json:15` | duplicate of f057 |
| f062 | AndroidManifest ships usesCleartextTraffic="true"; network_s | `src/ClientApp/Platforms/Android/AndroidManifest.xml:3` | FP NSC supersedes the manifest flag on modern targetSdk so real devices permit zero cleartext; the sole carve-out 10.0.2.2 is the emulator's host-loopback alias documented as intentional MAUI dev scaffol... |
| f063 | "throw-fake-exception" magic string in the message body supp | `src/EventBusRabbitMQ/RabbitMQEventBus.cs:163` | FP Zero marginal capability: any malformed body traverses the identical catch-ack path, so an actor with broker access suppresses events with or without the string; publishing a poisoned message drops th... |
| f064 | ExternalController.Challenge accepts arbitrary caller-suppli | `src/Identity.API/Quickstart/Account/ExternalController.cs:34` | FP Dormant and structurally impossible as claimed: Identity.API registers zero external providers (only cookie schemes), an unregistered scheme throws at Challenge and a cookie scheme never writes the id... |
| f065 | Diagnostics endpoint dumps all session claims and cookie pro | `src/Identity.API/Quickstart/Diagnostics/DiagnosticsController.cs:13` | FP Decisive: the page renders HttpContext.AuthenticateAsync() - the auth-cookie principal, which contains only id/username/security-stamp/email/roles - NOT the token claims; card_number/card_security_num... |
| f066 | Outbox events stranded in InProgress/Failed states are never | `src/IntegrationEventLogEF/Services/IntegrationEventLogService.cs:22` | FP No sweeper confirmed, but every publish is wrapped in a Polly retry pipeline (RetryCount=10, exponential backoff) covering BrokerUnreachableException/SocketException - a one-shot injected connection r... |
| f067 | Postgres superuser credentials with weak placeholder passwor | `src/Ordering.API/appsettings.Development.json:3` | FP Deliberately fake, CredScan-suppressed-as-Dummy placeholder in Development-only localhost config; the supported topology injects Aspire-generated connection strings via WithReference env vars that ove... |
| f068 | Circuit-bound identity snapshots: ChatState captures the use | `src/WebApp/Components/Chatbot/Chatbot.razor:106` | FP The trigger cannot occur: logout is a static-SSR form post that signs out and issues a cross-origin redirect to the separate identity-api IdP - a full page load destroying the circuit; re-login round-... |
| f069 | SaveTokens persists the IdP access token inside the auth coo | `src/WebApp/Extensions/Extensions.cs:80` | FP The token sits inside the DataProtection-encrypted cookie ticket (no ITicketStore/custom TicketDataFormat anywhere), so a cookie thief holds an opaque blob and cannot extract the token without the ser... |
| f070 | Unauthenticated MapForwarder relays attacker-shaped {id} int | `src/WebApp/Program.cs:32` | FP Structurally dead: /product-images/{id} is a single-segment template and Kestrel percent-decodes the path before routing, so %2e%2e%2f decodes into three segments and never matches the 2-segment patte... |
| f071 | sub-less access tokens create subscriptions owned by NULL us | `src/Webhooks.API/Apis/WebHooksApi.cs:51` | FP No sub-less token is mintable: identity-api's only clients are GrantTypes.Code/Implicit user-delegation flows (always include sub), the relay forwards user tokens, and the JWT bearer pins the authorit... |
| f072 | Attacker-settable stored PictureFileName is resolved to a fi | `src/Catalog.API/Apis/CatalogApi.cs:263` | FP Live-today step yields nothing: Pics contains exactly 101 repo-shipped .webp product images that are already anonymously served, so pointing an item at one discloses nothing. The harmful SVG/content-t... |
| f073 | Database connection string with password committed to source | `src/Identity.API/appsettings.Development.json:3` | duplicate of f067 |
| f074 | Unauthenticated OPTIONS /check reflects arbitrary attacker h | `src/WebhookClient/Endpoints/WebhookEndpoints.cs:22` | FP The echo is the designed grant handshake: GrantUrlTesterService sends OPTIONS with the token and grants only when the receiver echoes it back, asserted by the unit test. Kestrel rejects CR/LF/NUL inbo... |
| f075 | DEBUG build ships an extra trusted issuer "https://10.0.2.2: | `src/eShop.ServiceDefaults/AuthenticationExtensions.cs:44` | FP JwtBearer still validates signatures against the Authority's JWKS regardless of the extra issuer string; JWKS publishes only public keys so 'obtaining a key from it' confers nothing, and holding the r... |
