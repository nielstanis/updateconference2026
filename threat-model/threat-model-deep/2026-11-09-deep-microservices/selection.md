# Architecture selection: eShop

This is private review material. It records a selection, not an analysis. Companion JSON: `selection.json` (model `eshop-2026-11-09`, revision `r00-selection`, status partial).

## Inspection coverage

- Evidence was read fresh in this run at revision `913acea` (taken from the session context; Git was not used, so revision and working-tree state are unverified).
- About 52 files were read in full and 17 partially (greps or line ranges). The unread parts include Identity Razor views, Ordering validators and repositories, Catalog AI code, webhook fan-out, Blazor pages, MAUI views, and dependency manifests. Details are in `unprocessed_inputs`.
- Unmapped boundaries: mobile-bff/ACA ingress exposure (G-ub1), broker credentials and ACLs (G-ub2), model-provider path (G-ub3), webhook egress policy (G-ub4).
- Complete bodies of the selected prompts were not read when this selection was made (G-sel-availability), so availability is only confirmed at the registry and README level.

## Primary

`microservices`. The decision this review supports is how much authority each service and each edge route carries. The evidence that drives the choice: several internal APIs sit behind a catch-all YARP gateway (E3), Catalog write routes have no authentication (E4), Ordering checks that a caller is logged in but not whose order it is (E7), and one RabbitMQ exchange connects every service with unsigned events (E19, E20).

## Bounded secondaries (recommended, not run in this chain)

| Architecture | Subsystem | What it adds | Left out |
| --- | --- | --- | --- |
| `identity-federation` | Identity.API client registry, shared JWT validation, WebApp/MAUI/WebhookClient OIDC settings | Audience, scope and PKCE handling; sample client secrets | Account linking, external IdPs, Razor views |
| `agentic-ai` | WebApp chatbot tools and model provider | Tool authority and claim disclosure to a model; active only when Foundry is enabled | Provider internals, embedding generation |

The microservices stages still touch these boundaries, since they own the token and tool hops they cross. They do not replace a dedicated pass.

## Excluded as primary

`web`, `event-driven`, `payments-transactions`, `multi-tenant-saas`, `cicd-supply-chain` and `mobile`. Each either duplicates the primary's boundaries (web, event-driven), has no matching evidence (payment is simulated, no tenant model), or was read too thinly (mobile, CI).

## Next smallest useful evidence

Generated ACA ingress and YARP effective configuration. That settles whether the Catalog write routes and the Ordering routes are reachable from outside (G-ub1).

## Not done in selection

No threats, controls, treatments, risk ratings or verification were created. The six deep stages follow in this run.
