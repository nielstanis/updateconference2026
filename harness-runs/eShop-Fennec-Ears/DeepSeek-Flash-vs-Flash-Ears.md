# Comparison: eShop-DeekSeek-v4.1-Flash vs eShop-DeekSeek-v4.1-Flash-Ears-v2

Both outputs were spot-checked against the source in `eShop/src`. Patches were ignored.

| | Flash | Flash-Ears-v2 |
|---|---|---|
| Findings produced | 61 | 25 |
| Triage outcome | 19 true, 38 false positives, 4 duplicates | 23 true, 2 false positives, 0 duplicates |
| Severity after triage | 6 high, 11 medium, 2 low | 6 high, 9 medium, 8 low |
| Threat model | 34 KB | 43 KB, with Fennec flow corroboration |

## Verdict

**Ears-v2 is the better result.**

- **Precision:** Flash raised 61 candidates and dismissed 38 as false positives. Most were speculative or low-value, such as CI tags, a `:latest` image tag, Info.plist settings and a mobile cleartext default. Ears-v2 kept only findings that were real and re-read against source, so it is much easier to act on.
- **Wrong dismissals in Flash:**
  - `ProfileService.cs` issues `card_number`, `card_security_number` and the address claims, as confirmed in the code. Flash dismissed this as a false positive on "intentional behavior". Ears-v2 reports it as F-008.
  - Flash also dismissed the demo credentials and the chatbot image rendering. Ears-v2 keeps the chatbot image rendering as F-020.
- **Dismissals Flash got right:**
  - It correctly refuted the "PAN stored in cleartext" finding. `OrdersApi.cs:140` masks the PAN first.
  - It also dropped the "CVV logged" claim from its first-pass list, though f026 still says PAN and CVV are logged.
- **Merging:** Ears-v2 merges related findings, such as the BFF catch-all routes plus unauthenticated Catalog writes. Flash lists them separately, then marks them as duplicates in triage.
- **Calibration:** Ears-v2 downgraded or suppressed 12 findings, so its severities are more credible. Flash rated several things HIGH (F-002, F-011) and then dismissed them in triage, which is inconsistent. Ears-v2 does have a few LOW items of marginal value.

## Coverage

**Unique to Ears-v2:**
- Redis basket key namespace.
- Consent and login open redirects.
- CVV persisted in the ordering database.
- The webhook grant-URL check comparing two caller-supplied URLs against each other (F-011).
- Unscoped webhook subscription broadcast.

**Unique to Flash:**
- MAUI client token handling and logout.
- Logout CSRF.
- Blind SSRF in `WebhooksSender`.
- Event body logging.
- Webhook token exposure in the WebhookClient UI.

Flash covers the mobile client and the event bus, which Ears-v2 left out of scope.

**Shared findings:**
- Committed signing key.
- `ValidateAudience=false` (confirmed at `AuthenticationExtensions.cs:49`).
- Unauthenticated Catalog writes.
- Order IDOR, and cancel/ship on any order.
- Client-trusted `UserId` and prices.
- Shared client secret `secret`.
- Order entity logged with card data (confirmed at `CreateOrderCommandHandler.cs:50`, which logs `{@Order}`).

## Bottom line

Ears-v2 gives a tighter, more accurate and better calibrated report. Flash covers more surface, including the mobile client and the event bus, but its false-positive rate is about 62% and it dismissed at least one real issue. Combining Ears-v2 with Flash's mobile and event-bus findings would give the best coverage.

I did not verify every finding in either report.
