# Password strength and breach coverage

This change addresses audit item 18 (provider failure must not mean safe), and parts of items 22/23 (password logging and explicit provider choice). It does not close those items across all services.

## Request and privacy

`POST /api/check-password` accepts a password string of 1–1024 characters and optional boolean `check_breaches` (default false). Authentication and global CSRF requirements remain unchanged. Validation occurs before atomic daily quota reservation. Invalid consent types do not reserve quota. Accepted attempts count even if the provider later fails.

The password reaches the MyScanner server for strength analysis. The optional external lookup sends only the first five uppercase hexadecimal characters of its SHA-1 hash to the fixed HTTPS Pwned Passwords range endpoint. The full password and complete digest are not sent to that provider. The request uses `Add-Padding: true`, rejects redirects, bounds connect/read timeouts and response size, and checks an elapsed-time deadline between received chunks. This is a streaming deadline check, not a hard process deadline.

The page discloses server processing and optional prefix disclosure; the checkbox is unchecked by default. No password, password fragment, digest or provider exception text is intentionally logged or returned. Operational proxies and historical logs still need the deployment privacy review. The analyzer's request session closes after each endpoint attempt.

## Result contract

| `pwned.status` | `is_pwned` | `count` | Meaning |
|---|---|---|---|
| `found` | true | Positive integer | A matching suffix with positive occurrence count was received |
| `not_found` | false | 0 | A valid complete range response had no positive matching entry |
| `unavailable` | null | null | Request failure, HTTP error/redirect, incomplete or malformed response, bounds exceeded |
| `skipped` | null | null | The user did not request the optional lookup |

Every record must have a 35-character uppercase hexadecimal suffix and bounded nonnegative decimal count; duplicate suffixes invalidate the response. The whole response is checked before issuing a match result. Zero-count padding entries do not indicate exposure. Occurrences are dataset counts, not a claim about the number of separate breaches.

A failed lookup preserves the strength estimate and returns overall `status: partial` with `coverage.breach_lookup: unavailable`. A skipped lookup reports that it was not checked; completion of requested local work does not imply complete breach coverage. Confirmed exposure retains the existing score penalty. Strength labels are estimates, never a safety verdict. Existing entropy/crack-time heuristics and the generator need separate quality review; this change does not validate them as real attack-time predictions.

The interface and copied report distinguish all four states. Missing/legacy `is_pwned: false` without an explicit completed dataset status is treated as unknown. A positive finding remains visible even if a status field is missing.

## Validation and remaining work

Twenty new tests cover positive/negative matches, padding, HTTP errors, malformed and partially streamed responses, time and size bounds, prefix-only requests, log privacy, consent, quota-preserving validation, session cleanup, generic errors and rendered/copied states. One JavaScript execution test requires Node; the remaining 19 run without it. Existing five-tool XSS execution fixtures also cover the updated password renderer.

Provider protocol reference: https://haveibeenpwned.com/API/V3#PwnedPasswords . Tests use mock responses and do not submit a real password or prove live-provider availability. Live deployment integration, historical logs, other providers' coverage, browser generation and strength-estimation quality remain pending.
