# Overall URL assessment

The report, saved JSON, API and PDF use one deterministic evidence index (`url-evidence-v3`). It combines URLVet, local checks and Deep Content. It is a heuristic index, not a probability or a guarantee of safety. Source scores remain in saved data and are not averaged. The web report presents one primary combined score; provider, connection and deep evidence sit in native expandable sections.

| Evidence category | Maximum deduction |
| --- | ---: |
| HTTPS, certificate and defensive headers | 20 |
| URL identity and domain naming/history | 20 |
| Page content | 25 |
| Redirect behavior | 15 |
| Threat reputation | 20 |

The index starts at 100 and subtracts evidence deductions, capped within each category. Stable evidence codes deduplicate overlapping findings across sources. Forms or keywords alone do not confirm phishing. A reported malicious finding caps the score at 10 and preserves the threat verdict. Unverified database submissions do not confirm phishing; missing, failed or unrecorded checks produce partial coverage and cannot confirm safety. With no usable evidence the score is unavailable.

Coverage deductions are explicit and separate from risk indicators (`url-evidence-v3`). An entirely unassessed category loses its full weight. Within an assessed category each unique missing check costs 5 points; quick/deep duplicates count once. Risk and coverage deductions combined cannot exceed that category's weight. `score` is the resulting assessment index; `evidence_score` is the risk-only calculation. Neither is a probability. Missing coverage alone does not establish a threat, so the verdict can remain unknown even when the numeric index is high. With no usable evidence there is no numeric score. Historical reports are recalculated from saved evidence when read, without sending new requests; legacy reports missing source availability remain partial. The original source evidence stays in the saved JSON.

Worker failure diagnostics expose only a fixed stage, an allowed exception class and known project module/line locations. They omit exception text, target URLs and credentials. The shortened-link failure still requires a reproduction on the Docker worker; this change does not bypass SSRF, redirect or TLS protections.

The web layout separates the main verdict, category observations, scored findings and coverage gaps. Unknown source outcomes use “Not verified”, not “Clean”. Source subtotals in expanded evidence are labeled as heuristic subtotals rather than probabilities.

URLhaus requires an Auth-Key HTTP header (https://urlhaus-api.abuse.ch/). The integration supports URLHAUS_AUTH_KEY or URLHAUS_AUTH_KEY_FILE and reports a fixed coverage_reason when unconfigured, rejected, rate-limited or unavailable; it never prints the key or follows provider redirects. The URLVet Compose override mounts this optional credential in web and worker only. The generator creates an empty placeholder; run `python scripts/configure_urlhaus.py` locally to enter the key through a hidden prompt. Existing nonempty keys are preserved. Recreate web and worker to apply the secret mount.
