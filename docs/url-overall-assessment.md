# Overall URL assessment

The report, saved JSON, API and PDF use one deterministic evidence index (`url-evidence-v1`). It combines URLVet, local checks and Deep Content. It is a heuristic index, not a probability or a guarantee of safety. Source scores remain visible as source details and are not averaged.

| Evidence category | Maximum deduction |
| --- | ---: |
| HTTPS, certificate and defensive headers | 20 |
| URL identity and domain naming/history | 20 |
| Page content | 25 |
| Redirect behavior | 15 |
| Threat reputation | 20 |

The index starts at 100 and subtracts evidence deductions, capped within each category. Stable evidence codes deduplicate overlapping findings across sources. Forms or keywords alone do not confirm phishing. A reported malicious finding caps the score at 10 and preserves the threat verdict. Unverified database submissions do not confirm phishing; missing, failed or unrecorded checks produce partial coverage and cannot confirm safety. With no usable evidence the score is unavailable.

Coverage is displayed separately from score. A high provisional score only describes the evidence that was assessed. Historical reports are recalculated from saved evidence when read, without sending new requests; legacy reports missing source availability remain partial. The original source evidence stays in the saved JSON.

Worker failure diagnostics expose only a fixed stage, an allowed exception class and known project module/line locations. They omit exception text, target URLs and credentials. The shortened-link failure still requires a reproduction on the Docker worker; this change does not bypass SSRF, redirect or TLS protections.
