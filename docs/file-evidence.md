# File evidence and reputation

File uploads remain static inspection only. No sample is executed, extracted to disk or submitted to MalwareBazaar. Only a SHA-256 hash query is sent to that provider.

## Credentials

MalwareBazaar requires an abuse.ch Auth-Key. The rehearsal URLVet overlay supplies MALWAREBAZAAR_AUTH_KEY_FILE using the already mounted abuse.ch credential. No key is embedded in the image or echoed. Other deployments may set MALWAREBAZAAR_AUTH_KEY_FILE, MALWAREBAZAAR_AUTH_KEY or the legacy ABUSE_CH_KEY. An explicit unreadable or invalid file does not silently fall back to another credential. Missing credentials produce not_configured without a request. Authentication rejection, rate limiting and other failures have separate generic reason codes.

## Static observations

- ZIP and OpenXML identification uses the directory rather than only the first 1000 bytes.
- Archive inspection checks member paths, executable/script presence, encryption and compression ratios without extracting members.
- OpenXML inspection checks VBA project names, embedded objects and external relationships. Ordinary printer-setting .bin members are not labeled macros.
- XML reads are limited to 1 MiB per member and 2 MiB total; encrypted, oversized, highly compressed and declaration-bearing XML stays unassessed. At most 1000 member records are inspected and 100 displayed. A truncated check does not establish absence.
- UTF-8 text is identified as text. A language label comes from the filename, not execution or an authenticity check.
- File names, familiar domains and document extensions cannot suppress byte observations or raise a benign score.
- A low heuristic score indicates high risk rather than confirmed malware. A matched malicious hash overrides benign heuristics. A failed local analysis has no invented numerical score.

## Limits

This is not a multi-engine antivirus or a sandbox. Legacy OLE macro parsing and unsupported archive formats remain explicitly unavailable. PDF checks examine visible byte tokens; compressed streams and the object graph are not parsed. External relationships remain inert strings and are not fetched. A container directory inspection does not establish that each member is harmless.

## Rehearsal

Run `python -m unittest discover -s tests -p test_file_evidence_upgrade.py -v`, rebuild and start the full rehearsal Compose stack, then upload a small non-sensitive script and document. In the file report, inspect MalwareBazaar status and reason: `not_found` is a dataset negative; `not_configured` or `unavailable` is not a safety conclusion. Verify live connectivity locally before merging.
