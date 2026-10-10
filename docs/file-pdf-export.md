# File PDF export

The file scanner report toolbar provides Download PDF after a new scan. The export uses a server-issued, signed receipt bound to the logged-in owner and valid for one hour. Export does not rescan or upload the sample to another service. A new scan is required after expiry or for reports created before this feature.

The authenticated POST endpoint `/api/file-report/pdf` remains under global CSRF protection. It accepts only the receipt, not an arbitrary client-supplied report. Responses are private/no-store PDF attachments, and invalid, expired or foreign receipts are rejected. Receipt content is signed rather than encrypted; it contains a bounded subset of evidence already returned to that same account. JSON export omits the receipt.

The A4 report includes verdict and coverage, provider status, recommendations, file format, fingerprints, metadata, findings and embedded indicators. Partial evidence never becomes a perfect overall safety score. A confirmed malicious verdict/hash match remains visible even with incomplete coverage. Indicators are inert text with no active PDF links. Fonts bundled with ReportLab are embedded for consistent layout; unsupported non-ASCII characters are represented by Unicode escapes. PDF sections are bounded and JSON remains the full-data export.

Validation: `python -m unittest discover -s tests -p test_file_pdf.py -v`. The three text-extraction tests use optional `pypdf`; ownership/expiry/CSRF/download checks run without it. `node tests/test_file_workspace.cjs` tests the actual PDF button request and expired-export feedback.

Local smoke check: rebuild the rehearsal stack, refresh the file scanner, run a new small-file scan, and click Download PDF. Check page breaks, long filename/hash wrapping, source status and a partial result's unassigned score.

The cover and workspace display the versioned file-evidence-v1 index as a percentage. It starts with the local static index, deducts 15 points when hash reputation is unverified, 10 for reported missing checks (or otherwise partial coverage), and 25 for absent local index or failed metadata. Missing local index receives no baseline credit. Confirmed malicious verdicts/hashes force zero; suspicious/high-risk verdicts cap at 59/29. Zero therefore requires reading the verdict and coverage. This index is a policy summary, not a probability of safety. The raw local index remains in JSON.
