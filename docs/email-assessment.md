# Email evidence assessment

The email page has a responsive input view and a single result report. Five categories contribute to an evidence index: routing 20, sender records 25, domain reputation 25, SMTP acceptance 15, domain history 15. Findings deduct points within each category; unavailable checks deduct five points each, limited by the remaining category weight. The index is neither a probability of safety nor a delivery guarantee.

SMTP is off by default. Selecting its checkbox explicitly requests a recipient probe that discloses the address to the receiving mail server. No email body is sent. Bulk checks use the default and skip SMTP. A server acceptance or rejection only describes that probe, and does not establish ownership or future delivery.

DNS failures remain unavailable. DKIM message verification and breach exposure are explicitly not checked. SPF/DMARC record presence is reported; full sender-policy evaluation is not implemented. DNS blocklist results describe an IP and do not establish that a mailbox is malicious. Unrecognized blocklist response codes remain unavailable.

The report explains findings and coverage deductions, exposes source details in native expandable sections, and offers JSON, CSV and clipboard exports. CSV cells neutralize leading spreadsheet formula characters. Provider text is escaped or assigned with textContent. Exported reports contain the address and evidence; handle them accordingly.

Validation: email assessment, DNS failure and source-code handling, SMTP opt-in and public-target tests, template rendering and Node execution of hostile result data. Browser layout and a fresh end-to-end email scan must also be reviewed in the Docker rehearsal before merge.
