# TLS observation workspace

SSL Checker performs one verified TLS handshake to a public target on port 443. It retains hostname/SNI and the default trust store and uses public_connection to validate and pin the TCP address. No unverified fallback is made after failed certificate verification.

Reports distinguish verified connection, verification failure and unavailable observations. DNS failure, timeout and other connection failures never become invalid-certificate claims. Failed certificate verification is negative evidence, but does not establish which individual trust, hostname or lifetime check failed; these remain unavailable in the report. Certificate details are returned only after successful verification.

Certificate lifetime does not determine an A–F grade. Short-lived automatically renewed certificates can be valid. A renewal observation is added below 14 days. Negotiated TLS version, cipher name/reported secret bits, issuer, subject/SANs, validity timestamps, serial number and leaf SHA-256 fingerprint are returned. The response is not a full chain inventory.

The percentage measures observation coverage, not website safety or a comprehensive TLS security grade. A single negotiation does not enumerate all supported protocol versions/cipher suites or check OCSP/CRL revocation, CT completeness or HTTP headers. These limitations appear in the workspace and exported JSON.

Domain or standard HTTP(S) URL inputs are accepted up to 2048 characters. Paths are not requested, custom ports and credentials are rejected, and TLS is always observed on 443. The authenticated permission/CSRF-protected endpoint validates payloads, masks exceptions and returns no-store responses.

Run test_ssl_workspace.py and test_ssl_workspace.cjs, and the shared test_tool_result_xss.py. Rebuild the rehearsal stack and verify /ssl-checker using authorized targets before merge. Local offline tests do not validate actual provider connectivity or responsive browser layout.
