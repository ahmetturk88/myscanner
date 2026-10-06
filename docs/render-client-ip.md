# Render client IP diagnostic

The admin-only `/admin/proxy-check` page compares a normal request with two independent probes carrying CF-Connecting-IP and X-Forwarded-For respectively. Results are rendered as text and both endpoints disable caching. It changes no proxy settings and performs no authentication attempts.

Sign in as administrator on the deployed site, open the page, click Run check and inspect both results. Repeat using the custom domain and the Render service domain. A missing candidate, changed address or preserved test value requires investigation; do not enable header trust. A successful comparison is evidence for those requests only, not proof of every ingress path.

The parsed candidate is diagnostic only. Neither the candidate nor Cloudflare headers are used to change REMOTE_ADDR or rate-limit identities. Existing explicit TRUSTED_PROXY_CIDRS/TRUSTED_PROXY_HOPS handling remains unchanged.

Cloudflare documents CF-Connecting-IP and its Pseudo IPv4/IPv6 behavior. Same-zone Workers can influence CF-Connecting-IP. Render documents Cloudflare in its public ingress, but that alone does not establish which headers reach this application or whether all alternative ingress paths are safe. Verify the actual ingress contract before implementing a trust profile.

Sources:
- https://developers.cloudflare.com/fundamentals/reference/http-headers/
- https://render.com/articles/how-render-handles-ddos-attacks

Cloudflare error 1000 can occur when a request includes CF-Connecting-IP. The diagnostic reports this as an edge rejection, keeps the normal request and the other probe results, and never treats a blocked probe as a passed comparison or an administrator permission failure.
- https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1000/
