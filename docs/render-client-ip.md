# Render client IP diagnostic

The admin-only `/admin/proxy-check` page compares a normal request with two independent probes carrying CF-Connecting-IP and X-Forwarded-For respectively. Results are rendered as text and both endpoints disable caching. It changes no proxy settings and performs no authentication attempts.

Sign in as administrator on the deployed site, open the page, click Run check and inspect both results. Repeat using the custom domain and the Render service domain. A missing candidate, changed address or preserved test value requires investigation; do not enable header trust. A successful comparison is evidence for those requests only, not proof of every ingress path.

By default the parsed candidate is diagnostic only. Render client identity requires the explicit opt-in below. Generic TRUSTED_PROXY_CIDRS/TRUSTED_PROXY_HOPS handling remains available for a VPS or another known proxy topology.

Cloudflare documents CF-Connecting-IP and its Pseudo IPv4/IPv6 behavior. Same-zone Workers can influence CF-Connecting-IP. Render documents Cloudflare in its public ingress, but that alone does not establish which headers reach this application or whether all alternative ingress paths are safe. Verify the actual ingress contract before implementing a trust profile.

Sources:
- https://developers.cloudflare.com/fundamentals/reference/http-headers/
- https://render.com/articles/how-render-handles-ddos-attacks

Cloudflare error 1000 can occur when a request includes CF-Connecting-IP. The diagnostic reports this as an edge rejection, keeps the normal request and the other probe results, and never treats a blocked probe as a passed comparison or an administrator permission failure.
- https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1000/

## Opt-in for the public Render web service

Set `RENDER_CLIENT_IP_SOURCE=cloudflare` only after reviewing actual ingress. `RENDER=true` must also be present (Render supplies it). Do not set TRUSTED_PROXY_CIDRS or TRUSTED_PROXY_HOPS at the same time. Unknown profiles, non-Render activation and mixed configuration fail startup instead of silently weakening trust. No profile is enabled automatically in render.yaml.

This profile relies on the PUBLIC Render ingress contract, not cryptographic header authentication. The native Gunicorn app must only receive public requests through the provider edge, or requests from trusted local/private processes. Untrusted private-network callers, local forwarding endpoints, and same-zone Workers that can alter client identity invalidate this assumption. Do not activate it for those deployments. Review this assumption again when adding Workers, services or alternative ingress.

Observed on this service's custom and onrender.com domains: the normal CF-Connecting-IP matched the visitor, an X-Forwarded-For prefix did not change it, and a supplied CF-Connecting-IP was rejected upstream with error 1000. These samples inform the opt-in decision; they do not establish all possible ingress behavior or guarantee future provider behavior.

The middleware uses a single valid public CF-Connecting-IP only when the socket peer is 127.0.0.1 or ::1. It supports IPv4-mapped IPv6 and the documented Pseudo IPv4/IPv6 companion case. Invalid, private, reserved, multicast, scoped or oversized candidates leave the socket identity unchanged, keeping the shared proxy quota rather than accepting a fabricated address. X-Forwarded-For is never used as a fallback; Host, scheme, port and URL prefix are unchanged. An IP is a quota key, not authorization or user identity proof.

After deployment and explicit activation, sign in as admin and check `/admin/proxy-info` on both domains. Expect configured=true, applied=true, identity_source=render-cloudflare, peer_ip=127.0.0.1 and client_ip matching edge_candidate. Repeat the diagnostic button; edge rejection remains a review result. Test from an independent internet connection when available to verify separate quota identities. Users sharing a phone hotspot naturally share an IP quota.

To roll back, remove RENDER_CLIENT_IP_SOURCE and redeploy. Remove the Render-specific setting before moving to the VPS; configure the actual trusted proxy CIDRs/hops there.
