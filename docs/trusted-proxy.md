# Trusted reverse proxies

Proxy headers are ignored by default. Do not enable trust solely because a request
contains X-Forwarded-For or because the application is in production.

Configure both TRUSTED_PROXY_CIDRS (comma-separated exact proxy networks) and
TRUSTED_PROXY_HOPS (1–10). A direct peer must belong to those networks. Each
intermediate address in the selected trusted suffix must also be trusted.
The client is selected by counting from the right; extra spoofed prefixes are ignored.
Malformed, oversized, too-short, or untrusted chains fall back to the direct peer.

HTTPS is applied only from a trusted request with a valid forwarded IP chain and
the final X-Forwarded-Proto value http/https. Host, Port, and Prefix headers are never
trusted. Proxies MUST overwrite or correctly append their forwarded headers.

## VPS with one Nginx proxy on loopback

Bind Gunicorn only to 127.0.0.1:10000, keeping the backend inaccessible from the Internet.
Set:
TRUSTED_PROXY_CIDRS=127.0.0.1/32,::1/128
TRUSTED_PROXY_HOPS=1

Nginx must set:
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header Host $host;

For Docker, use the actual isolated proxy network/address instead of the loopback example.
Do not trust all IPv4/IPv6 addresses or arbitrarily broad private networks.

## Render: measure before enabling

The number of proxies and their networks must be verified for the actual service.
Do not assume a single proxy or select the leftmost header blindly.
No Render trust values are automatically enabled by this change.

Sign in as an administrator and visit /admin/proxy-info over the hosted HTTPS URL.
The response shows only peer/client IPs, forwarded chain/protocol, and whether the
middleware was configured/applied. It is admin-only and Cache-Control=no-store.
This metadata describes a request; it does NOT prove a peer/network is trustworthy.
Validate the proxy topology/networks with the provider before configuring trust.

After configuration, compare requests from two different networks and a request
with a fake X-Forwarded-For prefix. Client identities must remain correct, spoofing
must not reset authentication quotas, and scheme must remain https.
Do not switch production security off to work around incorrect proxy settings.

Sources:
https://flask.palletsprojects.com/en/stable/deploying/proxy_fix/
https://werkzeug.palletsprojects.com/en/stable/middleware/proxy_fix/
