"""Gate Werkzeug proxy handling on explicitly trusted peers and proxy hops."""
import ipaddress
import os
from werkzeug.middleware.proxy_fix import ProxyFix


def address(value):
    if '%' in value:
        raise ValueError('Scoped addresses are not accepted')
    parsed = ipaddress.ip_address(value)
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        return parsed.ipv4_mapped
    return parsed


class TrustedProxyMiddleware:
    def __init__(self, app, networks, hops):
        self.app = app
        self.networks = networks
        self.hops = hops
        # Never trust forwarded Host, Port, or URL Prefix.
        self.fixed = ProxyFix(app, x_for=hops, x_proto=1, x_host=0, x_port=0, x_prefix=0)

    def trusted(self, value):
        return any(value.version == network.version and value in network for network in self.networks)

    def __call__(self, environ, start_response):
        environ['myscanner.proxy_peer'] = environ.get('REMOTE_ADDR', '')
        environ['myscanner.proxy_applied'] = False
        try:
            peer = address(environ.get('REMOTE_ADDR', ''))
            raw = environ.get('HTTP_X_FORWARDED_FOR', '')
            if not self.trusted(peer) or not raw or len(raw) > 2048:
                raise ValueError('Forwarded headers are not trusted')
            parts = raw.split(',')
            if not self.hops <= len(parts) <= 20:
                raise ValueError('Forwarded headers are not trusted')
            chain = [address(part.strip()) for part in parts]
            # Proxies between the selected client and direct peer must also
            # belong to configured networks. A spoofed prefix is not selected.
            intermediates = chain[-(self.hops - 1):] if self.hops > 1 else []
            if any(not self.trusted(proxy) for proxy in intermediates):
                raise ValueError('Forwarded headers are not trusted')
            proto = environ.get('HTTP_X_FORWARDED_PROTO', '').split(',')[-1].strip()
            if proto not in {'http', 'https'}:
                raise ValueError('Forwarded headers are not trusted')
        except ValueError:
            return self.app(environ, start_response)
        environ['HTTP_X_FORWARDED_FOR'] = ', '.join(str(part) for part in chain)
        environ['HTTP_X_FORWARDED_PROTO'] = proto
        environ['myscanner.proxy_applied'] = True
        return self.fixed(environ, start_response)


def render_edge_candidate(environ):
    """Parse a header value, not proof that the sender is a trusted edge."""
    try:
        raw = environ.get('HTTP_CF_CONNECTING_IP', '')
        companion = environ.get('HTTP_CF_CONNECTING_IPV6', '')
        if len(raw) > 100 or len(companion) > 100:
            return None
        candidate = address(raw.strip())
        # Only use the IPv6 companion when Cloudflare supplied a Class E
        # Pseudo IPv4; a client-provided IPv6 header cannot override normal IPv4.
        if isinstance(candidate, ipaddress.IPv4Address) and candidate in ipaddress.ip_network('240.0.0.0/4'):
            candidate = address(companion.strip())
            if not isinstance(candidate, ipaddress.IPv6Address):
                return None
        return str(candidate) if candidate.is_global and not candidate.is_multicast and not candidate.is_reserved else None
    except ValueError:
        return None


class RenderEdgeMiddleware:
    """Explicit public Render ingress contract, never general header trust.

    The operator must ensure requests only reach this app through Render's
    public edge or other trusted processes. Loopback alone is not proof that
    a header originated at Cloudflare. See docs/render-client-ip.md.
    """
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        peer_text = environ.get('REMOTE_ADDR', '')
        environ['myscanner.proxy_peer'] = peer_text
        environ['myscanner.proxy_applied'] = False
        environ['myscanner.identity_source'] = 'direct'
        try:
            peer = address(peer_text)
        except ValueError:
            peer = None
        candidate = render_edge_candidate(environ)
        if peer is not None and str(peer) in {'127.0.0.1', '::1'} and candidate:
            environ['REMOTE_ADDR'] = candidate
            environ['myscanner.proxy_applied'] = True
            environ['myscanner.identity_source'] = 'render-cloudflare'
        # No X-Forwarded-For hop guesses or changes to scheme/Host/Port/Prefix.
        return self.app(environ, start_response)


def configure_trusted_proxy(app, environ=None):
    env = os.environ if environ is None else environ
    raw = env.get('TRUSTED_PROXY_CIDRS', '').strip()
    count = env.get('TRUSTED_PROXY_HOPS', '').strip()
    source = env.get('RENDER_CLIENT_IP_SOURCE', '').strip().lower()
    if source:
        if source != 'cloudflare' or env.get('RENDER', '').strip().lower() != 'true':
            raise RuntimeError('Render client identity requires RENDER=true and RENDER_CLIENT_IP_SOURCE=cloudflare.')
        if raw or count:
            raise RuntimeError('Choose Render client identity or generic trusted proxies, not both.')
        middleware = RenderEdgeMiddleware(app.wsgi_app)
        app.wsgi_app = middleware
        return middleware
    if not raw and not count:
        return None
    if not raw or not count:
        raise RuntimeError('Set both TRUSTED_PROXY_CIDRS and TRUSTED_PROXY_HOPS.')
    try:
        hops = int(count)
        networks = [ipaddress.ip_network(part.strip(), strict=True) for part in raw.split(',')]
        if not 1 <= hops <= 10 or any(network.prefixlen == 0 for network in networks):
            raise ValueError('Unsafe proxy configuration')
    except ValueError as error:
        raise RuntimeError('Invalid trusted proxy networks or hop count.') from error
    middleware = TrustedProxyMiddleware(app.wsgi_app, networks, hops)
    app.wsgi_app = middleware
    return middleware
