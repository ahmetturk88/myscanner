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


def configure_trusted_proxy(app, environ=None):
    env = os.environ if environ is None else environ
    raw = env.get('TRUSTED_PROXY_CIDRS', '').strip()
    count = env.get('TRUSTED_PROXY_HOPS', '').strip()
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
