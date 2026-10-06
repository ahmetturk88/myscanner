"""Public HTTP(S) targets only, with validated IPs pinned at connection time."""
from dataclasses import dataclass
import ipaddress
import re
import socket
import time
from urllib.parse import urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter


class UnsafeTargetError(requests.exceptions.RequestException):
    """The target is outside the public web scanner's network policy."""


@dataclass(frozen=True)
class PublicTarget:
    url: str
    hostname: str
    port: int
    addresses: tuple


def normalize_url(value):
    if not isinstance(value, str) or not value:
        raise UnsafeTargetError('A public HTTP or HTTPS URL is required')
    if any(ord(c) <= 32 or ord(c) == 127 for c in value) or '\\' in value:
        raise UnsafeTargetError('Invalid URL characters')
    if '://' not in value:
        value = 'https://' + value
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in ('http', 'https') or not parts.hostname:
            raise ValueError()
        if parts.username is not None or parts.password is not None:
            raise ValueError()
        host = parts.hostname.encode('idna').decode('ascii').lower()
        port = parts.port if parts.port is not None else (443 if parts.scheme.lower() == 'https' else 80)
        if port not in (80, 443) or '%' in host:
            raise ValueError()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            labels = host.rstrip('.').split('.')
            if len(labels) < 2 or all(label.isdigit() for label in labels):
                raise ValueError()
            if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels):
                raise ValueError()
        authority = '[' + host + ']' if ':' in host else host
        if parts.port is not None:
            authority += ':' + str(port)
        return urlunsplit((parts.scheme.lower(), authority, parts.path or '/', parts.query, ''))
    except (ValueError, UnicodeError) as error:
        raise UnsafeTargetError('Only public HTTP(S) targets on ports 80 or 443 without credentials are allowed') from error


def _public_address(value):
    address = ipaddress.ip_address(value)
    # Reject IPv6 transition mechanisms as well as special/non-global ranges.
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped or address.sixtofour or address.teredo:
            return False
        if address in ipaddress.ip_network('64:ff9b::/96') or address in ipaddress.ip_network('64:ff9b:1::/48'):
            return False
    return address.is_global and not address.is_multicast


def validate_public_url(value):
    url = normalize_url(value)
    parts = urlsplit(url)
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == 'https' else 80)
    try:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None and not _public_address(str(literal)):
            raise UnsafeTargetError('The target must resolve only to public IP addresses')
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not records or any(not _public_address(record[4][0]) for record in records):
            raise UnsafeTargetError('The target must resolve only to public IP addresses')
    except (socket.gaierror, ValueError) as error:
        raise UnsafeTargetError('The target could not be resolved to public IP addresses') from error
    return PublicTarget(url, host, port, tuple(records))


def public_connection(domain, port=443, timeout=10):
    """Create a TCP connection to a validated address, without resolving again."""
    scheme = 'https' if port == 443 else 'http'
    authority = '[' + domain + ']' if ':' in domain and not domain.startswith('[') else domain
    target = validate_public_url(f'{scheme}://{authority}:{port}')
    family, socktype, protocol, _, address = target.addresses[0]
    connection = socket.socket(family, socktype, protocol)
    connection.settimeout(timeout)
    try:
        connection.connect(address)
    except BaseException:
        connection.close()
        raise
    return connection


class PublicHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, response_limit=5 * 1024 * 1024, deadline=None, **kwargs):
        self.response_limit = response_limit
        self.deadline = deadline
        super().__init__(*args, **kwargs)

    def _pool(self, url, pool_kwargs=None, proxies=None):
        if proxies and any(proxies.values()):
            raise UnsafeTargetError('Proxies are disabled for public target scans')
        target = validate_public_url(url)
        scheme = urlsplit(target.url).scheme
        kwargs = dict(pool_kwargs or {})
        if scheme == 'https':
            kwargs.update(assert_hostname=target.hostname, server_hostname=target.hostname)
        return self.poolmanager.connection_from_host(
            target.addresses[0][4][0], port=target.port, scheme=scheme, pool_kwargs=kwargs,
        )

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        _, kwargs = self.build_connection_pool_key_attributes(request, verify, cert)
        return self._pool(request.url, kwargs, proxies)

    def get_connection(self, url, proxies=None):
        # Compatibility for local Requests versions before 2.32.2.
        return self._pool(url, proxies=proxies)

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        if verify is False:
            raise UnsafeTargetError('TLS certificate verification is required')
        parts = urlsplit(normalize_url(request.url))
        # Recompute for every redirect; never forward another origin's Host.
        request.headers['Host'] = parts.netloc
        response = super().send(request, stream=True, timeout=timeout or 15,
                                verify=verify, cert=cert, proxies=proxies)
        try:
            content = bytearray()
            for chunk in response.iter_content(65536):
                content.extend(chunk)
                if self.deadline is not None and time.monotonic() >= self.deadline:
                    raise UnsafeTargetError('The response exceeded the scan time budget')
                if len(content) > self.response_limit:
                    raise UnsafeTargetError('The target response exceeds the scan size limit')
            response._content = bytes(content)
            response._content_consumed = True
            return response
        finally:
            response.close()


class PublicHTTPSession(requests.Session):
    def __init__(self, response_limit=5 * 1024 * 1024, deadline=None):
        super().__init__()
        self.trust_env = False
        self.max_redirects = 5
        self.mount('http://', PublicHTTPAdapter(response_limit=response_limit, deadline=deadline))
        self.mount('https://', PublicHTTPAdapter(response_limit=response_limit, deadline=deadline))

    def request(self, method, url, **kwargs):
        return super().request(method, normalize_url(url), **kwargs)
