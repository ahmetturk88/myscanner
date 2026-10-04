"""Offline tests: no real HTTP, DNS, Redis or external scanner requests."""
from io import BytesIO
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

import requests
from urllib3.response import HTTPResponse
from services.safe_http import (PublicHTTPSession, UnsafeTargetError,
    normalize_url, validate_public_url, public_connection)


def records(*ips):
    return [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM,
             socket.IPPROTO_TCP, '', (ip, 443, 0, 0) if ':' in ip else (ip, 443)) for ip in ips]


def response(status=200, location=None, body=b'public page'):
    headers = {'Content-Type': 'text/html; charset=utf-8'}
    if location:
        headers['Location'] = location
    return HTTPResponse(body=BytesIO(body), status=status, headers=headers,
                        preload_content=False)


class TargetPolicyTests(unittest.TestCase):
    def test_special_ipv4_and_ipv6_addresses_rejected_before_dns(self):
        for host in ['127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.0.1',
                     '169.254.169.254', '100.100.100.200', '0.0.0.0',
                     '224.0.0.1', '192.0.2.1', '[::1]', '[::]', '[fc00::1]',
                     '[fe80::1]', '[::ffff:127.0.0.1]', '[64:ff9b::7f00:1]',
                     '[2002:7f00:1::1]']:
            with self.subTest(host=host), patch('services.safe_http.socket.getaddrinfo') as dns:
                with self.assertRaises(UnsafeTargetError):
                    validate_public_url('http://' + host)
                dns.assert_not_called()

    def test_mixed_public_private_dns_is_rejected(self):
        with patch('services.safe_http.socket.getaddrinfo', return_value=records('8.8.8.8', '::1')):
            with self.assertRaises(UnsafeTargetError):
                validate_public_url('https://example.com')

    def test_all_public_dns_records_are_accepted(self):
        with patch('services.safe_http.socket.getaddrinfo', return_value=records('8.8.8.8', '2606:4700:4700::1111')):
            target = validate_public_url('example.com/path?q=1#fragment')
        self.assertEqual(target.url, 'https://example.com/path?q=1')
        self.assertEqual(len(target.addresses), 2)

    def test_ambiguous_urls_schemes_credentials_and_ports_rejected(self):
        for url in ['file:///etc/passwd', 'ftp://example.com', 'gopher://example.com',
                    'http://user:pass@example.com', 'http://example.com:6379',
                    'http://example.com:0', 'http://example.com:65536',
                    'http://example.com\\@127.0.0.1', 'http://example.com\r\nX: a',
                    'http://[fe80::1%25eth0]', 'http://2130706433', 'http://127.1',
                    'http://localhost', 'http://%31%32%37.0.0.1']:
            with self.subTest(url=url), self.assertRaises(UnsafeTargetError):
                normalize_url(url)

    def test_alternative_ipv4_encoding_resolving_private_is_rejected(self):
        with patch('services.safe_http.socket.getaddrinfo', return_value=records('127.0.0.1')):
            with self.assertRaises(UnsafeTargetError):
                validate_public_url('http://0x7f000001.example.com')

    def test_dns_failure_is_closed(self):
        with patch('services.safe_http.socket.getaddrinfo', side_effect=socket.gaierror()):
            with self.assertRaises(UnsafeTargetError):
                validate_public_url('https://example.com')

    def test_idn_normalization(self):
        self.assertEqual(normalize_url('https://bücher.de'), 'https://xn--bcher-kva.de/')

    def test_tls_tcp_connection_uses_validated_address_without_second_resolution(self):
        with patch('services.safe_http.socket.getaddrinfo', return_value=records('8.8.8.8')) as dns, patch('services.safe_http.socket.socket') as factory:
            conn = public_connection('example.com')
        self.assertEqual(conn, factory.return_value)
        conn.connect.assert_called_once_with(('8.8.8.8', 443))
        self.assertEqual(dns.call_count, 1)

    def test_tcp_failure_closes_socket(self):
        with patch('services.safe_http.socket.getaddrinfo', return_value=records('8.8.8.8')), patch('services.safe_http.socket.socket') as factory:
            factory.return_value.connect.side_effect = OSError('unreachable')
            with self.assertRaises(OSError):
                public_connection('example.com')
            factory.return_value.close.assert_called_once()


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.session = PublicHTTPSession()
        self.addCleanup(self.session.close)

    def mock_pool(self, scheme, responses):
        adapter = self.session.get_adapter(scheme + '://')
        pool = Mock()
        pool.urlopen.side_effect = responses
        patcher = patch.object(adapter.poolmanager, 'connection_from_host', return_value=pool)
        factory = patcher.start()
        self.addCleanup(patcher.stop)
        return factory, pool

    def test_https_pins_ip_preserves_host_sni_and_certificate_checks(self):
        factory, pool = self.mock_pool('https', [response()])
        with patch('services.safe_http.socket.getaddrinfo', return_value=records('8.8.8.8')) as dns:
            result = self.session.get('https://example.com/path', headers={'Host':'127.0.0.1'})
        self.assertEqual(result.text, 'public page')
        self.assertEqual(result.url, 'https://example.com/path')
        self.assertEqual(factory.call_args.args, ('8.8.8.8',))
        kwargs = factory.call_args.kwargs['pool_kwargs']
        self.assertEqual(kwargs['server_hostname'], 'example.com')
        self.assertEqual(kwargs['assert_hostname'], 'example.com')
        self.assertEqual(pool.urlopen.call_args.kwargs['headers']['Host'], 'example.com')
        self.assertEqual(pool.cert_reqs, 'CERT_REQUIRED')
        self.assertEqual(dns.call_count, 1)

    def test_redirect_to_metadata_is_blocked_without_second_http_request(self):
        factory, pool = self.mock_pool('http', [response(302, 'http://169.254.169.254/latest/meta-data/')])
        with patch('services.safe_http.socket.getaddrinfo', return_value=records('8.8.8.8')):
            with self.assertRaises(UnsafeTargetError):
                self.session.get('http://example.com')
        self.assertEqual(pool.urlopen.call_count, 1)
        self.assertEqual(factory.call_count, 1)

    def test_public_redirect_retains_history_and_updates_host(self):
        factory, pool = self.mock_pool('https', [response(302, 'https://other.example.com/final'), response()])
        with patch('services.safe_http.socket.getaddrinfo', side_effect=[records('8.8.8.8'), records('1.1.1.1')]):
            result = self.session.get('https://example.com')
        self.assertEqual(result.url, 'https://other.example.com/final')
        self.assertEqual(len(result.history), 1)
        self.assertEqual(factory.call_args_list[1].args, ('1.1.1.1',))
        self.assertEqual(pool.urlopen.call_args.kwargs['headers']['Host'], 'other.example.com')

    def test_dns_rebinding_on_redirect_is_blocked(self):
        factory, pool = self.mock_pool('https', [response(302, '/second')])
        with patch('services.safe_http.socket.getaddrinfo', side_effect=[records('8.8.8.8'), records('127.0.0.1')]):
            with self.assertRaises(UnsafeTargetError):
                self.session.get('https://example.com')
        self.assertEqual(pool.urlopen.call_count, 1)

    def test_redirect_loop_is_bounded(self):
        _, pool = self.mock_pool('https', [response(302, '/loop') for _ in range(6)])
        with patch('services.safe_http.socket.getaddrinfo', return_value=records('8.8.8.8')):
            with self.assertRaises(requests.exceptions.TooManyRedirects):
                self.session.get('https://example.com')
        self.assertEqual(pool.urlopen.call_count, 6)

    def test_proxy_and_disabled_tls_verification_rejected(self):
        self.assertFalse(self.session.trust_env)
        for kwargs in [{'proxies':{'https':'http://127.0.0.1:3128'}}, {'verify':False}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(UnsafeTargetError):
                self.session.get('https://example.com', **kwargs)

    def test_oversized_response_is_closed(self):
        raw = response(body=b'x' * (5 * 1024 * 1024 + 1))
        self.mock_pool('https', [raw])
        with patch('services.safe_http.socket.getaddrinfo', return_value=records('8.8.8.8')):
            with self.assertRaises(UnsafeTargetError):
                self.session.get('https://example.com')
        self.assertTrue(raw.closed)


class AnalyzerIntegrationTests(unittest.TestCase):
    def test_url_analyzers_reject_private_input_before_provider_or_cache(self):
        from services.url_analyzer import URLDeepAnalyzer
        from services.url_deep_analyzer import URLDeepAnalyzer as LegacyURLDeepAnalyzer
        for cls in [URLDeepAnalyzer, LegacyURLDeepAnalyzer]:
            with tempfile.TemporaryDirectory() as folder:
                analyzer = cls(cache_dir=folder)
                self.addCleanup(analyzer.session.close)
                for method in [analyzer.comprehensive_analysis, analyzer.comprehensive_deep_analysis]:
                    with self.subTest(cls=cls.__module__, method=method.__name__), patch.object(analyzer, '_get_cached_result') as cache, patch.object(analyzer, 'analyze_with_urlvet') as provider:
                        with self.assertRaises(UnsafeTargetError):
                            method('http://127.0.0.1')
                        cache.assert_not_called()
                        provider.assert_not_called()

    def test_site_and_ssl_analyzers_reject_private_input(self):
        from services.site_analyzer import SiteAnalyzer
        from services.ssl_analyzer import SSLAnalyzer
        with tempfile.TemporaryDirectory() as folder:
            analyzer = SiteAnalyzer(cache_dir=folder)
            self.addCleanup(analyzer.session.close)
            with patch.object(analyzer, '_get_cached_result') as cache:
                with self.assertRaises(UnsafeTargetError):
                    analyzer.comprehensive_analysis('http://10.0.0.1')
                cache.assert_not_called()
        with patch('services.safe_http.socket.socket') as connection:
            with self.assertRaises(UnsafeTargetError):
                SSLAnalyzer().analyze_certificate('https://192.168.1.1')
            connection.assert_not_called()

    def test_blocked_redirect_is_propagated_instead_of_scored_safe(self):
        from services.url_analyzer import URLDeepAnalyzer
        from services.site_analyzer import SiteAnalyzer
        with tempfile.TemporaryDirectory() as folder:
            for analyzer in [URLDeepAnalyzer(cache_dir=folder), SiteAnalyzer(cache_dir=folder)]:
                self.addCleanup(analyzer.session.close)
                with patch.object(analyzer.session, 'get', side_effect=UnsafeTargetError('blocked')):
                    with self.assertRaises(UnsafeTargetError):
                        analyzer.check_security_headers('https://example.com')


import test_task_ownership


class ScannerEndpointTests(test_task_ownership.TaskOwnershipTests):
    def setUp(self):
        super().setUp()
        self.app.register_error_handler(UnsafeTargetError, self.production.unsafe_scan_target)
        for route, name in [('/api/url-analyze', 'api_url_analyze'),
                            ('/api/site-scan', 'api_site_scan'),
                            ('/api/ssl-checker', 'api_ssl_checker'),
                            ('/api/scan-subdomain', 'api_scan_subdomain'),
                            ('/api/scan-qr-url', 'api_scan_qr_url')]:
            self.app.add_url_rule(route, name, getattr(self.production, name), methods=['POST'])
        from routes.sandbox_routes import sandbox_bp
        self.app.register_blueprint(sandbox_bp)

    def test_private_targets_return_json_400_in_scanner_routes(self):
        self.sign_in(self.owner)
        for route, field in [('/api/url-analyze', 'url'), ('/api/site-scan', 'domain'),
                             ('/api/ssl-checker', 'domain'), ('/api/scan-subdomain', 'domain'),
                             ('/api/scan-qr-url', 'url'), ('/api/sandbox/analyze-url', 'url')]:
            with self.subTest(route=route), patch('services.safe_http.socket.socket') as network:
                result = self.client.post(route, json={field:'http://127.0.0.1'})
                self.assertEqual(result.status_code, 400)
                self.assertIn('error', result.json)
                network.assert_not_called()

    def test_valid_public_url_can_be_analyzed(self):
        self.sign_in(self.owner)
        page = requests.Response()
        page.status_code = 200
        page._content = b'<html><title>Example</title></html>'
        with patch('services.safe_http.socket.getaddrinfo', return_value=records('8.8.8.8')), \
             patch('services.url_analyzer.URLDeepAnalyzer.check_ssl_certificate', return_value={'valid':True}), \
             patch('services.url_analyzer.URLDeepAnalyzer.check_dns_records', return_value={}), \
             patch('services.url_analyzer.URLDeepAnalyzer.analyze_with_urlvet', return_value={'verdict':'unknown'}), \
             patch.object(PublicHTTPSession, 'get', return_value=page):
            result = self.client.post('/api/url-analyze', json={'url':'https://example.com'})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json['domain'], 'example.com')
        self.assertIn('security_score', result.json)
