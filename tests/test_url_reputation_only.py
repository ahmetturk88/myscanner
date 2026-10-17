"""Addresses on ports other than 80/443 are judged by reputation only and never contacted."""
import unittest
from unittest import mock

from services.safe_http import (UnsafeTargetError, accept_scan_url, needs_reputation_only, normalize_url,
                                reputation_only_url)
from services.url_assessment import NOT_VISITED, assess_url

MALWARE = 'http://61.53.153.148:38141/bin.sh'


class AddressTests(unittest.TestCase):
    def test_other_ports_become_reputation_only(self):
        self.assertEqual(reputation_only_url(MALWARE), MALWARE)
        self.assertEqual(reputation_only_url('https://Example.com:8443/a'), 'https://example.com:8443/a')
        self.assertIsNone(reputation_only_url('https://example.com/'))
        self.assertTrue(needs_reputation_only(MALWARE))
        self.assertFalse(needs_reputation_only('https://example.com:443/'))

    def test_private_credentials_and_invalid_ports_stay_refused(self):
        for url in ('http://127.0.0.1:8080/', 'http://10.0.0.5:22/', 'http://user:pw@example.com:8080/',
                    'http://example.com:0/', 'http://example.com:65536/', 'ftp://example.com:21/', 'http://localhost:8080/'):
            with self.subTest(url=url), self.assertRaises(UnsafeTargetError):
                accept_scan_url(url)

    def test_visiting_still_refuses_other_ports(self):
        with self.assertRaises(UnsafeTargetError):
            normalize_url(MALWARE)


class AnalysisTests(unittest.TestCase):
    def test_reputation_only_analysis_never_connects_to_the_address(self):
        from services.url_analyzer import URLDeepAnalyzer
        analyzer = URLDeepAnalyzer()
        osint = {'urlhaus': True, 'urlhaus_status': 'matched', 'urlhaus_reason': None, 'details': []}
        with mock.patch('services.url_analyzer.public_connection', side_effect=AssertionError('connected')), \
                mock.patch('services.safe_http.socket.getaddrinfo', side_effect=AssertionError('resolved')), \
                mock.patch.object(analyzer, 'check_osint_sources', return_value=osint) as lookup:
            local, deep = analyzer.reputation_only_analysis(MALWARE)
        lookup.assert_called_once_with(MALWARE)
        self.assertTrue(local['reputation_only'] and deep['reputation_only'])
        self.assertTrue(local['structure']['contains_ip'])
        result = assess_url(local, deep)
        self.assertEqual(result['verdict'], 'malicious')
        self.assertEqual(result['missing_checks'], [NOT_VISITED])

    def test_unlisted_address_is_not_called_clean(self):
        local = {'reputation_only': True, 'structure': {'is_https': False, 'contains_ip': True}, 'phishing': {'risk_score': 0}}
        deep = {'reputation_only': True, 'osint': {'urlhaus': False, 'urlhaus_status': 'not_found'}}
        result = assess_url(local, deep)
        self.assertEqual(result['verdict'], 'suspicious')
        self.assertEqual(result['missing_checks'], [NOT_VISITED])


if __name__ == '__main__':
    unittest.main()
