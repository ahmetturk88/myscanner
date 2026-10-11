"""A slow target can make URL checks unavailable but cannot hold a worker (S-07)."""
import time
import unittest
from unittest.mock import Mock, patch

from services.safe_http import PublicHTTPSession, ScanBudgetExceeded, _cap_timeout


class SessionBudgetTests(unittest.TestCase):
    def test_expired_budget_stops_before_any_connection(self):
        with PublicHTTPSession() as session, \
             patch('requests.adapters.HTTPAdapter.send') as network, \
             patch('services.safe_http.socket.getaddrinfo') as dns:
            session.set_deadline(time.monotonic() - 1)
            with self.assertRaises(ScanBudgetExceeded):
                session.get('https://example.com/', timeout=15)
            network.assert_not_called()
            dns.assert_not_called()

    def test_request_timeout_is_capped_by_remaining_budget(self):
        import io, requests
        response = requests.Response()
        response.status_code, response.raw, response.url = 200, io.BytesIO(b'ok'), 'https://example.com/'
        with PublicHTTPSession() as session, \
             patch('requests.adapters.HTTPAdapter.send', return_value=response) as network:
            session.set_deadline(time.monotonic() + 2)
            session.get('https://example.com/', timeout=15, allow_redirects=False)
            self.assertLessEqual(network.call_args.kwargs['timeout'], 2)

    def test_cap_handles_connect_read_tuples(self):
        self.assertEqual(_cap_timeout((5, 30), 3), (3, 3))
        self.assertEqual(_cap_timeout((1, None), 3), (1, 3))
        self.assertEqual(_cap_timeout(None, 4), 4)

    def test_budget_is_a_timeout_not_a_policy_rejection(self):
        # Analyzers re-raise UnsafeTargetError (blocked target) but record
        # timeouts as unavailable checks, which keeps the report partial.
        import requests
        from services.safe_http import UnsafeTargetError
        self.assertTrue(issubclass(ScanBudgetExceeded, requests.exceptions.Timeout))
        self.assertFalse(issubclass(ScanBudgetExceeded, UnsafeTargetError))


class URLAnalyzerBudgetTests(unittest.TestCase):
    def setUp(self):
        from services.url_analyzer import URLDeepAnalyzer
        self.analyzer = URLDeepAnalyzer()
        self.addCleanup(self.analyzer.session.close)

    def test_urlvet_runs_once_for_quick_and_deep_phases(self):
        client = Mock()
        client.analyze_url.return_value = {'verdict': 'harmless', 'trust_score': 90}
        self.analyzer._urlvet_client = client
        first = self.analyzer.analyze_with_urlvet('https://example.com/')
        first['verdict'] = 'mutated by caller'
        second = self.analyzer.analyze_with_urlvet('https://example.com/')
        self.assertEqual(client.analyze_url.call_count, 1)
        self.assertEqual(second['verdict'], 'harmless')

    def test_urlvet_errors_are_not_reused(self):
        client = Mock()
        client.analyze_url.return_value = {'verdict': 'error', 'error': 'timeout'}
        self.analyzer._urlvet_client = client
        self.analyzer.analyze_with_urlvet('https://example.com/')
        self.analyzer.analyze_with_urlvet('https://example.com/')
        self.assertEqual(client.analyze_url.call_count, 2)

    def test_exhausted_budget_leaves_header_check_unavailable(self):
        self.analyzer.session.set_deadline(time.monotonic() - 1)
        with patch('requests.adapters.HTTPAdapter.send') as network:
            result = self.analyzer.check_security_headers('https://example.com/')
        network.assert_not_called()
        self.assertIn('error', result)

    def test_whois_has_a_timeout(self):
        import whois
        from services.url_analyzer import WHOIS_TIMEOUT
        with patch.object(whois, 'whois', side_effect=TimeoutError()) as lookup:
            self.analyzer.analyze_whois('example.com')
        self.assertEqual(lookup.call_args.kwargs['timeout'], WHOIS_TIMEOUT)

    def test_url_task_has_a_hard_time_limit(self):
        from tasks import scan_url_task
        self.assertLessEqual(scan_url_task.soft_time_limit, 300)
        self.assertLess(scan_url_task.soft_time_limit, scan_url_task.time_limit)


if __name__ == '__main__':
    unittest.main()
