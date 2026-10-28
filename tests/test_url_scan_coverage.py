"""Offline provider-coverage regression checks, including both analyzer copies."""
import copy
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from services.url_scan_coverage import apply_url_coverage, reputation_settled, url_scan_outcome, urlvet_available, PARTIAL_WARNING


class URLCoverageTests(unittest.TestCase):
    def test_zero_is_valid_provider_score(self):
        self.assertTrue(urlvet_available({'verdict': 'malicious', 'trust_score': 0}))

    def test_invalid_or_failed_provider_is_unavailable(self):
        for provider in [None, {}, {'verdict': 'error', 'trust_score': 0},
                         {'verdict': 'harmless', 'trust_score': 100, 'errors': ['timeout']},
                         {'verdict': 'harmless', 'trust_score': float('nan')},
                         {'verdict': 'harmless', 'trust_score': True}]:
            with self.subTest(provider=provider):
                self.assertFalse(urlvet_available(provider))

    def test_partial_safe_becomes_unknown_and_warning_is_idempotent(self):
        result = {'verdict': 'safe', 'urlvet': {'error': 'offline', 'trust_score': 0},
                  'recommendations': ['✅ No threats detected - URL appears safe to visit']}
        apply_url_coverage(result)
        apply_url_coverage(result)
        self.assertEqual(result['verdict'], 'unknown')
        self.assertEqual(result['assessment_status'], 'partial')
        self.assertEqual(result['recommendations'], [PARTIAL_WARNING])

    def test_partial_preserves_detected_threat(self):
        for verdict in ['suspicious', 'high_risk', 'malicious']:
            with self.subTest(verdict=verdict):
                local = apply_url_coverage({'verdict': verdict, 'urlvet': {}})
                self.assertEqual(url_scan_outcome(local, {'urlvet': {}}), ('partial', verdict))

    def test_completed_requires_both_provider_results(self):
        good = {'verdict': 'safe', 'urlvet': {'verdict': 'harmless', 'trust_score': 95}}
        self.assertEqual(url_scan_outcome(good, good), ('completed', 'harmless'))
        self.assertEqual(url_scan_outcome(good, {'verdict': 'safe', 'urlvet': {}}), ('partial', 'unknown'))

    def test_deep_provider_failure_adds_no_fake_risk_and_is_not_cached(self):
        from services import url_analyzer, url_deep_analyzer
        for module in [url_analyzer, url_deep_analyzer]:
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as cache:
                analyzer = module.URLDeepAnalyzer()
                methods = {
                    'analyze_behavior': {'behavior_risk_score': 0},
                    'analyze_page_content': {'content_risk_score': 0},
                    'analyze_whois': {'whois_risk_score': 0},
                    'check_osint_sources': {'osint_risk_score': 0},
                    'analyze_url_structure': {'is_https': True},
                    'check_phishing_indicators': {'risk_score': 0},
                    'check_ssl_certificate': {}, 'check_dns_records': {},
                    'check_security_headers': {'score': 100},
                    'analyze_with_urlvet': {'verdict': 'error', 'trust_score': 0, 'error': 'offline'},
                }
                from contextlib import ExitStack
                with ExitStack() as stack:
                    stack.enter_context(patch.object(module, 'validate_public_url', return_value=SimpleNamespace(url='https://example.invalid')))
                    stack.enter_context(patch.object(analyzer, '_get_cached_result', return_value=None))
                    saved = stack.enter_context(patch.object(analyzer, '_save_cached_result'))
                    for name, value in methods.items():
                        stack.enter_context(patch.object(analyzer, name, return_value=copy.deepcopy(value)))
                    result = analyzer.comprehensive_deep_analysis('https://example.invalid')
                self.assertEqual(result['overall_risk_score'], 0)
                self.assertEqual(result['verdict'], 'unknown')
                saved.assert_not_called()

    def test_a_threat_list_outage_is_never_reused_from_the_cache(self):
        # A Web Risk billing error cached for a day hid listed phishing pages on re-scans.
        good = {'osint': {'urlhaus_status': 'not_found', 'web_risk': {'status': 'not_found'}}}
        self.assertTrue(reputation_settled(good))
        self.assertTrue(reputation_settled({'osint': {'urlhaus_status': 'matched', 'web_risk': {'status': 'not_configured'}}}))
        self.assertTrue(reputation_settled({'osint': {'urlhaus_status': 'unavailable', 'urlhaus_reason': 'disabled_by_operator'}}))
        self.assertFalse(reputation_settled({'osint': {'urlhaus_status': 'not_found',
                                                       'web_risk': {'status': 'unavailable', 'google_reason': 'BILLING_DISABLED'}}}))
        self.assertFalse(reputation_settled({'osint': {'urlhaus_status': 'unavailable'}}))
        self.assertFalse(reputation_settled({}))
        from services import url_analyzer, url_deep_analyzer
        for module in [url_analyzer, url_deep_analyzer]:
            with self.subTest(module=module.__name__), tempfile.TemporaryDirectory() as cache:
                analyzer = module.URLDeepAnalyzer(cache_dir=cache)
                stale = {'urlvet': {'verdict': 'harmless', 'trust_score': 100},
                         'osint': {'urlhaus_status': 'not_found', 'web_risk': {'status': 'unavailable'}}}
                analyzer._save_cached_result('https://example.invalid', stale)
                with patch.object(module, 'validate_public_url', return_value=SimpleNamespace(url='https://example.invalid')), \
                        patch.object(analyzer, 'analyze_behavior', side_effect=RuntimeError('scanned again')):
                    with self.assertRaises(RuntimeError):
                        analyzer.comprehensive_deep_analysis('https://example.invalid')


if __name__ == '__main__':
    unittest.main()
