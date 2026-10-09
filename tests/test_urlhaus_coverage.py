import os
import unittest
from unittest.mock import Mock,patch
from services.url_analyzer import URLDeepAnalyzer

class URLhausCoverageTests(unittest.TestCase):
    def analyzer(self):
        a=URLDeepAnalyzer.__new__(URLDeepAnalyzer);a.session=Mock();a._save_phishing_cache=Mock();return a
    def test_missing_key_skips_network_and_reports_configuration(self):
        a=self.analyzer()
        with patch.dict(os.environ,{'URLHAUS_AUTH_KEY':'','URLHAUS_AUTH_KEY_FILE':''}):r=a.check_urlhaus('https://example.com')
        a.session.post.assert_not_called();self.assertEqual(r['coverage_reason'],'not_configured');self.assertEqual(r['coverage_status'],'unavailable')
    def test_key_header_and_no_redirect_with_negative_dataset_match(self):
        a=self.analyzer();a.session.post.return_value.status_code=200;a.session.post.return_value.json.return_value={'query_status':'no_results'}
        with patch.dict(os.environ,{'URLHAUS_AUTH_KEY':'test-secret','URLHAUS_AUTH_KEY_FILE':''}):r=a.check_urlhaus('https://example.com')
        self.assertEqual(a.session.post.call_args.kwargs['headers'],{'Auth-Key':'test-secret'})
        self.assertFalse(a.session.post.call_args.kwargs['allow_redirects']);self.assertEqual(r['coverage_status'],'not_found');self.assertNotIn('test-secret',str(r))
    def test_rejections_rate_limits_and_redirects_stay_unavailable(self):
        for status,reason in [(401,'authentication_rejected'),(403,'authentication_rejected'),(429,'rate_limited'),(302,'http_error')]:
            a=self.analyzer();a.session.post.return_value.status_code=status
            with patch.dict(os.environ,{'URLHAUS_AUTH_KEY':'test-secret','URLHAUS_AUTH_KEY_FILE':''}):r=a.check_urlhaus('https://example.com')
            self.assertEqual(r['coverage_reason'],reason);self.assertFalse(r['is_malicious']);self.assertEqual(r['coverage_status'],'unavailable')
    def test_exception_does_not_expose_key_in_result_or_log(self):
        a=self.analyzer();a.session.post.side_effect=RuntimeError('SECRET-key-value')
        with patch.dict(os.environ,{'URLHAUS_AUTH_KEY':'SECRET-key-value','URLHAUS_AUTH_KEY_FILE':''}),self.assertLogs('services.url_analyzer',level='WARNING') as logs:r=a.check_urlhaus('https://example.com')
        self.assertNotIn('SECRET-key-value',str(r)+str(logs.output));self.assertEqual(r['coverage_reason'],'connection_or_response_error')
if __name__=='__main__':unittest.main()
