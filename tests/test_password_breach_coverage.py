"""Provider failures, bounded range parsing, privacy and real password endpoint behavior."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest.mock import Mock, patch
import requests
from services.password_analyzer import PasswordAnalyzer
import test_task_ownership

PASSWORD='Private-Example!782'
SUFFIX=hashlib.sha1(PASSWORD.encode()).hexdigest().upper()[5:]
OTHER='A'*35 if SUFFIX!='A'*35 else 'B'*35

class BreachCoverageTests(unittest.TestCase):
    def setUp(self):
        self.analyzer=PasswordAnalyzer();self.addCleanup(self.analyzer.close)
        self.response=Mock(status_code=200)
        self.response.iter_content.return_value=[(OTHER+':12\r\n').encode()]
        self.get=patch.object(self.analyzer.session,'get',return_value=self.response).start();self.addCleanup(patch.stopall)
    def body(self,value):self.response.iter_content.return_value=[value.encode()]
    def test_matching_positive_count_is_confirmed_exposure(self):
        self.body(SUFFIX+':42\r\n'+OTHER+':3');r=self.analyzer.check_pwned(PASSWORD)
        self.assertEqual((r['status'],r['is_pwned'],r['count']),('found',True,42));self.response.close.assert_called_once()
    def test_valid_no_match_is_limited_to_the_dataset(self):
        r=self.analyzer.check_pwned(PASSWORD);self.assertEqual((r['status'],r['is_pwned'],r['count']),('not_found',False,0));self.assertIn('does not prove',r['message'])
    def test_zero_count_padding_does_not_mark_exposure(self):
        self.body(SUFFIX+':0\r\n'+OTHER+':7');self.assertEqual(self.analyzer.check_pwned(PASSWORD)['status'],'not_found')
    def test_http_failures_and_redirects_never_become_negative_matches(self):
        for code in [301,302,403,404,429,500,503]:
            self.response.status_code=code;r=self.analyzer.check_pwned(PASSWORD)
            self.assertEqual(r['status'],'unavailable');self.assertIsNone(r['is_pwned']);self.assertIsNone(r['count'])
        self.response.iter_content.assert_not_called()
    def test_malformed_empty_duplicate_and_mixed_response_are_unknown(self):
        for body in ['', '<html>blocked</html>',OTHER+':-1',OTHER+':abc',OTHER+':1\n'+OTHER+':2',SUFFIX+':5\nmalformed',OTHER+':1234567890123']:
            with self.subTest(body=body):
                self.body(body);self.assertEqual(self.analyzer.check_pwned(PASSWORD)['status'],'unavailable')
    def test_non_ascii_data_is_unknown(self):
        self.body('é:1');self.assertEqual(self.analyzer.check_pwned(PASSWORD)['status'],'unavailable')
    def test_response_size_is_bounded(self):
        self.response.iter_content.return_value=[b'A'*262145];self.assertEqual(self.analyzer.check_pwned(PASSWORD)['status'],'unavailable');self.response.close.assert_called_once()
    def test_stream_failure_discards_earlier_positive_match(self):
        def chunks():
            yield (SUFFIX+':42\n').encode()
            raise requests.ConnectionError('private provider response')
        self.response.iter_content.side_effect=chunks
        self.assertEqual(self.analyzer.check_pwned(PASSWORD)['status'],'unavailable');self.response.close.assert_called_once()
    def test_deadline_rejects_slow_response(self):
        with patch('services.password_analyzer.monotonic',side_effect=[0,13]):self.assertEqual(self.analyzer.check_pwned(PASSWORD)['status'],'unavailable')
    def test_only_hash_prefix_is_sent_and_padding_requested(self):
        self.analyzer.check_pwned(PASSWORD);args,kwargs=self.get.call_args
        digest=hashlib.sha1(PASSWORD.encode()).hexdigest().upper()
        self.assertEqual(args,(f'https://api.pwnedpasswords.com/range/{digest[:5]}',));self.assertEqual(kwargs['headers'],{'Add-Padding':'true'});self.assertFalse(kwargs['allow_redirects']);self.assertTrue(kwargs['stream']);self.assertNotIn(PASSWORD,str(self.get.call_args));self.assertNotIn(digest,str(self.get.call_args))
    def test_provider_exception_does_not_expose_password_or_hash_in_logs(self):
        self.get.side_effect=requests.Timeout(PASSWORD+' '+SUFFIX)
        with self.assertLogs('services.password_analyzer',level='WARNING') as logs:r=self.analyzer.check_pwned(PASSWORD)
        self.assertNotIn(PASSWORD,str(logs.output)+str(r));self.assertNotIn(SUFFIX,str(logs.output)+str(r));self.assertIsNone(r['is_pwned'])
    def test_common_pattern_logging_does_not_include_password_prefix(self):
        secret='qwerty-secret-to-never-log'
        with self.assertLogs('services.password_analyzer',level='WARNING') as logs:self.analyzer.check_common_patterns(secret)
        self.assertNotIn(secret,str(logs.output));self.assertNotIn('qwe***',str(logs.output))
    def test_default_lookup_is_skipped_without_network(self):
        r=self.analyzer.comprehensive_analysis(PASSWORD);self.get.assert_not_called();self.assertEqual(r['pwned']['status'],'skipped');self.assertIsNone(r['pwned']['is_pwned']);self.assertIn('unknown',' '.join(r['recommendations']))
    def test_unavailable_lookup_preserves_strength_and_marks_coverage(self):
        self.get.side_effect=requests.Timeout('failure');local=self.analyzer.comprehensive_analysis(PASSWORD);partial=self.analyzer.comprehensive_analysis(PASSWORD,check_breaches=True)
        self.assertEqual(local['final']['score'],partial['final']['score']);self.assertEqual(partial['status'],'partial');self.assertEqual(partial['coverage']['breach_lookup'],'unavailable');self.assertNotIn(PASSWORD,json.dumps(partial))
    def test_confirmed_exposure_penalty_remains_applied(self):
        local=self.analyzer.comprehensive_analysis(PASSWORD);self.body(SUFFIX+':100')
        exposed=self.analyzer.comprehensive_analysis(PASSWORD,check_breaches=True);self.assertEqual(exposed['final']['score'],max(0,local['final']['score']-50))

class PasswordEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):test_task_ownership.TaskOwnershipTests.setUpClass();cls.production=test_task_ownership.TaskOwnershipTests.production
    @classmethod
    def tearDownClass(cls):test_task_ownership.TaskOwnershipTests.tearDownClass()
    def setUp(self):
        test_task_ownership.TaskOwnershipTests.setUp(self)
        self.app.add_url_rule('/api/check-password','api_check_password',self.production.api_check_password,methods=['POST'])
        test_task_ownership.TaskOwnershipTests.sign_in(self,self.owner)
    def tearDown(self):test_task_ownership.TaskOwnershipTests.tearDown(self)
    def test_default_and_explicit_consent_are_forwarded_and_session_closed(self):
        with patch.object(self.production,'PasswordAnalyzer') as analyzer:
            analyzer.return_value.comprehensive_analysis.return_value={'pwned':{'status':'skipped'}}
            for payload,expected in [({'password':PASSWORD},False),({'password':PASSWORD,'check_breaches':True},True)]:
                r=self.client.post('/api/check-password',json=payload);self.assertEqual(r.status_code,200)
                analyzer.return_value.comprehensive_analysis.assert_called_with(PASSWORD,check_breaches=expected)
            self.assertEqual(analyzer.return_value.close.call_count,2)
    def test_non_boolean_consent_never_starts_analysis(self):
        with patch.object(self.production,'PasswordAnalyzer') as analyzer:
            r=self.client.post('/api/check-password',json={'password':PASSWORD,'check_breaches':'false'});self.assertEqual(r.status_code,400);analyzer.assert_not_called()
        from extensions import db
        from models import User
        db.session.expire_all();self.assertEqual(db.session.get(User,self.owner).password_check_remaining,3)
    def test_analyzer_failure_is_generic_and_closes_session(self):
        with patch.object(self.production,'PasswordAnalyzer') as analyzer:
            analyzer.return_value.comprehensive_analysis.side_effect=RuntimeError(PASSWORD)
            r=self.client.post('/api/check-password',json={'password':PASSWORD});self.assertEqual(r.status_code,503);self.assertNotIn(PASSWORD,r.get_data(as_text=True));analyzer.return_value.close.assert_called_once()

class PasswordInterfaceTests(unittest.TestCase):
    def test_optional_lookup_has_disclosure_and_no_clean_claim(self):
        source=(Path(__file__).resolve().parents[1]/'templates/password_check.html').read_text(encoding='utf-8')
        self.assertIn('id="check-breaches"',source);self.assertNotIn('id="check-breaches" checked',source);self.assertNotIn('✅ Clean',source);self.assertIn('processing',source)
    @unittest.skipUnless(shutil.which('node'),'Node.js is needed for password renderer execution tests')
    def test_renderer_and_export_distinguish_unknown_and_dataset_match(self):
        r=subprocess.run([shutil.which('node'),str(Path(__file__).with_name('test_tool_result_xss.cjs'))],capture_output=True,text=True,encoding='utf-8',check=True)
        self.assertIn('sections',json.loads(r.stdout))

if __name__=='__main__':unittest.main()
