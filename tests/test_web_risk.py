"""Google Web Risk: lookups, verdict effect, and the secret wiring."""
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.configure_web_risk import save_key
from services.url_assessment import assess_url
from services.web_risk import check_web_risk, web_risk_key

ROOT = Path(__file__).resolve().parents[1]


def response(status=200, body=None):
    r = mock.Mock(status_code=status)
    r.json.return_value = {} if body is None else body
    return r


class LookupTests(unittest.TestCase):
    def test_no_key_is_not_configured_and_sends_nothing(self):
        session = mock.Mock()
        with mock.patch.dict('os.environ', {}, clear=True):
            self.assertIsNone(web_risk_key())
            self.assertEqual(check_web_risk('https://example.com/', session)['status'], 'not_configured')
        session.get.assert_not_called()

    def test_empty_answer_is_not_found_and_request_names_all_threat_types(self):
        session = mock.Mock(); session.get.return_value = response(body={})
        result = check_web_risk('https://example.com/a?b=1', session, key='k' * 39)
        self.assertEqual(result['status'], 'not_found')
        params = session.get.call_args.kwargs['params']
        self.assertEqual([v for k, v in params if k == 'threatTypes'], ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'])
        self.assertIn(('uri', 'https://example.com/a?b=1'), params)

    def test_match_and_failures(self):
        session = mock.Mock()
        session.get.return_value = response(body={'threat': {'threatTypes': ['SOCIAL_ENGINEERING'], 'expireTime': 'x'}})
        self.assertEqual(check_web_risk('https://p.example/', session, key='k' * 39)['threat_types'], ['SOCIAL_ENGINEERING'])
        for status, reason in ((403, 'authentication_rejected'), (429, 'quota_exceeded'), (500, 'http_error')):
            session.get.return_value = response(status)
            self.assertEqual(check_web_risk('https://p.example/', session, key='k' * 39)['reason'], reason)
        denied = response(403, {'error': {'status': 'PERMISSION_DENIED', 'details': [{'reason': 'BILLING_DISABLED'}], 'message': 'free text'}})
        session.get.return_value = denied
        self.assertEqual(check_web_risk('https://p.example/', session, key='k' * 39)['google_reason'], 'BILLING_DISABLED')
        session.get.side_effect = OSError('down')
        self.assertEqual(check_web_risk('https://p.example/', session, key='k' * 39)['status'], 'unavailable')


def reports(web_risk):
    provider = {'verdict': 'suspicious', 'trust_score': 60, 'phishing': {'in_database': False, 'verified': False, 'valid': False}}
    local = {'urlvet': dict(provider), 'structure': {'is_https': True}, 'ssl': {'valid': True}, 'security_headers': {'score': 100}, 'phishing': {'risk_score': 0}}
    deep = {'urlvet': dict(provider), 'structure': {'is_https': True}, 'ssl': {'valid': True}, 'page_content': {'title': 'x', 'content_risk_score': 0},
            'behavior': {'behavior_risk_score': 0}, 'osint': {'urlhaus_status': 'not_found', 'web_risk': web_risk}}
    return local, deep


class AssessmentTests(unittest.TestCase):
    def test_web_risk_match_confirms_phishing(self):
        r = assess_url(*reports({'status': 'matched', 'threat_types': ['SOCIAL_ENGINEERING']}))
        self.assertEqual(r['verdict'], 'malicious'); self.assertTrue(r['threat_override'])
        self.assertIn('web_risk_social_engineering', [x['code'] for x in r['reasons']])
        self.assertIn('google_web_risk', r['sources'])

    def test_unconfigured_or_unavailable_web_risk_is_not_a_gap(self):
        for status in ('not_configured', 'unavailable'):
            r = assess_url(*reports({'status': status, 'threat_types': []}))
            self.assertEqual(r['verdict'], 'suspicious', status)  # the provider flag still asks for review
            self.assertFalse(any('Web Risk' in m for m in r['missing_checks']))


class SecretTests(unittest.TestCase):
    def test_key_is_stored_privately_and_not_replaced(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / '.deploy' / 'rehearsal'; directory.mkdir(parents=True)
            (Path(root) / '.env.vps.rehearsal').write_text('test')
            save_key('AIza' + 'x' * 35, root)
            self.assertEqual((directory / 'web_risk_api_key').read_text().strip(), 'AIza' + 'x' * 35)
            with self.assertRaises(RuntimeError):
                save_key('AIza' + 'y' * 35, root)

    def test_only_the_worker_receives_the_key(self):
        source = (ROOT / 'compose.urlvet.yml').read_text()
        self.assertEqual(source.count('WEB_RISK_API_KEY_FILE: /run/secrets/web_risk_api_key'), 1)
        worker = source[source.index('  worker:'):source.index('  urlvet:')]
        self.assertIn('web_risk_api_key', worker)


if __name__ == '__main__':
    unittest.main()
