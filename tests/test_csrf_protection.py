"""Offline CSRF tests with a disposable database and mocked scanner services."""
from io import BytesIO
from pathlib import Path
import unittest
from unittest.mock import patch

from extensions import db
from models import User, VulnerabilityScan
import test_task_ownership


class CSRFProtectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse only the disposable import setup, not its CSRF-free route fixtures.
        test_task_ownership.TaskOwnershipTests.setUpClass()
        cls.production = test_task_ownership.TaskOwnershipTests.production

    @classmethod
    def tearDownClass(cls):
        test_task_ownership.TaskOwnershipTests.tearDownClass()

    def setUp(self):
        self.app = self.production.app
        self.assertEqual(self.app.config['SQLALCHEMY_DATABASE_URI'], 'sqlite:///' + str(Path(test_task_ownership.TaskOwnershipTests.temporary.name, 'import.db')))
        self.client = self.app.test_client()
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            owner = User(username='csrf-owner', email='csrf-owner@example.invalid', password_hash='unused', is_admin=True)
            db.session.add(owner)
            db.session.flush()
            self.owner = owner.id
            db.session.add(VulnerabilityScan(scan_uuid='csrf-scan', user_id=owner.id,
                target='https://example.invalid', scan_type='web_application', status='running'))
            db.session.commit()
        self.login(self.client)

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def login(self, client):
        with client.session_transaction() as session:
            session['_user_id'] = str(self.owner)
            session['_fresh'] = True

    def token(self, client=None):
        client = client or self.client
        from bs4 import BeautifulSoup
        response = client.get('/login')
        # A signed-in user is redirected; use the publicly available contact page.
        if response.status_code != 200:
            response = client.get('/contact')
        self.assertEqual(response.status_code, 200)
        return BeautifulSoup(response.data, 'html.parser').find('meta', {'name':'csrf-token'})['content']

    def test_production_has_no_csrf_exemptions(self):
        self.assertFalse(self.production.csrf._exempt_views)
        self.assertFalse(self.production.csrf._exempt_blueprints)

    def test_missing_tokens_block_all_state_changing_routes(self):
        # Before login checks, quota updates, database writes, queueing or providers.
        for rule in self.app.url_map.iter_rules():
            for method in sorted(rule.methods & {'POST', 'PUT', 'DELETE', 'PATCH'}):
                url = str(rule)
                import re
                url = re.sub(r'<(?:[^:>]+:)?([^>]+)>', lambda m: '1' if m[1] in ['user_id','scan_id','ioc_id','source_id'] else 'csrf-scan', url)
                with self.subTest(url=url, method=method):
                    result = self.client.open(url, method=method, json={})
                    self.assertEqual(result.status_code, 400)
                    self.assertEqual(result.json['code'], 'csrf_failed')

    def test_invalid_header_token_is_rejected(self):
        self.token()
        result = self.client.post('/api/url-analyze', json={'url':'https://example.invalid'}, headers={'X-CSRFToken':'invalid'})
        self.assertEqual(result.status_code, 400)
        self.assertEqual(result.json['code'], 'csrf_failed')

    def test_token_from_another_session_is_rejected(self):
        token = self.token()
        other = self.app.test_client()
        self.login(other)
        self.token(other)
        result = other.post('/api/url-analyze', json={}, headers={'X-CSRFToken':token})
        self.assertEqual(result.status_code, 400)
        self.assertEqual(result.json['code'], 'csrf_failed')

    def test_expired_token_is_rejected(self):
        token = self.token()
        with patch.dict(self.app.config, WTF_CSRF_TIME_LIMIT=-1):
            result = self.client.post('/api/url-analyze', json={}, headers={'X-CSRFToken':token})
        self.assertEqual(result.status_code, 400)
        self.assertEqual(result.json['code'], 'csrf_failed')

    def test_valid_token_allows_json_scanner_request(self):
        token = self.token()
        with patch.object(self.production, 'URLDeepAnalyzer') as analyzer:
            analyzer.return_value.comprehensive_analysis.return_value = {'verdict':'unknown'}
            result = self.client.post('/api/url-analyze', json={'url':'https://example.invalid'}, headers={'X-CSRFToken':token})
        self.assertEqual(result.status_code, 200)
        analyzer.return_value.comprehensive_analysis.assert_called_once()

    def test_valid_token_allows_file_upload(self):
        token = self.token()
        with patch.object(self.production, 'FileDeepAnalyzer') as analyzer:
            analyzer.return_value.comprehensive_analysis.return_value = {'verdict':'unknown'}
            result = self.client.post('/api/file-deep-analysis', data={'file':(BytesIO(b'test-only'), 'sample.pdf')}, headers={'X-CSRFToken':token})
        self.assertEqual(result.status_code, 200)
        analyzer.return_value.comprehensive_analysis.assert_called_once()

    def test_vulnerability_stop_requires_token_and_still_checks_owner(self):
        token = self.token()
        with patch('routes.vuln_routes.get_orchestrator') as orchestrator:
            orchestrator.return_value.stop_scan.return_value = True
            self.assertEqual(self.client.post('/vulnerability/stop/csrf-scan').status_code, 400)
            orchestrator.assert_not_called()
            self.assertEqual(self.client.post('/vulnerability/stop/csrf-scan', headers={'X-CSRFToken':token}).status_code, 200)
            orchestrator.return_value.stop_scan.assert_called_once_with('csrf-scan')

    def test_sandbox_json_request_accepts_valid_token(self):
        token = self.token()
        with patch('routes.sandbox_routes.HybridAnalysisService') as provider:
            provider.return_value.lookup_hash.return_value = {'status':'unknown'}
            result = self.client.post('/api/sandbox/hash-lookup', json={'hash':'a' * 64}, headers={'X-CSRFToken':token})
        self.assertEqual(result.status_code, 200)

    def test_logout_get_cannot_change_session(self):
        result = self.client.get('/logout')
        self.assertEqual(result.status_code, 405)
        with self.client.session_transaction() as session:
            self.assertEqual(session['_user_id'], str(self.owner))

    def test_logout_form_with_valid_token_clears_login(self):
        token = self.token()
        result = self.client.post('/logout', data={'csrf_token':token})
        self.assertEqual(result.status_code, 302)
        with self.client.session_transaction() as session:
            self.assertNotIn('_user_id', session)

    def test_form_failure_shows_refresh_page_without_logging_out(self):
        result = self.client.post('/logout')
        self.assertEqual(result.status_code, 400)
        self.assertIn(b'Refresh required', result.data)
        with self.client.session_transaction() as session:
            self.assertEqual(session['_user_id'], str(self.owner))

    def test_templates_have_one_token_and_post_logout_forms(self):
        from bs4 import BeautifulSoup
        result = self.client.get('/profile')
        soup = BeautifulSoup(result.data, 'html.parser')
        self.assertEqual(len(soup.select('meta[name="csrf-token"]')), 1)
        self.assertTrue(soup.select_one('script[src="/static/csrf.js"]'))
        forms = soup.select('form[action="/logout"]')
        self.assertEqual(len(forms), 3)
        for form in forms:
            self.assertEqual(form['method'].upper(), 'POST')
            self.assertTrue(form.select_one('input[name="csrf_token"]')['value'])
        admin = self.client.get('/admin')
        soup = BeautifulSoup(admin.data, 'html.parser')
        self.assertEqual(len(soup.select('meta[name="csrf-token"]')), 1)

    def test_https_valid_token_requires_same_origin_referrer(self):
        token = self.token()
        with patch.object(self.production, 'URLDeepAnalyzer') as analyzer:
            analyzer.return_value.comprehensive_analysis.return_value = {'verdict':'unknown'}
            for referrer in [None, 'https://external.example/page']:
                headers = {'X-CSRFToken':token}
                if referrer:
                    headers['Referer'] = referrer
                result = self.client.post('/api/url-analyze', base_url='https://localhost', json={'url':'https://example.invalid'}, headers=headers)
                self.assertEqual(result.status_code, 400)
                self.assertEqual(result.json['code'], 'csrf_failed')
            analyzer.assert_not_called()
            result = self.client.post('/api/url-analyze', base_url='https://localhost', json={'url':'https://example.invalid'}, headers={'X-CSRFToken':token, 'Referer':'https://localhost/scanner'})
            self.assertEqual(result.status_code, 200)
