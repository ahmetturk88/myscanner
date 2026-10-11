"""Regression tests for the 11 Oct 2026 review fixes (R-S03..R-S07)."""
from pathlib import Path
from unittest.mock import patch
import os
import unittest

from bs4 import BeautifulSoup
from flask import Flask
from flask_login import LoginManager

from extensions import db
from models import User, AsyncScanTask
import test_task_ownership


class ResetAndHeaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_task_ownership.TaskOwnershipTests.setUpClass()
        cls.production = test_task_ownership.TaskOwnershipTests.production

    @classmethod
    def tearDownClass(cls):
        test_task_ownership.TaskOwnershipTests.tearDownClass()

    def setUp(self):
        self.app = self.production.app
        self.assertEqual(self.app.config['SQLALCHEMY_DATABASE_URI'], 'sqlite:///' + str(Path(test_task_ownership.TaskOwnershipTests.temporary.name, 'import.db')))
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            user = User(username='reset-user', email='reset@example.invalid', is_verified=True)
            user.set_password('Original#2026')
            db.session.add(user)
            db.session.commit()
        self.client = self.app.test_client()
        page = self.client.get('/login')
        self.token = BeautifulSoup(page.data, 'html.parser').find('meta', {'name': 'csrf-token'})['content']
        self.sent = []
        patcher = patch.object(self.production, 'send_email', side_effect=lambda *a, **k: self.sent.append(a) or True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def forgot(self, email='reset@example.invalid', ip='127.0.0.1'):
        return self.client.post('/forgot-password', data={'email': email, 'csrf_token': self.token},
                                environ_overrides={'REMOTE_ADDR': ip})

    def reset_path(self):
        body = self.sent[-1][2]
        return '/reset-password/' + body.split('/reset-password/')[1].split()[0]

    def reset(self, path, password):
        return self.client.post(path, data={'password': password, 'confirm_password': password, 'csrf_token': self.token})

    def test_forgot_password_is_rate_limited_per_account_and_per_ip(self):
        for i in range(3):
            self.assertEqual(self.forgot(ip='192.0.2.' + str(i + 1)).status_code, 302)
        self.assertEqual(self.forgot(ip='198.51.100.9').status_code, 429)
        self.assertEqual(len(self.sent), 3)
        for i in range(10):
            self.assertEqual(self.forgot(email=f'nobody{i}@example.invalid', ip='203.0.113.5').status_code, 302)
        self.assertEqual(self.forgot(email='late@example.invalid', ip='203.0.113.5').status_code, 429)

    def test_reset_link_is_single_use(self):
        self.forgot()
        path = self.reset_path()
        self.assertIn('/login', self.reset(path, 'Changed#2026a').headers['Location'])
        with self.app.app_context():
            self.assertTrue(User.query.filter_by(username='reset-user').one().check_password('Changed#2026a'))
        replay = self.reset(path, 'Attacker#2026b')
        self.assertIn('/forgot-password', replay.headers['Location'])
        with self.app.app_context():
            self.assertTrue(User.query.filter_by(username='reset-user').one().check_password('Changed#2026a'))

    def test_reset_applies_registration_password_policy(self):
        self.forgot()
        path = self.reset_path()
        weak = self.reset(path, 'alllowercase')
        self.assertIn('/reset-password/', weak.headers['Location'])
        with self.app.app_context():
            self.assertTrue(User.query.filter_by(username='reset-user').one().check_password('Original#2026'))

    def test_legacy_email_only_token_is_rejected(self):
        legacy = self.production.serializer.dumps('reset@example.invalid', salt='password-reset')
        response = self.client.get('/reset-password/' + legacy)
        self.assertIn('/forgot-password', response.headers['Location'])

    def test_baseline_security_headers(self):
        response = self.client.get('/login')
        self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(response.headers['X-Frame-Options'], 'DENY')
        self.assertEqual(response.headers['Referrer-Policy'], 'strict-origin-when-cross-origin')
        self.assertIn('camera=(self)', response.headers['Permissions-Policy'])
        self.assertNotIn('Strict-Transport-Security', response.headers)

    def test_hsts_only_for_production_https(self):
        from flask import Response
        from services.security_headers import apply_security_headers
        self.assertIn('Strict-Transport-Security', apply_security_headers(Response(), True, True).headers)
        self.assertNotIn('Strict-Transport-Security', apply_security_headers(Response(), True, False).headers)
        self.assertNotIn('Strict-Transport-Security', apply_security_headers(Response(), False, True).headers)


class SandboxSubmissionPrivacyTests(unittest.TestCase):
    def test_file_and_url_submission_disabled_by_default(self):
        from services import hybrid_analysis
        with patch.dict(os.environ, {'HYBRID_ANALYSIS_SUBMISSIONS_ENABLED': ''}), \
             patch.object(hybrid_analysis, 'HYBRID_API_KEY', 'configured'), \
             patch.object(hybrid_analysis.requests, 'post') as post:
            service = hybrid_analysis.HybridAnalysisService()
            self.assertFalse(service.submit_file(b'sample', 'a.exe')['submitted'])
            self.assertFalse(service.submit_url('https://example.com/')['submitted'])
            post.assert_not_called()

    def test_enabled_submission_never_requests_public_sharing(self):
        from services import hybrid_analysis
        with patch.dict(os.environ, {'HYBRID_ANALYSIS_SUBMISSIONS_ENABLED': 'true'}), \
             patch.object(hybrid_analysis, 'HYBRID_API_KEY', 'configured'), \
             patch.object(hybrid_analysis.requests, 'post') as post:
            post.return_value.status_code = 500
            service = hybrid_analysis.HybridAnalysisService()
            service.submit_file(b'sample', 'a.exe')
            service.submit_url('https://example.com/')
            for call in post.call_args_list:
                self.assertIs(call.kwargs['data']['allow_community_access'], False)
                self.assertIs(call.kwargs['data']['no_share_third_party'], True)
            self.assertEqual(post.call_count, 2)


class ErrorDisclosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_task_ownership.TaskOwnershipTests.setUpClass()
        cls.production = test_task_ownership.TaskOwnershipTests.production

    @classmethod
    def tearDownClass(cls):
        test_task_ownership.TaskOwnershipTests.tearDownClass()

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(TESTING=True, SECRET_KEY='test-only', SQLALCHEMY_DATABASE_URI='sqlite:///:memory:')
        db.init_app(self.app)
        login = LoginManager(self.app)
        login.user_loader(lambda user_id: db.session.get(User, int(user_id)))
        self.app.add_url_rule('/api/task-status/<task_id>', 'task_status', self.production.task_status)
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()
        user = User(username='owner', email='owner@example.invalid', password_hash='unused')
        db.session.add(user)
        db.session.flush()
        db.session.add(AsyncScanTask(task_id='failed-task', user_id=user.id))
        db.session.commit()
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session['_user_id'] = str(user.id)
            session['_fresh'] = True

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.context.pop()

    def test_task_failure_does_not_return_exception_text(self):
        with patch('app.AsyncResult') as result:
            result.return_value.state = 'FAILURE'
            result.return_value.info = RuntimeError('postgresql://user:SECRET@db/private')
            body = self.client.get('/api/task-status/failed-task').get_json()
        self.assertEqual(body['state'], 'FAILURE')
        self.assertNotIn('SECRET', str(body))


if __name__ == '__main__':
    unittest.main()
