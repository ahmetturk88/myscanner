"""Offline redirect policy and real login-route regression checks."""
import unittest
from pathlib import Path
from unittest.mock import patch
from bs4 import BeautifulSoup
from extensions import db
from models import User
from services.login_redirect import safe_login_redirect
import test_task_ownership

UNSAFE = ['https://evil.invalid', '//evil.invalid', '///evil.invalid',
          '/\\evil.invalid', '/%5cevil.invalid', '/%2fevil.invalid',
          '/%252fevil.invalid', '/\nevil.invalid', '/%0devil.invalid',
          'javascript:alert(1)', 'dashboard', ' https://evil.invalid']


class RedirectPolicyTests(unittest.TestCase):
    def test_external_encoded_and_control_destinations_are_rejected(self):
        for value in UNSAFE:
            with self.subTest(value=value):
                self.assertEqual(safe_login_redirect(value, '/dashboard'), '/dashboard')

    def test_local_path_query_and_fragment_are_preserved(self):
        for value in ['/profile', '/result/1?tab=details#summary', '/dashboard?search=hello%20world']:
            with self.subTest(value=value):
                self.assertEqual(safe_login_redirect(value, '/dashboard'), value)

    def test_missing_value_uses_fallback(self):
        for value in [None, '', 5]:
            self.assertEqual(safe_login_redirect(value, '/dashboard'), '/dashboard')


class LoginRedirectTests(unittest.TestCase):
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
            db.session.add(User(username='redirect-user', email='redirect@example.invalid',
                                password_hash='unused', is_verified=True))
            db.session.commit()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def login(self, destination):
        client = self.app.test_client()
        response = client.get('/login')
        token = BeautifulSoup(response.data, 'html.parser').find('meta', {'name': 'csrf-token'})['content']
        with patch.object(User, 'check_password', return_value=True):
            response = client.post('/login', query_string={'next': destination},
                                   data={'email': 'redirect@example.invalid', 'password': 'unused', 'csrf_token': token})
        self.assertEqual(response.status_code, 302)
        with client.session_transaction() as session:
            self.assertIn('_user_id', session)
        return response.headers['Location']

    def test_successful_login_blocks_external_and_encoded_redirects(self):
        for destination in UNSAFE:
            with self.subTest(destination=destination):
                self.assertEqual(self.login(destination), '/dashboard')

    def test_successful_login_preserves_internal_redirect(self):
        self.assertEqual(self.login('/profile?tab=account'), '/profile?tab=account')


if __name__ == '__main__':
    unittest.main()
