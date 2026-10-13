"""Google/GitHub sign-in: state checks, verified emails only, safe account linking."""
import os
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse
import unittest

from bs4 import BeautifulSoup

from extensions import db
from models import User
from services import oauth_login
import test_task_ownership

ENV = {'GOOGLE_CLIENT_ID': 'gid', 'GOOGLE_CLIENT_SECRET': 'gsecret', 'GITHUB_CLIENT_ID': 'hid', 'GITHUB_CLIENT_SECRET': 'hsecret'}


def reply(payload):
    response = MagicMock(); response.json.return_value = payload
    return response


class ProviderTests(unittest.TestCase):
    def test_providers_need_both_id_and_secret(self):
        with patch.dict(os.environ, {'GOOGLE_CLIENT_ID': 'x'}, clear=True):
            self.assertEqual(oauth_login.enabled_providers(), [])
        with patch.dict(os.environ, ENV, clear=True):
            self.assertEqual(oauth_login.enabled_providers(), ['google', 'github'])

    def test_secret_can_come_from_a_file(self):
        import tempfile
        with tempfile.NamedTemporaryFile('w', delete=False) as handle:
            handle.write('from-file\n')
        self.addCleanup(os.remove, handle.name)
        with patch.dict(os.environ, {'GITHUB_CLIENT_ID': 'hid', 'GITHUB_CLIENT_SECRET_FILE': handle.name}, clear=True):
            self.assertEqual(oauth_login.credentials('github'), ('hid', 'from-file'))

    def start(self, provider='google'):
        session = {}
        with patch.dict(os.environ, ENV, clear=True):
            url = oauth_login.start(provider, 'https://app.example/auth/' + provider + '/callback', session)
        return session, parse_qs(urlparse(url).query)

    def test_start_sets_state_and_pkce(self):
        session, query = self.start()
        self.assertEqual(query['state'][0], session['oauth_pending']['state'])
        self.assertEqual(query['code_challenge_method'][0], 'S256')
        self.assertNotIn('gsecret', str(query))

    def finish(self, session, args, http):
        with patch.dict(os.environ, ENV, clear=True):
            return oauth_login.finish(session['oauth_pending']['provider'] if 'oauth_pending' in session else 'google', args, 'https://app.example/cb', session, http=http)

    def test_wrong_or_replayed_state_is_rejected(self):
        session, query = self.start()
        http = MagicMock()
        with self.assertRaises(oauth_login.OAuthError):
            self.finish(session, {'state': 'forged', 'code': 'c'}, http)
        with self.assertRaises(oauth_login.OAuthError):  # state is single use
            self.finish(session, {'state': query['state'][0], 'code': 'c'}, http)
        http.post.assert_not_called()

    def test_google_requires_a_verified_email(self):
        for verified, expected in ((True, ('a@example.com', 'Ann')), (False, None)):
            session, query = self.start()
            verifier = session['oauth_pending']['verifier']
            http = MagicMock()
            http.post.return_value = reply({'access_token': 't'})
            http.get.return_value = reply({'email': 'A@Example.com', 'email_verified': verified, 'name': 'Ann'})
            if expected:
                self.assertEqual(self.finish(session, {'state': query['state'][0], 'code': 'c'}, http), expected)
                self.assertEqual(http.post.call_args.kwargs['data']['code_verifier'], verifier)
            else:
                with self.assertRaises(oauth_login.OAuthError):
                    self.finish(session, {'state': query['state'][0], 'code': 'c'}, http)

    def test_github_uses_the_primary_verified_email(self):
        session, query = self.start('github')
        http = MagicMock()
        http.post.return_value = reply({'access_token': 't'})
        http.get.side_effect = [reply({'login': 'octo', 'name': None}), reply([
            {'email': 'unverified@example.com', 'verified': False, 'primary': True},
            {'email': 'second@example.com', 'verified': True, 'primary': False}])]
        self.assertEqual(self.finish(session, {'state': query['state'][0], 'code': 'c'}, http), ('second@example.com', 'octo'))

    def test_unique_username(self):
        taken = {'Ann_Lee'}
        name = oauth_login.unique_username('Ann Lee', 'ann@example.com', lambda c: c in taken)
        self.assertTrue(name.startswith('Ann_Lee_'))
        self.assertEqual(oauth_login.unique_username('<script>', 'x@e.com', lambda c: False), 'script')


class CallbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_task_ownership.TaskOwnershipTests.setUpClass()
        cls.production = test_task_ownership.TaskOwnershipTests.production

    @classmethod
    def tearDownClass(cls):
        test_task_ownership.TaskOwnershipTests.tearDownClass()

    def setUp(self):
        self.app = self.production.app
        with self.app.app_context():
            db.drop_all(); db.create_all()
        self.client = self.app.test_client()
        env = patch.dict(os.environ, ENV); env.start(); self.addCleanup(env.stop)

    def tearDown(self):
        with self.app.app_context():
            db.session.remove(); db.drop_all()

    def sign_in_with(self, email='new@example.com', name='New Person'):
        start = self.client.get('/auth/google/start?next=/profile')
        state = parse_qs(urlparse(start.headers['Location']).query)['state'][0]
        with patch('services.oauth_login.finish', return_value=(email, name)) as finish:
            response = self.client.get('/auth/google/callback', query_string={'state': state, 'code': 'c'})
        return response, finish

    def test_new_verified_user_is_created_and_signed_in(self):
        response, _ = self.sign_in_with()
        self.assertEqual(response.headers['Location'], '/profile')
        with self.app.app_context():
            user = User.query.filter_by(email='new@example.com').one()
            self.assertTrue(user.is_verified)
            self.assertEqual(user.username, 'New_Person')
        with self.client.session_transaction() as session:
            self.assertEqual(session['_user_id'], str(user.id))

    def test_unverified_squatter_loses_the_password_it_set(self):
        with self.app.app_context():
            squatter = User(username='squat', email='victim@example.com', is_verified=False)
            squatter.set_password('Squatter#2026'); db.session.add(squatter); db.session.commit()
        self.sign_in_with('victim@example.com')
        with self.app.app_context():
            user = User.query.filter_by(email='victim@example.com').one()
            self.assertTrue(user.is_verified)
            self.assertFalse(user.check_password('Squatter#2026'))

    def test_existing_verified_account_keeps_its_password(self):
        with self.app.app_context():
            owner = User(username='owner', email='owner@example.com', is_verified=True)
            owner.set_password('Owner#2026'); db.session.add(owner); db.session.commit()
        self.sign_in_with('owner@example.com')
        with self.app.app_context():
            self.assertTrue(User.query.filter_by(email='owner@example.com').one().check_password('Owner#2026'))

    def test_failure_returns_to_login_without_signing_in(self):
        self.client.get('/auth/google/start')
        response = self.client.get('/auth/google/callback', query_string={'state': 'forged', 'code': 'c'})
        self.assertEqual(urlparse(response.headers['Location']).path, '/login')
        with self.client.session_transaction() as session:
            self.assertNotIn('_user_id', session)

    def test_unknown_provider_and_external_next_are_refused(self):
        self.assertEqual(urlparse(self.client.get('/auth/facebook/start').headers['Location']).path, '/login')
        self.client.get('/auth/google/start?next=https://evil.example/')
        with self.client.session_transaction() as session:
            self.assertEqual(session['oauth_next'], '/dashboard')

    def test_login_page_shows_only_configured_providers(self):
        soup = BeautifulSoup(self.client.get('/login').data, 'html.parser')
        self.assertEqual(len(soup.select('.auth-social a')), 2)
        with patch.dict(os.environ, {'GITHUB_CLIENT_SECRET': ''}):
            soup = BeautifulSoup(self.client.get('/register').data, 'html.parser')
            self.assertEqual([a.get_text(strip=True) for a in soup.select('.auth-social a')], ['Continue with Google'])
        with patch.dict(os.environ, {'GITHUB_CLIENT_SECRET': '', 'GOOGLE_CLIENT_SECRET': ''}):
            self.assertFalse(BeautifulSoup(self.client.get('/login').data, 'html.parser').select('.auth-social'))


if __name__ == '__main__':
    unittest.main()
