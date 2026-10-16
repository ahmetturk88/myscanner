"""Mobile app API: token sign-in, cookie isolation, tool access and account deletion."""
import json
import unittest
from datetime import timedelta
from unittest.mock import patch

from bs4 import BeautifulSoup

from extensions import db
from models import AIContext, ApiToken, LogEntry, Scan, User
from services import ai_assistant, mobile_auth
import test_task_ownership

PASSWORD = 'Original#2026'


class MobileApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_task_ownership.TaskOwnershipTests.setUpClass()
        cls.app = test_task_ownership.TaskOwnershipTests.production.app

    @classmethod
    def tearDownClass(cls):
        test_task_ownership.TaskOwnershipTests.tearDownClass()

    def setUp(self):
        with self.app.app_context():
            db.drop_all(); db.create_all()
            for name, verified in (('owner', True), ('other', True), ('pending', False)):
                user = User(username=name, email=f'{name}@example.invalid', is_verified=verified)
                user.set_password(PASSWORD)
                db.session.add(user)
            db.session.commit()
            self.owner, self.other = (User.query.filter_by(username=n).one().id for n in ('owner', 'other'))
        self.client = self.app.test_client()

    def login(self, email='owner@example.invalid', password=PASSWORD, device='Pixel 9'):
        return self.client.post('/api/mobile/v1/auth/login', json={'email': email, 'password': password, 'device': device})

    def token(self, **kwargs):
        response = self.login(**kwargs)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return response.json['token']

    def auth(self, token):
        return {'Authorization': f'Bearer {token}'}

    def test_sign_in_returns_a_token_stored_only_as_a_hash(self):
        response = self.login()
        token = response.json['token']
        self.assertTrue(token.startswith('msk_'));self.assertEqual(response.json['user']['username'], 'owner')
        self.assertIn('allowance', response.json['user'])
        with self.app.app_context():
            row = ApiToken.query.one()
            self.assertNotEqual(row.token_hash, token);self.assertNotIn(token, row.token_hash)
            self.assertEqual(row.device, 'Pixel 9')
        self.assertNotIn('Set-Cookie', response.headers)
        me = self.client.get('/api/mobile/v1/me', headers=self.auth(token))
        self.assertEqual(me.json['user']['email'], 'owner@example.invalid')

    def test_bad_credentials_unverified_and_malformed_requests_are_refused(self):
        self.assertEqual(self.login(password='wrong').status_code, 401)
        self.assertEqual(self.login(email='nobody@example.invalid').status_code, 401)
        self.assertEqual(self.login(email='pending@example.invalid').status_code, 403)
        for body in ({}, {'email': 'owner@example.invalid'}, [], {'email': 'x', 'password': 5}):
            self.assertEqual(self.client.post('/api/mobile/v1/auth/login', json=body).status_code, 400)
        with self.app.app_context():
            self.assertEqual(ApiToken.query.count(), 0)

    def test_sign_in_attempts_are_rate_limited(self):
        statuses = [self.login(password='wrong').status_code for _ in range(21)]
        self.assertEqual(statuses[:20], [401] * 20);self.assertEqual(statuses[20], 429)
        self.assertEqual(self.login().status_code, 429)

    def test_routes_need_a_valid_token_and_ignore_the_session_cookie(self):
        with self.client.session_transaction() as session:
            session['_user_id'] = str(self.owner);session['_fresh'] = True
        for headers in ({}, {'Authorization': 'Bearer msk_forged'}, {'Authorization': 'Basic abc'}, {'Authorization': 'Bearer '}):
            response = self.client.get('/api/mobile/v1/me', headers=headers)
            self.assertEqual(response.status_code, 401);self.assertEqual(response.headers['WWW-Authenticate'], 'Bearer')
        token = self.token(email='other@example.invalid')
        self.assertEqual(self.client.get('/api/mobile/v1/me', headers=self.auth(token)).json['user']['username'], 'other')

    def test_tokens_expire_are_capped_and_logout_revokes_them(self):
        tokens = [self.token(device=f'd{i}') for i in range(mobile_auth.TOKENS_PER_USER + 2)]
        with self.app.app_context():
            self.assertEqual(ApiToken.query.filter_by(user_id=self.owner).count(), mobile_auth.TOKENS_PER_USER)
        self.assertEqual(self.client.get('/api/mobile/v1/me', headers=self.auth(tokens[0])).status_code, 401)
        latest = tokens[-1]
        self.assertEqual(self.client.post('/api/mobile/v1/auth/logout', headers=self.auth(latest)).status_code, 200)
        self.assertEqual(self.client.get('/api/mobile/v1/me', headers=self.auth(latest)).status_code, 401)
        with self.app.app_context():
            row = ApiToken.query.filter_by(device='d10').one()
            row.expires_at -= timedelta(days=mobile_auth.TOKEN_DAYS + 1)
            db.session.commit()
        self.assertEqual(self.client.get('/api/mobile/v1/me', headers=self.auth(tokens[-2])).status_code, 401)

    def test_tools_run_the_website_endpoints_without_a_csrf_token(self):
        token = self.token()
        response = self.client.post('/api/mobile/v1/tools/password', headers=self.auth(token),
                                    json={'password': 'correct horse battery staple', 'check_breaches': False})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertIn('local_strength', response.json);self.assertNotIn('password', response.json)
        self.assertEqual(self.client.post('/api/mobile/v1/tools/admin', headers=self.auth(token), json={}).status_code, 404)
        self.assertEqual(self.client.post('/api/mobile/v1/tools/password', json={'password': 'x'}).status_code, 401)
        # The website's own endpoint still requires its CSRF token.
        with self.client.session_transaction() as session:
            session['_user_id'] = str(self.owner);session['_fresh'] = True
        self.assertEqual(self.client.post('/api/check-password', json={'password': 'x', 'check_breaches': False}).status_code, 400)

    def test_reports_stay_private_to_their_owner(self):
        with self.app.app_context():
            scan = Scan(url='https://example.org', user_id=self.other, status='completed', result='{}')
            db.session.add(scan);db.session.commit()
            scan_id = scan.id
        token = self.token()
        self.assertEqual(self.client.get(f'/api/mobile/v1/scans/{scan_id}', headers=self.auth(token)).status_code, 404)
        recent = self.client.get('/api/mobile/v1/scans/recent', headers=self.auth(token))
        self.assertEqual(recent.status_code, 200);self.assertNotIn('example.org', recent.get_data(as_text=True))

    def test_ai_assistant_streams_through_the_app_api(self):
        token = self.token()
        stream = iter(['Use the URL ', 'Scanner.'])
        with patch.object(ai_assistant, 'providers', return_value=[('groq', 'q' * 20, 'm')]), \
             patch.object(ai_assistant, 'STREAMERS', {'groq': lambda *a: stream}):
            response = self.client.post('/api/mobile/v1/ai/assistant', headers=self.auth(token), json={'message': 'Is this safe?'})
        events = [json.loads(line[5:]) for line in response.get_data(as_text=True).splitlines() if line.startswith('data:')]
        self.assertEqual(events[-1], {'done': True, 'answer': 'Use the URL Scanner.'})

    def test_password_reset_signs_out_every_device(self):
        token = self.token()
        with self.app.app_context():
            mobile_auth.revoke_all(self.owner);db.session.commit()
        self.assertEqual(self.client.get('/api/mobile/v1/me', headers=self.auth(token)).status_code, 401)

    def test_account_deletion_from_the_app_removes_the_user_and_their_data(self):
        token = self.token()
        other_token = self.token(email='other@example.invalid')
        with self.app.app_context():
            db.session.add_all([Scan(url='https://mine.example', user_id=self.owner, status='completed'),
                                Scan(url='https://theirs.example', user_id=self.other, status='completed'),
                                AIContext(id='a' * 36, user_id=self.owner, tool='url', evidence='{}', explanations='{}', chat='[]'),
                                LogEntry(action='login', user_id=self.owner, username='owner')])
            db.session.commit()
        wrong = self.client.post('/api/mobile/v1/account/delete', headers=self.auth(token), json={'confirm_email': 'other@example.invalid'})
        self.assertEqual(wrong.status_code, 400)
        done = self.client.post('/api/mobile/v1/account/delete', headers=self.auth(token), json={'confirm_email': ' OWNER@example.invalid '})
        self.assertEqual(done.status_code, 200)
        with self.app.app_context():
            self.assertIsNone(db.session.get(User, self.owner))
            self.assertEqual([s.url for s in Scan.query.all()], ['https://theirs.example'])
            self.assertEqual(AIContext.query.count(), 0);self.assertEqual(ApiToken.query.filter_by(user_id=self.owner).count(), 0)
            self.assertEqual(LogEntry.query.filter_by(username='owner').count(), 0)
        self.assertEqual(self.client.get('/api/mobile/v1/me', headers=self.auth(token)).status_code, 401)
        self.assertEqual(self.client.get('/api/mobile/v1/me', headers=self.auth(other_token)).status_code, 200)

    def test_account_deletion_on_the_website_needs_the_email_and_csrf(self):
        with self.client.session_transaction() as session:
            session['_user_id'] = str(self.owner);session['_fresh'] = True
        page = self.client.get('/account/delete')
        self.assertEqual(page.status_code, 200)
        csrf = BeautifulSoup(page.data, 'html.parser').find('input', {'name': 'csrf_token'})['value']
        self.assertEqual(self.client.post('/account/delete', data={'confirm_email': 'owner@example.invalid'}).status_code, 400)
        self.client.post('/account/delete', data={'csrf_token': csrf, 'confirm_email': 'wrong@example.invalid'})
        with self.app.app_context():
            self.assertIsNotNone(db.session.get(User, self.owner))
        response = self.client.post('/account/delete', data={'csrf_token': csrf, 'confirm_email': 'owner@example.invalid'})
        self.assertEqual(response.status_code, 302)
        with self.app.app_context():
            self.assertIsNone(db.session.get(User, self.owner))
        self.assertIn('/login', self.client.get('/profile').headers.get('Location', ''))


if __name__ == '__main__':
    unittest.main()
