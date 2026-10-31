"""Mobile app API: token sign-in, cookie isolation, tool access and account deletion."""
import base64
import hashlib
import json
import unittest
from urllib.parse import parse_qs, urlparse
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
        for path in ('', '/analysis', '/screenshot'):
            self.assertEqual(self.client.get(f'/api/mobile/v1/scans/{scan_id}{path}', headers=self.auth(token)).status_code, 404, path)
        recent = self.client.get('/api/mobile/v1/scans/recent', headers=self.auth(token))
        self.assertEqual(recent.status_code, 200);self.assertNotIn('example.org', recent.get_data(as_text=True))

    def test_the_owner_gets_the_page_screenshot_with_the_app_token(self):
        from services.url_screenshot import screenshot_path
        with self.app.app_context():
            scan = Scan(url='https://example.org', user_id=self.owner, status='completed', result='{}')
            db.session.add(scan);db.session.commit()
            scan_id = scan.id
            path = screenshot_path(scan_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'\xff\xd8\xff\xe0jpeg')
        self.addCleanup(path.unlink, missing_ok=True)
        url = f'/api/mobile/v1/scans/{scan_id}/screenshot'
        self.assertEqual(self.client.get(url).status_code, 401)
        response = self.client.get(url, headers=self.auth(self.token()))
        self.assertEqual((response.status_code, response.mimetype), (200, 'image/jpeg'))
        self.assertEqual(response.headers['Cache-Control'], 'private, no-store')

    def test_ai_assistant_streams_through_the_app_api(self):
        token = self.token()
        stream = iter(['Use the URL ', 'Scanner.'])
        with patch.object(ai_assistant, 'providers', return_value=[('groq', 'q' * 20, 'm')]), \
             patch.object(ai_assistant, 'STREAMERS', {'groq': lambda *a: stream}):
            response = self.client.post('/api/mobile/v1/ai/assistant', headers=self.auth(token), json={'message': 'Is this safe?'})
        events = [json.loads(line[5:]) for line in response.get_data(as_text=True).splitlines() if line.startswith('data:')]
        self.assertEqual(events[-1], {'done': True, 'answer': 'Use the URL Scanner.'})

    def test_report_pdfs_reach_the_app_as_one_time_links(self):
        import sys
        sys.path.insert(0, 'tests')
        from test_report_pdf import email_result, site_result
        from services.report_receipts import issue_receipt
        token = self.token()
        secret = self.app.config['SECRET_KEY']
        for kind, result in (('site', site_result()), ('email', email_result())):
            receipt = issue_receipt(kind, result, str(self.owner), secret)
            answer = self.client.post(f'/api/mobile/v1/reports/{kind}/pdf', headers=self.auth(token), json={'receipt': receipt})
            self.assertEqual(answer.status_code, 200, answer.get_data(as_text=True))
            link = answer.json['url']
            self.assertRegex(link, r'^/api/mobile/v1/pdf/[0-9a-f]{48}$')
            pdf = self.client.get(link)  # the browser has no app token: the link is the credential
            self.assertEqual((pdf.status_code, pdf.mimetype), (200, 'application/pdf'))
            self.assertTrue(pdf.data.startswith(b'%PDF'))
            self.assertEqual(self.client.get(link).status_code, 404)  # one time only
        foreign = issue_receipt('site', site_result(), str(self.other), secret)
        refused = self.client.post('/api/mobile/v1/reports/site/pdf', headers=self.auth(token), json={'receipt': foreign})
        self.assertEqual(refused.status_code, 400)
        self.assertEqual(self.client.post('/api/mobile/v1/reports/site/pdf', json={'receipt': foreign}).status_code, 401)
        self.assertEqual(self.client.post('/api/mobile/v1/reports/admin/pdf', headers=self.auth(token), json={}).status_code, 404)
        self.assertEqual(self.client.get('/api/mobile/v1/pdf/../../etc/passwd').status_code, 404)

    def test_pdf_links_are_limited_per_user_and_in_number(self):
        import sys
        from unittest.mock import patch
        sys.path.insert(0, 'tests')
        from test_report_pdf import email_result
        from services.report_receipts import issue_receipt
        import routes.mobile_api as mobile_api
        token = self.token()
        receipt = issue_receipt('email', email_result(), str(self.owner), self.app.config['SECRET_KEY'])
        post = lambda: self.client.post('/api/mobile/v1/reports/email/pdf', headers=self.auth(token), json={'receipt': receipt})  # noqa: E731
        with patch.object(mobile_api, 'PDF_PENDING_MAX', 1):
            first, second = post(), post()
            self.assertEqual(first.status_code, 200)
            self.assertEqual(second.status_code, 503)  # one link already waiting: the store is full
            self.client.get(first.json['url'])
        with patch.object(mobile_api, 'PDF_PER_USER', (1, 600)):
            self.assertEqual(post().status_code, 429)
        link = self.client.post('/api/mobile/v1/reports/email/pdf', headers=self.auth(self.token(email='other@example.invalid')),
                                json={'receipt': issue_receipt('email', email_result(), str(self.other), self.app.config['SECRET_KEY'])})
        self.assertEqual(link.status_code, 200)
        pdf = self.client.get(link.json['url'])
        self.assertEqual(pdf.headers['Referrer-Policy'], 'no-referrer')
        self.assertIn('noindex', pdf.headers['X-Robots-Tag'])

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

    def oauth_round_trip(self, redirect='myscanner://auth', verifier='v' * 50, email='owner@example.invalid'):
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
        with patch('services.oauth_login.credentials', return_value=('id', 'secret')):
            start = self.client.get(f'/api/mobile/v1/auth/oauth/google?redirect={redirect}&challenge={challenge}')
        self.assertEqual(start.status_code, 302);self.assertIn('accounts.google.com', start.headers['Location'])
        with patch('services.oauth_login.finish', return_value=(email, 'Owner')):
            back = self.client.get('/auth/google/callback?code=x&state=y')
        self.assertEqual(back.status_code, 302)
        return back.headers['Location']

    def test_google_sign_in_returns_a_one_time_code_bound_to_the_app(self):
        location = self.oauth_round_trip(redirect='exp://192.168.1.5:8081/--/auth')
        self.assertTrue(location.startswith('exp://192.168.1.5:8081/--/auth?code='))
        code = parse_qs(urlparse(location).query)['code'][0]
        with self.client.session_transaction() as session:
            self.assertNotIn('_user_id', session)  # no website session is created
        bad = self.client.post('/api/mobile/v1/auth/oauth/exchange', json={'code': code, 'verifier': 'w' * 50})
        self.assertEqual(bad.status_code, 401)
        good = self.client.post('/api/mobile/v1/auth/oauth/exchange', json={'code': code, 'verifier': 'v' * 50, 'device': 'Pixel'})
        self.assertEqual(good.status_code, 200);self.assertEqual(good.json['user']['username'], 'owner')
        again = self.client.post('/api/mobile/v1/auth/oauth/exchange', json={'code': code, 'verifier': 'v' * 50})
        self.assertEqual(again.status_code, 401)
        self.assertEqual(self.client.get('/api/mobile/v1/me', headers=self.auth(good.json['token'])).status_code, 200)

    def test_google_sign_in_rejects_foreign_redirects_and_reports_failures_to_the_app(self):
        challenge = 'c' * 43
        for redirect in ('https://evil.example/auth', 'myscanner://other', 'exp://host/--/auth?x=1', ''):
            response = self.client.get(f'/api/mobile/v1/auth/oauth/google?redirect={redirect}&challenge={challenge}')
            self.assertEqual(response.status_code, 400, redirect)
        self.assertEqual(self.client.get('/api/mobile/v1/auth/oauth/google?redirect=myscanner://auth&challenge=short').status_code, 400)
        from services.oauth_login import OAuthError
        with patch('services.oauth_login.credentials', return_value=('id', 'secret')):
            self.client.get(f'/api/mobile/v1/auth/oauth/google?redirect=myscanner://auth&challenge={challenge}')
        with patch('services.oauth_login.finish', side_effect=OAuthError('Sign-in was cancelled.')):
            back = self.client.get('/auth/google/callback?error=access_denied')
        self.assertTrue(back.headers['Location'].startswith('myscanner://auth?error=Sign-in+was+cancelled'))

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
