"""Redesigned About/Contact/Profile/Workspace pages and their account data."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
import re
import time
import unittest

from bs4 import BeautifulSoup

from extensions import db
from models import Scan, User
import test_task_ownership
from services.contact_guard import form_token

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)


class AllowanceTests(unittest.TestCase):
    def user(self, **kw):
        base = dict(is_admin=False, role='user', scans_reset_date=datetime(2026, 10, 13, 1), **{
            s + '_remaining': 0 for s in ('site_scan', 'file_scan', 'url_analyzer', 'email_check', 'ip_check',
                                          'domain_lookup', 'ssl_check', 'qr_scan', 'subdomain_finder', 'password_check', 'ai_assistant')})
        base.update(kw)
        return NS(**base)

    def rows(self, user):
        from services.account_overview import daily_allowance
        return {row['service']: row for row in daily_allowance(user, now=NOW)}

    def test_today_uses_stored_balance_clamped_to_limit(self):
        rows = self.rows(self.user(url_analyzer_remaining=2, email_check_remaining=999, file_scan_remaining=-4))
        self.assertEqual((rows['url_analyzer']['remaining'], rows['url_analyzer']['limit']), (2, 10))
        self.assertEqual(rows['email_check']['remaining'], 15)
        self.assertEqual((rows['file_scan']['remaining'], rows['file_scan']['percent']), (0, 0))
        self.assertNotIn('sandbox_analysis', rows)

    def test_a_previous_day_shows_full_limits_without_writing(self):
        user = self.user(scans_reset_date=NOW.replace(tzinfo=None) - timedelta(days=1))
        rows = self.rows(user)
        self.assertEqual(rows['url_analyzer']['remaining'], 10)
        self.assertEqual(user.url_analyzer_remaining, 0)

    def test_admin_is_unlimited(self):
        rows = self.rows(self.user(is_admin=True))
        self.assertTrue(all(r['limit'] is None for r in rows.values()))


class PageTests(unittest.TestCase):
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
            user = User(username='owner', email='owner@example.invalid', is_verified=True)
            user.set_password('Original#2026')
            other = User(username='other', email='other@example.invalid', is_verified=True)
            other.set_password('Original#2026')
            db.session.add_all([user, other]); db.session.flush()
            verdicts = ['harmless'] * 9 + ['malicious', 'suspicious', 'high_risk', 'unknown']
            db.session.add_all(Scan(url=f'https://e{i}.example/', verdict=v, status='completed', user_id=user.id) for i, v in enumerate(verdicts))
            db.session.add(Scan(url='https://other.example/', verdict='malicious', status='completed', user_id=other.id))
            db.session.commit()
            self.owner = user.id
        self.client = self.app.test_client()
        self.token = BeautifulSoup(self.client.get('/login').data, 'html.parser').find('meta', {'name': 'csrf-token'})['content']

    def tearDown(self):
        with self.app.app_context():
            db.session.remove(); db.drop_all()

    def sign_in(self):
        with self.client.session_transaction() as session:
            session['_user_id'] = str(self.owner); session['_fresh'] = True

    def test_profile_counts_every_scan_not_just_the_recent_ten(self):
        from services.account_overview import scan_counts
        with self.app.app_context():
            self.assertEqual(scan_counts(self.owner), {'total': 13, 'malicious': 1, 'review': 2, 'harmless': 9, 'unresolved': 1})
        self.sign_in()
        soup = BeautifulSoup(self.client.get('/profile').data, 'html.parser')
        self.assertEqual([el.get_text() for el in soup.select('.pg-metric strong')], ['13', '1', '2', '9'])
        self.assertEqual(len(soup.select('.pg-scan')), 10)
        self.assertEqual(len(soup.select('.pg-quota-row')), 11)

    def test_recent_scans_limit_is_bounded(self):
        self.sign_in()
        self.assertEqual(len(self.client.get('/api/recent_scans').json['scans']), 13)
        self.assertEqual(len(self.client.get('/api/recent_scans?limit=2').json['scans']), 2)
        self.assertEqual(len(self.client.get('/api/recent_scans?limit=-5').json['scans']), 1)
        self.assertEqual(len(self.client.get('/api/recent_scans?limit=100000').json['scans']), 13)

    def test_workspace_renders_without_a_chart_cdn(self):
        self.sign_in()
        html = self.client.get('/dashboard-v2').get_data(as_text=True)
        self.assertNotIn('chart.js', html.lower())
        self.assertIn('id="verdict-donut"', html)
        self.assertIn('13 URL scans saved so far', html)

    def contact(self, sent):
        with patch.object(self.production, 'send_email', return_value=sent) as mail:
            response = self.client.post('/contact', data={'csrf_token': self.token, 'form_token': form_token(self.production.app.config['SECRET_KEY'], time.time() - 10), 'name': 'A', 'email': 'a@example.com',
                                        'subject': 'Bug Report', 'message': 'Hi'}, headers={'X-Requested-With': 'XMLHttpRequest'})
        return response, mail

    def test_contact_reports_mail_failure_instead_of_success(self):
        response, mail = self.contact(False)
        self.assertEqual(response.status_code, 500)
        self.assertFalse(response.json['success'])
        mail.assert_called_once()
        response, _ = self.contact(True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json['success'])

    def test_public_pages_render_with_new_phone_and_no_floating_whatsapp(self):
        for path in ('/about', '/contact'):
            html = self.client.get(path).get_data(as_text=True)
            self.assertIn('+90 551 841 44 87', html)
            self.assertNotIn('wa-float', html)
            self.assertNotIn('5382131162', html)


class StaticContentTests(unittest.TestCase):
    def test_old_number_and_whatsapp_button_are_gone_everywhere(self):
        for path in list((ROOT / 'templates').rglob('*.html')) + list((ROOT / 'static').glob('*.*')):
            if path.suffix in ('.html', '.css', '.js'):
                text = path.read_text(encoding='utf-8', errors='ignore')
                self.assertNotRegex(text, r'538\s?213\s?1162|5382131162', path.name)
                self.assertNotIn('wa-float', text, path.name)

    def test_page_icons_exist(self):
        css = (ROOT / 'static/icons.css').read_text()
        for name in re.findall(r'url\(icons/([a-z]+)\.svg\)', css):
            self.assertTrue((ROOT / 'static/icons' / f'{name}.svg').is_file(), name)

    def test_no_text_below_ten_pixels(self):
        for path in (ROOT / 'static').glob('*.css'):
            for size in re.findall(r'font(?:-size)?\s*:\s*(?:[a-z0-9 ]+\s)?(\d+(?:\.\d+)?)px', path.read_text()):
                self.assertGreaterEqual(float(size), 10, path.name)


if __name__ == '__main__':
    unittest.main()
