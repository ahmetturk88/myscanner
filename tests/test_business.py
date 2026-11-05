"""MyScanner İşletme: public page and pre-registration, pilot gate, and DNS ownership proof without real DNS."""
import unittest
from unittest.mock import patch

import dns.exception
import dns.resolver
from bs4 import BeautifulSoup

import test_task_ownership  # noqa: F401  (sets up the test database)
from extensions import db
from models import BusinessDomain, BusinessLead, BusinessWorkspace, User
from services import business, business_page


class BusinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = test_task_ownership._import_production_app()[1].app
        with cls.app.app_context():
            db.create_all()

    def setUp(self):
        self.client = self.app.test_client()
        with self.app.app_context():
            for model in (BusinessDomain, BusinessWorkspace, BusinessLead):
                model.query.delete()
            User.query.filter(User.email.like('%@biz.invalid')).delete(synchronize_session=False)
            db.session.commit()
            users = [User(username=name, email=name + '@biz.invalid', password_hash='unused', is_verified=True,
                          is_admin=name == 'bossadmin') for name in ('pilot', 'stranger', 'bossadmin')]
            db.session.add_all(users)
            db.session.commit()
            self.ids = {u.username: u.id for u in users}
        self.env = patch.dict('os.environ', {'BUSINESS_PILOT_EMAILS': 'Pilot@biz.invalid, someone@else.invalid'})
        self.env.start()
        self.addCleanup(self.env.stop)

    def login(self, name):
        with self.client.session_transaction() as session:
            session['_user_id'] = str(self.ids[name])
            session['_fresh'] = True

    def token(self, path='/isletme'):
        page = BeautifulSoup(self.client.get(path).data, 'html.parser')
        return page.find('input', attrs={'name': 'csrf_token'})['value']

    # ------------------------------------------------------------- public page

    def test_page_in_both_languages_is_honest_about_price_and_pilot(self):
        turkish = self.client.get('/isletme?lang=tr').get_data(as_text=True)
        self.assertIn('MyScanner İşletme', turkish)
        self.assertIn('Pilot süresince ücretsiz', turkish)
        self.assertIn('≈ $25', turkish)
        english = self.client.get('/isletme?lang=en').get_data(as_text=True)
        self.assertIn('Free during the pilot', english)
        self.assertEqual(self.client.get('/business').status_code, 302)
        # Hidden until the planned pilot: not indexed, every feature listed, nothing described as still coming.
        self.assertIn('<meta name="robots" content="noindex, nofollow">', turkish)
        for key in business_page.FEATURES:
            self.assertIn(business_page.CONTENT['tr']['features'][key][0], turkish)
        self.assertNotIn('adım adım', turkish)
        self.assertNotIn('step by step', english)
        for lang in ('en', 'tr'):
            text = business_page.CONTENT[lang]
            self.assertEqual(set(text), set(business_page.CONTENT['tr']))
            self.assertEqual(set(text['errors']), set(business_page.CONTENT['tr']['errors']))
            self.assertLessEqual(len(text['description']), 170)
            # Jinja reads t.copy as dict.copy: a key named like a dict method would print '<built-in method …>'.
            self.assertEqual([key for key in text if hasattr(dict, key)], [])

    def test_pre_registration_needs_consent_and_is_kept_once(self):
        token = self.token()
        refused = self.client.post('/isletme', data={'csrf_token': token, 'email': 'shop@firma.com.tr'})
        self.assertEqual(refused.status_code, 400)
        data = {'csrf_token': token, 'email': 'Shop@Firma.com.tr', 'website': 'https://www.Firma.com.tr/iletisim',
                'sector': 'eshop', 'consent': 'yes'}
        self.assertIn('Ön kaydınız alındı', self.client.post('/isletme?lang=tr', data=data).get_data(as_text=True))
        self.assertIn('zaten', self.client.post('/isletme?lang=tr', data=data).get_data(as_text=True))
        with self.app.app_context():
            lead = BusinessLead.query.one()
            self.assertEqual((lead.email, lead.website, lead.sector), ('shop@firma.com.tr', 'firma.com.tr', 'eshop'))

    def test_honeypot_and_bad_input_store_nothing(self):
        token = self.token()
        self.client.post('/isletme', data={'csrf_token': token, 'email': 'bot@x.com', 'consent': 'yes', 'company_url': 'spam'})
        self.client.post('/isletme', data={'csrf_token': token, 'email': 'not-an-email', 'consent': 'yes'})
        self.client.post('/isletme', data={'csrf_token': token, 'email': 'a@b.co', 'consent': 'yes', 'sector': '<script>'})
        with self.app.app_context():
            self.assertEqual([(l.email, l.sector) for l in BusinessLead.query.all()], [('a@b.co', 'other')])

    def test_pre_registration_requires_csrf(self):
        response = self.client.post('/isletme', data={'email': 'x@y.com', 'consent': 'yes'})
        self.assertEqual(response.status_code, 400)

    # ------------------------------------------------------------- pilot gate

    def test_workspace_needs_login_and_a_pilot_invitation(self):
        self.assertIn('/login', self.client.get('/isletme/panel').headers['Location'])
        self.login('stranger')
        response = self.client.get('/isletme/panel')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/isletme', response.headers['Location'])
        self.login('pilot')
        self.assertEqual(self.client.get('/isletme/panel').status_code, 200)
        self.login('bossadmin')
        self.assertEqual(self.client.get('/isletme/panel').status_code, 200)

    def test_pilot_gate_requires_a_verified_email(self):
        from types import SimpleNamespace
        user = SimpleNamespace(is_authenticated=True, is_admin=False, role='user', email='Pilot@biz.invalid', is_verified=False)
        self.assertFalse(business.pilot_allowed(user, {'BUSINESS_PILOT_EMAILS': 'pilot@biz.invalid'}))
        user.is_verified = True
        self.assertTrue(business.pilot_allowed(user, {'BUSINESS_PILOT_EMAILS': 'pilot@biz.invalid'}))
        self.assertFalse(business.pilot_allowed(user, {}))

    # ------------------------------------------------------------- domains and proof

    def test_domain_names_are_normalized_and_unsafe_ones_refused(self):
        for value, expected in [('https://www.Magazam.com/iletisim?x=1', 'magazam.com'), ('magazam.com.tr', 'magazam.com.tr'),
                                ('shop.magazam.com', 'shop.magazam.com'), ('www.bücher.de', 'xn--bcher-kva.de')]:
            self.assertEqual(business.normalize_domain(value), expected)
        for value in ('', 'localhost', '127.0.0.1', 'intranet.local', 'a..com', 'user:pass@x.com', 'x.com:8080', None):
            with self.subTest(value=value), self.assertRaises(business.BusinessError):
                business.normalize_domain(value)

    def test_add_verify_and_remove_a_domain(self):
        self.login('pilot')
        token = self.token('/isletme/panel')
        self.client.post('/isletme/panel/domains', data={'csrf_token': token, 'domain': 'https://www.magazam.com/'})
        with self.app.app_context():
            domain = BusinessDomain.query.one()
            record, value = business.record_name(domain), business.record_value(domain)
            self.assertEqual(record, '_myscanner.magazam.com')
            self.assertTrue(value.startswith('myscanner-business=') and len(value) > 40)
            domain_id = domain.id
        page = self.client.get('/isletme/panel?lang=tr').get_data(as_text=True)
        self.assertIn(value, page)
        self.assertIn('Doğrulama bekleniyor', page)
        with patch('services.business.lookup_txt', return_value=['v=spf1 -all', 'myscanner-business=wrong']):
            self.client.post(f'/isletme/panel/domains/{domain_id}/verify', data={'csrf_token': token})
        self.assertIn('henüz bulunamadı', self.client.get('/isletme/panel?lang=tr').get_data(as_text=True))
        with patch('services.business.lookup_txt', return_value=[value]):
            self.client.post(f'/isletme/panel/domains/{domain_id}/verify', data={'csrf_token': token})
        page = self.client.get('/isletme/panel?lang=tr').get_data(as_text=True)
        self.assertIn('Doğrulandı', page)
        with self.app.app_context():
            self.assertIsNotNone(db.session.get(BusinessDomain, domain_id).verified_at)
        self.client.post(f'/isletme/panel/domains/{domain_id}/remove', data={'csrf_token': token})
        with self.app.app_context():
            self.assertEqual(BusinessDomain.query.count(), 0)

    def test_dns_errors_never_verify(self):
        with self.app.app_context():
            workspace = BusinessWorkspace(owner_id=self.ids['pilot'], name='pilot')
            db.session.add(workspace)
            db.session.commit()
            domain = business.add_domain(workspace, 'magazam.com')
            for error in (dns.exception.Timeout(), dns.resolver.NoNameservers(), OSError()):
                with self.assertRaises(business.BusinessError) as caught:
                    business.verify_domain(domain, lookup=lambda name, e=error: (_ for _ in ()).throw(e))
                self.assertEqual(str(caught.exception), 'dns_unavailable')
            with self.assertRaises(business.BusinessError) as caught:
                business.verify_domain(domain, lookup=lambda name: (_ for _ in ()).throw(dns.resolver.NXDOMAIN()))
            self.assertEqual(str(caught.exception), 'not_found_yet')
            self.assertIsNone(domain.verified_at)

    def test_another_company_cannot_touch_my_domain(self):
        with self.app.app_context():
            mine = BusinessWorkspace(owner_id=self.ids['pilot'], name='pilot')
            db.session.add(mine)
            db.session.commit()
            domain_id = business.add_domain(mine, 'magazam.com').id
        self.login('bossadmin')  # even an administrator's own workspace cannot reach another workspace's domain
        token = self.token('/isletme/panel')
        with patch('services.business.lookup_txt', return_value=[]):
            self.assertEqual(self.client.post(f'/isletme/panel/domains/{domain_id}/verify', data={'csrf_token': token}).status_code, 404)
        self.assertEqual(self.client.post(f'/isletme/panel/domains/{domain_id}/remove', data={'csrf_token': token}).status_code, 404)
        with self.app.app_context():
            self.assertEqual(BusinessDomain.query.count(), 1)

    def test_pilot_domain_limit(self):
        with self.app.app_context():
            workspace = BusinessWorkspace(owner_id=self.ids['pilot'], name='pilot')
            db.session.add(workspace)
            db.session.commit()
            for name in ('a.com', 'b.com', 'c.com'):
                business.add_domain(workspace, name)
            self.assertEqual(business.add_domain(workspace, 'a.com').domain, 'a.com')  # the same domain again is not a new one
            with self.assertRaises(business.BusinessError):
                business.add_domain(workspace, 'd.com')

    def test_admin_leads_page_is_admin_only(self):
        self.login('stranger')
        self.assertEqual(self.client.get('/admin/business-leads').status_code, 404)
        self.login('bossadmin')
        self.assertEqual(self.client.get('/admin/business-leads').status_code, 200)


if __name__ == '__main__':
    unittest.main()
