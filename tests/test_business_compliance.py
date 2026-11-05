"""MyScanner İşletme KVKK / legal pages checklist: detection, shops, events, workspace and report. No network."""
import io
import json
import unittest
from datetime import datetime, timedelta

from pypdf import PdfReader

import test_task_ownership  # noqa: F401  (sets up the test database)
from extensions import db
from models import BusinessDomain, BusinessEvent, BusinessSnapshot, BusinessWorkspace, User
from services import business_compliance as kvkk
from services.business_monitor import event_line
from services.business_page import CONTENT

T0 = datetime(2026, 11, 5, 9, 0)

HOME = """<html><head><script src="https://www.googletagmanager.com/gtag/js?id=G-1"></script></head><body>
<a href="/kvkk-aydinlatma-metni">KVKK</a> <a href="/iletisim">İletişim</a> <a href="https://other.example/kvkk">elsewhere</a>
<form action="/abone" method="post"><input name="email"></form><p>Merhaba</p></body></html>"""
KVKK_PAGE = '<html><body><h1>Kişisel Verilerin Korunması Kanunu Aydınlatma Metni</h1></body></html>'
CONTACT = '<html><body>info@magazam.com · 0212 555 12 34 · Atatürk Mah. Deniz Sok. No:3</body></html>'
SHOP_HOME = """<html><body><button>Sepete ekle</button> 1.250,00 TL 899,90 TL
<a href="/mesafeli-satis-sozlesmesi">Mesafeli Satış Sözleşmesi</a><p>Cookiebot</p>
<script src="https://consent.cookiebot.com/uc.js"></script></body></html>"""


class AssessTests(unittest.TestCase):
    def test_a_site_with_tracking_but_no_consent(self):
        result = kvkk.assess([('https://magazam.com/', HOME), ('https://magazam.com/kvkk-aydinlatma-metni', KVKK_PAGE),
                              ('https://magazam.com/iletisim', CONTACT)])
        items = result['items']
        self.assertEqual(items['kvkk'], {'state': 'ok', 'where': '/kvkk-aydinlatma-metni'})
        self.assertEqual(items['privacy']['state'], 'warn')
        self.assertEqual(items['consent'], {'state': 'warn', 'trackers': ['Google Analytics']})
        self.assertEqual(items['contact'], {'state': 'ok', 'address': True})
        self.assertEqual(items['forms']['state'], 'ok')
        self.assertFalse(result['shop'])
        self.assertNotIn('distance', items)

    def test_shops_get_the_e_commerce_items_and_insecure_forms_are_bad(self):
        page = SHOP_HOME.replace('</body>', '<form action="http://magazam.com/login"></form></body>')
        contract = '<html><body><h1>Mesafeli Satış Sözleşmesi</h1></body></html>'
        self.assertEqual(kvkk.assess([('https://magazam.com/', page)])['items']['distance']['state'], 'warn')  # a link alone
        result = kvkk.assess([('https://magazam.com/', page), ('https://magazam.com/mesafeli-satis-sozlesmesi', contract)])
        self.assertTrue(result['shop'])
        self.assertEqual(result['items']['consent']['state'], 'ok')
        self.assertEqual(result['items']['distance']['state'], 'ok')
        self.assertEqual(result['items']['etbis']['state'], 'warn')
        self.assertEqual(result['items']['forms']['state'], 'bad')

    def test_only_the_sites_own_legal_pages_are_read(self):
        from unittest.mock import patch
        import contextlib
        asked = []

        def fake_get(session, url):
            asked.append(url)
            return url, (HOME.replace('</body>', '<a href="/urunler/ayakkabi">shoes</a><a href="/gizlilik">Gizlilik</a></body>')
                         if url.endswith('magazam.com/') else '<p>x</p>')
        with patch.object(kvkk, '_get', fake_get), patch('services.safe_http.PublicHTTPSession', lambda **k: contextlib.nullcontext()):
            pages = kvkk.probe_pages('magazam.com')
        self.assertEqual(asked, ['https://magazam.com/', 'https://magazam.com/kvkk-aydinlatma-metni',
                                 'https://magazam.com/iletisim', 'https://magazam.com/gizlilik'])
        self.assertEqual(len(pages), 4)

    def test_events_name_the_item(self):
        line = event_line({'code': 'kvkk_missing', 'params': {'item': 'kvkk'}}, CONTENT['tr'])
        self.assertEqual(line, 'Sitenizde artık bulunamadı: KVKK aydınlatma metni. Sayfa kaldırıldıysa yeniden ekleyin.')


class RunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = test_task_ownership._import_production_app()[1].app
        with cls.app.app_context():
            db.create_all()

    def setUp(self):
        self.context = self.app.app_context()
        self.context.push()
        for model in (BusinessEvent, BusinessSnapshot, BusinessDomain, BusinessWorkspace):
            model.query.delete()
        User.query.filter(User.email.like('%@kvkk.invalid')).delete(synchronize_session=False)
        db.session.commit()
        self.user = User(username='kvkkowner', email='owner@kvkk.invalid', password_hash='unused', is_verified=True, is_admin=True)
        db.session.add(self.user)
        db.session.commit()
        self.workspace = BusinessWorkspace(owner_id=self.user.id, name='owner')
        db.session.add(self.workspace)
        db.session.commit()
        self.domain = BusinessDomain(workspace_id=self.workspace.id, domain='magazam.com', token='ab' * 16, verified_at=T0)
        db.session.add(self.domain)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        self.context.pop()

    PAGES = [('https://magazam.com/', HOME), ('https://magazam.com/kvkk-aydinlatma-metni', KVKK_PAGE),
             ('https://magazam.com/iletisim', CONTACT)]

    def test_first_run_is_quiet_then_changes_become_events(self):
        kvkk.run_compliance(self.domain, probe=lambda d: self.PAGES, now=T0)
        self.assertEqual(BusinessEvent.query.count(), 0)
        kvkk.run_compliance(self.domain, probe=lambda d: [('https://magazam.com/', HOME)], now=T0 + timedelta(days=7))
        codes = {(e.code, json.loads(e.params)['item']) for e in BusinessEvent.query.all()}
        self.assertEqual(codes, {('kvkk_missing', 'kvkk'), ('kvkk_missing', 'contact')})
        kvkk.run_compliance(self.domain, probe=lambda d: self.PAGES, now=T0 + timedelta(days=14))
        self.assertEqual(BusinessEvent.query.filter_by(code='kvkk_fixed').count(), 2)

    def test_no_answer_concludes_nothing(self):
        self.assertIsNone(kvkk.run_compliance(self.domain, probe=lambda d: [], now=T0))
        self.assertIsNone(kvkk.view(self.domain.id, CONTENT['tr']))

    def test_workspace_and_report(self):
        client = self.app.test_client()
        with client.session_transaction() as session:
            session['_user_id'] = str(self.user.id)
            session['_fresh'] = True
        self.assertIn('İlk kontrol haftalık site incelemesiyle', client.get('/isletme/panel?lang=tr').get_data(as_text=True))
        kvkk.run_compliance(self.domain, probe=lambda d: self.PAGES, now=T0)
        page = client.get('/isletme/panel?lang=tr').get_data(as_text=True)
        self.assertIn('KVKK aydınlatma metni', page)
        self.assertIn('Var · /kvkk-aydinlatma-metni', page)
        self.assertIn('İzleme kodu var, onay aracı görülmedi (Google Analytics)', page)
        self.assertIn('hukuki görüş değildir', page)
        from services.business_report import generate_business_report
        pdf = generate_business_report(self.workspace, 'tr', now=T0 + timedelta(hours=1))
        text = ''.join(p.extract_text() for p in PdfReader(io.BytesIO(pdf.getvalue())).pages)
        self.assertIn('KVKK ve yasal sayfalar', text)
        self.assertIn('Gizlilik politikası', text)


if __name__ == '__main__':
    unittest.main()
