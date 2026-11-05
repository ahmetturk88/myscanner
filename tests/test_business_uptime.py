"""MyScanner İşletme uptime: probe answers, outage/recovery events, counts, alerts, panel and report. No network."""
import io
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

import requests
from pypdf import PdfReader

import test_task_ownership  # noqa: F401  (sets up the test database)
from extensions import db
from models import BusinessDomain, BusinessEvent, BusinessUptimeDay, BusinessWorkspace, User
from services import business_uptime as uptime
from services.business_monitor import event_line
from services.business_page import CONTENT

T0 = datetime(2026, 11, 5, 9, 0)


class ProbeTests(unittest.TestCase):
    def answers(self, *steps):
        steps = list(steps)

        def fetch(url):
            step = steps.pop(0)
            if isinstance(step, Exception):
                raise step
            return step
        return fetch

    def test_classification(self):
        with patch.object(uptime, '_fetch', self.answers((200, 120))):
            self.assertEqual(uptime.probe_site('a.com'), {'ok': True, 'status': 200, 'ms': 120, 'reason': None})
        with patch.object(uptime, '_fetch', self.answers((403, 80))):  # a firewall answering still means the site is up
            self.assertTrue(uptime.probe_site('a.com')['ok'])
        with patch.object(uptime, '_fetch', self.answers((503, 90))):
            self.assertEqual(uptime.probe_site('a.com')['reason'], 'server_error')
        with patch.object(uptime, '_fetch', self.answers(requests.exceptions.Timeout())):
            self.assertEqual(uptime.probe_site('a.com')['reason'], 'timeout')
        # HTTPS broken but plain HTTP answers: the site is reachable
        with patch.object(uptime, '_fetch', self.answers(requests.exceptions.SSLError(), (200, 50))):
            self.assertTrue(uptime.probe_site('a.com')['ok'])
        with patch.object(uptime, '_fetch', self.answers(requests.exceptions.SSLError(), requests.exceptions.ConnectionError())):
            self.assertEqual(uptime.probe_site('a.com')['reason'], 'connection')

    def test_reasons_are_translated_in_events(self):
        line = event_line({'code': 'site_down', 'params': {'reason': 'server_error', 'status': 502}}, CONTENT['tr'])
        self.assertEqual(line, 'Siteniz açılmıyor: sunucu hatası (HTTP 502). Barındırma (hosting) firmanızı kontrol edin.')
        self.assertIn('about 12 minutes', event_line({'code': 'site_up', 'params': {'minutes': 12}}, CONTENT['en']))


class UptimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = test_task_ownership._import_production_app()[1].app
        with cls.app.app_context():
            db.create_all()

    def setUp(self):
        self.context = self.app.app_context()
        self.context.push()
        for model in (BusinessEvent, BusinessUptimeDay, BusinessDomain, BusinessWorkspace):
            model.query.delete()
        User.query.filter(User.email.like('%@uptime.invalid')).delete(synchronize_session=False)
        db.session.commit()
        self.user = User(username='uptimeowner', email='owner@uptime.invalid', password_hash='unused', is_verified=True, is_admin=True)
        db.session.add(self.user)
        db.session.commit()
        self.workspace = BusinessWorkspace(owner_id=self.user.id, name='owner')
        db.session.add(self.workspace)
        db.session.commit()
        self.domain = BusinessDomain(workspace_id=self.workspace.id, domain='magazam.com', token='ef' * 16, verified_at=T0)
        self.pending = BusinessDomain(workspace_id=self.workspace.id, domain='bekliyor.com', token='aa' * 16)
        db.session.add_all([self.domain, self.pending])
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        self.context.pop()

    def run_at(self, minutes, answer, control=True):
        probes = {'control': lambda: control, 'site': lambda domain: dict(answer)}
        return uptime.run_uptime([self.domain], probes, now=T0 + timedelta(minutes=minutes))

    UP = {'ok': True, 'status': 200, 'ms': 300, 'reason': None}
    DOWN = {'ok': False, 'status': None, 'ms': None, 'reason': 'timeout'}

    def test_only_verified_domains_that_are_due(self):
        self.assertEqual(uptime.due_domains(T0), [self.domain])
        self.run_at(0, self.UP)
        self.assertEqual(uptime.due_domains(T0 + timedelta(minutes=2)), [])
        self.assertEqual(uptime.due_domains(T0 + timedelta(minutes=5)), [self.domain])

    def test_our_own_network_failing_concludes_nothing(self):
        self.assertEqual(self.run_at(0, self.DOWN, control=False), {})
        self.assertIsNone(self.domain.up_state)
        self.assertEqual(BusinessUptimeDay.query.count(), 0)

    def test_two_failures_make_an_outage_and_a_success_ends_it(self):
        self.assertEqual(self.run_at(0, self.UP), {})
        self.assertEqual(self.domain.up_state, 'up')
        self.assertEqual(self.run_at(5, self.DOWN), {})  # one failure alone never alerts
        found = self.run_at(10, self.DOWN)
        self.assertEqual(found[self.domain.id], [('site_down', 'bad', {'reason': 'timeout'})])
        self.assertEqual((self.domain.up_state, self.domain.down_since), ('down', T0 + timedelta(minutes=5)))
        self.assertEqual(self.run_at(15, self.DOWN), {})  # still down: told once
        found = self.run_at(40, self.UP)
        self.assertEqual(found[self.domain.id], [('site_up', 'good', {'minutes': 35})])
        self.assertEqual((self.domain.up_state, self.domain.up_fails, self.domain.down_since), ('up', 0, None))
        self.assertEqual(BusinessEvent.query.filter_by(code='site_down').count(), 1)

    def test_daily_counts_and_summary(self):
        for minute, answer in ((0, self.UP), (5, self.UP), (10, self.DOWN), (15, dict(self.UP, ms=500))):
            self.run_at(minute, answer)
        row = BusinessUptimeDay.query.one()
        self.assertEqual((row.checks, row.ups, row.total_ms), (4, 3, 1100))
        self.assertEqual(uptime.summary(self.domain.id, now=T0), {'percent': 75.0, 'avg_ms': 367, 'checks': 4})
        self.assertEqual(uptime.view(self.domain, CONTENT['tr'], now=T0)['percent'], '75')
        self.assertEqual(uptime.summary(self.pending.id, now=T0)['percent'], None)

    def test_outages_are_urgent_alerts(self):
        from services import business_alerts
        self.run_at(0, self.DOWN)
        self.run_at(5, self.DOWN)
        sent = []
        business_alerts.send_instant(self.domain, sender=lambda *a: sent.append(a) or True, now=T0)
        self.assertEqual(len(sent), 1)
        self.assertIn('Siteniz açılmıyor: yanıt vermiyor (zaman aşımı)', sent[0][2])

    def test_workspace_and_report_show_availability(self):
        for minute in range(0, 100, 5):
            self.run_at(minute, self.UP if minute % 20 else self.DOWN)
        client = self.app.test_client()
        with client.session_transaction() as session:
            session['_user_id'] = str(self.user.id)
            session['_fresh'] = True
        page = client.get('/isletme/panel?lang=tr').get_data(as_text=True)
        self.assertIn('Erişilebilirlik: Açık', page)
        self.assertIn('Son 30 gün: %75 · ortalama yanıt 300 ms', page)
        from services.business_report import generate_business_report
        pdf = generate_business_report(self.workspace, 'tr', now=T0 + timedelta(hours=2))
        text = ''.join(p.extract_text() for p in PdfReader(io.BytesIO(pdf.getvalue())).pages)
        self.assertIn('Erişilebilirlik (son 30 gün): %75', text)
        self.assertIn('erişilebilirdi', text)  # below 99%: on the to-do list


if __name__ == '__main__':
    unittest.main()
