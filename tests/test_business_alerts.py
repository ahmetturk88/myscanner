"""MyScanner İşletme alerts and weekly site inspection: who gets what, once, in which language. No network, no real email."""
import json
import unittest
from datetime import datetime, timedelta

from bs4 import BeautifulSoup

import test_task_ownership  # noqa: F401  (sets up the test database)
from extensions import db
from models import BusinessDomain, BusinessEvent, BusinessSnapshot, BusinessWorkspace, User
from services import business_alerts as alerts
from services import business_monitor as monitor

T0 = datetime(2026, 11, 5, 9, 0)


class Outbox:
    def __init__(self, ok=True):
        self.sent, self.ok = [], ok

    def __call__(self, to, subject, text, html):
        self.sent.append({'to': to, 'subject': subject, 'text': text, 'html': html})
        return self.ok


class AlertTests(unittest.TestCase):
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
        User.query.filter(User.email.like('%@alert.invalid')).delete(synchronize_session=False)
        db.session.commit()
        self.user = User(username='alertowner', email='owner@alert.invalid', password_hash='unused', is_verified=True, is_admin=True)
        db.session.add(self.user)
        db.session.commit()
        self.workspace = BusinessWorkspace(owner_id=self.user.id, name='Mağaza <A&B>')
        db.session.add(self.workspace)
        db.session.commit()
        self.domain = BusinessDomain(workspace_id=self.workspace.id, domain='magazam.com', token='ab' * 16, verified_at=T0)
        db.session.add(self.domain)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        self.context.pop()

    def event(self, code, severity, params=None, at=T0):
        row = BusinessEvent(domain_id=self.domain.id, code=code, severity=severity, params=json.dumps(params or {}), created_at=at)
        db.session.add(row)
        db.session.commit()
        return row

    # ------------------------------------------------------------------ instant

    def test_urgent_events_are_emailed_once_in_turkish(self):
        self.event('dns_changed', 'warn', {'kind': 'A', 'before': '1.1.1.1', 'after': '<b>2.2.2.2</b>'})
        self.event('tls_renewed', 'info', {'expires': '2027-01-01'})
        outbox = Outbox()
        self.assertEqual(alerts.send_instant(self.domain, sender=outbox, now=T0), 1)
        mail = outbox.sent[0]
        self.assertEqual(mail['to'], 'owner@alert.invalid')
        self.assertIn('magazam.com: dikkat gerektiren', mail['subject'])
        self.assertIn('A kayıtları değişti', mail['text'])
        self.assertIn('&lt;b&gt;2.2.2.2&lt;/b&gt;', mail['html'])  # every value is escaped
        self.assertIn('Mağaza &lt;A&amp;B&gt;', mail['html'])
        self.assertIn('/isletme/panel', mail['html'])
        self.assertNotIn('SSL sertifikası yenilendi', mail['text'])  # not urgent: waits for the digest
        self.assertEqual(alerts.send_instant(self.domain, sender=outbox, now=T0), 0)
        self.assertEqual(len(outbox.sent), 1)

    def test_instant_off_unverified_owner_or_failed_send_send_nothing(self):
        self.event('reputation_bad', 'bad', {'lists': 'Google Web Risk'})
        self.workspace.instant_alerts = False
        db.session.commit()
        self.assertEqual(alerts.send_instant(self.domain, sender=Outbox(), now=T0), 0)
        self.workspace.instant_alerts = True
        self.user.is_verified = False
        db.session.commit()
        self.assertEqual(alerts.send_instant(self.domain, sender=Outbox(), now=T0), 0)
        self.user.is_verified = True
        db.session.commit()
        failing = Outbox(ok=False)
        self.assertEqual(alerts.send_instant(self.domain, sender=failing, now=T0), 0)
        self.assertEqual(BusinessEvent.query.filter(BusinessEvent.notified_at.isnot(None)).count(), 0)  # retried later

    def test_english_alerts(self):
        self.workspace.alert_lang = 'en'
        db.session.commit()
        self.event('blocklist_bad', 'bad', {'lists': 'zen.spamhaus.org', 'ip': '203.0.113.10'})
        outbox = Outbox()
        alerts.send_instant(self.domain, sender=outbox, now=T0)
        self.assertIn('a change that needs your attention', outbox.sent[0]['subject'])
        self.assertIn('is on a blocklist', outbox.sent[0]['text'])

    # ------------------------------------------------------------------ digest

    def test_daily_digest_sends_everything_left_once(self):
        self.event('tls_renewed', 'info', {'expires': '2027-01-01'})
        self.event('mail_fixed', 'good')
        self.event('monitoring_started', 'info', at=T0 - timedelta(days=9))  # too old for a digest
        outbox = Outbox()
        self.assertEqual(alerts.send_digest(self.workspace, sender=outbox, now=T0), 2)
        self.assertIn('günlük özet: 2 değişiklik', outbox.sent[0]['subject'])
        self.assertEqual(self.workspace.last_digest_at, T0)
        self.assertEqual(alerts.send_digest(self.workspace, sender=outbox, now=T0), 0)
        self.assertEqual(len(outbox.sent), 1)

    def test_digest_timing(self):
        self.assertEqual(alerts.digests_due(now=datetime(2026, 11, 5, 3, 0)), [])  # 06:00 in Türkiye: too early
        self.assertEqual([w.id for w in alerts.digests_due(now=T0)], [self.workspace.id])
        self.workspace.last_digest_at = T0 - timedelta(hours=5)
        db.session.commit()
        self.assertEqual(alerts.digests_due(now=T0), [])
        self.workspace.last_digest_at = None
        self.workspace.daily_digest = False
        db.session.commit()
        self.assertEqual(alerts.digests_due(now=T0), [])

    # ------------------------------------------------------------------ weekly site inspection

    def test_weekly_inspection_reports_new_and_fixed_issues(self):
        first = {'tone': 'caution', 'reasons': [{'tone': 'warn', 'title': 'It runs old software'},
                                                {'tone': 'warn', 'title': 'Missing security headers'},
                                                {'tone': 'ok', 'title': 'Secure connection'}]}
        monitor.run_weekly(self.domain, probe=lambda d: first, now=T0)
        second = {'tone': 'caution', 'reasons': [{'tone': 'warn', 'title': 'Missing security headers'}]}
        monitor.run_weekly(self.domain, probe=lambda d: second, now=T0 + timedelta(days=7))
        rows = [(e.code, json.loads(e.params).get('title')) for e in BusinessEvent.query.order_by(BusinessEvent.id)]
        self.assertEqual(rows, [('site_issue', 'It runs old software'), ('site_issue', 'Missing security headers'),
                                ('site_issue_fixed', 'It runs old software')])
        from services.business_page import CONTENT
        line = monitor.event_line({'code': 'site_issue', 'params': {'title': 'It runs old software'}}, CONTENT['tr'])
        self.assertIn('Eski yazılım', line)
        self.assertEqual(self.domain.weekly_at, T0 + timedelta(days=7))

    def test_a_failed_inspection_reports_nothing(self):
        def broken(domain):
            raise OSError('site down')
        monitor.run_weekly(self.domain, probe=broken, now=T0)
        self.assertEqual(BusinessEvent.query.count(), 0)

    # ------------------------------------------------------------------ settings

    def test_settings_are_saved_from_the_workspace(self):
        client = self.app.test_client()
        with client.session_transaction() as session:
            session['_user_id'] = str(self.user.id)
            session['_fresh'] = True
        page = client.get('/isletme/panel?lang=tr')
        self.assertIn('owner@alert.invalid', page.get_data(as_text=True))
        token = BeautifulSoup(page.data, 'html.parser').find('input', attrs={'name': 'csrf_token'})['value']
        client.post('/isletme/panel/settings', data={'csrf_token': token, 'alert_lang': 'en', 'daily_digest': 'on'})
        db.session.refresh(self.workspace)
        self.assertEqual((self.workspace.alert_lang, self.workspace.instant_alerts, self.workspace.daily_digest), ('en', False, True))
        client.post('/isletme/panel/settings', data={'csrf_token': token, 'alert_lang': 'xx'})
        db.session.refresh(self.workspace)
        self.assertEqual(self.workspace.alert_lang, 'tr')


if __name__ == '__main__':
    unittest.main()
