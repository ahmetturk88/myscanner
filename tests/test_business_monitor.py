"""MyScanner İşletme monitoring: states, score, change events, ownership grace, scheduling and the workspace view.
No network: every probe is replaced."""
import json
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from bs4 import BeautifulSoup

import test_task_ownership  # noqa: F401  (sets up the test database)
from extensions import db
from models import BusinessDomain, BusinessEvent, BusinessSnapshot, BusinessWorkspace, User
from services import business_monitor as monitor
from services.business_page import CONTENT

T0 = datetime(2026, 11, 5, 9, 0)


def probes(**over):
    base = {
        'ownership': lambda d: True,
        'tls': lambda d: {'valid': True, 'days_remaining': 74, 'issuer': "Let's Encrypt", 'expiry_date': '2027-01-18',
                          'certificate_sha256': 'aa' * 32, 'tls_version': 'TLSv1.3'},
        'registration': lambda d: {'_whois_status': 'assessed', 'days_until_expiry': 300, 'registrar': 'Example Registrar',
                                   'expires': '2027-09-01T00:00:00Z'},
        'dns': lambda d: {'A': ['203.0.113.10'], 'AAAA': [], 'MX': ['10 mx.magazam.com'], 'NS': ['ns1.host.net', 'ns2.host.net']},
        'mail': lambda d: {'status': 'completed', 'spf': 'v=spf1 include:_spf.host.net -all', 'dmarc_policy': 'none', 'protected': False},
        'blocklist': lambda d, ip: {'queried_ips': [ip], 'blacklisted_on': [], 'coverage_status': 'completed'},
        'reputation': lambda d: {'web_risk': {'status': 'not_found'}, 'urlhaus': {'coverage_status': 'not_found'}},
    }
    base.update(over)
    return base


class ReadingTests(unittest.TestCase):
    def test_states_from_probe_results(self):
        self.assertEqual(monitor.read_tls({'valid': True, 'days_remaining': 10})['state'], 'warn')
        self.assertEqual(monitor.read_tls({'valid': True, 'days_remaining': 3})['state'], 'bad')
        self.assertEqual(monitor.read_tls({'valid': False, 'reason_code': 'expired'})['state'], 'bad')
        self.assertEqual(monitor.read_tls({'valid': None})['state'], 'na')  # an outage is never "ok"
        self.assertEqual(monitor.read_registration({'_whois_status': 'assessed', 'days_until_expiry': 20})['state'], 'warn')
        self.assertEqual(monitor.read_registration({'_whois_status': 'unavailable'})['state'], 'na')
        self.assertEqual(monitor.read_mail({'status': 'completed', 'spf': '', 'dmarc_policy': 'missing'})['state'], 'bad')
        self.assertEqual(monitor.read_mail({'status': 'completed', 'spf': 'v=spf1 -all', 'dmarc_policy': 'reject', 'protected': True})['state'], 'ok')
        self.assertEqual(monitor.read_dns({'A': [], 'AAAA': []})['state'], 'bad')
        self.assertEqual(monitor.read_blocklist({'queried_ips': ['1.2.3.4'], 'blacklisted_on': ['zen.spamhaus.org']})['state'], 'bad')
        self.assertEqual(monitor.read_blocklist({'queried_ips': ['1.2.3.4'], 'blacklisted_on': [], 'coverage_status': 'partial'})['state'], 'na')
        # Spamhaus refuses public resolvers: the lists that did answer still count, and the reader sees how many.
        partial = monitor.read_blocklist({'queried_ips': ['1.2.3.4'], 'blacklisted_on': [], 'coverage_status': 'partial',
                                          'clean_on': ['bl.spamcop.net'], 'unavailable_on': ['zen.spamhaus.org']})
        self.assertEqual((partial['state'], partial['clean'], partial['total']), ('ok', 1, 2))
        from services.business_page import CONTENT
        row = dict((name, value) for name, _, value in monitor.check_rows({'blocklist': partial}, CONTENT['tr']))
        self.assertEqual(row['Kara listeler'], 'Listede yok (1/2 liste yanıt verdi)')
        self.assertEqual(monitor.read_reputation({'web_risk': {'status': 'matched'}, 'urlhaus': {}})['lists'], ['Google Web Risk'])
        self.assertEqual(monitor.read_reputation({'web_risk': {'status': 'unavailable'}, 'urlhaus': {}})['state'], 'na')

    def test_score_needs_enough_checks(self):
        self.assertIsNone(monitor.score({'tls': {'state': 'ok'}, 'dns': {'state': 'ok'}}))
        full = {k: {'state': 'ok'} for k in monitor.CHECKS}
        self.assertEqual(monitor.score(full), 100)
        full['reputation'] = {'state': 'bad'}
        full['mail'] = {'state': 'warn'}
        self.assertEqual(monitor.score(full), 40)

    def test_every_event_and_value_renders_in_both_languages(self):
        params = {'days': 5, 'expires': '2027-01-01', 'issuer': 'X', 'lists': 'zen.spamhaus.org', 'ip': '1.2.3.4',
                  'kind': 'A', 'before': 'a', 'after': 'b', 'dmarc': 'none', 'spf': 'v=spf1', 'left': 2, 'reason': 'expired'}
        for lang in ('tr', 'en'):
            for code in CONTENT[lang]['events']:
                self.assertNotIn('{', monitor.event_line({'code': code, 'params': params}, CONTENT[lang]))
            results = {k: {'state': 'na'} for k in monitor.CHECKS}
            self.assertEqual(len(monitor.check_rows(results, CONTENT[lang])), len(monitor.CHECKS))


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
        User.query.filter(User.email.like('%@mon.invalid')).delete(synchronize_session=False)
        db.session.commit()
        self.user = User(username='monowner', email='owner@mon.invalid', password_hash='unused', is_verified=True, is_admin=True)
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

    def events(self):
        return [(e.code, e.severity, json.loads(e.params)) for e in BusinessEvent.query.order_by(BusinessEvent.id)]

    def test_first_run_stores_a_snapshot_and_reports_problems(self):
        snapshot = monitor.run_domain(self.domain, probes(), now=T0)
        self.assertEqual(snapshot.score, 90)  # weak email protection only
        self.assertEqual([c for c, _, _ in self.events()], ['monitoring_started', 'mail_warn'])
        self.assertEqual(self.domain.monitored_at, T0)

    def test_changes_between_runs(self):
        monitor.run_domain(self.domain, probes(), now=T0)
        BusinessEvent.query.delete()
        changed = probes(
            tls=lambda d: {'valid': True, 'days_remaining': 89, 'issuer': "Let's Encrypt", 'expiry_date': '2027-02-02',
                           'certificate_sha256': 'bb' * 32},
            dns=lambda d: {'A': ['198.51.100.7'], 'AAAA': [], 'MX': ['10 mx.magazam.com'], 'NS': ['ns1.evil.example']},
            mail=lambda d: {'status': 'completed', 'spf': 'v=spf1 -all', 'dmarc_policy': 'reject', 'protected': True},
            registration=lambda d: {'_whois_status': 'assessed', 'days_until_expiry': 299, 'registrar': 'Other Registrar'},
            reputation=lambda d: {'web_risk': {'status': 'matched'}, 'urlhaus': {'coverage_status': 'not_found'}})
        monitor.run_domain(self.domain, changed, now=T0 + timedelta(days=1))
        codes = {(c, s) for c, s, _ in self.events()}
        self.assertTrue({('mail_fixed', 'good'), ('reputation_bad', 'bad'), ('tls_renewed', 'info'),
                         ('registrar_changed', 'warn')} <= codes)
        dns_changes = [p for c, _, p in self.events() if c == 'dns_changed']
        self.assertEqual({p['kind'] for p in dns_changes}, {'A', 'NS'})

    def test_a_failing_probe_is_not_a_pass(self):
        def broken(*args):
            raise OSError('down')
        snapshot = monitor.run_domain(self.domain, probes(tls=broken, reputation=broken), now=T0)
        results = json.loads(snapshot.results)
        self.assertEqual((results['tls']['state'], results['reputation']['state']), ('na', 'na'))

    def test_missing_proof_pauses_monitoring_after_grace(self):
        missing = probes(ownership=lambda d: False)
        for day in range(3):
            monitor.run_domain(self.domain, missing, now=T0 + timedelta(days=day))
        codes = [c for c, _, _ in self.events()]
        self.assertEqual(codes.count('proof_missing'), 2)
        self.assertIn('proof_lost', codes)
        self.assertIsNone(self.domain.verified_at)
        self.assertIsNone(monitor.run_domain(self.domain, probes(), now=T0 + timedelta(days=4)))

    def test_due_domains(self):
        other = BusinessDomain(workspace_id=self.workspace.id, domain='other.com', token='cd' * 16, verified_at=T0,
                               monitored_at=T0 - timedelta(hours=2))
        unverified = BusinessDomain(workspace_id=self.workspace.id, domain='new.com', token='ef' * 16)
        db.session.add_all([other, unverified])
        db.session.commit()
        self.assertEqual([d.domain for d in monitor.due_domains(now=T0)], ['magazam.com'])
        self.assertEqual([d.domain for d in monitor.due_domains(now=T0 + timedelta(hours=23))], ['magazam.com', 'other.com'])


class WorkspaceTests(RunTests):
    def login(self, client):
        with client.session_transaction() as session:
            session['_user_id'] = str(self.user.id)
            session['_fresh'] = True

    def test_workspace_shows_score_checks_and_changes(self):
        monitor.run_domain(self.domain, probes(), now=T0)
        client = self.app.test_client()
        self.login(client)
        page = client.get('/isletme/panel?lang=tr').get_data(as_text=True)
        self.assertIn('Güvenlik durumu', page)
        self.assertIn('74 gün geçerli', page)
        self.assertIn('Koruma zayıf (DMARC: none)', page)
        self.assertIn('İzleme başladı.', page)
        self.assertIn('Şimdi kontrol et', page)

    def test_check_now_queues_once_per_click_and_is_limited(self):
        client = self.app.test_client()
        self.login(client)
        token = BeautifulSoup(client.get('/isletme/panel?lang=tr').data, 'html.parser').find('input', attrs={'name': 'csrf_token'})['value']
        with patch('celery_app.require_broker'), patch('celery_app.celery.send_task') as send:
            for _ in range(6):
                client.post(f'/isletme/panel/domains/{self.domain.id}/check', data={'csrf_token': token})
        self.assertEqual(send.call_count, 5)
        send.assert_called_with('business_check_now', args=[self.domain.id])
        self.assertIn('elle kontrol hakkınız doldu', client.get('/isletme/panel?lang=tr').get_data(as_text=True))
        self.domain.verified_at = None
        db.session.commit()
        self.assertEqual(client.post(f'/isletme/panel/domains/{self.domain.id}/check', data={'csrf_token': token}).status_code, 404)


if __name__ == '__main__':
    unittest.main()
