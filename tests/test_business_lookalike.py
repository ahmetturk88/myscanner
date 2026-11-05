"""MyScanner İşletme look-alike watch: candidate names, certificate names, risk, events, dismissing. No network."""
import json
import unittest
from datetime import datetime, timedelta

from bs4 import BeautifulSoup

import test_task_ownership  # noqa: F401  (sets up the test database)
from extensions import db
from models import BusinessDomain, BusinessEvent, BusinessLookalike, BusinessWorkspace, User
from services import business_lookalike as look
from services.business_monitor import event_line
from services.business_page import CONTENT

T0 = datetime(2026, 11, 5, 9, 0)


class NameTests(unittest.TestCase):
    def test_candidates_cover_the_usual_tricks_and_never_the_domain_itself(self):
        names = look.candidates('www.magazam.com.tr')
        self.assertNotIn('magazam.com.tr', names)
        for expected in ('magazam.com', 'magazam.shop', 'magzam.com.tr', 'magazamm.com.tr', 'maagzam.com.tr',
                         'm4gazam.com.tr', 'rnagazam.com.tr', 'magazam-giris.com', 'odeme-magazam.com.tr', 'magazamdestek.com'):
            self.assertIn(expected, names)
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(len(n) <= 253 for n in names))
        self.assertEqual(names[0], 'magazam.com')  # other endings first: the most common squats

    def test_certificate_names_must_carry_the_brand(self):
        self.assertTrue(look.resembles('secure.magaz4m-odeme.xyz', 'magazam'))
        self.assertTrue(look.resembles('magazam.co', 'magazam'))
        self.assertFalse(look.resembles('magazine.com', 'magazam'))
        self.assertFalse(look.resembles('abc.com', 'abc'))  # too short a brand to judge

    def test_risk(self):
        self.assertEqual(look.risk_of({'live': False}), 'low')
        self.assertEqual(look.risk_of({'live': True}), 'medium')
        self.assertEqual(look.risk_of({'live': True, 'asks': True}), 'high')
        self.assertEqual(look.risk_of({'live': True, 'brand': True}), 'high')

    def test_newly_registered_names_move_up_one_step(self):
        self.assertEqual(look.risk_of({'live': False}, new=True), 'medium')
        self.assertEqual(look.risk_of({'live': True}, new=True), 'high')
        self.assertEqual(look.risk_of({'live': True, 'asks': True}, new=True), 'high')

    def test_ownership_hints_compare_public_infrastructure(self):
        own = {'NS': ['houston.ns.cloudflare.com', 'nena.ns.cloudflare.com'], 'A': ['203.0.113.9'], 'AAAA': [],
               'MX': ['10 route1.mx.cloudflare.net']}
        self.assertEqual(look.ownership_hint(own, {'NS': ['nena.ns.cloudflare.com', 'houston.ns.cloudflare.com']})[0], 'ns')
        self.assertEqual(look.ownership_hint(own, {'NS': ['ns1.other.net'], 'A': ['203.0.113.9']}), ('ip', '203.0.113.9'))
        self.assertEqual(look.ownership_hint(own, {'NS': [], 'A': [], 'MX': ['5 route1.mx.cloudflare.net.']}),
                         ('mx', 'route1.mx.cloudflare.net'))
        # One shared name server is not enough: every customer of a big provider shares some.
        self.assertEqual(look.ownership_hint(own, {'NS': ['houston.ns.cloudflare.com', 'other.ns.cloudflare.com']}), (None, None))
        self.assertEqual(look.ownership_hint(None, {'NS': ['x']}), (None, None))
        self.assertEqual(look.ownership_hint(own, None), (None, None))

    def test_events_render_with_translated_risk(self):
        line = event_line({'code': 'lookalike_found', 'params': {'name': 'magazam-giris.com', 'risk': 'high'}}, CONTENT['tr'])
        self.assertEqual(line, 'Markanıza benzeyen bir alan adı bulundu: magazam-giris.com (risk: yüksek).')


class WatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = test_task_ownership._import_production_app()[1].app
        with cls.app.app_context():
            db.create_all()

    def setUp(self):
        self.context = self.app.app_context()
        self.context.push()
        for model in (BusinessEvent, BusinessLookalike, BusinessDomain, BusinessWorkspace):
            model.query.delete()
        User.query.filter(User.email.like('%@look.invalid')).delete(synchronize_session=False)
        db.session.commit()
        self.user = User(username='lookowner', email='owner@look.invalid', password_hash='unused', is_verified=True, is_admin=True)
        db.session.add(self.user)
        db.session.commit()
        self.workspace = BusinessWorkspace(owner_id=self.user.id, name='owner')
        db.session.add(self.workspace)
        db.session.commit()
        self.domain = BusinessDomain(workspace_id=self.workspace.id, domain='magazam.com.tr', token='ab' * 16, verified_at=T0)
        db.session.add(self.domain)
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        self.context.pop()

    OWN = {'NS': ['ns1.hosting.example', 'ns2.hosting.example'], 'A': ['198.51.100.1'], 'AAAA': [], 'MX': []}

    def probes(self, existing, live=(), ct=(), records=None, registration=None):
        def resolve(name):
            return ['203.0.113.9'] if name in existing else []
        def inspect(name, label):
            if name in live:
                return {'live': True, 'title': 'Magazam Giriş', 'brand': True, 'asks': True}
            return {'live': False}
        def dns_records(name):
            if name == 'magazam.com.tr':
                return self.OWN
            return (records or {}).get(name, {'NS': ['ns.elsewhere.example'], 'A': ['203.0.113.9'], 'AAAA': [], 'MX': []})
        def rdap(name):
            return (registration or {}).get(name, {'created': '2015-04-01T00:00:00Z', 'registrar': 'Example Registrar'})
        return {'resolve': resolve, 'inspect': inspect, 'ct': lambda label: set(ct), 'records': dns_records, 'registration': rdap}

    def test_new_imitations_are_recorded_once_with_their_risk(self):
        found = look.run_lookalikes(self.domain, self.probes({'magazam.com', 'magazam-giris.com', 'magazam-login.xyz'},
                                                             live={'magazam-giris.com'}, ct={'magazam-login.xyz', 'unrelated.com', 'magazam.com.tr'}), now=T0)
        rows = {r.name: (r.source, r.risk, r.live) for r in BusinessLookalike.query.all()}
        self.assertEqual(rows['magazam.com'], ('typo', 'low', False))
        self.assertEqual(rows['magazam-login.xyz'][0], 'ct')
        self.assertNotIn('unrelated.com', rows)
        self.assertNotIn('magazam.com.tr', rows)
        self.assertEqual({(c, p['name']) for c, _, p in found if p['name'] == 'magazam-login.xyz'}, {('lookalike_found', 'magazam-login.xyz')})
        if 'magazam-giris.com' in rows:  # in the first batch of 120 candidates
            self.assertEqual(rows['magazam-giris.com'][1:], ('high', True))
        self.domain.lookalike_cursor = 0
        db.session.commit()
        again = look.run_lookalikes(self.domain, self.probes({'magazam.com'}), now=T0 + timedelta(hours=1))
        self.assertEqual([c for c, _, p in again if p['name'] == 'magazam.com'], [])

    def test_a_registered_name_that_goes_live_is_reported(self):
        look.run_lookalikes(self.domain, self.probes({'magazam.com'}), now=T0)
        self.domain.lookalike_cursor = 0
        db.session.commit()
        later = look.run_lookalikes(self.domain, self.probes({'magazam.com'}, live={'magazam.com'}), now=T0 + timedelta(days=2))
        self.assertIn(('lookalike_live', 'bad', {'name': 'magazam.com', 'risk': 'high'}), later)

    def test_dns_failures_and_certificate_errors_conclude_nothing(self):
        def broken_ct(label):
            raise OSError('crt.sh down')
        probes = {'resolve': lambda name: None, 'inspect': lambda n, l: {'live': True}, 'ct': broken_ct,
                  'records': lambda name: None, 'registration': lambda name: None}
        self.assertEqual(look.run_lookalikes(self.domain, probes, now=T0), [])
        self.assertEqual(BusinessLookalike.query.count(), 0)
        self.assertEqual(self.domain.lookalike_cursor, look.BATCH)  # the next run continues with the next batch

    def test_the_whole_candidate_list_is_covered_in_batches(self):
        seen = set()
        total = len(look.candidates(self.domain.domain))
        for day in range(-(-total // look.BATCH)):
            probes = self.probes(set())
            original = probes['resolve']
            probes['resolve'] = lambda name: (seen.add(name), original(name))[1]
            look.run_lookalikes(self.domain, probes, now=T0 + timedelta(days=day))
        self.assertEqual(seen, set(look.candidates(self.domain.domain)))

    def test_facts_hint_ownership_and_flag_new_registrations(self):
        mine = dict(self.OWN)
        found = look.run_lookalikes(self.domain, self.probes(
            {'magazam.com', 'magazam.net'}, records={'magazam.com': mine},
            registration={'magazam.net': {'created': (T0 - timedelta(days=6)).isoformat() + 'Z', 'registrar': ' Quick Names Ltd '}}), now=T0)
        rows = {r.name: r for r in BusinessLookalike.query.all()}
        self.assertEqual((rows['magazam.com'].hint, rows['magazam.com'].hint_value), ('ns', 'ns1.hosting.example, ns2.hosting.example'))
        self.assertEqual(rows['magazam.com'].registrar, 'Example Registrar')
        self.assertEqual(rows['magazam.com'].risk, 'low')
        self.assertIsNone(rows['magazam.net'].hint)
        self.assertEqual(rows['magazam.net'].registrar, 'Quick Names Ltd')
        self.assertEqual(rows['magazam.net'].registered, (T0 - timedelta(days=6)).date())
        self.assertEqual(rows['magazam.net'].risk, 'medium')  # only in DNS, but registered 6 days ago
        self.assertIn(('lookalike_found', 'warn', {'name': 'magazam.net', 'risk': 'medium'}), found)

    def test_names_recorded_before_facts_get_them_later(self):
        old = BusinessLookalike(domain_id=self.domain.id, name='magazam.org', source='typo', first_seen=T0, last_seen=T0,
                                resolves=True, live=True, risk='medium')
        db.session.add(old)
        db.session.commit()
        self.domain.lookalike_cursor = 300  # a batch that does not contain magazam.org
        look.run_lookalikes(self.domain, self.probes(set(), registration={'magazam.org': {'created': '2026-11-01', 'registrar': 'R'}}),
                            now=T0 + timedelta(days=1))
        db.session.refresh(old)
        self.assertIsNotNone(old.facts_at)
        self.assertEqual(old.risk, 'high')  # live and registered 5 days ago
        stamp = old.facts_at
        look.run_lookalikes(self.domain, self.probes(set()), now=T0 + timedelta(days=2))
        db.session.refresh(old)
        self.assertEqual((old.facts_at, old.risk), (stamp, 'high'))  # read once, raised once

    def test_owner_marks_a_name_as_theirs(self):
        look.run_lookalikes(self.domain, self.probes({'magazam.com', 'magazam.net'}, records={'magazam.com': dict(self.OWN)}), now=T0)
        rows = {r.name: r for r in BusinessLookalike.query.all()}
        client = self.app.test_client()
        with client.session_transaction() as session:
            session['_user_id'] = str(self.user.id)
            session['_fresh'] = True
        page = client.get('/isletme/panel?lang=tr').get_data(as_text=True)
        self.assertIn('Size ait olabilir: alan adınızla aynı ad sunucularını kullanıyor (ns1.hosting.example, ns2.hosting.example)', page)
        self.assertIn('Bu ad bana mı ait?', page)
        token = BeautifulSoup(page, 'html.parser').find('input', attrs={'name': 'csrf_token'})['value']
        client.post(f'/isletme/panel/lookalikes/{rows["magazam.com"].id}/mine', data={'csrf_token': token})
        db.session.refresh(rows['magazam.com'])
        self.assertEqual(rows['magazam.com'].status, 'mine')
        self.assertEqual([r.name for r in look.open_lookalikes(self.domain.id)], ['magazam.net'])
        page = client.get('/isletme/panel?lang=tr').get_data(as_text=True)
        self.assertIn('Size ait olarak işaretlenenler: magazam.com', page)
        self.assertEqual(client.post('/isletme/panel/lookalikes/999999/mine', data={'csrf_token': token}).status_code, 404)
        # Marked names never raise alerts again, even when they go live.
        self.domain.lookalike_cursor = 0
        db.session.commit()
        later = look.run_lookalikes(self.domain, self.probes({'magazam.com'}, live={'magazam.com'}), now=T0 + timedelta(days=3))
        self.assertEqual([p['name'] for _, _, p in later if p['name'] == 'magazam.com'], [])

    def test_workspace_lists_and_dismisses_only_its_own_names(self):
        look.run_lookalikes(self.domain, self.probes({'magazam.com'}), now=T0)
        row = BusinessLookalike.query.one()
        client = self.app.test_client()
        with client.session_transaction() as session:
            session['_user_id'] = str(self.user.id)
            session['_fresh'] = True
        page = client.get('/isletme/panel?lang=tr').get_data(as_text=True)
        self.assertIn('Taklit alan adları', page)
        self.assertIn('magazam.com', page)
        self.assertNotIn('href="http://magazam.com', page)  # shown as text, never as a link
        token = BeautifulSoup(page, 'html.parser').find('input', attrs={'name': 'csrf_token'})['value']
        client.post(f'/isletme/panel/lookalikes/{row.id}/dismiss', data={'csrf_token': token})
        db.session.refresh(row)
        self.assertEqual(row.status, 'dismissed')
        self.assertEqual(client.post('/isletme/panel/lookalikes/999999/dismiss', data={'csrf_token': token}).status_code, 404)

    def test_imitations_are_urgent_alerts(self):
        from services import business_alerts
        look.run_lookalikes(self.domain, self.probes({'magazam.com'}), now=T0)
        sent = []
        business_alerts.send_instant(self.domain, sender=lambda *a: sent.append(a) or True, now=T0)
        self.assertEqual(len(sent), 1)
        self.assertIn('magazam.com', sent[0][2])


if __name__ == '__main__':
    unittest.main()
