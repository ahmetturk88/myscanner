"""MyScanner İşletme takedown assistant: RDAP abuse contacts, report texts, page, marking, gone event. No network."""
import unittest
from datetime import date, datetime, timedelta
from unittest.mock import patch
from urllib.parse import unquote

from bs4 import BeautifulSoup

import test_task_ownership  # noqa: F401  (sets up the test database)
from extensions import db
from models import BusinessDomain, BusinessEvent, BusinessLookalike, BusinessMember, BusinessWorkspace, User
from services import business_lookalike as look
from services import business_takedown as td

T0 = datetime(2026, 11, 5, 9, 0)

RDAP_DOMAIN = {'entities': [{'roles': ['registrar'], 'vcardArray': ['vcard', [['fn', {}, 'text', 'Example Registrar']]],
                             'entities': [{'roles': ['abuse'], 'vcardArray': ['vcard', [['email', {}, 'text', 'Abuse@Registrar.example']]]}]}]}
RDAP_IP = {'name': 'NET-1', 'entities': [
    {'roles': ['registrant'], 'vcardArray': ['vcard', [['fn', {}, 'text', 'Hosting Co']]]},
    {'roles': ['abuse'], 'vcardArray': ['vcard', [['email', {}, 'text', 'not an email']]],
     'entities': [{'roles': ['abuse'], 'vcardArray': ['vcard', [['email', {}, 'text', 'abuse@host.example']]]}]}]}


class ParsingTests(unittest.TestCase):
    def test_abuse_contacts_from_rdap(self):
        with patch.object(td, '_rdap', lambda path: RDAP_DOMAIN):
            self.assertEqual(td.probe_domain('magazam-giris.com'), {'abuse': 'abuse@registrar.example'})
        with patch.object(td, '_rdap', lambda path: RDAP_IP):
            self.assertEqual(td.probe_ip('203.0.113.9'), {'org': 'Hosting Co', 'abuse': 'abuse@host.example'})
        with patch.object(td, '_rdap', lambda path: None):
            self.assertIsNone(td.probe_domain('x.com'))

    def row(self, **extra):
        values = dict(name='magazam-giris.com', source='typo', first_seen=T0, last_seen=T0, resolves=True, live=True,
                      risk='high', title='Magazam Giriş', registered=date(2026, 11, 1), registrar='Example Registrar',
                      host_ip='203.0.113.9', host_org='Hosting Co', abuse_registrar='abuse@registrar.example',
                      abuse_host='abuse@host.example')
        values.update(extra)
        return BusinessLookalike(**values)

    def test_report_texts_are_defanged_and_complete(self):
        subject, body = td.report_text(self.row(), 'magazam.com', 'Magazam Ltd', 'owner@magazam.com', 'en', now=T0)
        self.assertEqual(subject, 'Brand impersonation / possible phishing: magazam-giris[.]com')
        for expected in ('hxxps://magazam-giris[.]com/', 'magazam[.]com', 'registered only 4 days ago', '"Magazam Giriş"',
                         '203.0.113.9 (Hosting Co)', 'Magazam Ltd', 'owner@magazam.com'):
            self.assertIn(expected, body)
        self.assertNotIn('magazam-giris.com', subject + body)
        _, turkish = td.report_text(self.row(), 'magazam.com', 'Magazam Ltd', 'owner@magazam.com', 'tr', now=T0)
        self.assertIn('Kanıtlar:', turkish)

    def test_reports_list_the_most_direct_first(self):
        records = {'NS': ['dakota.ns.cloudflare.com'], 'A': ['203.0.113.9']}
        items = td.reports(self.row(), 'magazam.com', 'Magazam', 'o@m.com', records, 'tr', now=T0)
        self.assertEqual([i['key'] for i in items], ['registrar', 'host', 'cloudflare', 'usom', 'google'])
        self.assertTrue(items[0]['mailto'].startswith('mailto:abuse%40registrar.example?subject='))
        self.assertNotIn('\n', items[0]['mailto'])
        self.assertIn('hxxps://magazam-giris[.]com/', unquote(items[0]['mailto']))
        same = td.reports(self.row(abuse_host='abuse@registrar.example', abuse_registrar='abuse@registrar.example'),
                          'magazam.com', 'M', 'o@m.com', {}, 'tr', now=T0)
        self.assertEqual([i['key'] for i in same], ['registrar', 'usom', 'google'])
        bare = td.reports(self.row(abuse_host=None, abuse_registrar=None), 'magazam.com', 'M', 'o@m.com', {}, 'tr', now=T0)
        self.assertEqual([i['key'] for i in bare], ['usom', 'google'])


class TakedownTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = test_task_ownership._import_production_app()[1].app
        with cls.app.app_context():
            db.create_all()

    def _clean(self):
        for model in (BusinessEvent, BusinessLookalike, BusinessMember, BusinessDomain, BusinessWorkspace):
            model.query.delete()
        User.query.filter(User.email.like('%@td.invalid')).delete(synchronize_session=False)
        db.session.commit()

    def setUp(self):
        self.context = self.app.app_context()
        self.context.push()
        self._clean()
        self.owner = self.person('owner', admin=True)
        self.workspace = BusinessWorkspace(owner_id=self.owner.id, name='Magazam Ltd')
        db.session.add(self.workspace)
        db.session.commit()
        self.domain = BusinessDomain(workspace_id=self.workspace.id, domain='magazam.com', token='ab' * 16, verified_at=T0)
        db.session.add(self.domain)
        db.session.commit()
        self.row = BusinessLookalike(domain_id=self.domain.id, name='magazam-giris.com', source='typo', first_seen=T0,
                                     last_seen=T0, resolves=True, live=True, risk='high', title='Giriş')
        db.session.add(self.row)
        db.session.commit()
        self.calls = []
        self.probes = patch.dict(td.PROBES, {
            'records': lambda name: {'NS': ['ns1.host.example'], 'A': ['203.0.113.9'], 'AAAA': [], 'MX': []},
            'domain': lambda name: self.calls.append(name) or {'abuse': 'abuse@registrar.example'},
            'ip': lambda ip: {'org': 'Hosting Co', 'abuse': 'abuse@host.example'}})
        self.probes.start()

    def tearDown(self):
        self.probes.stop()
        self._clean()
        db.session.remove()
        self.context.pop()

    def person(self, name, admin=False):
        user = User(username=f'td{name}', email=f'{name}@td.invalid', password_hash='unused', is_verified=True, is_admin=admin)
        db.session.add(user)
        db.session.commit()
        return user

    def client_for(self, user):
        from flask import g
        for key in ('_login_user', 'csrf_token'):  # the test's app context is shared by requests
            g.pop(key, None)
        client = self.app.test_client()
        with client.session_transaction() as session:
            session['_user_id'] = str(user.id)
            session['_fresh'] = True
        return client

    def test_facts_are_read_at_most_daily(self):
        td.gather(self.row, now=T0)
        self.assertEqual((self.row.host_ip, self.row.host_org, self.row.abuse_registrar, self.row.abuse_host),
                         ('203.0.113.9', 'Hosting Co', 'abuse@registrar.example', 'abuse@host.example'))
        td.gather(self.row, now=T0 + timedelta(hours=3))
        self.assertEqual(len(self.calls), 1)
        td.gather(self.row, now=T0 + timedelta(days=2))
        self.assertEqual(len(self.calls), 2)

    def test_owner_reports_and_marks_members_only_look(self):
        owner = self.client_for(self.owner)
        page = owner.get(f'/isletme/panel/lookalikes/{self.row.id}/takedown?lang=tr')
        self.assertEqual(page.status_code, 200)
        self.assertIn('no-referrer', page.headers['Referrer-Policy'])
        html = page.get_data(as_text=True)
        soup = BeautifulSoup(html, 'html.parser')
        self.assertIn('Taklit siteyi kapattırın', html)
        self.assertIn('abuse@registrar.example', html)
        self.assertIn('hxxps://magazam-giris[.]com/', soup.find('textarea').text)
        self.assertEqual(soup.find('input', id='td-address')['value'], 'https://magazam-giris.com/')
        self.assertFalse([a for a in soup.find_all('a') if 'magazam-giris.com' in (a.get('href') or '').replace('%2E', '.')
                          and not a['href'].startswith('mailto:')])  # never a link to the fake site
        token = soup.find('input', attrs={'name': 'csrf_token'})['value']
        owner.post(f'/isletme/panel/lookalikes/{self.row.id}/reported', data={'csrf_token': token})
        db.session.refresh(self.row)
        self.assertIsNotNone(self.row.reported_at)
        self.assertIn('Bildirildi:', owner.get('/isletme/panel?lang=tr').get_data(as_text=True))

        member = self.person('member')
        db.session.add(BusinessMember(workspace_id=self.workspace.id, email='member@td.invalid', token='q' * 43,
                                      user_id=member.id, accepted_at=T0))
        db.session.commit()
        colleague = self.client_for(member)
        html = colleague.get(f'/isletme/panel/lookalikes/{self.row.id}/takedown?lang=tr').get_data(as_text=True)
        self.assertNotIn('/reported', html)
        token = BeautifulSoup(html, 'html.parser').find('input', attrs={'name': 'csrf_token'})['value']
        self.assertEqual(colleague.post(f'/isletme/panel/lookalikes/{self.row.id}/reported', data={'csrf_token': token}).status_code, 403)

        stranger = self.person('stranger', admin=True)
        self.assertEqual(self.client_for(stranger).get(f'/isletme/panel/lookalikes/{self.row.id}/takedown').status_code, 404)

    def test_a_name_that_disappears_is_reported_as_gone(self):
        self.domain.lookalike_cursor = 0
        db.session.commit()
        probes = {'resolve': lambda name: [], 'inspect': lambda n, l: {'live': False}, 'ct': lambda label: {'magazam-giris.com'},
                  'records': lambda name: None, 'registration': lambda name: None}
        found = look.run_lookalikes(self.domain, probes, now=T0 + timedelta(days=3))
        self.assertIn(('lookalike_gone', 'good', {'name': 'magazam-giris.com'}), found)
        db.session.refresh(self.row)
        self.assertFalse(self.row.resolves)
        self.assertEqual([p for c, _, p in look.run_lookalikes(self.domain, probes, now=T0 + timedelta(days=4))
                          if c == 'lookalike_gone'], [])  # told once


if __name__ == '__main__':
    unittest.main()
