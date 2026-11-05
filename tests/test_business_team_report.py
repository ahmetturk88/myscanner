"""MyScanner İşletme stage 5: team members (invite, accept, roles, removal) and the monthly PDF report. No network."""
import io
import json
import unittest
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

from bs4 import BeautifulSoup
from pypdf import PdfReader

import test_task_ownership  # noqa: F401  (sets up the test database)
from extensions import db
from models import (BusinessDomain, BusinessEvent, BusinessLookalike, BusinessMember, BusinessSnapshot, BusinessWorkspace,
                    User)
from services import business
from services import business_alerts as alerts
from services import business_report as report

T0 = datetime(2026, 11, 5, 9, 0)
MODELS = (BusinessEvent, BusinessSnapshot, BusinessLookalike, BusinessMember, BusinessDomain, BusinessWorkspace)


class Outbox:
    def __init__(self):
        self.sent = []

    def __call__(self, to, subject, text, html):
        self.sent.append({'to': to, 'subject': subject, 'text': text, 'html': html})
        return True


class TeamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = test_task_ownership._import_production_app()[1].app
        with cls.app.app_context():
            db.create_all()

    def _clean(self):
        for model in MODELS:
            model.query.delete()
        User.query.filter(User.email.like('%@team.invalid')).delete(synchronize_session=False)
        db.session.commit()

    def setUp(self):
        self.context = self.app.app_context()
        self.context.push()
        self._clean()
        self.owner = self.person('owner', admin=True)
        self.colleague = self.person('colleague')
        self.stranger = self.person('stranger')
        self.workspace = business.workspace_for(self.owner, create=True)
        self.domain = BusinessDomain(workspace_id=self.workspace.id, domain='magazam.com.tr', token='cd' * 16, verified_at=T0)
        db.session.add(self.domain)
        db.session.commit()

    def tearDown(self):
        self._clean()
        db.session.remove()
        self.context.pop()

    def person(self, name, admin=False, verified=True):
        user = User(username=f'team{name}', email=f'{name}@team.invalid', password_hash='unused', is_verified=verified, is_admin=admin)
        db.session.add(user)
        db.session.commit()
        return user

    def client_for(self, user):
        from flask import g
        g.pop('_login_user', None)  # the test's app context is shared by requests: forget the last signed-in user
        client = self.app.test_client()
        with client.session_transaction() as session:
            session['_user_id'] = str(user.id)
            session['_fresh'] = True
        return client

    def token(self, client):
        page = client.get('/isletme/panel?lang=tr').get_data(as_text=True)
        return BeautifulSoup(page, 'html.parser').find('input', attrs={'name': 'csrf_token'})['value']

    def join(self):
        member = business.invite(self.workspace, self.owner, 'Colleague@team.invalid')
        self.assertEqual(business.accept(member.token, self.colleague), 'accepted')
        return member

    # ------------------------------------------------------------------ rules

    def test_invitations_are_checked_and_limited(self):
        for bad, code in (('not-an-email', 'bad_email'), ('OWNER@team.invalid', 'self')):
            with self.assertRaises(business.BusinessError) as raised:
                business.invite(self.workspace, self.owner, bad)
            self.assertEqual(str(raised.exception), code)
        first = business.invite(self.workspace, self.owner, 'a@team.invalid')
        self.assertEqual(business.invite(self.workspace, self.owner, 'A@team.invalid').id, first.id)  # once per address
        for name in 'bcd':
            business.invite(self.workspace, self.owner, f'{name}@team.invalid')
        with self.assertRaises(business.BusinessError) as raised:
            business.invite(self.workspace, self.owner, 'e@team.invalid')
        self.assertEqual(str(raised.exception), 'team_full')

    def test_only_the_invited_verified_account_can_accept(self):
        member = business.invite(self.workspace, self.owner, 'colleague@team.invalid')
        self.assertEqual(business.accept('x' * 30, self.colleague), 'invalid')
        self.assertEqual(business.accept(None, self.colleague), 'invalid')
        self.assertEqual(business.accept(member.token, self.stranger), 'wrong_account')
        unverified = SimpleNamespace(id=999, email='colleague@team.invalid', is_verified=False)
        self.assertEqual(business.accept(member.token, unverified), 'unverified')
        self.assertEqual(business.access(self.colleague), (None, None))
        self.assertEqual(business.accept(member.token, self.colleague), 'accepted')
        self.assertEqual(business.accept(member.token, self.colleague), 'accepted')
        self.assertEqual(business.access(self.colleague), (self.workspace, 'member'))
        self.assertEqual(business.access(self.stranger), (None, None))

    def test_alerts_reach_accepted_members_who_want_them(self):
        business.invite(self.workspace, self.owner, 'pending@team.invalid')
        member = self.join()
        self.assertEqual(alerts._recipients(self.workspace), ['owner@team.invalid', 'colleague@team.invalid'])
        member.alerts = False
        db.session.commit()
        self.assertEqual(alerts._recipients(self.workspace), ['owner@team.invalid'])

    # ------------------------------------------------------------------ routes

    def test_the_sign_in_prompt_is_translated(self):
        # An invitation link opened while signed out lands on the sign-in page with this message.
        from services.i18n_site_tr import SITE_TR
        self.assertEqual(SITE_TR['Please log in to access this page.'], 'Bu sayfayı görmek için giriş yapın.')

    def test_owner_invites_by_email_and_the_colleague_joins(self):
        owner = self.client_for(self.owner)
        outbox = Outbox()
        with patch('app.send_email', outbox):
            owner.post('/isletme/panel/members', data={'csrf_token': self.token(owner), 'email': 'colleague@team.invalid'})
        member = BusinessMember.query.one()
        self.assertEqual(len(outbox.sent), 1)
        self.assertEqual(outbox.sent[0]['to'], 'colleague@team.invalid')
        self.assertIn(f'/isletme/davet/{member.token}', outbox.sent[0]['text'])
        self.assertIn('owner@team.invalid', outbox.sent[0]['text'])

        stranger = self.client_for(self.stranger).get(f'/isletme/davet/{member.token}?lang=tr')
        self.assertEqual(stranger.status_code, 403)
        self.assertEqual(stranger.headers['Referrer-Policy'], 'no-referrer')
        self.assertEqual(self.client_for(self.colleague).get('/isletme/davet/' + 'z' * 40).status_code, 404)

        colleague = self.client_for(self.colleague)
        joined = colleague.get(f'/isletme/davet/{member.token}')
        self.assertEqual(joined.status_code, 302)
        page = colleague.get('/isletme/panel?lang=tr').get_data(as_text=True)
        self.assertIn('ekip üyesi olarak', page)
        self.assertIn('magazam.com.tr', page)
        self.assertNotIn('name="domain"', page)  # no owner controls
        self.assertNotIn('/members/', page)

    def test_members_can_look_but_not_change_anything(self):
        member = self.join()
        look = BusinessLookalike(domain_id=self.domain.id, name='magazam.com', source='typo', first_seen=T0, last_seen=T0,
                                 resolves=True, live=False, risk='low')
        db.session.add(look)
        db.session.commit()
        client = self.client_for(self.colleague)
        token = self.token(client)
        for url, data in (('/isletme/panel/domains', {'domain': 'baska.com'}),
                          (f'/isletme/panel/domains/{self.domain.id}/verify', {}),
                          (f'/isletme/panel/domains/{self.domain.id}/remove', {}),
                          (f'/isletme/panel/lookalikes/{look.id}/dismiss', {}),
                          (f'/isletme/panel/lookalikes/{look.id}/mine', {}),
                          ('/isletme/panel/settings', {'alert_lang': 'en'}),
                          ('/isletme/panel/members', {'email': 'x@team.invalid'}),
                          (f'/isletme/panel/members/{member.id}/remove', {})):
            self.assertEqual(client.post(url, data=dict(data, csrf_token=token)).status_code, 403, url)
        self.assertEqual(BusinessDomain.query.count(), 1)
        self.assertEqual(BusinessMember.query.count(), 1)
        db.session.refresh(look)
        self.assertEqual(look.status, 'open')

    def test_removing_a_member_ends_their_access(self):
        member = self.join()
        other_workspace = business.workspace_for(self.person('other', admin=True), create=True)
        foreign = BusinessMember(workspace_id=other_workspace.id, email='z@team.invalid', token='f' * 43)
        db.session.add(foreign)
        db.session.commit()
        owner = self.client_for(self.owner)
        token = self.token(owner)
        self.assertEqual(owner.post(f'/isletme/panel/members/{foreign.id}/remove', data={'csrf_token': token}).status_code, 404)
        owner.post(f'/isletme/panel/members/{member.id}/remove', data={'csrf_token': token})
        self.assertIsNone(db.session.get(BusinessMember, member.id))
        self.assertEqual(self.client_for(self.colleague).get('/isletme/panel').status_code, 302)

    # ------------------------------------------------------------------ monthly report

    def history(self):
        for day in range(10):
            results = {'ownership': {'state': 'ok'}, 'tls': {'state': 'warn', 'days': 9}, 'registration': {'state': 'ok', 'days': 200},
                       'dns': {'state': 'ok', 'records': {'A': ['203.0.113.5']}}, 'mail': {'state': 'bad'},
                       'blocklist': {'state': 'ok'}, 'reputation': {'state': 'ok'}}
            db.session.add(BusinessSnapshot(domain_id=self.domain.id, kind='daily', created_at=T0 - timedelta(days=day),
                                            score=60 + day, results=json.dumps(results)))
        db.session.add(BusinessSnapshot(domain_id=self.domain.id, kind='daily', created_at=T0 - timedelta(days=60), score=10,
                                        results=json.dumps({})))  # outside the period
        db.session.add(BusinessEvent(domain_id=self.domain.id, code='lookalike_found', severity='bad', created_at=T0 - timedelta(days=2),
                                     params=json.dumps({'name': 'magazam-giris.com', 'risk': 'high'})))
        db.session.add(BusinessLookalike(domain_id=self.domain.id, name='magazam-giris.com', source='typo', first_seen=T0, last_seen=T0,
                                         resolves=True, live=True, risk='high', title='Giriş'))
        db.session.commit()

    def test_report_covers_the_last_30_days_with_actions(self):
        self.history()
        data = report.domain_data(self.domain, __import__('services.business_page', fromlist=['CONTENT']).CONTENT['tr'],
                                  T0 - report.PERIOD, T0)
        self.assertEqual(data['runs'], 10)
        self.assertEqual(data['average'], round(sum(range(60, 70)) / 10))
        todo = report.actions_for([data], 'tr')
        self.assertTrue(todo[0].startswith('magazam.com.tr için SPF'))  # problems before warnings
        self.assertTrue(any('SSL' in line for line in todo))
        self.assertTrue(todo[-1].startswith('magazam-giris.com'))
        english = report.actions_for([data], 'en')
        self.assertIn('Add SPF and DMARC records for magazam.com.tr', english[0])

        pdf = report.generate_business_report(self.workspace, 'tr', now=T0)
        text = ''.join(page.extract_text() for page in PdfReader(io.BytesIO(pdf.getvalue())).pages)
        for expected in ('AYLIK GÜVENLİK RAPORU', 'Yapılacaklar', 'magazam-giris.com', 'Hafta hafta durum', 'yüksek', 'DÖNEM'):
            self.assertIn(expected, text)
        self.assertTrue(report.generate_business_report(self.workspace, 'en', now=T0).getvalue().startswith(b'%PDF'))

    def test_report_without_verified_domains_still_renders(self):
        self.domain.verified_at = None
        db.session.commit()
        pdf = report.generate_business_report(self.workspace, 'en', now=T0)
        text = ''.join(page.extract_text() for page in PdfReader(io.BytesIO(pdf.getvalue())).pages)
        self.assertIn('No verified domain yet', text)

    def test_owner_and_members_download_the_report_others_do_not(self):
        self.join()
        for user in (self.owner, self.colleague):
            response = self.client_for(user).get('/isletme/panel/report.pdf?lang=en')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.mimetype, 'application/pdf')
            self.assertIn('private', response.headers['Cache-Control'])
            self.assertTrue(response.data.startswith(b'%PDF'))
        self.assertEqual(self.client_for(self.stranger).get('/isletme/panel/report.pdf').status_code, 302)

    def test_monthly_email_goes_once_at_the_start_of_the_month(self):
        self.join()
        start = datetime(2026, 12, 1, 7, 0)
        self.assertEqual(report.reports_due(datetime(2026, 12, 4, 7, 0)), [])
        self.assertEqual(report.reports_due(datetime(2026, 12, 1, 2, 0)), [])  # at night in Türkiye
        self.assertIn(self.workspace, report.reports_due(start))
        outbox = Outbox()
        self.assertEqual(report.send_monthly(self.workspace, sender=outbox, now=start), 2)
        self.assertEqual({m['to'] for m in outbox.sent}, {'owner@team.invalid', 'colleague@team.invalid'})
        self.assertIn('aylık raporunuz hazır', outbox.sent[0]['subject'])
        self.assertIn('/isletme/panel#report', outbox.sent[0]['text'])
        self.assertNotIn(self.workspace, report.reports_due(start + timedelta(hours=2)))
        self.assertIn(self.workspace, report.reports_due(datetime(2027, 1, 1, 7, 0)))


if __name__ == '__main__':
    unittest.main()
