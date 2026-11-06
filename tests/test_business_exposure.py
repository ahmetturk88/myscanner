"""MyScanner İşletme exposed-files check: proofs, soft-404 safety, events, alerts, workspace, report. No network."""
import io
import json
import unittest
from datetime import datetime, timedelta
from unittest.mock import patch

from pypdf import PdfReader

import test_task_ownership  # noqa: F401  (sets up the test database)
from extensions import db
from models import BusinessDomain, BusinessEvent, BusinessSnapshot, BusinessWorkspace, User
from services import business_exposure as exposure
from services.business_monitor import event_line
from services.business_page import CONTENT

T0 = datetime(2026, 11, 6, 9, 0)
SECRET_ENV = b'APP_KEY=base64:abc\nDB_PASSWORD=hunter2-secret\nMAIL_HOST=smtp.example\n'
HOME = b'<!doctype html><html><body>Magazam - A=1\nB=2</body></html>'


def site(files, soft=False, broken=False):
    """A fake fetch: `files` maps a path to its body; everything else is 404 (or the home page when `soft`)."""
    asked = []

    def fetch(path):
        asked.append(path)
        if broken:
            raise OSError('no route')
        if path in files:
            return 200, files[path]
        return (200, HOME) if soft else (404, b'')
    fetch.asked = asked
    return fetch


class ScanTests(unittest.TestCase):
    def test_real_files_are_proven_by_their_content(self):
        result = exposure.scan(site({'/.env': SECRET_ENV, '/.git/HEAD': b'ref: refs/heads/main\n', '/backup.zip': b'PK\x03\x04rest',
                                     '/db.sql': b'-- MySQL dump 10.13\nCREATE TABLE users', '/phpmyadmin/': b'<title>phpMyAdmin</title>'}))
        self.assertEqual([f['key'] for f in result['found']], ['env', 'git', 'database_dump', 'archive', 'phpmyadmin'])
        self.assertEqual(result['found'][1]['path'], '/.git/HEAD')

    def test_sites_that_answer_200_for_everything_never_alarm(self):
        fetch = site({}, soft=True)
        self.assertEqual(exposure.scan(fetch)['found'], [])
        self.assertTrue(fetch.asked[0].startswith('/myscanner-'))  # the random baseline comes first
        # HTML that happens to contain KEY=value lines is not a .env either
        self.assertEqual(exposure.scan(site({'/.env': HOME}))['found'], [])

    def test_one_proof_per_finding_and_no_answer_means_no_conclusion(self):
        fetch = site({'/backup.sql': b'INSERT INTO orders VALUES (1)'})
        result = exposure.scan(fetch)
        self.assertEqual(result['found'], [{'key': 'database_dump', 'path': '/backup.sql'}])
        self.assertNotIn('/db.sql', fetch.asked)  # the finding is known: its other paths are not asked
        self.assertIsNone(exposure.scan(site({}, broken=True)))

    def test_the_fetch_never_follows_redirects_and_reads_little(self):
        calls = []

        class Response:
            status_code = 200

            def iter_content(self, size):
                for _ in range(100):
                    yield b'x' * size

            def close(self):
                pass

        class Session:
            def __init__(self, **kwargs):
                self.headers = {}

            def get(self, url, **kwargs):
                calls.append((url, kwargs))
                return Response()

            def close(self):
                pass
        with patch('services.safe_http.PublicHTTPSession', Session):
            fetch, _ = exposure.make_fetch('magazam.com')
            status, body = fetch('/.env')
        self.assertEqual((status, len(body)), (200, exposure.READ_LIMIT))
        self.assertEqual(calls[0][0], 'https://magazam.com/.env')
        self.assertFalse(calls[0][1]['allow_redirects'])

    def test_events_explain_the_fix(self):
        line = event_line({'code': 'exposure_found', 'params': {'key': 'env', 'path': '/.env'}}, CONTENT['tr'])
        self.assertTrue(line.startswith('Sitenizde herkese açık hassas dosya: /.env (.env yapılandırma dosyası). Dosyayı hemen kaldırın'))


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
        User.query.filter(User.email.like('%@exp.invalid')).delete(synchronize_session=False)
        db.session.commit()
        self.user = User(username='expowner', email='owner@exp.invalid', password_hash='unused', is_verified=True, is_admin=True)
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

    def run_with(self, files, days=0):
        return exposure.run_exposure(self.domain, probe=lambda d: exposure.scan(site(files)), now=T0 + timedelta(days=days))

    def test_found_once_alerted_at_once_and_fixed_later(self):
        snapshot = self.run_with({'/.env': SECRET_ENV})
        self.assertNotIn('hunter2', snapshot.results)  # contents are never stored
        events = BusinessEvent.query.all()
        self.assertEqual([(e.code, e.severity, json.loads(e.params)) for e in events],
                         [('exposure_found', 'bad', {'key': 'env', 'path': '/.env'})])
        from services import business_alerts
        sent = []
        business_alerts.send_instant(self.domain, sender=lambda *a: sent.append(a) or True, now=T0)
        self.assertEqual(len(sent), 1)
        self.assertIn('/.env', sent[0][2])
        self.run_with({'/.env': SECRET_ENV}, days=7)
        self.assertEqual(BusinessEvent.query.filter_by(code='exposure_found').count(), 1)
        self.run_with({}, days=14)
        self.assertEqual(BusinessEvent.query.filter_by(code='exposure_fixed').count(), 1)

    def test_unverified_or_silent_sites_are_left_alone(self):
        self.assertIsNone(exposure.run_exposure(self.domain, probe=lambda d: None, now=T0))
        self.domain.verified_at = None
        self.assertIsNone(self.run_with({'/.env': SECRET_ENV}))
        self.assertEqual(BusinessSnapshot.query.count(), 0)

    def test_workspace_and_report(self):
        client = self.app.test_client()
        with client.session_transaction() as session:
            session['_user_id'] = str(self.user.id)
            session['_fresh'] = True
        self.run_with({})
        page = client.get('/isletme/panel?lang=tr').get_data(as_text=True)
        self.assertIn('Açıkta kalan dosyalar', page)
        self.assertIn('Bulunmadı (17 adres kontrol edildi', page)
        self.run_with({'/.git/config': b'[core]\n\trepositoryformatversion = 0\n'}, days=7)
        page = client.get('/isletme/panel?lang=tr').get_data(as_text=True)
        self.assertIn('.git klasörü (sitenin kaynak kodu)', page)
        self.assertIn('/.git/config', page)
        from services.business_report import generate_business_report
        pdf = generate_business_report(self.workspace, 'tr', now=T0 + timedelta(days=7, hours=1))
        text = ''.join(p.extract_text() for p in PdfReader(io.BytesIO(pdf.getvalue())).pages)
        self.assertIn('Açıkta kalan dosyalar', text)
        self.assertIn('magazam.com/.git/config', text)


if __name__ == '__main__':
    unittest.main()
