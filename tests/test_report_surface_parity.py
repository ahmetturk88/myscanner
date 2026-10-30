"""Saved evidence produces the same decision on web JSON, mobile JSON and PDF."""
import io
import json
import unittest
from datetime import datetime
from types import SimpleNamespace

from pypdf import PdfReader
from extensions import db
from models import Scan
from services.pdf_report_generator import generate_vulnerability_report
from services.url_assessment import assess_url, POLICY_VERSION
from services.url_report_view import plain_report
import test_mobile_api
from test_url_redirect_destination import evidence


class ReportSurfaceParityTests(unittest.TestCase):
    setUpClass = classmethod(test_mobile_api.MobileApiTests.setUpClass.__func__)
    tearDownClass = classmethod(test_mobile_api.MobileApiTests.tearDownClass.__func__)
    setUp = test_mobile_api.MobileApiTests.setUp
    login = test_mobile_api.MobileApiTests.login
    token = test_mobile_api.MobileApiTests.token
    auth = test_mobile_api.MobileApiTests.auth

    def test_category_only_and_confirmed_threat_keep_the_same_decision(self):
        token = self.token()
        for confirmed in (False, True):
            local, deep = evidence('https://content.example/', rank=0)
            deep['page_content']['scam_signals'] = ['gambling']
            if confirmed:
                deep['osint'] = {'urlhaus': True, 'urlhaus_status': 'matched'}
            aggregate = assess_url(local, deep)
            # url-evidence-v14: betting alone asks for care; a listing still makes it malicious.
            self.assertEqual(aggregate['verdict'], 'malicious' if confirmed else 'suspicious')
            local['aggregate_assessment'] = aggregate
            expected = plain_report(aggregate, local, deep, local['url'])
            with self.app.app_context():
                scan = Scan(url=local['url'], user_id=self.owner, status='completed', verdict=aggregate['verdict'], result='saved',
                            raw_report=json.dumps({'local_analysis': local, 'deep_analysis': deep, 'aggregate_assessment': aggregate}))
                db.session.add(scan); db.session.commit()
                scan_id = scan.id
            with self.client.session_transaction() as session:
                session['_user_id'], session['_fresh'] = str(self.owner), True
            web = self.client.get(f'/api/url-analysis/{scan_id}', headers={'Accept-Language': 'en'})
            mobile = self.client.get(f'/api/mobile/v1/scans/{scan_id}/analysis', headers={**self.auth(token), 'Accept-Language': 'en'})
            self.assertEqual(web.status_code, 200)
            self.assertEqual(mobile.status_code, 200)
            self.assertEqual(web.json['plain'], mobile.json['plain'])
            self.assertEqual(mobile.json['plain'], expected)
            self.assertEqual(mobile.json['aggregate_assessment']['policy_version'], POLICY_VERSION)
            pdf = generate_vulnerability_report(SimpleNamespace(id=scan_id, url=local['url'], date_posted=datetime(2026, 10, 30)), local, 'tester', deep=deep, lang='en')
            text = ' '.join(page.extract_text() for page in PdfReader(io.BytesIO(pdf.read())).pages)
            self.assertIn(expected['label'], text)
            self.assertIn('An online gambling site', text)
            self.assertNotIn('without a licence are illegal', text)
