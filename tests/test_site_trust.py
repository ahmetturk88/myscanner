"""site-trust-v1: the website check uses Google Web Risk, look-alike names, domain age and scam content."""
import unittest
from unittest.mock import patch

import requests

from routes.mobile_api import TOOLS
from services.report_i18n import translate_plain
from services.safe_http import PublicHTTPSession
from services.simple_report_view import plain_web_report
from services.web_assessment import WebAssessment

LISTED = {'status': 'matched', 'threat_types': ['SOCIAL_ENGINEERING']}
CLEAN = {'status': 'not_found', 'threat_types': []}


def page(body):
    r = requests.Response(); r.status_code = 200; r._content = body; r._content_consumed = True
    r.headers['Content-Type'] = 'text/html'
    return r


def records(host, types=('A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'), deadline=None):
    return {kind: {'status': 'completed' if kind == 'A' else 'no_record', 'values': ['8.8.8.8'] if kind == 'A' else []} for kind in types}


def assess(url, body=b'<html><title>Shop</title><p>Welcome</p></html>', web_risk=CLEAN, age=None):
    age_result = {'status': 'completed', 'age_days': age, 'created': '2026-10-20'} if age is not None else {'status': 'unavailable'}
    with patch('services.web_assessment.validate_public_url'), patch('services.web_assessment.dns_records', side_effect=records), \
            patch('services.web_assessment.certificate_details', return_value={'status': 'completed', 'verified': True, 'days_remaining': 80}), \
            patch.object(PublicHTTPSession, 'get', return_value=page(body)), \
            patch('services.web_risk.check_web_risk', return_value=web_risk), \
            patch('services.site_trust.domain_age', return_value=age_result):
        result = WebAssessment().analyze(url)
    return result, plain_web_report(result, source='site')


def rows(plain):
    return {c['name']: (c['state'], c['result']) for c in plain['checks']}


class SiteTrustTests(unittest.TestCase):
    def test_an_ordinary_site_is_green_without_url_vet(self):
        result, plain = assess('https://www.example.com', age=9000)
        self.assertEqual(result['verdict'], 'clean')
        self.assertEqual(plain['tone'], 'safe')
        self.assertEqual(rows(plain)['Threat lists'], ('ok', 'Not listed'))
        self.assertEqual(rows(plain)['Domain age'], ('ok', '24 years'))
        self.assertEqual(rows(plain)['Copies a brand’s name'], ('ok', 'No'))

    def test_google_listing_is_dangerous(self):
        result, plain = assess('https://evil.example', web_risk=LISTED)
        self.assertEqual(result['verdict'], 'malicious')
        self.assertEqual((plain['tone'], plain['headline']), ('danger', 'Don’t use this website'))
        self.assertEqual(plain['reasons'][0]['title'], 'Google lists it as dangerous')
        self.assertEqual(translate_plain(plain, 'tr')['headline'], 'Bu siteyi kullanma')

    def test_a_copied_bank_name_on_a_new_domain(self):
        body = b'<html><title>Giris</title><form action="/p"><input type="password" name="sifre"></form></html>'
        result, plain = assess('https://garanti-bbva-giris.xyz/login', body=body, age=5)
        self.assertEqual(result['verdict'], 'suspicious')
        titles = [r['title'] for r in plain['reasons']]
        self.assertIn('The address copies Garanti BBVA', titles)
        self.assertIn('The site is brand new', titles)
        self.assertEqual(rows(plain)['Domain age'], ('warn', '5 days'))
        turkish = translate_plain(plain, 'tr')
        self.assertIn('Adres Garanti BBVA adını taklit ediyor', [r['title'] for r in turkish['reasons']])
        self.assertIn('5 gün önce kaydedilmiş', ' '.join(r['detail'] for r in turkish['reasons']))

    def test_a_new_site_alone_is_only_noted(self):
        result, plain = assess('https://yeni-kahve.example', age=10)
        self.assertEqual(result['verdict'], 'clean')
        self.assertEqual(rows(plain)['Domain age'], ('info', '10 days'))

    def test_gambling_page(self):
        body = b'<html><title>Casino</title><p>canli casino slot bahis bonus rulet</p></html>'
        result, plain = assess('https://kazan-casino.example', body=body, age=9000)
        self.assertEqual(result['verdict'], 'clean')
        self.assertEqual(rows(plain)['Content category'], ('info', 'Gambling site'))
        self.assertNotEqual(rows(plain)['Page content'][0], 'warn')

    def test_an_error_page_is_not_green(self):
        with patch('services.web_assessment.validate_public_url'), patch('services.web_assessment.dns_records', side_effect=records), \
                patch('services.web_assessment.certificate_details', return_value={'status': 'completed'}), \
                patch.object(PublicHTTPSession, 'get', return_value=page(b'')) as get, \
                patch('services.web_risk.check_web_risk', return_value=CLEAN):
            get.return_value.status_code = 404
            self.assertEqual(WebAssessment().analyze('https://example.com/missing')['verdict'], 'unknown')

    def test_the_app_uses_the_website_check_with_a_summary(self):
        self.assertEqual(TOOLS['site'], 'api_site_scan')


if __name__ == '__main__':
    unittest.main()
