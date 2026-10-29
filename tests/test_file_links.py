"""file-evidence-v6: fake bank and government apps, and links inside files."""
import unittest
from unittest.mock import patch

from scripts import file_samples
from services import format_inspectors as fi
from services.file_deep_analyzer import FileDeepAnalyzer
from services.file_links import check_links, file_urls, impersonation
from services.file_report_view import plain_file_report
from services.report_i18n import translate_plain

CLEAN_HASH = {'status': 'not_found', 'is_malicious': False, 'sources': []}
NOT_LISTED = {'status': 'not_found', 'threat_types': []}
LISTED = {'status': 'matched', 'threat_types': ['SOCIAL_ENGINEERING']}


def analyze(content, filename, web_risk=NOT_LISTED):
    with patch.object(FileDeepAnalyzer, 'check_hash_reputation', return_value=CLEAN_HASH), \
            patch('services.clamav_client.scan_bytes', return_value={'status': 'clean'}), \
            patch('services.web_risk.check_web_risk', return_value=web_risk) as lookup:
        report = FileDeepAnalyzer().comprehensive_analysis(content, filename)
    return report, plain_file_report(report), lookup


class FakeAppTests(unittest.TestCase):
    def test_brand_named_app_files_ask_for_review(self):
        for package, filename, brand in (('com.edevlet.giris', 'app.apk', 'e-Devlet'), ('org.example.app', 'e-Devlet.apk', 'e-Devlet'),
                                         ('com.ptt.kargotakip', 'takip.apk', 'PTT Kargo'), ('tr.com.garanti.cepsubesi', 'g.apk', 'Garanti BBVA')):
            result = fi.inspect(file_samples.apk(package, ['android.permission.INTERNET']), filename, {'actual_type': 'zip'})
            self.assertTrue(result['raises_review'], filename)
            self.assertEqual(result['findings'][0]['title'], 'The app pretends to be ' + brand)
            self.assertEqual(result['facts']['brand'], brand)

    def test_ordinary_names_are_not_brands(self):
        for package, filename in (('org.example.notes', 'notes.apk'), ('com.purchase.chaser', 'chaser.apk'),
                                  ('com.example.backups', 'Backups.apk'), ('org.telegram.messenger', 'Telegram.apk')):
            self.assertIsNone(fi.apk_brand(package, filename), filename)

    def test_one_takeover_permission_is_enough(self):
        result = fi.inspect(file_samples.apk('org.example.helper', ['android.permission.BIND_ACCESSIBILITY_SERVICE']), 'helper.apk', {'actual_type': 'zip'})
        self.assertTrue(result['raises_review'])

    def test_fake_edevlet_app_report(self):
        data = file_samples.apk('com.edevlet.giris', ['android.permission.BIND_ACCESSIBILITY_SERVICE', 'android.permission.INTERNET'])
        report, plain, _ = analyze(data, 'e-Devlet.apk')
        self.assertEqual(report['verdict'], 'suspicious')
        self.assertEqual(plain['tone'], 'caution')
        self.assertEqual(plain['reasons'][0]['title'], 'The app pretends to be e-Devlet')
        turkish = translate_plain(plain, 'tr')
        self.assertEqual(turkish['reasons'][0]['title'], 'Uygulama kendini e-Devlet gibi gösteriyor')
        self.assertIn("Google Play'de", turkish['reasons'][0]['detail'])


class LinkTests(unittest.TestCase):
    def test_impersonation(self):
        self.assertEqual(impersonation('https://garanti-bbva-giris.xyz/login'), 'Garanti BBVA')
        self.assertEqual(impersonation('https://garantibbva.com.tr.giris.xyz/'), 'Garanti BBVA')
        self.assertIsNone(impersonation('https://www.garantibbva.com.tr/'))
        self.assertIsNone(impersonation('https://example.com/'))

    def test_lookups_are_capped_and_look_alikes_go_first(self):
        urls = [f'https://site{i}.example/' for i in range(9)] + ['https://ptt-kargo-odeme.xyz/pay']
        seen = []
        result = check_links(urls, lookup=lambda url: seen.append(url) or NOT_LISTED)
        self.assertEqual(len(seen), 5)
        self.assertEqual(seen[0], 'https://ptt-kargo-odeme.xyz/pay')
        self.assertEqual((result['status'], result['sites'], result['listed']), ('checked', 10, []))

    def test_outage_and_missing_key(self):
        down = check_links(['https://a.example/'], lookup=lambda url: {'status': 'unavailable', 'threat_types': []})
        self.assertEqual(down['status'], 'unavailable')
        off = check_links(['https://a.example/'], lookup=lambda url: {'status': 'not_configured', 'threat_types': []})
        self.assertEqual(off['status'], 'not_configured')
        broken = check_links(['https://a.example/'], lookup=lambda url: 1 / 0)
        self.assertEqual(broken['status'], 'unavailable')

    def test_links_are_gathered_from_every_parser(self):
        meta = {'uris': ['https://a.example/x', 'mailto:me@example.com'],
                'external_relationships': [{'type': 'hyperlink', 'target': 'https://b.example/'}, {'type': 'oleObject', 'target': 'https://c.example/'}]}
        self.assertEqual(file_urls(meta, {'urls': ['www.d.example', 'https://a.example/x']}),
                         ['https://a.example/x', 'https://b.example/', 'http://www.d.example'])

    def test_pdf_linking_to_a_listed_site_is_dangerous(self):
        report, plain, lookup = analyze(file_samples.pdf_with_link('https://kargo-teslimat.example/odeme'), 'Fatura.pdf', LISTED)
        self.assertEqual(report['verdict'], 'malicious')
        self.assertEqual(lookup.call_count, 1)
        self.assertEqual((plain['tone'], plain['reasons'][0]['title']), ('danger', 'A link inside is a known scam site'))
        self.assertIn('kargo-teslimat.example', plain['reasons'][0]['detail'])
        self.assertIn(('Links inside', 'bad', 'Known scam site'), [(c['name'], c['state'], c['result']) for c in plain['checks']])
        self.assertIn('Google lists', plain['summary'])

    def test_pdf_with_a_look_alike_link_needs_care(self):
        report, plain, _ = analyze(file_samples.pdf_with_link('https://garanti-bbva-giris.xyz/login'), 'Fatura.pdf')
        self.assertEqual(report['verdict'], 'suspicious')
        self.assertEqual(plain['reasons'][0]['title'], 'A link pretends to be Garanti BBVA')
        self.assertEqual(translate_plain(plain, 'tr')['reasons'][0]['title'], 'Bir bağlantı kendini Garanti BBVA gibi gösteriyor')

    def test_pdf_with_an_ordinary_link_stays_clear(self):
        report, plain, _ = analyze(file_samples.pdf_with_link('https://www.garantibbva.com.tr/'), 'brosur.pdf')
        self.assertEqual(report['verdict'], 'not_found')
        self.assertIn(('Links inside', 'ok', '1 checked'), [(c['name'], c['state'], c['result']) for c in plain['checks']])

    def test_web_page_links_are_checked(self):
        page = b'<html><body><a href="https://evil-page.example/login">Giris</a></body></html>'
        report, plain, lookup = analyze(page, 'odeme.html', LISTED)
        self.assertEqual(report['verdict'], 'malicious')
        self.assertEqual(lookup.call_args[0][0], 'https://evil-page.example/login')


class SampleScriptTests(unittest.TestCase):
    def test_every_sample_gets_its_expected_verdict(self):
        def web_risk(url, session):
            return LISTED if url == file_samples.GOOGLE_TEST_PHISHING else NOT_LISTED
        with patch.object(FileDeepAnalyzer, 'check_hash_reputation', return_value=CLEAN_HASH), \
                patch('services.clamav_client.scan_bytes', return_value={'status': 'clean'}), \
                patch('services.web_risk.check_web_risk', side_effect=web_risk):
            for name, content, expected in file_samples.samples():
                self.assertIn(FileDeepAnalyzer().comprehensive_analysis(content, name)['verdict'], expected, name)


if __name__ == '__main__':
    unittest.main()
