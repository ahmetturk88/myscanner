"""url-evidence-v12: a link that downloads a file instead of showing a page."""
import unittest
from unittest.mock import patch

import requests

from services.report_i18n import translate_plain
from services.safe_http import ResponseTooLarge
from services.url_analyzer import URLDeepAnalyzer, download_info
from services.url_assessment import assess_url
from services.url_report_view import plain_report
from test_url_redirect_destination import Page, evidence

EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


def file_page(name, kind, antivirus=None, program=None):
    download = {'content_type': kind, 'filename': name, 'extension': name.rsplit('.', 1)[-1], 'program': bool(program)}
    if antivirus:
        download['antivirus'] = antivirus
    return {'title': '', 'content_risk_score': 0, 'status_code': 200, 'visible_text_length': None, 'scam_signals': [], 'forms': [],
            'download': download}


class DownloadInfoTests(unittest.TestCase):
    def test_pages_are_not_downloads(self):
        for kind in ('text/html; charset=utf-8', 'application/json', 'image/png'):
            self.assertIsNone(download_info(Page('https://a.com/', 'x', kind=kind), scan=False), kind)

    def test_programs_and_attachments(self):
        apk = Page('https://e-devlet-destek.xyz/indir/e-Devlet.apk', 'PK', kind='application/octet-stream')
        info = download_info(apk, scan=False)
        self.assertEqual((info['filename'], info['extension'], info['program']), ('e-Devlet.apk', 'apk', True))
        named = Page('https://a.com/get?id=1', 'PK', kind='application/zip')
        named.headers['Content-Disposition'] = 'attachment; filename="fatura.zip"'
        self.assertEqual(download_info(named, scan=False)['filename'], 'fatura.zip')

    def test_the_file_is_scanned_by_the_antivirus(self):
        page = Page('https://secure.eicar.org/eicar.com', 'x', kind='application/octet-stream')
        page.content = EICAR
        found = {'status': 'found', 'signature': 'Eicar-Signature', 'kind': 'malware'}
        with patch('services.clamav_client.scan_bytes', return_value=found) as scan:
            info = download_info(page)
        scan.assert_called_once_with(EICAR)
        self.assertEqual(info['antivirus'], found)
        self.assertEqual(len(info['sha256']), 64)


class VerdictTests(unittest.TestCase):
    def test_eicar_download_is_dangerous(self):
        page = file_page('eicar.com', 'application/octet-stream', {'status': 'found', 'signature': 'Eicar-Signature', 'kind': 'malware'}, program=True)
        local, deep = evidence('https://secure.eicar.org/eicar.com', page=page)
        result = assess_url(local, deep)
        self.assertEqual(result['verdict'], 'malicious')
        plain = plain_report(result, local, deep, local['url'])
        self.assertEqual(plain['reasons'][0]['detail'], 'The link downloads “eicar.com”, and our antivirus found Eicar-Signature in it.')
        self.assertIn(('Page content', 'bad', 'Virus found'), [(c['name'], c['state'], c['result']) for c in plain['checks']])
        self.assertEqual(translate_plain(plain, 'tr')['reasons'][0]['detail'],
                         'Bağlantı “eicar.com” dosyasını indiriyor ve antivirüsümüz içinde Eicar-Signature buldu.')

    def test_fake_app_from_a_new_site(self):
        page = file_page('e-Devlet.apk', 'application/vnd.android.package-archive', {'status': 'clean'}, program=True)
        local, deep = evidence('https://e-devlet-destek.xyz/indir/e-Devlet.apk', age=20, rank=0, page=page)
        for data in (local, deep):
            data['urlvet']['tld_info'] = {'is_risky': True}
        result = assess_url(local, deep)
        self.assertEqual(result['verdict'], 'high_risk')
        self.assertIn('It downloads an app or program', [r['title'] for r in plain_report(result, local, deep, local['url'])['reasons']])

    def test_a_program_from_an_established_site_is_only_a_note(self):
        page = file_page('setup.exe', 'application/x-msdownload', {'status': 'clean'}, program=True)
        local, deep = evidence('https://download.example-vendor.com/setup.exe', age=5000, rank=2000, page=page)
        self.assertEqual(assess_url(local, deep)['verdict'], 'harmless')

    def test_a_download_is_not_a_hidden_page(self):
        page = file_page('report.pdf', 'application/pdf', {'status': 'clean'})
        local, deep = evidence('https://new-site.xyz/files/report.pdf', age=30, rank=0, page=page)
        self.assertNotIn('content_hidden', [r['code'] for r in assess_url(local, deep)['reasons']])


class PageAntivirusTests(unittest.TestCase):
    def test_eicar_text_page_is_malware_but_heuristics_on_pages_do_not_count(self):
        page = {'title': '', 'content_risk_score': 0, 'status_code': 200, 'visible_text_length': 68, 'scam_signals': [],
                'antivirus': {'status': 'found', 'signature': 'Eicar-Signature', 'kind': 'malware'}}
        local, deep = evidence('https://secure.eicar.org/eicar.com.txt', page=page)
        result = assess_url(local, deep)
        self.assertEqual(result['verdict'], 'malicious')
        self.assertEqual(plain_report(result, local, deep, local['url'])['reasons'][0]['detail'], 'Our antivirus found Eicar-Signature in this page.')
        page['antivirus'] = {'status': 'found', 'signature': 'Heuristics.Phishing.Email.SpoofedDomain', 'kind': 'heuristic'}
        self.assertEqual(assess_url(*evidence('https://www.example-news.com/', page=page))['verdict'], 'harmless')

    def test_every_fetched_page_goes_through_the_antivirus(self):
        analyzer = URLDeepAnalyzer()
        with patch.object(analyzer.session, 'get', return_value=Page('https://a.com/', '<title>A</title><p>hello</p>')), \
                patch('services.clamav_client.scan_bytes', return_value={'status': 'clean'}) as scan:
            content = analyzer.analyze_page_content('https://a.com/')
        scan.assert_called_once()
        self.assertEqual(content['antivirus'], {'status': 'clean'})


class LargeDownloadTests(unittest.TestCase):
    def test_a_big_app_does_not_break_the_scan(self):
        analyzer = URLDeepAnalyzer()
        big = Page('https://cdn.new-app.xyz/app.apk', '', kind='application/vnd.android.package-archive')
        def get(url, **kwargs):
            raise ResponseTooLarge('too large', response=big)
        with patch.object(analyzer.session, 'get', side_effect=get):
            behavior = analyzer.analyze_behavior('https://new-app.xyz/download')
            content = analyzer.analyze_page_content('https://cdn.new-app.xyz/app.apk')
        self.assertIsNone(behavior['error'])
        self.assertEqual(behavior['final_url'], 'https://cdn.new-app.xyz/app.apk')
        self.assertEqual(content['download']['filename'], 'app.apk')
        self.assertTrue(content['download']['too_large'])
        self.assertIsInstance(ResponseTooLarge('x'), requests.exceptions.RequestException)


if __name__ == '__main__':
    unittest.main()
