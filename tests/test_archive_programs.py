"""file-evidence-v6: programs and Android apps packed inside ZIP and RAR files."""
import ctypes.util
import os
import unittest
from unittest.mock import patch

from scripts.file_samples import apk, rar, zipped
from services.archive_directory import archive_apps
from services.file_deep_analyzer import FileDeepAnalyzer
from services.file_report_view import plain_file_report
from services.format_inspectors import archive_programs, inspect_archive
from services.report_i18n import translate_plain

LIBARCHIVE = os.name == 'posix' and ctypes.util.find_library('archive')
FAKE_EDEVLET = apk('com.edevlet.giris', ['android.permission.BIND_ACCESSIBILITY_SERVICE'])


def analyze(content, filename):
    with patch.object(FileDeepAnalyzer, 'check_hash_reputation', return_value={'status': 'not_found', 'is_malicious': False, 'sources': []}), \
            patch('services.clamav_client.scan_bytes', return_value={'status': 'clean'}):
        report = FileDeepAnalyzer().comprehensive_analysis(content, filename)
    return report, plain_file_report(report)


class NameTests(unittest.TestCase):
    def test_programs_by_name(self):
        names = ['Fatura/e-Devlet.apk', 'kurulum.exe', 'run.js', 'site/app.js', 'a.jpg', 'docs/', 'x.lnk', 'README']
        self.assertEqual(archive_programs(names), ['Fatura/e-Devlet.apk', 'kurulum.exe', 'run.js', 'x.lnk'])

    def test_nothing_risky_is_no_inspection(self):
        self.assertIsNone(inspect_archive(['tatil/deniz.jpg', 'site/app.js', 'notes.txt']))

    def test_disguised_program(self):
        result = inspect_archive(['Fatura.pdf.exe'])
        self.assertEqual(result['findings'][0]['title'], 'The archive hides a program dressed as a document')
        self.assertTrue(result['raises_review'])


@unittest.skipUnless(LIBARCHIVE, 'Linux libarchive needed')
class AppTests(unittest.TestCase):
    def test_app_inside_zip_is_read_like_an_uploaded_app(self):
        report, plain = analyze(zipped([('Fatura/e-Devlet.apk', FAKE_EDEVLET), ('oku.txt', b'hi')]), 'belgeler.zip')
        self.assertEqual(report['verdict'], 'suspicious')
        titles = [r['title'] for r in plain['reasons']]
        self.assertEqual(titles[:2], ['The archive hides an Android app', 'The app pretends to be e-Devlet'])
        self.assertIn(('Programs inside', 'warn', 'Android app'), [(c['name'], c['state'], c['result']) for c in plain['checks']])
        self.assertEqual(plain['actions'][0], 'Install apps only from Google Play, never from a link or a message.')
        turkish = translate_plain(plain, 'tr')
        self.assertEqual(turkish['reasons'][0]['title'], 'Arşivin içinde bir Android uygulaması gizli')
        self.assertIn('e-Devlet.apk', turkish['reasons'][0]['detail'])

    def test_app_inside_rar(self):
        result = archive_apps(rar('x/Kargo Takip.apk', apk('com.ptt.kargotakip', ['android.permission.RECEIVE_SMS'])), 'rar')
        self.assertEqual(result['apps'][0]['name'], 'x/Kargo Takip.apk')
        self.assertEqual(result['apps'][0]['inspection']['facts']['brand'], 'PTT Kargo')
        report, plain = analyze(rar('Kargo Takip.apk', apk('com.ptt.kargotakip', ['android.permission.RECEIVE_SMS'])), 'Kargo.rar')
        self.assertEqual(report['verdict'], 'suspicious')
        self.assertIn('The app pretends to be PTT Kargo', [r['title'] for r in plain['reasons']])

    def test_broken_app_and_plain_archives(self):
        self.assertEqual(archive_apps(zipped([('a.apk', b'not an app')]), 'zip')['apps'][0]['inspection']['status'], 'unavailable')
        report, plain = analyze(zipped([('tatil/deniz.jpg', b'\xff\xd8\xff\xe0'), ('site/app.js', b'x')]), 'photos.zip')
        self.assertEqual(report['verdict'], 'not_found')
        self.assertNotIn('Programs inside', [c['name'] for c in plain['checks']])

    def test_failure_is_a_missing_check_not_a_crash(self):
        with patch('services.archive_directory.archive_apps', return_value={'apps': [], 'error': 'App inspection timed out'}):
            report, _ = analyze(zipped([('e-Devlet.apk', FAKE_EDEVLET)]), 'a.zip')
        self.assertIn('Apps inside the archive were not inspected', report['missing_checks'])
        self.assertEqual(report['verdict'], 'suspicious')  # the app's name alone still asks for care


if __name__ == '__main__':
    unittest.main()
