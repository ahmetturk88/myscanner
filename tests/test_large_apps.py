"""A big Android app (thousands of members) is judged by the app inspector and the antivirus, not by archive budgets."""
import io
import unittest
import zipfile
from unittest.mock import patch

from scripts.file_samples import axml
from services.clamav_client import scan_timeout
from services.file_deep_analyzer import FileDeepAnalyzer


def big_app(members=1200):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('AndroidManifest.xml', axml('com.example.game', ['android.permission.INTERNET']))
        for n in range(members):
            archive.writestr(f'assets/part{n}.js', b'x')
    return stream.getvalue()


class LargeAppTests(unittest.TestCase):
    def test_archive_budgets_are_notes_for_an_app(self):
        with patch.object(FileDeepAnalyzer, 'check_hash_reputation', return_value={'status': 'not_found', 'is_malicious': False, 'sources': []}), \
                patch('services.clamav_client.scan_bytes', return_value={'status': 'clean'}):
            report = FileDeepAnalyzer().comprehensive_analysis(big_app(), 'game.apk')
        self.assertEqual(report['metadata']['inspection']['format'], 'apk')
        self.assertEqual(report['missing_checks'], [])
        self.assertIn('Container entry limit reached; only the first 1000 members inspected', report['metadata']['notes'])
        self.assertEqual(report['verdict'], 'not_found')

    def test_big_files_get_longer_to_scan(self):
        self.assertEqual(scan_timeout(1024), 60)
        self.assertEqual(scan_timeout(34 * 1024 * 1024), 162)
        self.assertEqual(scan_timeout(50 * 1024 * 1024), 170)


if __name__ == '__main__':
    unittest.main()
