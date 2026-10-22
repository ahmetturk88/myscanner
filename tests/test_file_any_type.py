"""Any-type uploads: byte patterns stay in their formats and unfamiliar names are not spoofing."""
import os
import tempfile
import unittest
from unittest.mock import patch

from services.file_deep_analyzer import FileDeepAnalyzer

NOT_FOUND = {'status': 'not_found', 'is_malicious': False}


class AnyTypeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.analyzer = FileDeepAnalyzer(cache_dir=self.directory.name, use_exiftool=False)

    def analyze(self, content, name):
        with patch.object(self.analyzer, 'check_hash_reputation', return_value=NOT_FOUND):
            return self.analyzer.comprehensive_analysis(content, name)

    def test_random_bytes_are_not_matched_against_short_patterns(self):
        # 8 MB of random bytes contains "Run", "VBA" or "/JS" by chance.
        result = self.analyze(os.urandom(8 << 20) + b' Run VBA /JS beacon upload ', 'video.dat')
        self.assertEqual(result['yara']['status'], 'not_checked')
        self.assertEqual(result['yara']['matched_rules'], [])
        self.assertEqual(result['iocs']['url'], [])
        self.assertNotEqual(result['verdict'], 'suspicious')

    def test_images_skip_byte_patterns_but_text_keeps_them(self):
        png = b'\x89PNG\r\n\x1a\n' + b'\x00' * 64 + b'powershell.exe - http://evil.example/x'
        self.assertEqual(self.analyze(png, 'photo.png')['yara']['status'], 'not_checked')
        text = self.analyze(b'cmd.exe /c powershell.exe - http://evil.example/x', 'notes.txt')
        self.assertIn('Suspicious_Processes', text['yara']['matched_rules'])
        self.assertTrue(text['iocs']['url'])

    def test_unfamiliar_names_are_not_spoofing_but_mismatches_are(self):
        cases = [(b'a,b\n1,2\n', 'data.csv', False), (b'<svg/>', 'logo.svg', False), (b'plain', 'README', False),
                 (b'plain text', 'invoice.pdf', True), (b'MZ' + b'\x00' * 200, 'photo.jpg', True),
                 (b'MZ' + b'\x00' * 200, 'setup.exe', False), (b'MZ' + b'\x00' * 200, 'update.dat', True)]
        for content, name, spoofed in cases:
            with self.subTest(name=name):
                self.assertEqual(self.analyzer.detect_file_type(content, name.lower())['is_spoofed'], spoofed)


if __name__ == '__main__':
    unittest.main()
