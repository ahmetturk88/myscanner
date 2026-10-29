"""Java, Android and macOS program code is recognised instead of "format unknown" (file-evidence-v6)."""
import unittest
from unittest.mock import patch

from services.file_deep_analyzer import FileDeepAnalyzer
from services.file_report_view import plain_file_report

JAVA = b'\xca\xfe\xba\xbe\x00\x00\x00\x34' + b'\x00' * 40      # class file, Java 8
FAT_MACHO = b'\xca\xfe\xba\xbe\x00\x00\x00\x02' + b'\x00' * 40  # universal binary, 2 architectures
DEX = b'dex\n035\x00' + b'\x00' * 40
MACHO = b'\xcf\xfa\xed\xfe' + b'\x00' * 40


def analyze(content, name):
    with patch.object(FileDeepAnalyzer, 'check_hash_reputation', return_value={'status': 'not_found', 'is_malicious': False, 'sources': []}), \
            patch('services.clamav_client.scan_bytes', return_value={'status': 'clean'}):
        return FileDeepAnalyzer().comprehensive_analysis(content, name)


class ProgramCodeTests(unittest.TestCase):
    def test_formats_are_recognised(self):
        for content, name, kind in ((JAVA, 'Test1.class', 'class'), (FAT_MACHO, 'tool', 'macho'),
                                    (DEX, 'classes.dex', 'dex'), (MACHO, 'libx.dylib', 'macho')):
            report = analyze(content, name)
            self.assertEqual(report['file_type']['actual_type'], kind, name)
            self.assertNotIn('File format could not be identified', report['missing_checks'], name)
            self.assertNotIn('error', report['metadata'], name)

    def test_a_clean_class_file_is_not_unsure(self):
        report = analyze(JAVA, 'Test1.class')
        self.assertEqual(report['verdict'], 'not_found')
        self.assertIn(('Real file type', 'ok', 'CLASS'), [(c['name'], c['state'], c['result']) for c in plain_file_report(report)['checks']])

    def test_program_code_named_as_a_document_is_spoofed(self):
        self.assertTrue(analyze(JAVA, 'Fatura.pdf')['file_type']['is_spoofed'])


if __name__ == '__main__':
    unittest.main()
