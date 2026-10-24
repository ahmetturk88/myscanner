"""The plain-language summary at the top of a file report says only what the analyzers observed."""
import logging
import unittest
from unittest.mock import patch

from services.file_deep_analyzer import EICAR_SIGNATURE
from services.file_report_view import plain_file_report, size_text
import services.file_threat_intel as threat_intel


class NotFound:
    def check_hash(self, value):
        return {'status': 'not_found', 'is_malicious': False, 'hash': value}


class Matched:
    def check_hash(self, value):
        return {'status': 'matched', 'is_malicious': True, 'hash': value, 'signature': 'AgentTesla'}


def scan(data, name, client=NotFound):
    logging.disable(logging.CRITICAL)
    try:
        with patch('services.malwarebazaar_client.get_malwarebazaar_client', return_value=client()), \
                patch.object(threat_intel, 'get_malwarebazaar_client', return_value=client()):
            return threat_intel.FileThreatIntel().comprehensive_file_scan(data, name)
    finally:
        logging.disable(logging.NOTSET)


def checks(plain):
    return {c['name']: (c['state'], c['result']) for c in plain['checks']}


class RealAnalyzerTests(unittest.TestCase):
    """Runs the real file analyzers offline; only the hash lookup is replaced."""

    def test_known_malware(self):
        report = scan(b'MZ' + b'\x00' * 300, 'setup.exe', Matched)
        plain = report['plain']
        self.assertEqual(report['verdict'], 'malicious')
        self.assertEqual((plain['tone'], plain['headline']), ('danger', 'Don’t open this file'))
        self.assertEqual(plain['reasons'][0]['title'], 'Known malware')
        self.assertIn('AgentTesla', plain['reasons'][0]['detail'])
        self.assertEqual(checks(plain)['Malware library'], ('bad', 'AgentTesla'))
        self.assertTrue(any('virus scan' in a for a in plain['actions']))

    def test_eicar_is_explained_not_feared(self):
        plain = scan(EICAR_SIGNATURE, 'eicar.com')['plain']
        self.assertEqual((plain['label'], plain['headline']), ('TEST FILE', 'This is an antivirus test file'))
        self.assertEqual([r['title'] for r in plain['reasons']], ['The EICAR test file'])
        self.assertEqual(checks(plain)['Real file type'], ('ok', 'Antivirus test file'))
        self.assertIn('harmless', plain['share_text'])

    def test_program_dressed_as_a_document(self):
        report = scan(b'MZ' + b'\x00' * 300, 'invoice.pdf.exe')
        plain = report['plain']
        self.assertEqual(report['verdict'], 'suspicious')
        self.assertEqual(plain['reasons'][0]['title'], 'The name hides a program')
        self.assertIn('(.exe)', plain['reasons'][0]['detail'])
        self.assertEqual(checks(plain)['Real file type'], ('bad', 'Program in disguise'))
        self.assertTrue(plain['actions'][0].startswith('Don’t open it: it is a program'))

    def test_plain_text_file(self):
        report = scan(b'hello world\n' * 20, 'notes.txt')
        plain = report['plain']
        self.assertEqual(checks(plain)['Real file type'], ('ok', 'TXT'))
        self.assertEqual(checks(plain)['Hidden code'], ('ok', 'None found'))
        self.assertEqual(plain['url']['host'], 'notes.txt')
        self.assertIn('240 bytes', plain['url']['rest'])
        if report['verdict'] == 'not_found':
            self.assertEqual(plain['tone'], 'safe')
            self.assertIn('isn’t a guarantee', plain['summary'])
        else:  # an optional parser (exiftool) is missing on this machine
            self.assertEqual(plain['reasons'][0]['title'], 'Some checks couldn’t run')


class SummaryTests(unittest.TestCase):
    def test_macro_document_asks_not_to_enable_content(self):
        plain = plain_file_report({'verdict': 'suspicious', 'filename': 'report.docm',
                                   'metadata': {'has_macros': True}, 'file_type': {'actual_type': 'docx'},
                                   'malwarebazaar': {'status': 'not_found'}})
        self.assertEqual(plain['reasons'][0]['title'], 'It contains macros')
        self.assertIn('Enable macros', plain['actions'][1])
        self.assertEqual(checks(plain)['Hidden code'], ('warn', 'Macros'))

    def test_locked_archive(self):
        plain = plain_file_report({'verdict': 'unknown', 'filename': 'photos.zip', 'missing_checks': ['Archive member contents'],
                                   'metadata': {'is_archive': True, 'encrypted': True}, 'file_type': {'actual_type': 'zip', 'is_archive': True}})
        self.assertEqual(plain['reasons'][0]['title'], 'Some checks couldn’t run')
        self.assertIn('Password-protected contents', [r['title'] for r in plain['reasons']])
        self.assertEqual(checks(plain)['Archive contents'], ('warn', 'Password-locked'))

    def test_links_inside_are_information_not_a_warning(self):
        plain = plain_file_report({'verdict': 'not_found', 'filename': 'a.pdf', 'iocs': {'urls': ['https://a.example']},
                                   'malwarebazaar': {'status': 'not_found'}})
        self.assertEqual(checks(plain)['Links inside'], ('info', '1 link'))

    def test_bad_input_is_handled(self):
        plain = plain_file_report(None)
        self.assertEqual(plain['tone'], 'unknown')
        self.assertEqual(plain['url']['host'], 'Unnamed file')
        plain = plain_file_report({'verdict': 'evil', 'filename': 'x' * 500, 'malwarebazaar': {'status': 'matched', 'is_malicious': True, 'signature': 's' * 200}})
        self.assertEqual(len(plain['url']['host']), 120)
        self.assertEqual(checks(plain)['Malware library'], ('bad', 'Known malware'))

    def test_antivirus_that_is_off_is_shown_as_not_checked(self):
        plain = plain_file_report({'verdict': 'unknown', 'filename': 'a.pdf', 'antivirus': {'status': 'not_configured'},
                                   'missing_checks': ['PDF contents were not scanned by an antivirus engine']})
        self.assertIn({'name': 'Antivirus', 'state': 'na', 'result': 'Not checked'}, plain['checks'])

    def test_size_text(self):
        self.assertEqual(size_text(512), '512 bytes')
        self.assertEqual(size_text(2048), '2.0 KB')
        self.assertEqual(size_text(3 * 1024 * 1024), '3.0 MB')
        self.assertEqual(size_text(True), '')


if __name__ == '__main__':
    unittest.main()
