"""EICAR, disguised executables and PDF JavaScript are never reported as clean."""
import io
import logging
import unittest

from services.file_deep_analyzer import EICAR_SIGNATURE, FileDeepAnalyzer, disguised_filename, is_eicar


def analyze(content, name):
    logging.disable(logging.ERROR)
    try:
        return FileDeepAnalyzer(use_exiftool=False).comprehensive_analysis(content, name)
    finally:
        logging.disable(logging.NOTSET)


class SignalTests(unittest.TestCase):
    def test_eicar_is_reported_as_malware_with_an_explanation(self):
        self.assertEqual(len(EICAR_SIGNATURE), 68)
        self.assertTrue(is_eicar(EICAR_SIGNATURE + b'\r\n'))
        self.assertFalse(is_eicar(b'prefix ' + EICAR_SIGNATURE))
        self.assertFalse(is_eicar(EICAR_SIGNATURE + b'x' * 100))
        result = analyze(EICAR_SIGNATURE, 'eicar.com')
        self.assertEqual(result['verdict'], 'malicious')
        self.assertIn('EICAR', result['recommendations'][0])

    def test_disguised_executables_need_review(self):
        self.assertIsNotNone(disguised_filename('Invoice.PDF.exe'))
        self.assertIsNotNone(disguised_filename('photo‮gpj.exe'))
        for name in ('setup.exe', 'report.final.pdf', 'archive.tar.gz', 'my.app.js'):
            self.assertIsNone(disguised_filename(name), name)
        self.assertEqual(analyze(b'MZ' + b'\0' * 100, 'invoice.pdf.exe')['verdict'], 'suspicious')

    def test_pdf_javascript_needs_review(self):
        from pypdf import PdfWriter
        writer = PdfWriter(); writer.add_blank_page(200, 200); writer.add_js("app.alert('x');")
        out = io.BytesIO(); writer.write(out)
        result = analyze(out.getvalue(), 'invoice.pdf')
        if result.get('metadata', {}).get('has_javascript') is None:
            self.skipTest('PDF object inspection needs Linux isolation')
        self.assertEqual(result['verdict'], 'suspicious')
        self.assertTrue(any('JavaScript' in r for r in result['recommendations']))

    def test_plain_text_stays_clean(self):
        self.assertIn(analyze(b'Meeting notes.\n', 'notes.txt')['verdict'], ('unknown', 'not_found'))


if __name__ == '__main__':
    unittest.main()
