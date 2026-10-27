"""The URL report PDF says what the report page says: same verdict, colour family, reasons and language."""
import io
import unittest
from datetime import datetime
from types import SimpleNamespace

from pypdf import PdfReader

from services.pdf_report_generator import generate_vulnerability_report, missing_text, present
from services.url_assessment import assess_url
from test_url_redirect_destination import evidence


def pdf_text(scan, local, deep, lang):
    data = generate_vulnerability_report(scan, local, 'tester', deep=deep, lang=lang).read()
    return ' '.join(page.extract_text() for page in PdfReader(io.BytesIO(data)).pages)


def dhl_case():
    # Manual check of report 140: the site said HIGH RISK, the old PDF said SUSPICIOUS.
    local, deep = evidence('https://www.dhl.smarthub.vuelogix.ai/?t=1', age=8 * 365, rank=0)
    for data in (local, deep):
        data['ssl'] = {'valid': False}
        data['urlvet'].update(red_flags=['🚩 Very low traffic volume.'], ssl_info={'has_tls': False, 'chain_valid': False, 'issuer': '',
                              'not_after': '0001-01-01T00:00:00Z'}, domain_info={'age_human': '8 years 10 months', 'dnssec': False})
    local['aggregate_assessment'] = assess_url(local, deep)
    scan = SimpleNamespace(id=140, url=local['url'], date_posted=datetime(2026, 10, 27, 8, 29))
    return scan, local, deep


class UrlPdfTests(unittest.TestCase):
    def test_verdict_and_reasons_match_the_report_page(self):
        scan, local, deep = dhl_case()
        self.assertEqual(local['aggregate_assessment']['verdict'], 'high_risk')
        text = pdf_text(scan, local, deep, 'en')
        self.assertIn('HIGH RISK', text)
        self.assertNotIn('SUSPICIOUS', text)
        self.assertIn('It uses the DHL name', text)
        self.assertIn('Don’t trust this link', text)
        self.assertNotIn('0001-01-01', text)       # url.vet's "no value" placeholder
        self.assertNotIn('🚩', text)
        self.assertNotIn('Typosquatting Risk', text)  # the old url.vet-only bars contradicted the verdict

    def test_turkish_pdf_with_turkish_letters(self):
        scan, local, deep = dhl_case()
        text = pdf_text(scan, local, deep, 'tr')
        for phrase in ('YÜKSEK RİSK', 'Bu bağlantıya güvenme', 'DHL adını kullanıyor', 'Neleri kontrol ettik', '8 yıl 10 ay', 'Çok düşük trafik hacmi'):
            self.assertIn(phrase, text)
        self.assertNotIn("Don’t trust this link", text)

    def test_helpers(self):
        self.assertEqual(missing_text(['local certificate check unavailable', 'deep certificate check unavailable']),
                         ['Certificate check unavailable'])
        self.assertIsNone(present('0001-01-01T00:00:00Z'))
        self.assertEqual(present('Key-Systems GmbH'), 'Key-Systems GmbH')


if __name__ == '__main__':
    unittest.main()
