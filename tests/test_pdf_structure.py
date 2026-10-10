import io
import os
import unittest
from unittest.mock import patch
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject,NameObject,TextStringObject,ArrayObject
from services.pdf_structure import inspect_pdf,pdf_observations
from services.file_deep_analyzer import FileDeepAnalyzer


def pdf(action=None,encrypted=False):
    writer=PdfWriter()
    writer.add_blank_page(width=100,height=100)
    if action:writer._root_object.update({NameObject('/OpenAction'):action})
    if encrypted:writer.encrypt('test-password')
    out=io.BytesIO();writer.write(out);return out.getvalue()


class PDFTests(unittest.TestCase):
    def test_report_text_is_not_action_or_c2(self):
        from reportlab.pdfgen import canvas
        out=io.BytesIO();c=canvas.Canvas(out,pageCompression=1)
        for _ in range(4):
            c.drawString(20,20,'c&c /AA /Launch /JavaScript callback example.com');c.showPage()
        c.save()
        r=inspect_pdf(out.getvalue())
        self.assertEqual(r['num_pages'],4)
        self.assertFalse(r['has_actions'])
        self.assertFalse(r['has_launch'])
        self.assertFalse(r['has_javascript'])
        self.assertEqual(r['uris'],[])
        a=FileDeepAnalyzer(use_exiftool=False)
        self.assertEqual(a.scan_with_yara(out.getvalue())['risk_score'],0)

    @unittest.skipUnless(os.name=='posix','Linux resource isolation required')
    def test_full_report_does_not_penalize_plain_pdf(self):
        from reportlab.pdfgen import canvas
        out=io.BytesIO();c=canvas.Canvas(out,pageCompression=1)
        c.drawString(20,20,'c&c /AA /Launch callback example.com');c.save()
        a=FileDeepAnalyzer(use_exiftool=False)
        with patch.object(a,'check_hash_reputation',return_value={'status':'not_found','is_malicious':False,'risk_score':0}):
            r=a.comprehensive_analysis(out.getvalue(),'ordinary.pdf')
        self.assertEqual(r['security_score'],100)
        self.assertEqual(r['yara']['risk_score'],0)
        self.assertTrue(all(not x for x in r['iocs'].values()))
        self.assertNotIn(r['verdict'],('high_risk','malicious'))

    def test_real_launch_and_javascript_preserved(self):
        launch=DictionaryObject({NameObject('/S'):NameObject('/Launch'),NameObject('/F'):TextStringObject('test.exe')})
        r=inspect_pdf(pdf(launch));self.assertTrue(r['has_launch']);self.assertTrue(r['has_actions'])
        js=DictionaryObject({NameObject('/S'):NameObject('/JavaScript'),NameObject('/JS'):TextStringObject('app.alert(1)')})
        self.assertTrue(inspect_pdf(pdf(js))['has_javascript'])

    def test_indirect_action(self):
        writer=PdfWriter();writer.add_blank_page(width=100,height=100)
        action=writer._add_object(DictionaryObject({NameObject('/S'):NameObject('/Launch')}))
        writer._root_object[NameObject('/OpenAction')]=action
        out=io.BytesIO();writer.write(out)
        r=inspect_pdf(out.getvalue());self.assertTrue(r['has_launch'])

    def test_navigation_open_action_is_not_execution(self):
        r=inspect_pdf(pdf(ArrayObject([NameObject('/Fit')])))
        self.assertFalse(r['has_actions'])

    def test_malformed_and_encrypted_do_not_become_safe(self):
        self.assertIn('error',inspect_pdf(b'%PDF-1.4\n/AA /Launch'))
        r=inspect_pdf(pdf(encrypted=True));self.assertTrue(r['is_encrypted'])
        self.assertIsNone(r['has_launch'])

    def test_object_budget_makes_absence_unknown(self):
        with patch('services.pdf_structure.MAX_NODES',1):
            r=inspect_pdf(pdf())
        self.assertIsNone(r['has_javascript'])
        self.assertTrue(any('budget' in x for x in r['missing_checks']))

    def test_uri_is_observation_not_automatic_threat(self):
        uri=DictionaryObject({NameObject('/S'):NameObject('/URI'),NameObject('/URI'):TextStringObject('https://example.com/')})
        r=inspect_pdf(pdf(uri));self.assertEqual(r['uris'],['https://example.com/'])
        self.assertFalse(r['has_launch'])

    @unittest.skipUnless(os.name=='posix','Linux resource isolation required')
    def test_actual_subprocess_and_cleanup(self):
        self.assertEqual(pdf_observations(pdf())['num_pages'],1)
        import subprocess
        from pathlib import Path
        with patch('services.pdf_structure.subprocess.run',side_effect=subprocess.TimeoutExpired('test',6)) as run:
            self.assertIn('error',pdf_observations(pdf()))
            self.assertFalse(Path(run.call_args.args[0][-1]).exists())


if __name__=='__main__':unittest.main()
