"""Offline URL report presentation and interaction checks."""
import subprocess
import shutil
import unittest
import test_scan_result_xss as renderer_tests
from types import SimpleNamespace
from bs4 import BeautifulSoup

class ReportLayoutTests(unittest.TestCase):
    def setUp(self):
        renderer_tests.TemplateRenderingTests.setUp(self)
    def test_loading_and_report_controls_have_accessible_names(self):
        html=self.env.get_template('result.html').render(scan=SimpleNamespace(id=1,status='queued',url='https://example.org'))
        soup=BeautifulSoup(html,'html.parser')
        self.assertEqual(soup.select_one('#loading-area')['aria-live'],'polite')
        self.assertEqual(len(soup.select('.scan-flow li')),3)
        self.assertEqual(soup.select_one('#evidence-search')['type'],'search')
        self.assertTrue(soup.select_one('.url-art')['aria-hidden']=='true')
        self.assertIsNotNone(soup.select_one('.url-art svg'))
        self.assertIn('prefers-reduced-motion',html)

@unittest.skipUnless(shutil.which('node'),'Node.js is required for report interaction checks')
class ReportInteractionTests(unittest.TestCase):
    def test_real_report_interactions(self):
        subprocess.run([shutil.which('node'),'tests/test_url_report_ui.cjs'],check=True,capture_output=True,text=True)

if __name__=='__main__':unittest.main()
