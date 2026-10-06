"""QR actions and subdomain renderers; no real scans or provider calls."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from types import SimpleNamespace
from bs4 import BeautifulSoup
from jinja2 import Environment, FileSystemLoader, select_autoescape
ROOT=Path(__file__).resolve().parents[1]

class TemplateTests(unittest.TestCase):
    def test_both_pages_render_with_shared_safe_helper(self):
        env=Environment(loader=FileSystemLoader(ROOT/'templates'),autoescape=select_autoescape(['html']))
        env.globals.update(url_for=lambda *a,**kw:'/static/'+kw.get('filename','test'),csrf_token=lambda:'test',
            get_flashed_messages=lambda **kw:[],current_user=SimpleNamespace(is_authenticated=False),request=SimpleNamespace(path='/qr-scanner'))
        for name in ['qr_scanner.html','subdomain_finder.html']:
            with self.subTest(page=name):
                soup=BeautifulSoup(env.get_template(name).render(),'html.parser')
                self.assertIsNotNone(soup.find('script',src='/static/scan_ui.js'))
                self.assertIsNotNone(soup.select_one('#result-card'))
                self.assertIsNotNone(soup.find('script',src='/static/web_assessment_ui.js'))

    def test_dynamic_button_values_are_not_embedded_in_event_attributes(self):
        qr=(ROOT/'templates/qr_scanner.html').read_text(encoding='utf-8')
        sub=(ROOT/'templates/subdomain_finder.html').read_text(encoding='utf-8')
        self.assertNotIn('onclick="copyToClipboard(',qr)
        self.assertNotIn('onclick="window.open(',qr)
        self.assertNotIn('onclick="scanSubdomain(',sub)
        self.assertIn("button.addEventListener('click'",qr)
        self.assertIn("node.addEventListener('click'",(ROOT/'static/web_assessment_ui.js').read_text(encoding='utf-8'))
        self.assertIn("'noopener,noreferrer'",qr)

@unittest.skipUnless(shutil.which('node'),'Node.js is required for QR/subdomain JavaScript execution tests')
class ExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result=subprocess.run([shutil.which('node'),str(ROOT/'tests/test_qr_subdomain_xss.cjs')],capture_output=True,text=True,encoding='utf-8',check=True)
        cls.output=json.loads(result.stdout)

    def test_malicious_markup_remains_text_in_all_rendered_sections(self):
        for section in ['qrStats','subHTML','modal']:
            with self.subTest(section=section):
                soup=BeautifulSoup(self.output[section],'html.parser')
                self.assertFalse(soup.find_all(['img','svg','script','iframe','object']))
                for tag in soup.find_all():
                    for attribute,value in tag.attrs.items():
                        if attribute.startswith('on'):
                            self.assertEqual(attribute,'onclick')
                            self.assertIn(value,['exportJSON()','exportList()'])
                self.assertIn(self.output['payload'],soup.get_text())

    def test_bound_actions_safe_urls_and_copy_fidelity(self):
        # The executable harness asserts original copy text, bound scan targets,
        # disabled unsafe links and opener isolation before producing this output.
        self.assertIn('&lt;img',self.output['qrStats'])
        soup=BeautifulSoup(self.output['subHTML'],'html.parser')
        self.assertEqual(len(soup.select('button.scan-subdomain')),2)
        self.assertTrue(all(not button.has_attr('onclick') for button in soup.select('button.scan-subdomain')))
