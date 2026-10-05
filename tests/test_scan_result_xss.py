"""Offline rendering checks; JavaScript checks run when Node.js is available."""
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
import unittest

from bs4 import BeautifulSoup
from jinja2 import Environment, FileSystemLoader, select_autoescape

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = '</script><script id="injected">alert(1)</script><img src=x onerror="alert(1)">'


class TemplateRenderingTests(unittest.TestCase):
    def setUp(self):
        self.env = Environment(loader=FileSystemLoader(ROOT / 'templates'), autoescape=select_autoescape(['html']))
        self.env.globals.update(csrf_token=lambda:'test-token', url_for=lambda *a,**kw:'/test',
            get_flashed_messages=lambda **kw:[], current_user=SimpleNamespace(is_authenticated=False),
            request=SimpleNamespace(path='/result/1'))

    def test_result_status_and_url_do_not_inject_html_or_script(self):
        scan = SimpleNamespace(id=1,status=PAYLOAD,url=PAYLOAD)
        result = self.env.get_template('result.html').render(scan=scan)
        soup = BeautifulSoup(result,'html.parser')
        self.assertIsNone(soup.select_one('#injected'))
        self.assertEqual(soup.select_one('#status-badge').get_text(), PAYLOAD.upper())
        self.assertIn('\\u003c/script\\u003e', result)
        self.assertFalse(any(tag.has_attr('onerror') for tag in soup.find_all()))

    def test_scanner_templates_render_and_load_shared_helper(self):
        for name in ['result.html','site_scanner.html','file_scanner.html']:
            with self.subTest(template=name):
                result = self.env.get_template(name).render(scan=SimpleNamespace(id=1,status='pending',url='https://example.invalid'))
                soup = BeautifulSoup(result,'html.parser')
                # url_for is stubbed, so verify the real base template reference.
                self.assertIn("filename='scan_ui.js'", (ROOT / 'templates/base.html').read_text())
                self.assertTrue(soup.find('script',src='/test'))
                self.assertIsNotNone(soup.find('main'))


@unittest.skipUnless(shutil.which('node'), 'Node.js is needed for JavaScript renderer tests; use the browser smoke checks when unavailable')
class JavaScriptRenderingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run([shutil.which('node'), str(ROOT/'tests/test_scan_result_xss.cjs'), '--json'],
            capture_output=True,text=True,check=True,encoding='utf-8')
        cls.sections = json.loads(result.stdout)

    def test_malicious_fields_remain_text_in_every_rendered_section(self):
        self.assertGreaterEqual(len(self.sections),30)
        for section in self.sections:
            with self.subTest(section=section['name']):
                soup = BeautifulSoup(section['html'],'html.parser')
                self.assertFalse(soup.find_all(['script','svg','iframe','object','embed','input']))
                for tag in soup.find_all():
                    for attr in tag.attrs:
                        if attr.lower().startswith('on'):
                            self.assertEqual(attr, 'onclick')
                            self.assertIn(tag[attr], ['exportJSON()','copyReport()'])
                        if attr.lower() in ['href','src']:
                            self.assertTrue(tag[attr].startswith(('http://','https://')))

    def test_screenshot_url_is_valid_and_has_no_inline_event_handler(self):
        section = next(s for s in self.sections if s['name']=='URL screenshot')
        image = BeautifulSoup(section['html'],'html.parser').find('img')
        self.assertEqual(image['src'],'https://images.example/screenshot.png?x=%22')
        self.assertNotIn('onerror',image.attrs)

    def test_values_are_not_double_escaped(self):
        # Entity decoding should recover the original text, not '&lt;img...'.
        section = next(s for s in self.sections if s['name']=='site error')
        text = BeautifulSoup(section['html'],'html.parser').find('p').get_text()
        self.assertTrue(text.startswith('<img src=x onerror='))
        self.assertNotIn('&lt;',text)
