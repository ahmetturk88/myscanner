"""XSS and attribute-boundary checks for five scanner result interfaces."""
import json
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
import unittest
from bs4 import BeautifulSoup
from jinja2 import Environment, FileSystemLoader, select_autoescape

ROOT=Path(__file__).resolve().parents[1]
PAGES=['ip_check.html','email_check.html','domain_lookup.html','ssl_checker.html','password_check.html']

class TemplateTests(unittest.TestCase):
    def test_all_five_pages_render_and_load_safe_helper_before_renderers(self):
        env=Environment(loader=FileSystemLoader(ROOT/'templates'),autoescape=select_autoescape(['html']))
        env.globals.update(url_for=lambda *a,**kw:'/static/'+kw.get('filename','test'),csrf_token=lambda:'test',get_flashed_messages=lambda **kw:[],current_user=SimpleNamespace(is_authenticated=False),request=SimpleNamespace(path='/ip-check'))
        for page in PAGES:
            with self.subTest(page=page):
                rendered=env.get_template(page).render()
                soup=BeautifulSoup(rendered,'html.parser')
                self.assertIsNotNone(soup.find('script',src='/static/scan_ui.js'))
                self.assertLess(rendered.index('/static/scan_ui.js'),rendered.index('function render'))
                self.assertIsNotNone(soup.select_one('#result-card'))

    def test_email_suggestions_bind_literal_data_without_inline_handler(self):
        source=(ROOT/'templates/email_check.html').read_text(encoding='utf-8')
        self.assertNotIn('onclick="useSuggestion(',source)
        self.assertIn("button.addEventListener('click'",source)
        self.assertIn('corrected.textContent = suggestion.suggested',source)

@unittest.skipUnless(shutil.which('node'),'Node.js is needed for scanner renderer execution tests')
class ExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result=subprocess.run([shutil.which('node'),str(ROOT/'tests/test_tool_result_xss.cjs')],check=True,capture_output=True,text=True,encoding='utf-8')
        cls.output=json.loads(result.stdout)

    def test_malicious_provider_data_stays_text_across_all_five_tools(self):
        self.assertGreaterEqual(len(self.output['sections']),15)
        for section in self.output['sections']:
            with self.subTest(section=section['name']):
                soup=BeautifulSoup(section['html'],'html.parser')
                self.assertFalse(soup.find_all(['script','svg','img','iframe','object','embed']))
                for tag in soup.find_all():
                    for key,value in tag.attrs.items():
                        if key.startswith('on'):
                            self.assertEqual(key,'onclick')
                            self.assertIn(value,['exportJSON()','copyReport()'])
                        if key in ['src','href']:
                            self.fail('Unexpected dynamic link in hostile renderer fixture')
                        if key=='style':
                            self.assertNotIn('onerror',value)
                            self.assertNotIn('<',value)
                            self.assertNotIn('url(',value)

    def test_original_text_is_recovered_without_double_escaping(self):
        for label in ['IP stats-grid','email details-table','domain dns-list','SSL result-card','password result-card','email suggestions-list']:
            with self.subTest(section=label):
                section=next(s for s in self.output['sections'] if s['name']==label)
                self.assertIn(self.output['payload'],BeautifulSoup(section['html'],'html.parser').get_text())

    def test_suggestion_is_a_native_button_and_has_no_data_in_attributes(self):
        section=next(s for s in self.output['sections'] if s['name']=='email suggestions-list')
        button=BeautifulSoup(section['html'],'html.parser').find('button')
        self.assertEqual(button['type'],'button')
        self.assertFalse(button.has_attr('onclick'))
        # Harness also asserts the exact original suggestion reaches input/check action,
        # coordinate bounds and zero handling, grade/color allowlists and score bounds.

if __name__=='__main__':unittest.main()
