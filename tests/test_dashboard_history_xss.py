"""Dashboard template checks plus offline DOM tests when Node is available."""
from pathlib import Path
import shutil
import subprocess
import unittest
from types import SimpleNamespace
from bs4 import BeautifulSoup
from jinja2 import Environment, FileSystemLoader, select_autoescape

ROOT = Path(__file__).resolve().parents[1]

class DashboardTests(unittest.TestCase):
    def test_template_renders_and_loads_text_renderer_before_use(self):
        env = Environment(loader=FileSystemLoader(ROOT / 'templates'), autoescape=select_autoescape(['html']))
        env.globals.update(url_for=lambda *a,**kw: '/static/'+kw.get('filename','test'),
            csrf_token=lambda:'test-token', get_flashed_messages=lambda **kw:[],
            current_user=SimpleNamespace(is_authenticated=False), request=SimpleNamespace(path='/dashboard-v2'))
        rendered=env.get_template('dashboard-v2.html').render()
        soup=BeautifulSoup(rendered,'html.parser')
        self.assertIsNotNone(soup.select_one('#table-body'))
        self.assertIsNotNone(soup.find('script',src='/static/dashboard_ui.js'))
        self.assertLess(rendered.index('/static/dashboard_ui.js'), rendered.index('DashboardUI.renderRows'))
        self.assertIn('DashboardUI.normalizeScans',rendered)
        self.assertNotIn('.innerHTML',rendered)

    def test_renderer_has_no_html_or_attribute_injection_sink(self):
        source=(ROOT/'static/dashboard_ui.js').read_text(encoding='utf-8')
        for sink in ['innerHTML','outerHTML','insertAdjacentHTML','document.write','setAttribute','eval(']:
            self.assertNotIn(sink,source)
        self.assertIn('textContent',source)
        self.assertIn('replaceChildren',source)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for DOM execution tests; also check dashboard-v2 in your browser')
    def test_malicious_values_remain_text_and_unknown_verdict_is_constrained(self):
        result=subprocess.run([shutil.which('node'),str(ROOT/'tests/test_dashboard_history_xss.cjs')],
            capture_output=True,text=True,encoding='utf-8',check=True)
        self.assertIn('checks passed',result.stdout)
