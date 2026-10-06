"""Real TIP/Sandbox renderer execution and static dashboard integration."""
from pathlib import Path
import json
import shutil
import subprocess
import unittest
from types import SimpleNamespace
from bs4 import BeautifulSoup
from jinja2 import Environment, FileSystemLoader, select_autoescape
ROOT=Path(__file__).resolve().parents[1]
class TemplateTests(unittest.TestCase):
    def test_pages_render_with_versioned_helper_before_inline_scripts(self):
        env=Environment(loader=FileSystemLoader(ROOT/'templates'), autoescape=select_autoescape(['html']))
        env.globals.update(url_for=lambda *a,**kw:'/static/'+kw.get('filename','test')+('?v='+kw['v'] if 'v' in kw else ''),csrf_token=lambda:'test',get_flashed_messages=lambda **kw:[],current_user=SimpleNamespace(is_authenticated=True,is_admin=True,username='test'),request=SimpleNamespace(path='/tip'))
        for name in ['tip_dashboard.html','sandbox.html']:
            with self.subTest(name=name):
                rendered=env.get_template(name).render()
                self.assertIn('/static/scan_ui.js?v=',rendered)
                self.assertLess(rendered.index('/static/scan_ui.js?v='),rendered.index('function escapeHtml'))
    def test_static_dashboard_uses_shared_text_renderer(self):
        s=(ROOT/'static/dashboard/index.html').read_text(encoding='utf-8')
        self.assertIn('DashboardUI.normalizeScans',s)
        self.assertIn('DashboardUI.renderRows',s)
        self.assertNotIn('innerHTML',s)
        self.assertLess(s.index('/static/dashboard_ui.js?v='),s.index('DashboardUI.renderRows'))
@unittest.skipUnless(shutil.which('node'),'Node.js is needed for TIP/Sandbox renderer execution tests')
class ExecutionTests(unittest.TestCase):
    def test_provider_values_toasts_errors_and_numeric_fields(self):
        r=subprocess.run([shutil.which('node'),str(ROOT/'tests/test_tip_sandbox_xss.cjs')],capture_output=True,text=True,encoding='utf-8',check=True)
        result=json.loads(r.stdout);self.assertGreater(len(result['sections']),10)
        for section in result['sections']:
            with self.subTest(section=section['name']):
                soup=BeautifulSoup(section['html'],'html.parser')
                self.assertFalse(soup.find_all(['img','svg','script','iframe','object','embed']))
                for element in soup.find_all():
                    self.assertFalse(any(k.startswith('on') for k in element.attrs))
                    self.assertNotIn('onerror',element.get('style',''))
        for label in ['sandbox sourcesRow','sandbox sigsBody','sandbox staticBody','tip table iocsTableBody','tip match lookupResult','tip no match lookupResult','tip exception lookupResult']:
            section=next(s for s in result['sections'] if s['name']==label)
            self.assertIn(result['payload'],BeautifulSoup(section['html'],'html.parser').get_text())
    def test_static_dashboard_loading_filter_and_text_fidelity(self):
        r=subprocess.run([shutil.which('node'),str(ROOT/'tests/test_dashboard_history_xss.cjs'),'--static'],capture_output=True,text=True,encoding='utf-8',check=True)
        self.assertIn('integration checks passed',r.stdout)
if __name__=='__main__':unittest.main()
