from pathlib import Path
from types import SimpleNamespace
import unittest
from jinja2 import Environment, FileSystemLoader

ROOT=Path(__file__).resolve().parents[1]
class HomeExperienceTests(unittest.TestCase):
    def render(self,name,admin=False):
        env=Environment(loader=FileSystemLoader(ROOT/'templates'),autoescape=True)
        return env.get_template(name).render(url_for=lambda endpoint,**kw:'/static/'+kw['filename'] if endpoint=='static' else '/result/0' if endpoint=='result_page' else '/'+endpoint,csrf_token=lambda:'csrf-fixture',current_user=SimpleNamespace(username='<img src=x onerror=alert(1)>',is_authenticated=name=='index.html',is_admin=admin),get_flashed_messages=lambda **kw:[])
    def test_public_page_has_account_cta_and_no_private_report_request(self):
        html=self.render('home.html')
        self.assertIn('href="/register"',html)
        self.assertNotIn('data-workspace',html)
        self.assertIn('ILLUSTRATION',html)
    def test_workspace_preserves_scan_post_csrf_and_escapes_identity(self):
        html=self.render('index.html')
        self.assertIn('method="POST" action="/dashboard"',html)
        self.assertIn('name="csrf_token" value="csrf-fixture"',html)
        self.assertIn('id="url-input" name="url"',html)
        self.assertNotIn('<img src=x onerror=alert(1)>',html)
        self.assertIn('&lt;img',html)
        self.assertEqual(html.count('class="hx-tool"'),10)
    def test_administrator_recent_scope_is_explicit(self):
        self.assertIn('Latest platform scans visible',self.render('index.html',True))
        self.assertIn('Your latest saved scans',self.render('index.html'))
