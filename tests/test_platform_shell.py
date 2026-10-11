import unittest
from pathlib import Path
from types import SimpleNamespace
from jinja2 import Environment, FileSystemLoader, select_autoescape
ROOT=Path(__file__).resolve().parents[1]
class ShellTests(unittest.TestCase):
 def render(self,authenticated=False):
  env=Environment(loader=FileSystemLoader(ROOT/'templates'),autoescape=select_autoescape(['html']))
  return env.get_template('base.html').render(current_user=SimpleNamespace(is_authenticated=authenticated,username='<img src=x onerror=alert(1)>'),request=SimpleNamespace(path='/'),url_for=lambda endpoint,**kw:'/static/'+kw['filename'] if endpoint=='static' else '/'+endpoint,csrf_token=lambda:'csrf-fixture',get_flashed_messages=lambda **kw:[])
 def test_anonymous_navigation_and_brand(self):
  html=self.render();self.assertIn('Sign in',html);self.assertNotIn('Sign out',html)
  self.assertIn('brand/myscanner-mark.png',html);self.assertIn('brand/myscanner-logo.png',html)
  self.assertEqual(html.count('data-shell-tool '),10)
 def test_authenticated_logout_is_post_and_escaped(self):
  html=self.render(True);self.assertIn('method="POST" action="/logout"',html)
  self.assertIn('value="csrf-fixture"',html);self.assertNotIn('<img src=x',html);self.assertIn('&lt;img',html)
 def test_landmarks_and_modal_accessibility(self):
  html=self.render();self.assertIn('href="#platform-main"',html);self.assertIn('<dialog',html)
  self.assertIn('aria-labelledby="shell-tools-title"',html);self.assertIn('role="status"',html)
  self.assertIn('aria-label="Footer inspections"',html)
 def test_safe_script_and_motion_preferences(self):
  js=(ROOT/'static/platform_shell.js').read_text();css=(ROOT/'static/platform_shell.css').read_text()
  for unsafe in ('innerHTML','eval(','localStorage','fetch('):self.assertNotIn(unsafe,js)
  self.assertIn("dialog.showModal()",js);self.assertIn("addEventListener('close'",js)
  self.assertIn('prefers-reduced-motion',css);self.assertIn('textContent',js)
 def test_assets_are_original_pngs(self):
  for name in ('myscanner-mark.png','myscanner-logo.png'):
   self.assertTrue((ROOT/'static/brand'/name).read_bytes().startswith(b'\x89PNG\r\n\x1a\n'))
if __name__=='__main__':unittest.main()
