import pathlib, shutil, subprocess, unittest
from jinja2 import Environment, FileSystemLoader
ROOT = pathlib.Path(__file__).resolve().parents[1]
class FileWorkspaceTests(unittest.TestCase):
    def test_template_renders_and_loads_workspace(self):
        env = Environment(loader=FileSystemLoader(ROOT / 'templates'))
        html = env.get_template('file_scanner.html').render(url_for=lambda endpoint, **kw: '/static/' + kw.get('filename', endpoint), current_user=type('User', (), {'is_authenticated': False})(), csrf_token=lambda: 'test-token', get_flashed_messages=lambda **kw: [])
        self.assertIn('file_workspace.css', html)
        self.assertIn('file_workspace.js', html)
        self.assertIn('Inspect this file', html)
        self.assertNotIn('70+', html)
        # Plain summary first; every earlier evidence block stays inside Full technical evidence.
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, 'html.parser')
        self.assertTrue(soup.select_one('#file-plain').has_attr('hidden'))
        tech = soup.select_one('details#file-tech')
        for selector in ('#verdict-banner', '#stats-grid', '#provider-summary', '#deep-analysis-container', '#evidence-search'):
            self.assertIsNotNone(tech.select_one(selector), selector)
        self.assertLess(html.index('plain_report.js'), html.index('file_workspace.js'))
    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for renderer execution tests')
    def test_real_workspace_behavior(self):
        subprocess.run(['node', str(ROOT / 'tests/test_file_workspace.cjs')], cwd=ROOT, check=True, timeout=15)
if __name__ == '__main__': unittest.main()
