"""Shared toolbar on inspection pages."""
from pathlib import Path
import unittest

from bs4 import BeautifulSoup

from extensions import db
from models import User
import test_task_ownership

ROOT = Path(__file__).resolve().parents[1]
TOOLS = {'/dashboard': 'true', '/site-scanner': 'true', '/ip-check': 'true', '/domain-lookup': 'true', '/ssl-checker': 'true',
         '/subdomain-finder': 'true', '/email-check': 'false', '/password-check': 'false', '/file-scanner': 'false', '/qr-scanner': 'false'}


class ToolRailTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_task_ownership.TaskOwnershipTests.setUpClass()
        cls.production = test_task_ownership.TaskOwnershipTests.production

    @classmethod
    def tearDownClass(cls):
        test_task_ownership.TaskOwnershipTests.tearDownClass()

    def setUp(self):
        self.app = self.production.app
        with self.app.app_context():
            db.drop_all(); db.create_all()
            user = User(username='railer', email='rail@example.invalid', is_verified=True); user.set_password('Rail#2026x')
            db.session.add(user); db.session.commit(); self.user = user.id
        self.client = self.app.test_client()
        with self.client.session_transaction() as session:
            session['_user_id'] = str(self.user); session['_fresh'] = True

    def tearDown(self):
        with self.app.app_context():
            db.session.remove(); db.drop_all()

    def test_every_tool_page_has_the_rail_and_secrets_are_never_remembered(self):
        for path, remember in TOOLS.items():
            soup = BeautifulSoup(self.client.get(path).data, 'html.parser')
            rail = soup.select_one('.tx-rail')
            self.assertIsNotNone(rail, path)
            self.assertEqual(rail['data-remember'], remember, path)
            self.assertEqual(soup.select_one('main')['class'], ['tx-page'])
            self.assertEqual(soup.select_one('.tx-switch [aria-current]')['href'], path, path)
            self.assertEqual(len(soup.select('.tx-switch a')), 10)
            if rail.get('data-input'):
                self.assertIsNotNone(soup.select_one(rail['data-input']), path)
            self.assertEqual(bool(soup.select('.tx-recent')), remember == 'true', path)

    def test_other_pages_have_no_rail(self):
        for path in ('/profile', '/about', '/dashboard-v2'):
            self.assertNotIn(b'tx-rail', self.client.get(path).data, path)

    def test_script_writes_text_only(self):
        source = (ROOT / 'static/tool_experience.js').read_text()
        for sink in ('innerHTML', 'outerHTML', 'insertAdjacentHTML', 'eval('):
            self.assertNotIn(sink, source)


if __name__ == '__main__':
    unittest.main()
