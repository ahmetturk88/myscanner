"""Privacy Policy and Terms of Service pages and the links that point to them."""
import unittest

from bs4 import BeautifulSoup

from extensions import db
import test_task_ownership


class LegalPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_task_ownership.TaskOwnershipTests.setUpClass()
        cls.app = test_task_ownership.TaskOwnershipTests.production.app

    @classmethod
    def tearDownClass(cls):
        test_task_ownership.TaskOwnershipTests.tearDownClass()

    def setUp(self):
        with self.app.app_context():
            db.drop_all(); db.create_all()
        self.client = self.app.test_client()

    def soup(self, path):
        response = self.client.get(path)
        self.assertEqual(response.status_code, 200, path)
        return BeautifulSoup(response.data, 'html.parser')

    def test_pages_render_for_anonymous_visitors_with_working_contents(self):
        for path, title in (('/privacy', 'Privacy Policy'), ('/terms', 'Terms of Service')):
            soup = self.soup(path)
            self.assertIn(title, soup.title.text)
            self.assertRegex(soup.text, r'Effective \d{1,2} [A-Z][a-z]+ 20\d\d')
            self.assertIn('info@myscanners.com', soup.text)
            anchors = [a['href'][1:] for a in soup.select('.legal-toc a')]
            self.assertEqual(len(anchors), 13)
            for anchor in anchors:
                self.assertIsNotNone(soup.find(id=anchor), f'{path}#{anchor}')

    def test_pages_link_to_each_other(self):
        self.assertTrue(self.soup('/privacy').select('.legal-body a[href="/terms"]'))
        self.assertTrue(self.soup('/terms').select('.legal-body a[href="/privacy"]'))

    def test_privacy_names_key_facts(self):
        text = self.soup('/privacy').text
        for fact in ('bcrypt', 'k-anonymity', 'never executed', '30 days', '14 days', 'KVKK', 'Resend', 'netcup'):
            self.assertIn(fact, text)

    def test_footer_register_and_contact_link_the_policies(self):
        footer = self.soup('/about').select_one('.shell-legal')
        self.assertTrue(footer.select('a[href="/privacy"]') and footer.select('a[href="/terms"]'))
        note = self.soup('/register').select_one('.auth-legal')
        self.assertTrue(note.select('a[href="/privacy"]') and note.select('a[href="/terms"]'))
        self.assertTrue(self.soup('/contact').select('form a[href="/privacy"]'))


if __name__ == '__main__':
    unittest.main()
