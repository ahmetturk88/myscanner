"""Password recovery pages, emails and contact replies."""
from pathlib import Path
from unittest.mock import patch
import unittest

from bs4 import BeautifulSoup

from extensions import db
from models import User
from services.email_templates import action_email
import test_task_ownership


class EmailTemplateTests(unittest.TestCase):
    def test_dynamic_values_are_escaped(self):
        html, text = action_email('Title', 'Hello <img src=x onerror=alert(1)>,', ['A & B'], 'Go', 'https://e.example/?a=1&b="2"')
        self.assertNotIn('<img src=x', html)
        self.assertIn('&lt;img', html)
        self.assertIn('href="https://e.example/?a=1&amp;b=&quot;2&quot;"', html)
        self.assertIn('Hello <img src=x onerror=alert(1)>,', text)


class RecoveryTests(unittest.TestCase):
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
            user = User(username='<b>bold</b>', email='person@example.com', is_verified=True)
            user.set_password('Original#2026'); db.session.add(user); db.session.commit()
        self.client = self.app.test_client()
        self.token = BeautifulSoup(self.client.get('/login').data, 'html.parser').find('meta', {'name': 'csrf-token'})['content']
        self.sent = []
        patcher = patch.object(self.production, 'send_email', side_effect=lambda *a, **k: self.sent.append((a, k)) or True)
        patcher.start(); self.addCleanup(patcher.stop)

    def tearDown(self):
        with self.app.app_context():
            db.session.remove(); db.drop_all()

    def forgot(self, email):
        return self.client.post('/forgot-password', data={'email': email, 'csrf_token': self.token}, follow_redirects=True)

    def test_sent_screen_is_identical_for_known_and_unknown_emails(self):
        known = BeautifulSoup(self.forgot('person@example.com').data, 'html.parser')
        self.assertIn('pe••', known.select_one('.auth-sent').get_text())
        self.assertNotIn('person@example.com', known.get_text())
        unknown = BeautifulSoup(self.forgot('ghost@example.com').data, 'html.parser')
        self.assertIsNotNone(unknown.select_one('.auth-sent'))
        self.assertEqual(len(self.sent), 1)
        args, kwargs = self.sent[0]
        self.assertNotIn('<b>bold</b>', args[3])
        self.assertIn('&lt;b&gt;bold', args[3])
        # Refreshing shows the form again rather than the sent state.
        self.assertIsNone(BeautifulSoup(self.client.get('/forgot-password').data, 'html.parser').select_one('.auth-sent'))

    def test_reset_sends_a_change_notice_and_link_works_once(self):
        self.forgot('person@example.com')
        path = '/reset-password/' + self.sent[0][0][2].split('/reset-password/')[1].split()[0]
        page = BeautifulSoup(self.client.get(path).data, 'html.parser')
        self.assertIn('pe••', page.get_text())
        response = self.client.post(path, data={'password': 'Changed#2026x', 'confirm_password': 'Changed#2026x', 'csrf_token': self.token})
        self.assertIn('/login', response.headers['Location'])
        self.assertEqual(self.sent[-1][0][1], 'Your MyScanner password was changed')
        self.assertIn('/forgot-password', self.client.get(path).headers['Location'])

    def test_contact_reply_goes_to_the_visitor(self):
        self.client.post('/contact', data={'csrf_token': self.token, 'name': 'Visitor', 'email': 'visitor@example.com',
                                           'subject': 'Feedback', 'message': 'Hi'}, headers={'X-Requested-With': 'XMLHttpRequest'})
        self.assertEqual(self.sent[-1][1]['reply_to'], 'visitor@example.com')
        self.client.post('/contact', data={'csrf_token': self.token, 'name': 'X', 'email': 'a@b.c, evil@example.com',
                                           'subject': 'Feedback', 'message': 'Hi'}, headers={'X-Requested-With': 'XMLHttpRequest'})
        self.assertIsNone(self.sent[-1][1]['reply_to'])


if __name__ == '__main__':
    unittest.main()
