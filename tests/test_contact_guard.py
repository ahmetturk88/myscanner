"""Contact form spam guard: bots get a quiet fake success, people get their message through."""
from pathlib import Path
from unittest.mock import patch
import time
import unittest

from bs4 import BeautifulSoup

from extensions import db
from services.contact_guard import MAX_AGE, TOPICS, check_submission, form_token, one_line
import test_task_ownership

SECRET = 'x' * 40


class CheckSubmissionTests(unittest.TestCase):
    def form(self, age=10, **extra):
        return {'form_token': form_token(SECRET, 1_000_000 - age), 'subject': 'Feedback', 'name': 'A',
                'email': 'a@example.com', 'message': 'Hi', **extra}

    def check(self, form):
        return check_submission(form, SECRET, now=1_000_000)

    def test_a_person_passes(self):
        self.assertEqual(self.check(self.form()), 'ok')

    def test_bots_are_recognised(self):
        self.assertEqual(self.check(self.form(website='http://spam.example')), 'bot')
        self.assertEqual(self.check(self.form(age=1)), 'bot')  # faster than a person can type
        self.assertEqual(self.check({**self.form(), 'form_token': ''}), 'bot')  # direct POST
        self.assertEqual(self.check({**self.form(), 'form_token': form_token('another-secret', 0)}), 'bot')

    def test_old_page_asks_for_a_reload(self):
        self.assertEqual(self.check(self.form(age=MAX_AGE + 1)), 'expired')

    def test_unknown_topic_or_oversized_field_is_invalid(self):
        self.assertEqual(self.check(self.form(subject='Buy now')), 'invalid')
        self.assertEqual(self.check(self.form(message='x' * 4001)), 'invalid')

    def test_one_line_removes_header_breaks(self):
        self.assertEqual(one_line(' Robert\r\nBcc: x@example.com ', 120), 'Robert Bcc: x@example.com')
        self.assertEqual(one_line('a' * 200, 120), 'a' * 120)

    def test_topics_match_the_page(self):
        page = (Path(__file__).resolve().parents[1]/'templates'/'contact.html').read_text(encoding='utf-8')
        for topic in TOPICS:
            self.assertIn(f"('{topic}',", page)


class ContactRouteTests(unittest.TestCase):
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
        self.client = self.app.test_client()
        page = BeautifulSoup(self.client.get('/contact').data, 'html.parser')
        self.token = page.find('meta', {'name': 'csrf-token'})['content']
        self.page = page

    def post(self, age=10, ip='203.0.113.5', **fields):
        data = {'csrf_token': self.token, 'form_token': form_token(self.app.config['SECRET_KEY'], time.time() - age),
                'name': 'Visitor', 'email': 'visitor@example.com', 'subject': 'Feedback', 'message': 'Hello', **fields}
        with patch.object(self.production, 'send_email', return_value=True) as mail:
            response = self.client.post('/contact', data=data, headers={'X-Requested-With': 'XMLHttpRequest'},
                                        environ_base={'REMOTE_ADDR': ip})
        return response, mail

    def test_page_carries_the_signed_time_and_a_hidden_trap(self):
        self.assertTrue(self.page.select_one('input[name="form_token"]')['value'])
        trap = self.page.select_one('input[name="website"]')
        self.assertEqual(trap['tabindex'], '-1')
        self.assertEqual(trap.find_parent('div')['aria-hidden'], 'true')

    def test_person_message_is_sent(self):
        response, mail = self.post()
        self.assertTrue(response.json['success'])
        mail.assert_called_once()

    def test_bot_gets_success_but_nothing_is_sent(self):
        for fields in ({'website': 'http://spam.example'}, {'age': 0}):
            response, mail = self.post(**fields)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json['success'])
            mail.assert_not_called()

    def test_expired_page_and_unknown_topic_are_explained(self):
        response, mail = self.post(age=MAX_AGE + 60)
        self.assertEqual(response.status_code, 400)
        self.assertIn('reload', response.json['error'])
        response, mail = self.post(subject='Casino')
        self.assertEqual(response.status_code, 400)
        mail.assert_not_called()

    def test_flood_from_one_address_is_limited(self):
        for i in range(5):
            response, _ = self.post(email=f'v{i}@example.com')
            self.assertTrue(response.json['success'], i)
        response, mail = self.post(email='v9@example.com')
        self.assertEqual(response.status_code, 429)
        self.assertIn('Too many messages', response.json['error'])
        mail.assert_not_called()
        response, _ = self.post(ip='203.0.113.77', email='other@example.com')
        self.assertTrue(response.json['success'])

    def test_one_sender_address_is_limited_across_addresses(self):
        for i in range(3):
            self.assertTrue(self.post(ip=f'203.0.113.{10 + i}')[0].json['success'])
        self.assertEqual(self.post(ip='203.0.113.20')[0].status_code, 429)

    def test_line_breaks_in_the_name_never_reach_the_subject(self):
        _, mail = self.post(name='Robert\r\nBcc: x@example.com')
        self.assertEqual(mail.call_args.kwargs['subject'], '[MyScanner Contact] Feedback from Robert Bcc: x@example.com')


if __name__ == '__main__':
    unittest.main()
