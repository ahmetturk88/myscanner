"""The Pro coming-soon page: real price in both languages, visit sources, and the waitlist."""
import unittest

from bs4 import BeautifulSoup

import test_task_ownership  # noqa: F401  (sets up the test database)
from extensions import db
from models import ProInterest
from services import pro_page


class ProPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = test_task_ownership._import_production_app()[1].app
        with cls.app.app_context():
            db.create_all()  # production builds tables with migrations

    def setUp(self):
        self.client = self.app.test_client()
        with self.app.app_context():
            ProInterest.query.delete()
            db.session.commit()

    def rows(self, **filters):
        with self.app.app_context():
            return [(row.kind, row.source, row.lang, row.email) for row in ProInterest.query.filter_by(**filters).order_by(ProInterest.id)]

    def post(self, email, **extra):
        page = BeautifulSoup(self.client.get('/pro').data, 'html.parser')
        token = page.find('input', attrs={'name': 'csrf_token'})['value']
        return self.client.post('/pro', data={'csrf_token': token, 'email': email, **extra})

    def test_both_languages_show_the_real_price_and_no_payment(self):
        english = self.client.get('/pro?lang=en').get_data(as_text=True)
        self.assertIn('$4.99', english)
        self.assertIn('No payment now', english)
        turkish = self.client.get('/pro?lang=tr').get_data(as_text=True)
        self.assertIn('₺199', turkish)
        self.assertIn('Ödemeden önce', turkish)
        for lang in ('en', 'tr'):
            text = pro_page.CONTENT[lang]
            self.assertEqual(set(text), set(pro_page.CONTENT['en']))
            self.assertLessEqual(len(text['description']), 170)

    def test_a_visit_is_counted_once_per_session_with_its_source(self):
        self.client.get('/pro?utm_source=LinkedIn', headers={'User-Agent': 'Mozilla/5.0'})
        self.client.get('/pro?utm_source=other', headers={'User-Agent': 'Mozilla/5.0'})
        self.assertEqual(self.rows(kind='visit'), [('visit', 'linkedin', 'en', None)])
        self.app.test_client().get('/pro', headers={'User-Agent': 'Googlebot/2.1'})
        self.assertEqual(len(self.rows(kind='visit')), 1)

    def test_source_from_referrer(self):
        source = pro_page.visit_source
        self.assertEqual(source({}, 'https://www.linkedin.com/feed/', 'myscanners.com'), 'linkedin.com')
        self.assertEqual(source({}, 'https://myscanners.com/scams', 'myscanners.com'), 'site')
        self.assertEqual(source({}, None, 'myscanners.com'), 'direct')
        self.assertEqual(source({'utm_source': '<script>'}, None, 'myscanners.com'), 'direct')

    def test_waitlist_signs_up_once_and_rejects_bad_email(self):
        self.client.get('/pro?utm_source=whatsapp', headers={'User-Agent': 'Mozilla/5.0'})
        self.assertIn('We’ll email you once', self.post(' Person@Example.com ').get_data(as_text=True))
        self.assertIn('We’ll email you once', self.post('person@example.com').get_data(as_text=True))  # same reply: the list isn't revealed
        self.assertEqual(self.rows(kind='signup'), [('signup', 'whatsapp', 'en', 'person@example.com')])
        self.assertEqual(self.post('not-an-email').status_code, 400)
        self.post('bot@example.com', website='spam')
        self.assertEqual(len(self.rows(kind='signup')), 1)

    def test_stats_and_admin_only(self):
        self.client.get('/pro?utm_source=linkedin', headers={'User-Agent': 'Mozilla/5.0'})
        self.post('a@example.com')
        with self.app.app_context():
            stats = pro_page.stats()
        self.assertEqual((stats['visits'], stats['signups'], stats['rate']), (1, 1, 100.0))
        self.assertEqual(stats['sources'], [('linkedin', {'visit': 1, 'signup': 1})])
        self.assertNotEqual(self.client.get('/admin/pro-interest').status_code, 200)

    def test_announcement_on_site_pages_but_never_where_the_app_opens_or_on_pro(self):
        for path in ('/', '/about', '/scams'):
            page = self.client.get(path + '?lang=en').get_data(as_text=True)
            self.assertIn('id="pro-pop"', page, path)
            self.assertIn('utm_source=site_popup', page)
        self.assertIn('₺199', self.client.get('/scams?lang=tr').get_data(as_text=True))
        # The app opens these in its browser; a price that leads outside Google Play must not show there.
        for path in ('/privacy', '/terms', '/contact', '/register', '/forgot-password', '/pro', '/login'):
            self.assertNotIn('id="pro-pop"', self.client.get(path).get_data(as_text=True), path)

    def test_top_menu_links_to_pro(self):
        page = BeautifulSoup(self.client.get('/about?lang=en').data, 'html.parser')
        self.assertTrue(page.select_one('.shell-nav-links a[href="/pro"]'))

    def test_in_sitemap_and_footer(self):
        self.assertIn('/pro?lang=tr', self.client.get('/sitemap.xml').get_data(as_text=True))
        self.assertIn('href="/pro"', self.client.get('/about').get_data(as_text=True))


if __name__ == '__main__':
    unittest.main()
