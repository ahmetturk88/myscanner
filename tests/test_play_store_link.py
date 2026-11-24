"""The site links to the Android app on Google Play, in English and Turkish."""
import unittest

import test_task_ownership  # noqa: F401  (sets up the test database)

PLAY = 'https://play.google.com/store/apps/details?id=com.myscanners.app'


class PlayStoreLinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = test_task_ownership._import_production_app()[1].app

    def page(self, path):
        return self.app.test_client().get(path).get_data(as_text=True)

    def test_home_and_footer_link_to_the_app(self):
        page = self.page('/?lang=en')
        self.assertEqual(page.count(PLAY), 2)  # the home section and the footer
        self.assertIn('The same checks.', page)
        self.assertIn('rel="noopener noreferrer"', page)

    def test_turkish_pages(self):
        page = self.page('/?lang=tr')
        self.assertIn('ANDROID İÇİN MYSCANNER', page)
        self.assertIn('deki Android uygulaması', page)
        self.assertIn('Artık cebinde.', page)

    def test_other_pages_keep_the_footer_link(self):
        self.assertIn(PLAY, self.page('/about?lang=en'))


if __name__ == '__main__':
    unittest.main()
