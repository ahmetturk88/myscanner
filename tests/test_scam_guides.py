"""Scam guides: every guide renders in English and Turkish, is in the sitemap and is linked from the footer."""
import json
import unittest

from bs4 import BeautifulSoup

import test_task_ownership  # noqa: F401  (sets up the test database)
from services.scam_guides import GUIDES, TOOL_NAMES, UI


class ScamGuideTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app import app
        cls.client = app.test_client()

    def test_every_guide_is_complete_in_both_languages(self):
        for guide in GUIDES:
            for lang in ('en', 'tr'):
                with self.subTest(slug=guide['slug'], lang=lang):
                    text = guide[lang]
                    for key in ('title', 'summary', 'description', 'example'):
                        self.assertTrue(text[key].strip())
                    self.assertGreaterEqual(len(text['signs']), 3)
                    self.assertGreaterEqual(len(text['todo']), 3)
                    self.assertLessEqual(len(text['description']), 170)
                    # Example addresses are defanged so they never become live links.
                    self.assertNotRegex(text['example'], r'\w\.(com|net|shop|store)\b')
                    if guide['tool']:
                        self.assertIn(guide['tool'], TOOL_NAMES[lang])

    def test_index_and_guides_render_in_english_and_turkish(self):
        index = self.client.get('/scams?lang=en').get_data(as_text=True)
        self.assertIn(UI['en']['index_lead'], index)
        self.assertIn('Dolandırıcılığı', self.client.get('/scams?lang=tr').get_data(as_text=True))
        for guide in GUIDES:
            for lang in ('en', 'tr'):
                with self.subTest(slug=guide['slug'], lang=lang):
                    response = self.client.get(f"/scams/{guide['slug']}?lang={lang}")
                    self.assertEqual(response.status_code, 200)
                    page = BeautifulSoup(response.data, 'html.parser')
                    self.assertEqual(page.find('h1').get_text(strip=True), guide[lang]['title'])
                    article = json.loads(page.find('script', type='application/ld+json').string)
                    self.assertEqual((article['@type'], article['inLanguage']), ('Article', lang))
        self.assertEqual(self.client.get('/scams/no-such-guide').status_code, 404)

    def test_guides_are_in_the_sitemap_and_the_footer(self):
        sitemap = self.client.get('/sitemap.xml').get_data(as_text=True)
        for guide in GUIDES:
            self.assertIn(f"/scams/{guide['slug']}?lang=tr", sitemap)
        footer = BeautifulSoup(self.client.get('/about').data, 'html.parser').find('footer')
        self.assertTrue(footer.find('a', href='/scams'))


if __name__ == '__main__':
    unittest.main()
