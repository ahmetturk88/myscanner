"""Search-engine basics: robots.txt, the sitemap, page metadata and the logo data on the home page."""
import json
import unittest

from bs4 import BeautifulSoup

from extensions import db
import test_task_ownership


class SeoTests(unittest.TestCase):
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

    def test_robots_points_to_sitemap_and_keeps_private_areas_out(self):
        response = self.client.get('/robots.txt')
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertIn('Sitemap: https://', text)
        for path in ('/admin', '/api/', '/result/'):
            self.assertIn(f'Disallow: {path}', text)

    def test_sitemap_lists_only_public_pages_that_render(self):
        response = self.client.get('/sitemap.xml')
        self.assertEqual(response.mimetype, 'application/xml')
        locs = [loc.text for loc in BeautifulSoup(response.data, 'html.parser').find_all('loc')]
        self.assertIn('https://myscanners.com/', locs)
        for loc in locs:
            path = loc.removeprefix('https://myscanners.com')
            self.assertEqual(self.client.get(path).status_code, 200, path)

    def test_home_page_has_metadata_and_organization_logo(self):
        page = BeautifulSoup(self.client.get('/').data, 'html.parser')
        self.assertTrue(page.find('meta', attrs={'name': 'description'})['content'])
        self.assertEqual(page.find('link', rel='canonical')['href'], 'https://myscanners.com/')
        self.assertTrue(page.find('meta', property='og:image')['content'].endswith('brand/myscanner-share.png'))
        graph = json.loads(page.find('script', type='application/ld+json').string)['@graph']
        org = next(node for node in graph if node['@type'] == 'Organization')
        self.assertTrue(org['logo'].endswith('brand/myscanner-mark.png'))
        self.assertEqual(self.client.get('/static/brand/myscanner-mark.png').status_code, 200)

    def test_structured_data_only_on_home(self):
        page = BeautifulSoup(self.client.get('/about').data, 'html.parser')
        self.assertIsNone(page.find('script', type='application/ld+json'))
        self.assertEqual(page.find('link', rel='canonical')['href'], 'https://myscanners.com/about')


if __name__ == '__main__':
    unittest.main()
