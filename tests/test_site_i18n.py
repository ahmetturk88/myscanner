"""Website language: Turkish pages and report summaries, chosen by link, cookie or browser."""
import json
import unittest

from flask import Flask, jsonify

from services import site_i18n


def make_app():
    app = Flask(__name__)
    app.after_request(site_i18n.localise_response)

    @app.route('/page')
    def page():
        return ('<!doctype html><html lang="en"><head><title>MyScanner — About</title>'
                '<meta name="description" content="Check links, files, emails and domains, and see exactly what was found and what is still unknown.">'
                '<script>var label = "Sign in";</script></head><body>'
                '<a href="/login">Sign in</a> <input placeholder="Your password"> <p>  Ahmed  </p>'
                '<span>Profile &amp; allowance</span><b>0 scans</b><i>22 Oct 2026</i></body></html>')

    @app.route('/api/report')
    def report():
        return jsonify(result={'plain': {'headline': 'No warning signs found', 'label': 'LOOKS SAFE', 'reasons': []}, 'raw': 'Sign in'})
    return app


class SiteLanguageTests(unittest.TestCase):
    def setUp(self):
        self.client = make_app().test_client()

    def test_english_by_default_and_unchanged(self):
        response = self.client.get('/page')
        self.assertIn('<a href="/login">Sign in</a>', response.get_data(as_text=True))
        self.assertIn('Cookie', response.headers['Vary'])
        self.assertNotIn('lang=', response.headers.get('Set-Cookie', ''))

    def test_link_translates_text_attributes_and_remembers_the_choice(self):
        response = self.client.get('/page?lang=tr')
        body = response.get_data(as_text=True)
        self.assertIn('<html lang="tr"', body)
        self.assertIn('<a href="/login">Giriş yap</a>', body)
        self.assertIn('placeholder="Şifren"', body)
        self.assertIn('<title>MyScanner — Hakkımızda</title>', body)
        self.assertIn('content="Bağlantıları, dosyaları', body)
        self.assertIn('Profil ve kullanım hakkı', body)
        self.assertIn('<b>0 tarama</b>', body)
        self.assertIn('<i>22 Eki 2026</i>', body)
        self.assertIn('var label = "Sign in";', body)       # scripts are never touched
        self.assertIn('<p>  Ahmed  </p>', body)              # untranslated text stays as it was
        self.assertIn('lang=tr', response.headers['Set-Cookie'])
        # The cookie carries the choice to the next page.
        self.assertIn('Giriş yap', self.client.get('/page').get_data(as_text=True))
        self.assertIn('Sign in</a>', self.client.get('/page?lang=en').get_data(as_text=True))

    def test_turkish_browser_gets_turkish(self):
        body = self.client.get('/page', headers={'Accept-Language': 'tr-TR,tr;q=0.9,en;q=0.8'}).get_data(as_text=True)
        self.assertIn('Giriş yap', body)

    def test_report_summaries_in_json_are_translated_and_other_fields_kept(self):
        data = json.loads(self.client.get('/api/report?lang=tr').get_data(as_text=True))
        self.assertNotEqual(data['result']['plain']['headline'], 'No warning signs found')
        self.assertEqual(data['result']['raw'], 'Sign in')


class RealPagesTests(unittest.TestCase):
    def test_public_pages_render_in_turkish(self):
        import test_task_ownership  # noqa: F401  (sets up the test database)
        from app import app
        client = app.test_client()
        for path, phrase in (('/?lang=tr', 'Tıklamadan önce.'), ('/about?lang=tr', 'Yayında ve hızla ilerliyor.'),
                             ('/login?lang=tr', "MyScanner'a giriş yap"), ('/register?lang=tr', 'Bir dakikada incelemeye başla')):
            with self.subTest(path=path):
                response = client.get(path)
                self.assertEqual(response.status_code, 200)
                self.assertIn(phrase, response.get_data(as_text=True))
                self.assertIn('hreflang="tr"', response.get_data(as_text=True))

    def test_browser_catalog_is_served_versioned_and_loaded_only_for_turkish(self):
        import test_task_ownership  # noqa: F401
        from app import app
        client = app.test_client()
        english = client.get('/?lang=en').get_data(as_text=True)
        self.assertNotIn('site_i18n.js', english)
        turkish = client.get('/?lang=tr').get_data(as_text=True)
        self.assertIn('/i18n/tr.js?v=', turkish)
        self.assertIn('site_i18n.js', turkish)
        script = client.get('/i18n/tr.js')
        self.assertEqual(script.status_code, 200)
        self.assertIn('max-age=604800', script.headers['Cache-Control'])
        body = script.get_data(as_text=True)
        self.assertTrue(body.startswith('window.MYSCANNER_I18N='))
        payload = json.loads(body[len('window.MYSCANNER_I18N='):-1])
        self.assertEqual(payload['words']['This file is empty. Choose a non-empty file.'], 'Bu dosya boş. Boş olmayan bir dosya seç.')
        self.assertIn(['^(\\d+) scans?$', '$1 tarama'], payload['patterns'])
        self.assertEqual(client.get('/i18n/en.js').status_code, 404)
        self.assertEqual(client.get('/i18n/xx.js').status_code, 404)


if __name__ == '__main__':
    unittest.main()
