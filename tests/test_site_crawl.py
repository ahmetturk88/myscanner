"""site-crawl-v1: the website check walks the site's own pages and checks what they link to and offer."""
import unittest
from unittest.mock import patch

import requests

from services import site_crawl
from services.safe_http import pasted_url
from services.simple_report_view import plain_web_report
from services.report_i18n import translate_plain

HOME = b'''<html><title>Super Indirim Magaza</title><body>
<a href="/urunler">Urunler</a> <a href="/wp-content/plugins/kit/login.html">Giris</a>
<a href="https://garanti-bbva-giris.xyz/">Banka</a> <a href="https://evil-listed.example/x">Firsat</a>
<a href="https://reffpa.com/L?tag=d_1m_2c_">Bonus</a> <a href="/app/Kargo.apk">Uygulama</a>
<a href="https://wa.me/905550000000">WhatsApp</a>
<p>Sepete ekle 1.299 TL Sepete ekle 899 TL Sepete ekle 499 TL %80 indirim %75 indirim. Havale / EFT ile odeme.</p></body></html>'''
PAGES = {
    'https://shop.example/': HOME,
    'https://shop.example/urunler': b'<html><title>Urunler</title><p>Sepete ekle 199 TL</p><a href="/">Ana sayfa</a></html>',
    'https://shop.example/wp-content/plugins/kit/login.html': b'<html><form><input type="password" name="sifre"></form></html>',
}


def response(url):
    r = requests.Response(); r.url = url
    if url in PAGES:
        r.status_code = 200; r._content = PAGES[url]; r.headers['Content-Type'] = 'text/html'
    else:
        r.status_code = 404; r._content = b''; r.headers['Content-Type'] = 'text/plain'
    r._content_consumed = True
    return r


def fake_chain(session, url, deadline):
    return response(url), [{'url': url, 'status_code': 200}], None


def lookup(url):
    return {'status': 'matched', 'threat_types': ['SOCIAL_ENGINEERING']} if 'evil-listed' in url else {'status': 'not_found', 'threat_types': []}


def walk():
    with patch('services.web_assessment.response_chain', side_effect=fake_chain):
        return site_crawl.crawl('https://shop.example/', pause=0)


class CrawlTests(unittest.TestCase):
    def test_walks_its_own_pages_and_collects_what_they_link_to(self):
        found = walk()
        self.assertEqual(found['pages_read'], 3)
        self.assertEqual(set(found['external']), {'garanti-bbva-giris.xyz', 'evil-listed.example', 'reffpa.com'})
        self.assertEqual([d['extension'] for d in found['downloads']], ['apk'])
        self.assertEqual(found['contacts']['whatsapp_links'], 1)

    def test_findings_and_fake_shop_signs(self):
        found = walk()
        with patch('services.site_crawl._download', return_value={'status': 'found', 'kind': 'malware', 'signature': 'Android.Banker'}) as download:
            evidence, findings = site_crawl.assess(found, age_days=10, lookup=lookup)
        download.assert_called_once()
        self.assertEqual(download.call_args[0][0], 'https://shop.example/app/Kargo.apk')
        codes = {f['code'] for f in findings}
        self.assertTrue({'crawl_link_listed', 'crawl_lookalike_links', 'crawl_betting_links', 'crawl_hidden_login',
                         'crawl_malware_download', 'fake_shop_signs'} <= codes, codes)
        self.assertEqual(evidence['listed_links'][0]['host'], 'evil-listed.example')
        self.assertTrue(evidence['shop']['bank_transfer_only'])
        self.assertIn('etbis', evidence['shop']['missing'])

    def test_a_plain_company_site_raises_nothing(self):
        PAGES_PLAIN = {'https://firma.example/': b'<html><title>Firma</title><p>Hakkimizda. Iletisim: 0212 555 44 33</p><a href="/hakkimizda">x</a></html>',
                       'https://firma.example/hakkimizda': b'<html><p>1998den beri</p></html>'}
        def chain(session, url, deadline):
            r = requests.Response(); r.url = url; r._content_consumed = True
            r.status_code, r._content = (200, PAGES_PLAIN[url]) if url in PAGES_PLAIN else (404, b'')
            r.headers['Content-Type'] = 'text/html'
            return r, [{'url': url, 'status_code': r.status_code}], None
        with patch('services.web_assessment.response_chain', side_effect=chain):
            found = site_crawl.crawl('https://firma.example/', pause=0)
        evidence, findings = site_crawl.assess(found, age_days=9000, lookup=lookup)
        self.assertEqual(findings, [])
        self.assertIsNone(evidence['shop'])

    def test_one_visit_per_path(self):
        pages = {'https://ara.example/': b'<html><a href="/sr?wb=1,2,3">a</a><a href="/sr?wc=4,5,6">b</a><a href="/sr?x=9">c</a></html>',
                 'https://ara.example/sr?wb=1,2,3': b'<html><p>Sonuclar</p></html>'}
        def chain(session, url, deadline):
            r = requests.Response(); r.url = url; r._content_consumed = True
            r.status_code, r._content = (200, pages[url]) if url in pages else (404, b'')
            r.headers['Content-Type'] = 'text/html'
            return r, [{'url': url, 'status_code': r.status_code}], None
        with patch('services.web_assessment.response_chain', side_effect=chain):
            found = site_crawl.crawl('https://ara.example/', pause=0)
        self.assertEqual([p['url'] for p in found['pages']], ['https://ara.example/', 'https://ara.example/sr?wb=1,2,3'])

    def test_robots_txt_is_honoured(self):
        pages = dict(PAGES, **{'https://shop.example/robots.txt': b'User-agent: *\nDisallow: /urunler\n'})
        def chain(session, url, deadline):
            r = response(url)
            if url.endswith('robots.txt'):
                r.status_code, r._content = 200, pages[url]; r.headers['Content-Type'] = 'text/plain'
            return r, [{'url': url, 'status_code': r.status_code}], None
        with patch('services.web_assessment.response_chain', side_effect=chain):
            found = site_crawl.crawl('https://shop.example/', pause=0)
        self.assertNotIn('https://shop.example/urunler', [p['url'] for p in found['pages']])
        self.assertEqual(found['skipped_by_robots'], 1)

    def test_report_shows_the_walk_in_turkish(self):
        with patch('services.site_crawl._download', return_value={'status': 'clean'}):
            evidence, findings = site_crawl.assess(walk(), age_days=10, lookup=lookup)
        result = {'url': 'https://shop.example/', 'verdict': 'suspicious', 'assessment_status': 'completed', 'tls': {'status': 'completed'},
                  'http': {'chain': [{'url': 'https://shop.example/'}], 'final_url': 'https://shop.example/'}, 'provider': {'status': 'not_requested'},
                  'content': {'status': 'completed'}, 'findings': findings, 'crawl': evidence, 'trust': {'web_risk': {'status': 'not_found'}}}
        plain = plain_web_report(result, source='site')
        rows = {c['name']: (c['state'], c['result']) for c in plain['checks']}
        self.assertEqual(rows['Pages read'], ('ok', '3'))
        self.assertEqual(rows['Links to other sites'], ('bad', 'Dangerous'))
        self.assertEqual(rows['Online shop'], ('warn', 'Fake shop signs'))
        turkish = translate_plain(plain, 'tr')
        titles = [r['title'] for r in turkish['reasons']]
        self.assertIn('Tehlikeli sitelere bağlantı veriyor', titles)
        self.assertNotIn('It links to dangerous sites', titles)


class ShopDetectionTests(unittest.TestCase):
    def test_product_data_marks_a_shop_whose_prices_are_drawn_by_scripts(self):
        self.assertIsNone(site_crawl.shop_signals('Willkommen', {}))
        shop = site_crawl.shop_signals('Willkommen', {}, age_days=6000, schema_pages=2)
        self.assertIsNotNone(shop)
        self.assertFalse(shop['fake_signs'])
        self.assertTrue(site_crawl.SHOP_SCHEMA.search('{"@context":"https://schema.org","@type": "Product","name":"x"}'))

    def test_the_turkish_page_is_requested(self):
        self.assertTrue(site_crawl.ACCEPT_LANGUAGE.startswith('tr-TR'))


class ForeignVersionTests(unittest.TestCase):
    def test_another_countrys_pages_are_noted_and_the_shop_is_not_judged(self):
        pages = {'https://magaza.example/': b'<html lang="de-DE"><title>Shop</title><p>In den Warenkorb 19,99 EUR In den Warenkorb 9,99 EUR Warenkorb</p></html>'}
        def chain(session, url, deadline):
            r = requests.Response(); r.url = url; r._content_consumed = True
            r.status_code, r._content = (200, pages[url]) if url in pages else (404, b'')
            r.headers['Content-Type'] = 'text/html'
            return r, [{'url': url, 'status_code': r.status_code}], None
        with patch('services.web_assessment.response_chain', side_effect=chain):
            found = site_crawl.crawl('https://magaza.example/', pause=0)
        self.assertEqual(found['language'], 'de')
        evidence, findings = site_crawl.assess(found, age_days=9000, lookup=lookup)
        self.assertEqual(evidence['shop'], {'language': 'de', 'not_judged': True})
        self.assertEqual([f['code'] for f in findings], ['crawl_foreign_version'])
        self.assertIn('German pages', findings[0]['detail'])
        result = {'url': 'https://magaza.example/', 'verdict': 'clean', 'assessment_status': 'completed', 'tls': {'status': 'completed'},
                  'http': {'chain': [{'url': 'https://magaza.example/'}], 'final_url': 'https://magaza.example/'}, 'provider': {'status': 'not_requested'},
                  'content': {'status': 'completed'}, 'findings': findings, 'crawl': evidence, 'trust': {'web_risk': {'status': 'not_found'}}}
        plain = plain_web_report(result, source='site')
        self.assertIn(('Online shop', 'na', 'Foreign version'), [(c['name'], c['state'], c['result']) for c in plain['checks']])
        self.assertIn('Almanca sayfalarını', ' '.join(r['detail'] for r in translate_plain(plain, 'tr')['reasons']))


class PastedAddressTests(unittest.TestCase):
    def test_markdown_debris_is_removed(self):
        self.assertEqual(pasted_url('http://testphp.vulnweb.com/](http://testphp.vulnweb.com'), 'http://testphp.vulnweb.com/')
        self.assertEqual(pasted_url('[site](https://a.example/x?y=1)'), 'https://a.example/x?y=1')
        self.assertEqual(pasted_url('example.com'), 'example.com')


if __name__ == '__main__':
    unittest.main()
