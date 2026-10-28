"""url-evidence-v12: tricks hidden in the address itself, read the way a browser reads it."""
import copy
import unittest

from services.report_i18n import translate_plain
from services.safe_http import UnsafeTargetError, accept_scan_url
from services.url_assessment import assess_url
from services.url_report_view import plain_report
from services.url_tricks import address_signals, loose_ipv4, unmask


def scan(raw, age=270, rank=0, page=None, desktop=None):
    url, tricks = unmask(raw)
    provider = {'verdict': 'harmless', 'trust_score': 100, 'rank': rank, 'domain_info': {'age_days': age},
                'phishing': {'in_database': False, 'verified': False, 'valid': False}}
    local = {'url': url, 'urlvet': copy.deepcopy(provider), 'structure': {'is_https': True}, 'ssl': {'valid': True},
             'security_headers': {'score': 100}, 'phishing': {'risk_score': 0}}
    if tricks:
        local['address_tricks'] = tricks
    deep = {'url': url, 'urlvet': copy.deepcopy(provider), 'structure': {'is_https': True}, 'ssl': {'valid': True},
            'page_content': page or {'title': 'Page', 'content_risk_score': 0, 'status_code': 200, 'visible_text_length': 900, 'scam_signals': []},
            'behavior': {'behavior_risk_score': 0, 'original_url': url, 'final_url': url, 'desktop_final_url': desktop or url},
            'osint': {'urlhaus_status': 'not_found'}, 'whois': {'age_days': age}}
    result = assess_url(local, deep)
    return result, plain_report(result, local, deep, url)


def codes(url):
    return {s['code']: s['strong'] for s in address_signals(url)}


class UnmaskTests(unittest.TestCase):
    def test_name_before_at_sign_is_removed_and_recorded(self):
        self.assertEqual(unmask('google.com@malicious-site.com/login'),
                         ('https://malicious-site.com/login', [{'code': 'userinfo_trick', 'shown': 'google.com'}]))
        self.assertEqual(unmask('https://medium.com/@someone')[1], [])  # "@" in the path is normal

    def test_ip_written_as_number_hex_or_octal(self):
        for raw in ('http://3627732462/', 'http://0xd83acdee/', 'http://0330.072.0315.0356/', 'http://216.0x3a.52718/'):
            url, tricks = unmask(raw)
            self.assertEqual(url, 'http://216.58.205.238/', raw)
            self.assertEqual(tricks[0]['code'], 'encoded_ip')
        self.assertEqual(unmask('http://216.58.205.238/')[1], [])
        self.assertIsNone(loose_ipv4('1e100.net'))

    def test_private_targets_stay_blocked_after_unmasking(self):
        for raw in ('http://2130706433/', 'http://0x7f.0.0.1/', 'http://user@127.0.0.1/', 'http://%31%32%37.0.0.1/'):
            with self.assertRaises(UnsafeTargetError, msg=raw):
                accept_scan_url(unmask(raw)[0])

    def test_percent_encoded_name(self):
        self.assertEqual(unmask('https://%67oogle-login.com/')[0], 'https://google-login.com/')
        self.assertEqual(unmask('https://example.com/a%20b'), ('https://example.com/a%20b', []))


class AddressSignalTests(unittest.TestCase):
    def test_look_alike_letters(self):
        self.assertTrue(codes('https://xn--pple-43d.com/')['homograph_name'])        # Cyrillic а in "apple"
        self.assertTrue(codes('https://xn--80ak6aa92e.com/')['homograph_name'])      # all-Cyrillic "аррӏе"
        self.assertNotIn('homograph_name', codes('https://xn--trkiye-3ya.com/'))     # türkiye: a real Turkish name
        self.assertEqual(codes('https://xn--trkiye-3ya.com/'), {})

    def test_digit_swaps_and_turkish_letters_copying_a_brand(self):
        self.assertTrue(codes('https://paypa1.com/')['lookalike_name'])
        self.assertTrue(codes('https://' + 'garantı.com'.encode('idna').decode() + '/')['lookalike_name'])
        self.assertFalse(codes('https://hepsiburda.com/')['lookalike_name'])          # one letter off: a weak sign

    def test_brand_address_used_as_a_decoy(self):
        for url in ('https://garanti.com.tr.giris-dogrula.com/', 'https://paypal.com-secure.xyz/',
                    'https://login.turkiye.gov.tr.odeme-iade.net/'):
            self.assertTrue(codes(url)['brand_in_subdomain'], url)
        self.assertEqual(address_signals('https://garanti.com.tr.giris-dogrula.com/')[0]['real'], 'giris-dogrula.com')

    def test_brand_names_in_addresses_they_do_not_own(self):
        for url, brand in (('https://ptt-kargo-odeme.com/', 'pttkargo'), ('https://e-devlet-giris.net/', 'edevlet'),
                           ('https://yurticikargo-takip.info/', 'yurticikargo'), ('https://secure-paypal-login.web.app/', 'paypal')):
            found = [s for s in address_signals(url) if s['code'] == 'brand_in_name']
            self.assertEqual(found[0]['brand'], brand, url)

    def test_real_sites_have_no_signals(self):
        for url in ('https://www.garantibbva.com.tr/', 'https://akbank.com/', 'https://www.turkiye.gov.tr/', 'https://ty.gl/abc',
                    'https://www.trendyol.com/', 'https://amazon.de/', 'https://pineapple.com/', 'https://offices.com/',
                    'https://www.n11.com/', 'https://accounts.google.com/', 'https://new-bakery.com/'):
            self.assertEqual(address_signals(url), [], url)


class VerdictTests(unittest.TestCase):
    def test_every_trick_is_high_risk(self):
        for raw in ('google.com@evil-site.com/login', 'http://3627732462/', 'https://%67oogle-login.com/',
                    'https://xn--pple-43d.com/', 'https://garanti.com.tr.giris-dogrula.com/'):
            self.assertEqual(scan(raw)[0]['verdict'], 'high_risk', raw)

    def test_tricks_count_even_on_an_old_domain(self):
        self.assertEqual(scan('https://paypa1.com/', age=4000, rank=900)[0]['verdict'], 'high_risk')

    def test_brand_name_needs_more_signs(self):
        self.assertEqual(scan('https://ptt-kargo-odeme.com/x')[0]['verdict'], 'suspicious')
        card = {'title': 'Ödeme', 'content_risk_score': 0, 'status_code': 200, 'visible_text_length': 900, 'scam_signals': ['collects_phone_or_card']}
        self.assertEqual(scan('https://ptt-kargo-odeme.com/x', page=card)[0]['verdict'], 'high_risk')
        # The free host is old and famous; the page on it is not.
        self.assertEqual(scan('https://secure-paypal-login.web.app/', age=4000, rank=500)[0]['verdict'], 'high_risk')
        self.assertEqual(scan('https://apple.stackexchange.com/', age=6000, rank=300)[0]['verdict'], 'harmless')
        self.assertEqual(scan('https://apple.stackexchange.com/', age=6000, rank=300)[0]['reasons'], [])

    def test_report_names_the_trick_in_both_languages(self):
        cases = {
            'google.com@evil-site.com/login': ('The link shows “google.com”, but it really opens evil-site.com.',
                                               'Bağlantı “google.com” gösteriyor ama gerçekte evil-site.com adresini açıyor.'),
            'http://3627732462/': ('“3627732462” is a disguised way of writing the IP address 216.58.205.238.',
                                   '“3627732462”, 216.58.205.238 IP adresinin gizlenmiş bir yazımı.'),
            'https://xn--pple-43d.com/': ('It is made to look like apple.com', 'apple.com gibi görünmesi için yapılmış'),
            'https://garanti.com.tr.giris-dogrula.com/': ('starts with garanti.com.tr to look official, but the site it opens is giris-dogrula.com',
                                                          'Bağlantı resmi görünmek için garanti.com.tr ile başlıyor ama açtığı site giris-dogrula.com.'),
            'https://paypa1.com/': ('copies PayPal with swapped letters', 'harfleri ya da rakamları değiştirerek PayPal adını kopyalıyor'),
        }
        for raw, (english, turkish) in cases.items():
            plain = scan(raw)[1]
            self.assertEqual(plain['tone'], 'danger', raw)
            self.assertIn(english, plain['reasons'][0]['detail'], raw)
            self.assertIn(turkish, translate_plain(plain, 'tr')['reasons'][0]['detail'], raw)
            self.assertIn('bad', [c['state'] for c in plain['checks']], raw)


class LiveFeedPatternTests(unittest.TestCase):
    """Patterns from 300 live phishing links that passed unflagged (url-evidence-v12)."""

    def test_cargo_or_bank_name_on_a_new_cheap_site(self):
        for url in ('https://mydpd.kslud.top/track-ch/', 'https://sbb-info.sbs/templates/cs', 'https://fedex.jfhzjs.shop/query'):
            self.assertEqual(scan(url, age=20)[0]['verdict'], 'high_risk', url)
        self.assertEqual(scan('https://fedex.jfhzjs.shop/query', age=None)[0]['verdict'], 'high_risk')
        self.assertEqual(scan('https://dkb.customersales.de/impressum.html', age=900)[0]['verdict'], 'suspicious')
        self.assertEqual(scan('https://ptt-kargo-odeme.com/x')[0]['verdict'], 'suspicious')

    def test_phones_and_computers_sent_to_different_sites(self):
        result, plain = scan('https://bitly.cx/Eo1PM/', age=4000, desktop='https://www.wikipedia.org/')
        self.assertEqual(result['verdict'], 'suspicious')
        self.assertEqual(scan('https://example.com/app', age=4000, desktop='https://example.com/')[0]['verdict'], 'harmless')

    def test_sign_in_path_on_a_new_or_cheap_site(self):
        for url in ('https://akctualisirens79.site/success-login/neues26a2sui55ss/', 'https://matelcc73.sbs/verify/94d2be02'):
            result, plain = scan(url, age=10)
            self.assertEqual(result['verdict'], 'suspicious', url)
            self.assertIn('login_path', [r['code'] for r in result['reasons']])
        self.assertEqual(scan('https://matelcc73.sbs/verify/94d2be02', age=4000, rank=900)[0]['verdict'], 'harmless')
        self.assertNotIn('login_path', [r['code'] for r in scan('https://new-bakery.com/login', age=10)[0]['reasons']])
        login = {'title': 'Sign in', 'content_risk_score': 0, 'status_code': 200, 'visible_text_length': 900, 'scam_signals': [],
                 'has_password_field': True}
        self.assertEqual(scan('https://matelcc73.sbs/verify/94d2be02', age=10, page=login)[0]['verdict'], 'high_risk')

    def test_free_host_page_titled_with_a_brand(self):
        page = {'title': 'WhatsApp Web', 'content_risk_score': 0, 'status_code': 200, 'visible_text_length': 900, 'scam_signals': []}
        result, plain = scan('https://mishab-dev.github.io/chat', age=4000, rank=10, page=page)
        self.assertEqual(result['verdict'], 'suspicious')
        self.assertEqual(plain['tone'], 'caution')
        self.assertIn('Sayfa kendini', str(translate_plain(plain, 'tr')))
        page['has_password_field'] = True
        self.assertEqual(scan('https://mishab-dev.github.io/chat', age=4000, rank=10, page=page)[0]['verdict'], 'high_risk')
        page = dict(page, title='WhatsApp Web', has_password_field=False)
        self.assertEqual(scan('https://www.whatsapp.com/', age=4000, rank=10, page=page)[0]['verdict'], 'harmless')

    def test_whf_bz_is_free_hosting(self):
        self.assertIn('free_hosting', codes('https://statensveagvesenno.whf.bz/eika/'))


class RequestTests(unittest.TestCase):
    def test_the_scan_request_carries_the_tricks_to_the_worker(self):
        import test_task_ownership  # noqa: F401  (sets up the test database)
        from unittest.mock import patch
        from flask_login import login_user
        from extensions import db
        from models import User
        from services import url_scan_request
        app = test_task_ownership._import_production_app()[1].app
        sent = {}
        with app.app_context():
            db.create_all()
            user = User.query.filter_by(email='tricks@example.com').first()
            if user is None:
                user = User(username='tricks', email='tricks@example.com')
                user.set_password('a-long-test-password')
                db.session.add(user)
                db.session.commit()
            with app.test_request_context(), \
                    patch('services.url_scan_storage.enqueue_url_scan',
                          side_effect=lambda task, url, uid, tricks=None: sent.update(url=url, tricks=tricks) or 1), \
                    patch('celery_app.require_broker'), patch('services.url_scan_request.reserve_request_quota', return_value=None):
                login_user(user)
                url_scan_request.queue_url_scan('google.com@evil-site.com/login')
        self.assertEqual(sent, {'url': 'https://evil-site.com/login', 'tricks': [{'code': 'userinfo_trick', 'shown': 'google.com'}]})


if __name__ == '__main__':
    unittest.main()
