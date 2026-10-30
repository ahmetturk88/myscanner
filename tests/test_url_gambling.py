"""Casino and betting sites: unlicensed betting is illegal in Turkey and often never pays out."""
import copy
import unittest

from services.report_i18n import translate_plain
from services.scam_content import gambling_site
from services.url_assessment import assess_url
from services.url_report_view import plain_report


def scan(url, title, text, rank=0, age=3000):
    provider = {'verdict': 'harmless', 'trust_score': 100, 'rank': rank, 'domain_info': {'age_days': age},
                'phishing': {'in_database': False, 'verified': False, 'valid': False}}
    page = {'title': title, 'content_risk_score': 0, 'status_code': 200, 'visible_text_length': 900,
            'scam_signals': ['gambling'] if gambling_site(f'{title} {text}', url) else []}
    local = {'url': url, 'urlvet': copy.deepcopy(provider), 'structure': {'is_https': True}, 'ssl': {'valid': True},
             'security_headers': {'score': 100}, 'phishing': {'risk_score': 0}}
    deep = {'url': url, 'urlvet': copy.deepcopy(provider), 'structure': {'is_https': True}, 'ssl': {'valid': True},
            'page_content': page, 'behavior': {'behavior_risk_score': 0, 'original_url': url, 'final_url': url},
            'osint': {'urlhaus_status': 'not_found'}, 'whois': {'age_days': age}}
    result = assess_url(local, deep)
    return result, plain_report(result, local, deep, url)


class GamblingTests(unittest.TestCase):
    def test_casino_and_betting_pages(self):
        cases = [('https://hbhdyw.com/egame/185', 'GK Slots', 'Please enter the game name. Newest. All Games.'),  # live, from a phishing feed
                 ('https://giris-bet123.com/', 'Canlı Casino', 'Deneme bonusu 500 TL, Sweet Bonanza, free spin'),
                 ('https://m.365bet447.com/eng/home/index', '365bet', '体育投注 真人视讯 彩票')]
        for url, title, text in cases:
            result, plain = scan(url, title, text)
            self.assertEqual(result['verdict'], 'harmless', url)
            category = next(r for r in result['reasons'] if r['code'] == 'gambling_site')
            self.assertEqual(category['deduction'], 0)
        self.assertIn('An online gambling site', [r['title'] for r in plain['reasons']])
        turkish = translate_plain(plain, 'tr')
        self.assertIn('Çevrim içi kumar sitesi', [r['title'] for r in turkish['reasons']])
        self.assertIn('Kumar sitesi', [c['result'] for c in turkish['checks']])

    def test_the_live_page_text_after_a_redirect_home(self):
        # Live: hbhdyw.com/egame/185 ends at the home page; the phone sees "bet365 … GK Slots … All Games".
        from services.url_analyzer import apply_rendered_text
        text = 'bet365\nLogin\nRegister\ndaily check-in\nGK Slots\nNewest\nAll Games\nKing of Glory\nPUBG'
        page = {'visible_text_length': 417, 'scam_signals': ['collects_phone_or_card']}
        apply_rendered_text(page, 'https://hbhdyw.com/', text, start_url='https://hbhdyw.com/egame/185')
        self.assertIn('gambling', page['scam_signals'])
        self.assertTrue(gambling_site('Casibom giriş - deneme bonusu', 'https://casibom1234.com/'))
        self.assertFalse(gambling_site('Yasa dışı bahis: Casibom sitesine erişim engeli, casino reklamları',
                                       'https://www.haber.example/gundem/x'))

    def test_betting_affiliate_links_and_brand_pages(self):
        from services.url_analyzer import apply_rendered_text
        # reffpa.com: 1xBet's partner link. Turkish providers block it; our server saw 1xBet's geo-block page.
        link = 'https://reffpa.com/L?tag=d_5543531m_97c_&site=5543531&ad=97&r=registration'
        self.assertTrue(gambling_site('', link))
        self.assertTrue(gambling_site('Welcome', 'https://refpa4293501.top/L?tag=d_1m_2c_'))
        page = {'visible_text_length': 30, 'scam_signals': []}
        apply_rendered_text(page, 'https://1xbet.com/tr', '1XBET\nErişim reddedildi!', start_url=link)
        self.assertIn('gambling', page['scam_signals'])
        self.assertTrue(gambling_site('Giriş', 'https://1xbet-giris7.com/'))
        for url in ('https://onwindows.com/', 'https://pinupgirls.com/', 'https://www.reference.com/', 'https://mybet365tips.blog/'):
            self.assertFalse(gambling_site('Ana sayfa', url), url)

    def test_news_licensed_betting_and_top_sites_are_not_flagged(self):
        self.assertFalse(gambling_site('Yasa dışı bahis operasyonu: 50 gözaltı. Bahis siteleri kapatıldı.',
                                       'https://www.hurriyet.com.tr/gundem/yasa-disi-bahis-operasyonu'))
        self.assertFalse(gambling_site('Las Vegas trip: we visited a casino.', 'https://travelblog.example/vegas'))
        self.assertFalse(gambling_site('iddaa, canlı bahis, poker, casino', 'https://www.nesine.com/'))
        result, _ = scan('https://bignews.example/sports', 'Casino slot poker news', 'casino slot poker', rank=900)
        self.assertNotIn('gambling_site', [r['code'] for r in result['reasons']])
        self.assertEqual(result['verdict'], 'harmless')


if __name__ == '__main__':
    unittest.main()
