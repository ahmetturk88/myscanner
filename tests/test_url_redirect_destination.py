"""url-evidence-v12: a link is judged by where it really ends, on phones and on computers."""
import copy
import unittest
from unittest.mock import patch

from services.report_i18n import translate_plain
from services.url_analyzer import URLDeepAnalyzer, page_redirect
from services.url_assessment import assess_url
from services.url_report_view import plain_report

PROVIDER = {'verdict': 'harmless', 'trust_score': 100, 'phishing': {'in_database': False, 'verified': False, 'valid': False}}


def evidence(url, final=None, age=6000, rank=100, destination=None, page=None, behavior=None):
    provider = dict(PROVIDER, rank=rank, domain_info={'age_days': age})
    local = {'url': url, 'urlvet': copy.deepcopy(provider), 'structure': {'is_https': True}, 'ssl': {'valid': True},
             'security_headers': {'score': 100}, 'phishing': {'risk_score': 0}}
    deep = {'url': url, 'urlvet': copy.deepcopy(provider), 'structure': {'is_https': True}, 'ssl': {'valid': True},
            'page_content': page or {'title': 'Page', 'content_risk_score': 0, 'status_code': 200, 'visible_text_length': 900, 'scam_signals': []},
            'behavior': dict({'behavior_risk_score': 0, 'original_url': url, 'final_url': final or url, 'error': None}, **(behavior or {})),
            'osint': {'urlhaus_status': 'not_found'}, 'whois': {'age_days': age}}
    if destination:
        deep['destination'] = destination
    return local, deep


def scam_destination(url='https://win-cash.buzz/gift?id=7', **extra):
    provider = dict(PROVIDER, verdict='suspicious', rank=0, tld_info={'tld': 'buzz', 'is_risky': True}, domain_info={'age_days': 30})
    return dict({'url': url, 'urlvet': provider, 'structure': {'is_https': True}, 'ssl': {'valid': True},
                 'phishing': {'risk_score': 0}, 'osint': {'urlhaus_status': 'not_found'}, 'whois': {'age_days': 30}}, **extra)


class DestinationTests(unittest.TestCase):
    def test_short_link_to_a_new_scam_site_is_judged_by_the_scam_site(self):
        prize = {'title': 'Tebrikler', 'content_risk_score': 0, 'status_code': 200, 'visible_text_length': 900, 'scam_signals': ['prize_offer']}
        local, deep = evidence('https://bit.ly/3xYz', final='https://win-cash.buzz/gift?id=7', destination=scam_destination(), page=prize,
                               behavior={'is_shortened': True})
        result = assess_url(local, deep)
        self.assertEqual(result['verdict'], 'high_risk')
        self.assertEqual(result['destination'], {'url': 'https://win-cash.buzz/gift?id=7', 'verdict': 'high_risk'})
        plain = plain_report(result, local, deep, local['url'])
        details = ' '.join(r['detail'] for r in plain['reasons'])
        self.assertIn('It promises free money or prizes', [r['title'] for r in plain['reasons']])
        self.assertIn('Redirects', [c['name'] for c in plain['checks'] if c['result'] == 'To another site'])
        turkish = translate_plain(plain, 'tr')
        self.assertNotIn('different site', ' '.join(r['detail'] for r in turkish['reasons']))
        self.assertTrue(details)

    def test_listed_destination_makes_the_link_malicious(self):
        listed = scam_destination(osint={'urlhaus': True, 'urlhaus_status': 'matched'})
        local, deep = evidence('https://tinyurl.com/abc', final=listed['url'], destination=listed)
        self.assertEqual(assess_url(local, deep)['verdict'], 'malicious')

    def test_short_link_to_a_normal_site_stays_clean(self):
        fine = dict(scam_destination('https://www.trendyol.com/kampanya'), urlvet=dict(PROVIDER, rank=40, domain_info={'age_days': 5000}),
                    whois={'age_days': 5000})
        local, deep = evidence('https://bit.ly/3abc', final=fine['url'], destination=fine)
        result = assess_url(local, deep)
        self.assertEqual(result['verdict'], 'harmless')
        self.assertEqual(result['destination']['url'], 'https://www.trendyol.com/kampanya')

    def test_trick_in_the_destination_address_counts(self):
        fake = dict(scam_destination('https://garanti.com.tr.hesap-onay.com/'), urlvet=dict(PROVIDER), whois={'age_days': 400})
        local, deep = evidence('https://t.co/xyz', final=fake['url'], destination=fake)
        self.assertEqual(assess_url(local, deep)['verdict'], 'high_risk')


class RedirectSignalTests(unittest.TestCase):
    def test_phone_and_computer_sent_to_different_sites(self):
        local, deep = evidence('https://kargo-takip.xyz/p/9', age=60, rank=0,
                               behavior={'desktop_final_url': 'https://www.google.com/'})
        for data in (local, deep):
            data['urlvet']['tld_info'] = {'is_risky': True}
        result = assess_url(local, deep)
        self.assertIn('device_cloaking', [r['code'] for r in result['reasons']])
        self.assertEqual(result['verdict'], 'high_risk')

    def test_app_download_links_are_not_cloaking(self):
        local, deep = evidence('https://ty.gl/app', final='https://play.google.com/store/apps/details?id=x',
                               behavior={'desktop_final_url': 'https://www.trendyol.com/'})
        self.assertNotIn('device_cloaking', [r['code'] for r in assess_url(local, deep)['reasons']])

    def test_redirect_loop(self):
        local, deep = evidence('https://new-promo.xyz/r', age=40, rank=0, behavior={'too_many_redirects': True, 'error': 'Too many redirects'})
        self.assertIn('redirect_loop', [r['code'] for r in assess_url(local, deep)['reasons']])


class Page:
    def __init__(self, url, html, kind='text/html; charset=utf-8', status=200, history=()):
        self.url, self.status_code, self.history = url, status, list(history)
        self.content = html.encode()
        self.text = html
        self.headers = {'Content-Type': kind}

    def close(self):
        pass


class PageRedirectTests(unittest.TestCase):
    def test_meta_refresh_and_script_redirects(self):
        self.assertEqual(page_redirect(Page('https://a.com/', '<meta http-equiv="refresh" content="0; url=https://b.xyz/x">')),
                         ('https://b.xyz/x', 'meta'))
        self.assertEqual(page_redirect(Page('https://a.com/', '<meta http-equiv=refresh content="2;URL=/next">')), ('https://a.com/next', 'meta'))
        self.assertEqual(page_redirect(Page('https://a.com/', '<script>window.location.href = "https://b.xyz/y";</script>')),
                         ('https://b.xyz/y', 'script'))
        self.assertEqual(page_redirect(Page('https://a.com/', '<script>location.replace("https://b.xyz/z")</script>')), ('https://b.xyz/z', 'script'))
        long_page = '<p>' + 'Real article text. ' * 60 + '</p><script>if(x){location.href="https://b.xyz/"}</script>'
        self.assertIsNone(page_redirect(Page('https://a.com/', long_page)))
        self.assertIsNone(page_redirect(Page('https://a.com/f.pdf', '%PDF', kind='application/pdf')))

    def test_behavior_follows_page_redirects_and_compares_a_desktop_visit(self):
        analyzer = URLDeepAnalyzer()
        pages = {
            'https://bit.ly/x': Page('https://hop.example/', '<meta http-equiv="refresh" content="0;url=https://win-cash.buzz/g">',
                                     history=[Page('https://bit.ly/x', '', status=301)]),
            'https://win-cash.buzz/g': Page('https://win-cash.buzz/g', '<h1>Tebrikler</h1>'),
        }
        def get(url, **kwargs):
            if 'Windows' in (kwargs.get('headers') or {}).get('User-Agent', ''):
                return Page('https://www.google.com/', '')
            return pages[url]
        with patch.object(analyzer.session, 'get', side_effect=get):
            behavior = analyzer.analyze_behavior('https://bit.ly/x')
        self.assertEqual(behavior['final_url'], 'https://win-cash.buzz/g')
        self.assertEqual(behavior['redirect_count'], 2)
        self.assertEqual(behavior['redirect_chain'][-1]['kind'], 'meta')
        self.assertEqual(behavior['desktop_final_url'], 'https://www.google.com/')
        self.assertEqual(analyzer.session.max_redirects, 10)


if __name__ == '__main__':
    unittest.main()
