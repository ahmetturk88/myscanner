"""url-evidence-v11: new, unlisted scam sites are caught by their combined signs.

Regression cases from real reports: txaat.buzz (a Somali "$50 for everyone"
prize scam on no threat list, rated "Looks safe" by v10) and ty.gl
(Trendyol's own short-link domain, which must stay clean).
"""
import copy
import unittest

from services.url_assessment import assess_url
from services.url_report_view import plain_report


def reports(url='https://txaat.buzz/rKMeEHV/so-en?1025&s=wa', **provider_extra):
    provider = {'verdict': 'harmless', 'trust_score': 100, 'phishing': {'in_database': False, 'verified': False, 'valid': False}}
    provider.update(provider_extra)
    local = {'urlvet': copy.deepcopy(provider), 'structure': {'is_https': True}, 'ssl': {'valid': True},
             'security_headers': {'score': 100}, 'phishing': {'risk_score': 0}}
    deep = {'urlvet': copy.deepcopy(provider), 'structure': {'is_https': True}, 'ssl': {'valid': True},
            'page_content': {'title': 'Page', 'content_risk_score': 0, 'status_code': 200, 'visible_text_length': 900, 'scam_signals': []},
            'behavior': {'behavior_risk_score': 0, 'original_url': url, 'final_url': url}, 'osint': {'urlhaus_status': 'not_found'},
            'whois': {'age_days': 270}}
    return local, deep


THROWAWAY = dict(verdict='suspicious', rank=0, tld_info={'tld': 'buzz', 'is_risky': True}, domain_info={'age_days': 270})


class ThrowawayScamTests(unittest.TestCase):
    def test_prize_scam_page_is_high_risk(self):
        local, deep = reports(**THROWAWAY)
        deep['page_content']['scam_signals'] = ['prize_offer', 'fake_comments']
        result = assess_url(local, deep)
        self.assertEqual(result['verdict'], 'high_risk')
        self.assertIn('scam_content', [r['code'] for r in result['reasons']])
        self.assertFalse(result['provider_note'])
        plain = plain_report(result, local, deep, deep['behavior']['final_url'])
        self.assertEqual(plain['tone'], 'danger')
        self.assertIn('It promises free money or prizes', [r['title'] for r in plain['reasons']])

    def test_page_hidden_from_the_scanner_is_not_called_safe(self):
        # The scam answered our scanner with a fake 404 (cloaking).
        local, deep = reports(**THROWAWAY)
        deep['page_content'].update(status_code=404, visible_text_length=30, title='')
        result = assess_url(local, deep)
        self.assertEqual(result['verdict'], 'high_risk')
        plain = plain_report(result, local, deep, deep['behavior']['final_url'])
        page = next(c for c in plain['checks'] if c['name'] == 'Page content')
        self.assertEqual((page['state'], page['result']), ('warn', 'Hidden from us'))

    def test_small_new_honest_site_stays_clean(self):
        local, deep = reports('https://new-bakery.com/menu', rank=0, tld_info={'tld': 'com', 'is_risky': False}, domain_info={'age_days': 90})
        self.assertEqual(assess_url(local, deep)['verdict'], 'harmless')

    def test_age_and_traffic_alone_never_flag(self):
        local, deep = reports('https://new-bakery.com/', verdict='suspicious', rank=0, tld_info={'is_risky': False}, domain_info={'age_days': 90})
        self.assertEqual(assess_url(local, deep)['verdict'], 'harmless')

    def test_established_short_link_domain_stays_clean(self):
        # ty.gl: Trendyol's short links; an old domain with several redirects.
        local, deep = reports('https://ty.gl/pg97170kox1ft', rank=0, domain_info={'age_days': 8 * 365})
        deep['whois']['age_days'] = 8 * 365
        deep['page_content'].update(status_code=404, visible_text_length=20)
        self.assertEqual(assess_url(local, deep)['verdict'], 'harmless')

    def test_risky_new_unranked_site_needs_care(self):
        local, deep = reports('https://shop-deals.xyz/', rank=0, tld_info={'tld': 'xyz', 'is_risky': True}, domain_info={'age_days': 40})
        self.assertEqual(assess_url(local, deep)['verdict'], 'suspicious')

    def test_phone_form_alone_is_not_a_scam(self):
        local, deep = reports('https://kargo-takip.com/sorgu', rank=0, domain_info={'age_days': 90})
        deep['page_content']['scam_signals'] = ['collects_phone_or_card']
        self.assertEqual(assess_url(local, deep)['verdict'], 'harmless')


if __name__ == '__main__':
    unittest.main()
