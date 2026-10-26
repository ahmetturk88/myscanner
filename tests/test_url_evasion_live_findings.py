"""Regressions from the first live --evasion run on the server (url-evidence-v12)."""
import unittest

from services.url_assessment import assess_url
from test_url_redirect_destination import PROVIDER, evidence, scam_destination
from test_url_downloads import file_page


class LiveFindingTests(unittest.TestCase):
    def test_app_store_page_showing_another_brand_is_clean(self):
        # play.google.com/store/apps/details?id=com.whatsapp: url.vet saw the WhatsApp brand on a Google domain.
        local, deep = evidence('https://play.google.com/store/apps/details?id=com.whatsapp', age=10000, rank=1)
        for data in (local, deep):
            data['urlvet'].update(verdict='suspicious', content={'brand_mismatch': True, 'brand_found': 'WhatsApp'})
        result = assess_url(local, deep)
        self.assertEqual(result['verdict'], 'harmless')
        self.assertNotIn('brand_mismatch', [r['code'] for r in result['reasons']])

    def test_brand_on_a_new_site_still_counts(self):
        local, deep = evidence('https://whatsapp-gold.xyz/indir', age=20, rank=0)
        for data in (local, deep):
            data['urlvet'].update(verdict='suspicious', content={'brand_mismatch': True, 'brand_found': 'WhatsApp'})
        self.assertIn('brand_mismatch', [r['code'] for r in assess_url(local, deep)['reasons']])
        self.assertNotEqual(assess_url(local, deep)['verdict'], 'harmless')

    def test_program_from_an_established_site_via_its_download_server(self):
        # github.com releases redirect to a download server whose age url.vet could not read.
        program = file_page('Git-2.47.0-64-bit.exe', 'application/octet-stream', {'status': 'clean'}, program=True)
        server = dict(scam_destination('https://release-assets.githubusercontent.com/github-production-release-asset/1/x'),
                      urlvet=dict(PROVIDER, errors=['whois_lookup: timeout']), whois={'error': 'unavailable'})
        local, deep = evidence('https://github.com/git-for-windows/git/releases/download/v2.47.0.windows.1/Git-2.47.0-64-bit.exe',
                               final=server['url'], destination=server, page=program)
        self.assertEqual(assess_url(local, deep)['verdict'], 'harmless')

    def test_our_own_whois_covers_a_url_vet_whois_gap(self):
        local, deep = evidence('https://httpbingo.org/redirect-to?url=https%3A%2F%2Fwww.wikipedia.org%2F', age=3000, rank=0)
        for data in (local, deep):
            data['urlvet']['errors'] = ['whois_lookup: timeout']
        result = assess_url(local, deep)
        self.assertNotIn('URLVet domain registration (WHOIS) check unavailable', result['missing_checks'])
        self.assertEqual(result['verdict'], 'harmless')

    def test_endless_redirects_need_care_even_on_an_old_site(self):
        local, deep = evidence('https://httpbingo.org/redirect/12', age=3000, rank=50000,
                               behavior={'too_many_redirects': True, 'error': 'Too many redirects'})
        self.assertEqual(assess_url(local, deep)['verdict'], 'suspicious')


if __name__ == '__main__':
    unittest.main()
