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


class SecondRunFindingTests(unittest.TestCase):
    """--live 3 --only threat: OpenPhish entries missed with Web Risk off, and URLhaus links on other ports."""

    def test_brand_name_on_a_swapped_ending(self):
        from services.url_tricks import address_signals
        local, deep = evidence('https://www.roblox.rw/games/88738945340571/Would-You-Rather', age=40, rank=0)
        self.assertEqual(assess_url(local, deep)['verdict'], 'high_risk')
        local, deep = evidence('https://migros.ch/', age=9000, rank=3000)   # an old site of the same name elsewhere
        self.assertEqual(assess_url(local, deep)['verdict'], 'harmless')
        self.assertEqual(address_signals('https://www.amazon.de/'), [])
        self.assertEqual(address_signals('https://www.paypal.fr/'), [])

    def test_sign_in_page_named_on_a_free_host(self):
        local, deep = evidence('http://xfinityhelplogin.weebly.com/', age=9000, rank=500)
        self.assertEqual(assess_url(local, deep)['verdict'], 'high_risk')
        local, deep = evidence('https://help-center-docs.github.io/', age=9000, rank=500)   # no brand, still a free-host sign-in name
        self.assertEqual(assess_url(local, deep)['verdict'], 'high_risk')
        local, deep = evidence('https://myname.github.io/blog', age=9000, rank=500)
        self.assertEqual(assess_url(local, deep)['verdict'], 'harmless')

    def test_unknown_short_link_service_that_did_not_redirect_is_not_called_safe(self):
        from services.url_tricks import looks_like_short_link
        self.assertTrue(looks_like_short_link('https://s4w.in/jZlxQ'))
        for url in ('https://n11.com/kampanya', 'https://www.example.com/jZlxQ', 'https://t.me/abc12', 'https://bit.ly/'):
            self.assertFalse(looks_like_short_link(url), url)
        local, deep = evidence('https://s4w.in/jZlxQ', age=3000, rank=0, behavior={'is_shortened': True})
        self.assertEqual(assess_url(local, deep)['verdict'], 'unknown')

    def test_redirect_to_another_port_stops_without_failing(self):
        import requests
        from services.safe_http import PublicHTTPSession
        response = requests.Response()
        response.status_code, response.url = 302, 'https://httpbingo.org/redirect-to'
        response.headers['Location'] = 'http://115.57.254.113:53294/i'
        self.assertIsNone(PublicHTTPSession().get_redirect_target(response))
        self.assertEqual(response.unfollowed_redirect, 'http://115.57.254.113:53294/i')
        response.headers['Location'] = 'market://details?id=x'
        self.assertIsNone(PublicHTTPSession().get_redirect_target(response))
        response.headers['Location'] = '/next'
        self.assertEqual(PublicHTTPSession().get_redirect_target(response), '/next')

    def test_listed_address_behind_a_redirect_to_another_port(self):
        from unittest.mock import patch
        from services.url_analyzer import URLDeepAnalyzer
        from test_url_redirect_destination import Page
        analyzer = URLDeepAnalyzer()
        stop = Page('https://httpbingo.org/redirect-to?url=x', '', status=302)
        stop.unfollowed_redirect = 'http://115.57.254.113:53294/i'
        with patch.object(analyzer.session, 'get', return_value=stop):
            behavior = analyzer.analyze_behavior('https://httpbingo.org/redirect-to?url=x')
        self.assertEqual((behavior['final_url'], behavior['unvisited_destination']), ('http://115.57.254.113:53294/i', True))
        self.assertEqual(behavior['desktop_final_url'], 'http://115.57.254.113:53294/i')
        listed = {'url': 'http://115.57.254.113:53294/i', 'structure': {'is_https': False, 'contains_ip': True},
                  'phishing': {'risk_score': 0}, 'osint': {'urlhaus': True, 'urlhaus_status': 'matched'}, 'whois': {}}
        local, deep = evidence('https://httpbingo.org/redirect-to?url=x', final=listed['url'], destination=listed,
                               behavior={'unvisited_destination': True})
        self.assertEqual(assess_url(local, deep)['verdict'], 'malicious')
        unlisted = dict(listed, osint={'urlhaus_status': 'not_found'})
        local, deep = evidence('https://httpbingo.org/redirect-to?url=x', final=listed['url'], destination=unlisted,
                               behavior={'unvisited_destination': True})
        result = assess_url(local, deep)
        self.assertEqual(result['verdict'], 'suspicious')
        self.assertIn('odd_port_destination', [r['code'] for r in result['reasons']])


class SecondRunReportTests(unittest.TestCase):
    def test_new_reasons_read_well_in_both_languages(self):
        from services.report_i18n import translate_plain
        from services.url_report_view import plain_report
        cases = {
            'https://www.roblox.rw/games/1': ('It uses the Roblox name with a different ending. It is not an official Roblox site.',
                                              'Roblox adını farklı bir uzantıyla kullanıyor. Bu resmi bir Roblox sitesi değil.'),
            'http://xfinityhelplogin.weebly.com/': (None, None),
        }
        for url, (english, turkish) in cases.items():
            local, deep = evidence(url, age=40, rank=0)
            result = assess_url(local, deep)
            plain = plain_report(result, local, deep, url)
            translated = translate_plain(plain, 'tr')
            if english:
                self.assertEqual(plain['reasons'][0]['detail'], english)
                self.assertEqual(translated['reasons'][0]['detail'], turkish)
            for reason, original in zip(translated['reasons'], plain['reasons']):
                self.assertNotEqual(reason['title'], original['title'], original['title'])


class ThirdRunFindingTests(unittest.TestCase):
    def test_listed_address_in_the_middle_of_a_redirect_chain(self):
        # httpbingo → github.com/…/raw/… (listed by URLhaus) → raw.githubusercontent.com/… (not listed).
        local, deep = evidence('https://httpbingo.org/redirect-to?url=x', final='https://raw.githubusercontent.com/a/b/main/x.zip')
        deep['chain_reputation'] = [{'url': 'https://github.com/a/b/raw/refs/heads/main/x.zip', 'status': 'matched', 'matched': True}]
        result = assess_url(local, deep)
        self.assertEqual(result['verdict'], 'malicious')
        from services.url_report_view import plain_report
        plain = plain_report(result, local, deep, local['url'])
        self.assertEqual(plain['reasons'][0]['title'], 'It passes through a malware address')
        self.assertIn(('Threat lists', 'bad'), [(c['name'], c['state']) for c in plain['checks']])

    def test_every_hop_is_looked_up(self):
        from unittest.mock import patch
        from services.url_analyzer import URLDeepAnalyzer
        analyzer = URLDeepAnalyzer()
        behavior = {'original_url': 'https://a.example/', 'final_url': 'https://c.example/end', 'error': None,
                    'redirect_chain': [{'url': 'https://a.example/'}, {'url': 'https://b.example/listed'}, {'url': 'https://c.example/end'}]}
        looked = []
        def urlhaus(url):
            looked.append(url)
            return {'coverage_status': 'matched' if 'listed' in url else 'not_found', 'is_malicious': 'listed' in url}
        empty = lambda *a, **k: {}
        with patch.object(analyzer, 'analyze_behavior', return_value=behavior), patch.object(analyzer, 'check_urlhaus', side_effect=urlhaus), \
                patch.object(analyzer, 'analyze_page_content', side_effect=empty), patch.object(analyzer, 'destination_evidence', side_effect=empty), \
                patch.object(analyzer, 'analyze_whois', side_effect=empty), patch.object(analyzer, 'check_osint_sources', side_effect=empty), \
                patch.object(analyzer, 'check_ssl_certificate', side_effect=empty), patch.object(analyzer, 'check_dns_records', side_effect=empty), \
                patch.object(analyzer, 'check_security_headers', side_effect=empty), patch.object(analyzer, 'analyze_with_urlvet', side_effect=empty), \
                patch('services.url_analyzer.validate_public_url', side_effect=lambda u: type('T', (), {'url': u})()):
            deep = analyzer.comprehensive_deep_analysis('https://a.example/')
        self.assertEqual(looked, ['https://b.example/listed'])
        self.assertEqual(deep['chain_reputation'], [{'url': 'https://b.example/listed', 'status': 'matched', 'matched': True}])


class FourthRunFindingTests(unittest.TestCase):
    def test_country_two_part_endings(self):
        from services.url_tricks import split_host
        self.assertEqual(split_host('robloxc.com.es')[1], 'robloxc.com.es')
        self.assertEqual(split_host('shop.example.org.pl'), (['shop'], 'example.org.pl', False))
        self.assertEqual(split_host('a.b.co')[1], 'b.co')   # .co alone is a normal ending

    def test_short_link_to_a_one_letter_off_brand(self):
        # s4w.in/jZlxQ → robloxc.com.es/users/…/profile (OpenPhish).
        fake = dict(scam_destination('https://robloxc.com.es/users/1901060764/profile'),
                    urlvet=dict(PROVIDER, rank=0), whois={'error': 'unavailable'})
        local, deep = evidence('https://s4w.in/jZlxQ', final=fake['url'], destination=fake, age=3000, rank=0,
                               behavior={'is_shortened': True})
        result = assess_url(local, deep)
        self.assertEqual(result['verdict'], 'high_risk')
        self.assertEqual(result['destination']['url'], 'https://robloxc.com.es/users/1901060764/profile')

    def test_one_letter_off_on_an_old_site_stays_a_note(self):
        local, deep = evidence('https://hepsiburda.com/', age=4000, rank=20000)
        self.assertEqual(assess_url(local, deep)['verdict'], 'harmless')

    def test_redirect_cases_use_a_service_that_follows_outside_redirects(self):
        from scripts import accuracy_check
        self.assertFalse([url for _, url, _ in accuracy_check.EVASION_CASES if 'httpbingo.org/redirect-to' in url])


class BlindRunFindingTests(unittest.TestCase):
    """--live 15 --blind (URLhaus and Web Risk off): links that came out "not sure"."""

    def test_a_switched_off_source_is_not_a_gap(self):
        local, deep = evidence('https://www.bbc.com/', age=10000, rank=100)
        deep['osint'] = {'urlhaus_status': 'unavailable', 'urlhaus_reason': 'disabled_by_operator'}
        result = assess_url(local, deep)
        self.assertEqual(result['verdict'], 'harmless')
        self.assertFalse([m for m in result['missing_checks'] if m.startswith('URLhaus')])

    def test_program_named_in_the_address_counts_when_the_file_was_not_fetched(self):
        # twejamaica.org/PPsEJEgc/SS.ps1: the server didn't answer our page fetch.
        local, deep = evidence('https://twejamaica.org/PPsEJEgc/SS.ps1', age=60, rank=0,
                               page={'error': 'Could not fetch page content'})
        result = assess_url(local, deep)
        self.assertIn('risky_download', [r['code'] for r in result['reasons']])
        self.assertIn(result['verdict'], ('suspicious', 'high_risk'))
        local, deep = evidence('https://cdn.example-shop.com/static/app.js', age=60, rank=0)
        self.assertNotIn('risky_download', [r['code'] for r in assess_url(local, deep)['reasons']])

    def test_free_host_page_hiding_from_the_scanner(self):
        hidden = {'title': '', 'content_risk_score': 0, 'status_code': 404, 'visible_text_length': 9, 'scam_signals': []}
        local, deep = evidence('https://lingering-cloud-8a93.zinhoooo.workers.dev/cbbcpznzn', age=6000, rank=900, page=hidden)
        self.assertEqual(assess_url(local, deep)['verdict'], 'suspicious')

    def test_sign_in_page_on_a_cloud_workstation_preview(self):
        login = {'title': 'Sign in', 'content_risk_score': 45, 'status_code': 200, 'visible_text_length': 400, 'scam_signals': [],
                 'has_password_field': True, 'has_login_form': True}
        local, deep = evidence('https://9000-firebase-anf-1781589572311.cluster-r7kbx.cloudworkstations.dev/login', age=900, rank=0, page=login)
        self.assertIn(assess_url(local, deep)['verdict'], ('suspicious', 'high_risk'))

    def test_page_on_a_rented_servers_default_name(self):
        local, deep = evidence('https://vmi3646823.contaboserver.net/we/paw/na/details.php/', age=6000, rank=0)
        result = assess_url(local, deep)
        self.assertEqual(result['verdict'], 'suspicious')
        self.assertIn('server_hostname', [r['code'] for r in result['reasons']])
        local, deep = evidence('https://vmi3646823.contaboserver.net/', age=6000, rank=0)
        self.assertEqual(assess_url(local, deep)['verdict'], 'harmless')


class ManualTestFindingTests(unittest.TestCase):
    """From a manual check of sp30ct10-varkako-biz-kuremi.pages.dev: Cloudflare had blocked it, we said "be careful"."""

    BLOCK_PAGE = ('<html><head><title>Suspected Malware | Cloudflare</title></head><body><h1>Warning</h1>'
                  '<h2>Suspected Malware</h2><p>This website has been reported for potentially distributing malware.</p>'
                  '<a>Learn More</a><a>Ignore &amp; Proceed</a><p>Cloudflare Ray ID: a50b928249b5d2e4</p></body></html>')

    def test_cloudflare_block_page_is_recognised(self):
        from services.url_analyzer import URLDeepAnalyzer
        analyzer = URLDeepAnalyzer()
        content = analyzer.analyze_page_content('http://sp30ct10-varkako-biz-kuremi.pages.dev/', html=self.BLOCK_PAGE)
        self.assertEqual(content['host_warning'], {'host': 'cloudflare', 'kind': 'malware'})
        phishing = self.BLOCK_PAGE.replace('Malware', 'Phishing').replace('distributing malware', 'phishing')
        self.assertEqual(analyzer.analyze_page_content('https://x.pages.dev/', html=phishing)['host_warning']['kind'], 'phishing')
        ordinary = '<title>Shop</title><p>Performance and security by Cloudflare. We remove suspected malware from uploads.</p>'
        self.assertNotIn('host_warning', analyzer.analyze_page_content('https://shop.example.com/', html=ordinary))

    def test_blocked_by_its_host_is_dangerous_in_both_languages(self):
        from services.report_i18n import translate_plain
        from services.url_report_view import plain_report
        page = {'title': 'Suspected Malware | Cloudflare', 'content_risk_score': 0, 'status_code': 403, 'visible_text_length': 300,
                'scam_signals': [], 'host_warning': {'host': 'cloudflare', 'kind': 'malware'}}
        local, deep = evidence('http://sp30ct10-varkako-biz-kuremi.pages.dev/', age=3000, rank=0, page=page)
        result = assess_url(local, deep)
        self.assertEqual(result['verdict'], 'malicious')
        plain = plain_report(result, local, deep, local['url'])
        self.assertEqual(plain['reasons'][0]['title'], 'Its own host blocked it as malware')
        self.assertIn(('Threat lists', 'bad'), [(c['name'], c['state']) for c in plain['checks']])
        self.assertEqual(translate_plain(plain, 'tr')['reasons'][0]['title'], 'Kendi barındırıcısı onu kötü amaçlı yazılım diye engelledi')

    def test_ai_is_told_the_colour_of_the_verdict(self):
        import json
        from services.ai_assistant import _verdict_reminder
        evidence_json = json.dumps({'final_verdict': {'label': 'BE CAREFUL', 'tone': 'caution', 'headline': 'Be careful with this link'}})
        self.assertIn('BE CAREFUL (shown in yellow)', _verdict_reminder(evidence_json))


class ManualTestSummaryTests(unittest.TestCase):
    def test_summary_names_the_real_source(self):
        from services.report_i18n import translate_plain
        from services.url_report_view import plain_report
        page = {'title': 'Suspected Malware | Cloudflare', 'content_risk_score': 0, 'status_code': 403, 'visible_text_length': 300,
                'scam_signals': [], 'host_warning': {'host': 'cloudflare', 'kind': 'malware'}}
        local, deep = evidence('http://sp30ct10-varkako-biz-kuremi.pages.dev/', age=3000, rank=0, page=page)
        plain = plain_report(assess_url(local, deep), local, deep, local['url'])
        self.assertEqual(plain['summary'], 'The company that hosts this site has blocked it after reports of malware. Don’t open it.')
        self.assertEqual(translate_plain(plain, 'tr')['summary'], 'Bu siteyi barındıran şirket, kötü amaçlı yazılım bildirimleri üzerine onu engelledi. Açma.')
        eicar = {'title': '', 'content_risk_score': 0, 'status_code': 200, 'visible_text_length': 68, 'scam_signals': [],
                 'antivirus': {'status': 'found', 'signature': 'Eicar-Signature', 'kind': 'malware'}}
        local, deep = evidence('https://secure.eicar.org/eicar.com.txt', page=eicar)
        self.assertEqual(plain_report(assess_url(local, deep), local, deep, local['url'])['summary'],
                         'Our antivirus found malware in it. Opening it could harm your device.')

    def test_ai_is_told_not_to_name_evidence_categories(self):
        from services.ai_assistant import SYSTEM_PROMPT
        self.assertIn('never label a point with an evidence category name', SYSTEM_PROMPT)


class ImpersonatedBrandTests(unittest.TestCase):
    """Manual check: www.dhl.smarthub.vuelogix.ai (invalid certificate) said "no fake brand" because vuelogix.ai is 8 years old."""

    def test_cargo_name_on_an_old_site_with_a_broken_certificate(self):
        from services.url_report_view import plain_report
        local, deep = evidence('https://www.dhl.smarthub.vuelogix.ai/', age=8 * 365, rank=0)
        for data in (local, deep):
            data['ssl'] = {'valid': False}
        result = assess_url(local, deep)
        self.assertEqual(result['verdict'], 'high_risk')
        plain = plain_report(result, local, deep, local['url'])
        self.assertIn('It uses the DHL name', [r['title'] for r in plain['reasons']])
        self.assertIn(('Look-alike or fake brand', 'warn'), [(c['name'], c['state']) for c in plain['checks']])

    def test_cargo_name_on_an_old_site_alone_needs_care(self):
        local, deep = evidence('https://dhl.partner-portal.example-logistics.com/', age=8 * 365, rank=900)
        self.assertEqual(assess_url(local, deep)['verdict'], 'suspicious')

    def test_other_brands_on_old_sites_stay_clean(self):
        local, deep = evidence('https://apple.stackexchange.com/', age=6000, rank=300)
        self.assertEqual(assess_url(local, deep)['verdict'], 'harmless')
        self.assertEqual(assess_url(local, deep)['reasons'], [])

    def test_a_brands_own_subsidiary_on_an_old_domain_stays_clean(self):
        local, deep = evidence('https://www.garantiemeklilik.com.tr/', age=6000, rank=20000)
        self.assertEqual(assess_url(local, deep)['verdict'], 'harmless')


class NoPreviewTests(unittest.TestCase):
    """When a link report has no screenshot, the report says why."""

    def reason(self, url='https://www.dhl.smarthub.vuelogix.ai/', **changes):
        from services.url_report_view import plain_report
        local, deep = evidence(url, age=3000, rank=0)
        for key, value in changes.items():
            target, field = key.split('__')
            (local if target == 'local' else deep)[field] = value
        return plain_report(assess_url(local, deep), local, deep, url)['no_preview']

    def test_each_cause_has_its_own_sentence(self):
        from services.url_report_view import NO_PREVIEW
        self.assertEqual(self.reason(local__ssl={'valid': False}, deep__ssl={'valid': False}), NO_PREVIEW['certificate'])
        download = {'title': '', 'content_risk_score': 0, 'status_code': 200, 'visible_text_length': None, 'scam_signals': [],
                    'download': {'filename': 'a.apk', 'program': True}}
        self.assertEqual(self.reason(deep__page_content=download), NO_PREVIEW['download'])
        self.assertEqual(self.reason(deep__behavior={'error': 'Connection refused', 'original_url': 'x', 'final_url': 'x'}), NO_PREVIEW['not_loaded'])
        self.assertEqual(self.reason(local__reputation_only=True), NO_PREVIEW['not_opened'])
        self.assertEqual(self.reason(), NO_PREVIEW['other'])

    def test_every_sentence_is_in_turkish(self):
        from services.report_i18n import translate
        from services.url_report_view import NO_PREVIEW
        for sentence in NO_PREVIEW.values():
            self.assertNotEqual(translate(sentence, 'tr'), sentence, sentence)
        self.assertEqual(translate('No preview', 'tr'), 'Önizleme yok')
