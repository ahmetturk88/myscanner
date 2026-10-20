"""Turkish report summaries: every sentence the English builders can produce has a translation."""
import copy
import itertools
import re
import unittest

import test_email_report_view as email_fixtures
import test_ip_domain_report_view as ip_domain_fixtures
import test_mobile_api
import test_simple_report_view as simple_fixtures
import test_url_report_view as url_fixtures
from services.domain_report_view import plain_domain_report
from services.email_report_view import VERDICTS as EMAIL_VERDICTS, plain_email_report
from services.file_report_view import VERDICTS as FILE_VERDICTS, plain_file_report
from services.i18n_tr import TR
from services.ip_report_view import plain_ip_report
from services.report_i18n import translate, translate_plain, translate_tally, preferred_language
from services.simple_report_view import (PATTERNS, SSL_FAILURES, WEB_FINDINGS, plain_password_report, plain_ssl_report,
                                         plain_subdomain_report, plain_web_report)
from services.url_assessment import SHORT_UNRESOLVED
from services.url_report_view import REASONS, VERDICTS as URL_VERDICTS, plain_report

# Values that read the same in both languages: scanned data the fixtures use (brands,
# hosts, registrars, organisations, places, file types) and numbers, scores and versions.
NEUTRAL_VALUES = {'PayPal', 'paypal.com', 'Example Registrar', 'Example Hosting', 'Germany', 'PDF', 'ZIP', 'EXE',
                  'AgentTesla', 'SPF + DMARC', ''}
NEUTRAL = re.compile(r'\d[\d,.]*|\d+/100|TLS ?v?1(\.\d)?|TLSv1')


def url_reports():
    """The URL summary for every verdict and reason, with and without the details that reword them."""
    yield from (url_fixtures.report(**kw)[1] for kw in (
        {}, {'https': False, 'age': 12, 'urlhaus': True}, {'age': 3, 'content_risk': 40, 'login': True},
        {'https': False}, {'age': 5}, {'reputation_only': True}, {'vet': {'verdict': 'suspicious'}}))
    for verdict, codes, extras in itertools.product(
            URL_VERDICTS, [[c] for c in REASONS] + [list(REASONS)[:3], ['ip_url', 'no_https', 'homoglyph'], []],
            ({}, {'brand': True, 'login': True, 'age': 40, 'copied': True}, {'payment': True, 'age': 400},
             {'age': 1, 'missing': ['x']}, {'missing': [SHORT_UNRESOLVED]}, {'reputation_only': True}, {'missing': ['a', 'b']},
             {'age': 5000, 'assessed': True}, {'assessed': True})):
        components = {k: {'status': 'assessed'} for k in ('reputation', 'transport', 'identity', 'content', 'behavior')} if extras.get('assessed') else {}
        assessment = {'verdict': verdict, 'reasons': [{'code': c, 'deduction': 10} for c in codes],
                      'components': components, 'missing_checks': extras.get('missing', [])}
        content = {'brand_found': 'PayPal'} if extras.get('brand') else {}
        content.update(has_login_form=bool(extras.get('login')), has_payment_form=bool(extras.get('payment')))
        local = {'urlvet': {'content': content}, 'reputation_only': bool(extras.get('reputation_only'))}
        if extras.get('copied'):
            local['phishing'] = {'issues': ['Possible typosquatting of paypal.com']}
        deep = {'whois': {'age_days': extras['age']}} if 'age' in extras else {}
        yield plain_report(assessment, local, deep, 'https://www.example.org/login')
    yield plain_report(None, None, None, None)


def password_reports():
    for value in ('Summer2024!', 'violet-anchor-quartz-meadow-71', 'qwerty', 'aaaaaa', 'abc123', '1987-04-12', 'password'):
        yield plain_password_report(simple_fixtures.password(value))
    for rank, strength in enumerate(['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong']):
        for pwned in ({'status': 'found', 'count': 52341}, {'status': 'found'}, {'status': 'not_found'}, {'status': 'skipped'}):
            yield plain_password_report({'password_length': 8 + rank * 3, 'pwned': pwned,
                                         'local_strength': {'status': 'completed', 'estimator_rank': rank, 'strength': strength,
                                                            'findings': [{'code': c} for c in PATTERNS]}})
        for code in PATTERNS:  # only four reasons fit, so each pattern also alone
            yield plain_password_report({'pwned': {'status': 'skipped'}, 'local_strength': {
                'status': 'completed', 'estimator_rank': rank, 'strength': strength, 'findings': [{'code': code}]}})
    for pwned in ({'status': 'found', 'count': 3}, {'status': 'not_found'}, {'status': 'skipped'}):
        yield plain_password_report({'local_strength': {'status': 'unavailable', 'strength': 'Unknown'}, 'pwned': pwned})


def ssl_reports():
    for code in list(SSL_FAILURES) + ['certificate_verification_failed']:
        for days in (-800, -400, -40, -1, 5, None):
            yield plain_ssl_report(simple_fixtures.ssl(valid=False, reason_code=code, days_remaining=days,
                                                       findings=[{'severity': 'danger', 'title': 'Certificate verification failed'}],
                                                       checks=[{'name': 'Chain trust', 'status': 'invalid'}]))
    for days, version, issuer in itertools.product((1, 5, 13, 30, 59, 100, 800), ('TLSv1.3', 'TLSv1.2', 'TLSv1', 'TLSv1.1', ''),
                                                   ('DigiCert Inc', 'Not provided', '')):
        yield plain_ssl_report(simple_fixtures.ssl(days_remaining=days, tls_version=version, issuer=issuer))
    for title in ('Certificate is not yet valid', 'Untrusted root in chain', 'Issuer not trusted', 'Incomplete certificate chain',
                  'Certificate revoked', 'Hostname does not match'):  # the analyzer's own titles, for a code we don't list
        yield plain_ssl_report(simple_fixtures.ssl(valid=False, reason_code='other', findings=[{'severity': 'danger', 'title': title}]))
    yield plain_ssl_report(simple_fixtures.ssl(days_remaining=None))
    yield plain_ssl_report(simple_fixtures.ssl(valid=False, days_remaining=None, checks=[{'name': 'Validity period', 'status': 'invalid'}]))
    for code in ('dns_unavailable', 'timeout'):
        yield plain_ssl_report({'domain': 'nope.example', 'valid': None, 'reason_code': code, 'checks': []})
    yield plain_ssl_report(None)


def web_reports():
    for verdict, source, codes, http, provider, tls in itertools.product(
            ('malicious', 'suspicious', 'clean', 'unknown', None), ('link', 'qr', 'site'),
            [[c] for c in WEB_FINDINGS] + [list(WEB_FINDINGS), []],
            ({'chain': [{}, {}, {}], 'final_url': 'https://other.example/'}, {'chain': [{}]}, {}),
            ('completed', 'not_requested', None), ('completed', 'invalid', None)):
        yield plain_web_report({'url': 'https://shop.example/pay', 'verdict': verdict, 'findings': [{'code': c} for c in codes],
                                'http': http, 'provider': {'status': provider}, 'tls': {'status': tls},
                                'assessment_status': 'partial' if verdict == 'unknown' else 'completed'}, source=source)
    yield plain_web_report(None)


def subdomain_reports():
    for found, active, redirects, errors, wildcard, partial, ct, groups in itertools.product(
            (0, 1, 5), (0, 1, 3), (0, 2), (0, 4), (False, True), (False, True), ('completed', 'not_requested', 'failed'),
            ({}, {'dns_only': ['a'], 'http_error': ['b']}, {'http_error': ['b', 'c']})):
        yield plain_subdomain_report({'domain': 'example.com', 'total_found': found, 'active_count': active, 'redirect_count': redirects,
                                      'dns_error_count': errors, 'total_checked': 120, 'wildcard': {'detected': wildcard},
                                      'assessment_status': 'partial' if partial else 'completed', 'subdomains': groups,
                                      'sources': [{'name': 'Certificate Transparency', 'status': ct}]})
    yield plain_subdomain_report(None)


def file_reports():
    flags = [{}, {'eicar': True}, {'matched': 'AgentTesla'}, {'matched': ''}, {'disguised_name': 'invoice.pdf.exe'},
             {'disguised_name': 'right-to-left override'}, {'spoofed': 'EXE'}, {'spoofed': ''},
             {'meta': {'has_macros': True}}, {'meta': {'has_javascript': True}}, {'meta': {'has_actions': True}},
             {'meta': {'has_macros': True, 'has_javascript': True, 'has_actions': True}},
             {'meta': {'has_macros': True, 'has_javascript': True}}, {'meta': {'has_macros': True, 'has_actions': True}},
             {'meta': {'has_javascript': True, 'has_actions': True}},
             {'meta': {'suspicious': ['External Office relationship: http://x']}}, {'meta': {'has_path_traversal': True, 'is_archive': True}},
             {'rules': ['a']}, {'rules': ['a', 'b']}, {'darkweb': True}, {'meta': {'encrypted': True, 'is_archive': True}},
             {'meta': {'is_archive': True, 'payload_inspection': {'status': 'assessed', 'inspected_members': 4}}},
             {'meta': {'is_archive': True}}, {'links': 1}, {'links': 3}, {'meta': {'error': 'x'}}, {'missing': ['a']},
             {'missing': ['a', 'b']}, {'actual': 'PDF'}, {'benign': True, 'meta': {'has_macros': True}}]
    for verdict, flag, name in itertools.product(list(FILE_VERDICTS) + ['bogus'], flags, ('report.pdf', '')):
        meta = dict(flag.get('meta', {}))
        report = {'verdict': verdict, 'filename': name, 'metadata': meta, 'file_size_bytes': 2048, 'scanned_at': '2026-05-01T10:00:00Z',
                  'file_type': {'actual_type': flag.get('actual', flag.get('spoofed', 'pdf')), 'is_spoofed': 'spoofed' in flag},
                  'yara': {'matched_rules': flag.get('rules', []), 'status': 'completed'},
                  'iocs': {'urls': ['u'] * flag.get('links', 0), 'onion_addresses': ['x.onion'] if flag.get('darkweb') else []},
                  'malwarebazaar': ({'status': 'matched', 'is_malicious': True, 'signature': flag['matched']} if 'matched' in flag
                                    else {'status': 'not_found'}),
                  'eicar': bool(flag.get('eicar')), 'disguised_name': flag.get('disguised_name'),
                  'is_likely_benign': bool(flag.get('benign')), 'missing_checks': flag.get('missing', [])}
        yield plain_file_report(report)
    yield plain_file_report({'verdict': 'unknown', 'malwarebazaar': {'status': 'unavailable'}})
    yield plain_file_report(None)


def email_reports():
    base = email_fixtures.report()
    dns_variants = [
        {}, {'mx': {'status': 'not_found'}}, {'mx': {'status': 'found', 'records': [{'exchange': '.'}]}},
        {'mx': {'status': 'found', 'infrastructure': [{'unsafe_addresses': ['10.0.0.1']}]}},
        {'spf': {'status': 'not_found'}}, {'dmarc': {'status': 'not_found'}},
        {'spf': {'status': 'not_found'}, 'dmarc': {'status': 'not_found'}},
        {'spf': {'status': 'found', 'audit': {'configuration_valid': False}}},
        {'spf': {'status': 'found', 'audit': {'configuration_valid': False}}, 'dmarc': {'status': 'found', 'audit': {'configuration_valid': False}}},
        {'dmarc': {'status': 'found', 'policy': 'none'}}, {'mx': {'status': 'error'}, 'spf': {'status': 'error'}},
    ]
    others = [{}, {'blacklist': {'is_blacklisted': True, 'blacklisted_on': ['zen.spamhaus.org']}},
              {'blacklist': {'is_blacklisted': True}}, {'blacklist': {}}, {'is_disposable': True}, {'is_free': True},
              {'domain_info': {'age_days': 1}}, {'domain_info': {'age_days': 10}}, {'domain_info': {'age_days': 300}},
              {'domain_info': {'error': 'x'}}, {'smtp': {'coverage_status': 'checked', 'valid': False}},
              {'smtp': {'coverage_status': 'checked', 'valid': True}}, {'domain': None, 'email': 'x@'}]
    for verdict, dns_change, other, missing in itertools.product(EMAIL_VERDICTS, dns_variants, others, ([], ['a'], ['a', 'b'])):
        data = copy.deepcopy(base)
        data['dns'].update(copy.deepcopy(dns_change))
        data.update(copy.deepcopy(other))
        data['assessment'] = {'verdict': verdict, 'missing_checks': missing}
        yield plain_email_report(data)
    yield plain_email_report(None)


def ip_reports():
    for status, score, reports, extra in itertools.product(
            ('matched', 'not_found', 'unavailable'), (0, 20, 87), (1, 412),
            ({}, {'is_tor': True}, {'is_tor': False, 'usage_type': 'Data Center/Web Hosting/Transit'},
             {'is_whitelisted': True, 'usage_type': 'Fixed Line ISP'}, {'distinct_reporters': 0})):
        yield plain_ip_report(ip_domain_fixtures.ip(status, score, reports, **extra))
    for usage in ('Commercial', 'Organization', 'Government', 'Military', 'University/College/School', 'Library',
                  'Content Delivery Network', 'Fixed Line ISP', 'Mobile ISP', 'Data Center/Web Hosting/Transit',
                  'Search Engine Spider', 'Reserved'):
        yield plain_ip_report(ip_domain_fixtures.ip(usage_type=usage))
    for owner_fields in ({'asn': None}, {'country': ''}, {'asn': None, 'country': ''}, {'org': '', 'isp': ''}):
        data = ip_domain_fixtures.ip('matched', 60, 3)
        data.update(owner_fields)
        yield plain_ip_report(data)
    yield plain_ip_report(None)


def domain_reports():
    variants = [{}, {'age_days': 4}, {'age_days': 1}, {'age_days': 100}, {'age_days': 400}, {'status': ['client hold']},
                {'status': ['pending delete']}, {'days_until_expiry': 1}, {'days_until_expiry': 20}, {'days_until_expiry': 0},
                {'days_until_expiry': 900}, {'days_until_expiry': -3}, {'spf_observation': {'status': 'multiple_records'}},
                {'coverage': {'whois': 'unavailable'}, 'age_days': None, 'days_until_expiry': None}, {'registrar': ''},
                {'dns': [{'type': 'A'}]}, {'dns': [{'type': 'MX'}]}, {'dns': []}]
    for change in variants:
        yield plain_domain_report(ip_domain_fixtures.domain(**change))
    yield plain_domain_report({'domain': 'gogle.cm', 'verdict': 'no_domain', 'dns': [], 'coverage': {'whois': 'not_found'}})
    yield plain_domain_report(None)


def all_reports():
    for builder in (url_reports, password_reports, ssl_reports, web_reports, subdomain_reports, file_reports,
                    email_reports, ip_reports, domain_reports):
        yield from builder()


def text_fields(plain):
    """(where, text) for every translatable text field of a plain summary."""
    for key in ('label', 'headline', 'summary', 'why_title', 'checked', 'tally', 'share_text', 'not_visited'):
        if isinstance(plain.get(key), str):
            yield key, plain[key]
    for i, reason in enumerate(plain['reasons']):
        yield f'reasons[{i}].title', reason['title']
        yield f'reasons[{i}].detail', reason['detail']
    for i, action in enumerate(plain['actions']):
        yield f'actions[{i}]', action
    for i, item in enumerate(plain['checks']):
        yield f'checks[{i}].name', item['name']
        yield f'checks[{i}].result', item['result']


def neutral(text):
    return text in NEUTRAL_VALUES or bool(NEUTRAL.fullmatch(text))


class CoverageTests(unittest.TestCase):
    def test_every_sentence_the_builders_produce_is_translated(self):
        untranslated, count = set(), 0
        for plain in all_reports():
            count += 1
            turkish = translate_plain(plain, 'tr')
            self.assertEqual(turkish['url'], plain['url'])
            self.assertEqual(turkish['tone'], plain['tone'])
            self.assertEqual([c['state'] for c in turkish['checks']], [c['state'] for c in plain['checks']])
            self.assertEqual([r['tone'] for r in turkish['reasons']], [r['tone'] for r in plain['reasons']])
            translated = dict(text_fields(turkish))
            for where, text in translated.items():  # an untranslated age inside a translated sentence
                self.assertIsNone(re.search(r'\d+ (day|days|months|years)\b', text), (where, text))
            for where, english in text_fields(plain):
                if translated[where] == english and not neutral(english):
                    untranslated.add((where.split('[')[0] + where.split(']')[-1], english))
                if where == 'tally':
                    for part in english.split(' · ') if english else []:
                        self.assertNotEqual(translate(part, 'tr'), part, part)
            if plain.get('share_text'):
                self.assertTrue(turkish['share_text'].endswith('https://myscanners.com'))
        self.assertGreater(count, 2000)
        self.assertEqual(sorted(untranslated), [])

    def test_share_text_keeps_the_defanged_address(self):
        _, plain = url_fixtures.report('http://update-chrome-free.top/setup.exe', https=False, age=12, urlhaus=True)
        turkish = translate_plain(plain, 'tr')['share_text']
        self.assertIn('hxxp://update-chrome-free[.]top/setup[.]exe', turkish)
        self.assertTrue(turkish.startswith('Uyarı: MyScanner bu bağlantıyı tehlikeli olarak'))

    def test_catalog_templates_are_consistent(self):
        placeholder = re.compile(r'\{([a-z_]+)\}')
        for english, turkish in TR.items():
            self.assertTrue(set(placeholder.findall(turkish)) <= set(placeholder.findall(english)), english)
            self.assertNotIn('’', turkish, english)  # Turkish suffixes use a straight apostrophe
            if english.isupper():
                self.assertTrue(turkish.isupper(), english)


class TranslateTests(unittest.TestCase):
    def test_exact_match(self):
        self.assertEqual(translate('DANGEROUS', 'tr'), 'TEHLİKELİ')
        self.assertEqual(translate('Don’t open this link', 'tr'), 'Bu bağlantıyı açma')

    def test_template_translates_the_captured_values(self):
        self.assertEqual(translate('It was registered 3 months ago.', 'tr'), '3 ay önce kaydedilmiş.')
        self.assertEqual(translate('A password-cracking model rates it very weak.', 'tr'), 'Bir şifre kırma modeline göre çok zayıf.')
        self.assertEqual(translate('in 23 months', 'tr'), '23 ay içinde')
        self.assertEqual(translate('1 day', 'tr'), '1 gün')

    def test_most_specific_template_wins_and_data_is_kept(self):
        self.assertEqual(translate('The connection used TLSv1. Modern sites use TLS 1.2 or 1.3.', 'tr'),
                         'Bağlantıda TLSv1 kullanıldı. Modern siteler TLS 1.2 ya da 1.3 kullanır.')
        self.assertEqual(translate('The page shows the Weak brand, but the address doesn’t belong to Weak.', 'tr'),
                         'Sayfa Weak markasını gösteriyor ama adres Weak markasına ait değil.')

    def test_tally_parts_are_translated_separately(self):
        self.assertEqual(translate_tally('2 bad · 1 warning · 3 fine · 1 not checked', 'tr'),
                         '2 kötü · 1 uyarı · 3 sorunsuz · 1 kontrol edilmedi')
        self.assertEqual(translate_tally('', 'tr'), '')

    def test_unknown_text_falls_back_to_english(self):
        self.assertEqual(translate('Something new the catalog has never seen.', 'tr'), 'Something new the catalog has never seen.')
        self.assertIsNone(translate(None, 'tr'))

    def test_input_is_not_mutated_and_english_is_unchanged(self):
        _, plain = url_fixtures.report('https://www.wikipedia.org/')
        before = copy.deepcopy(plain)
        turkish = translate_plain(plain, 'tr')
        self.assertEqual(plain, before)
        self.assertEqual(turkish['label'], 'GÜVENLİ GÖRÜNÜYOR')
        self.assertIs(translate_plain(plain, 'en'), plain)
        self.assertEqual(translate('DANGEROUS', 'en'), 'DANGEROUS')

    def test_preferred_language(self):
        self.assertEqual(preferred_language('tr-TR,tr;q=0.9,en;q=0.8'), 'tr')
        self.assertEqual(preferred_language('en-US'), 'en')
        self.assertEqual(preferred_language(None), '')


class MobileApiLanguageTests(unittest.TestCase):
    # The mobile API tests' app, users and token helpers.
    setUpClass = classmethod(test_mobile_api.MobileApiTests.setUpClass.__func__)
    tearDownClass = classmethod(test_mobile_api.MobileApiTests.tearDownClass.__func__)
    setUp = test_mobile_api.MobileApiTests.setUp
    login = test_mobile_api.MobileApiTests.login
    token = test_mobile_api.MobileApiTests.token
    auth = test_mobile_api.MobileApiTests.auth

    def check(self, token, **headers):
        return self.client.post('/api/mobile/v1/tools/password', headers={**self.auth(token), **headers},
                                json={'password': 'Summer2024!', 'check_breaches': False})

    def test_turkish_summary_on_request(self):
        token = self.token()
        english = self.check(token)
        self.assertEqual(english.status_code, 200)
        self.assertEqual(english.json['plain']['headline'], 'This password is easy to guess')
        turkish = self.check(token, **{'Accept-Language': 'tr-TR,tr;q=0.9,en;q=0.5'})
        self.assertEqual(turkish.status_code, 200)
        self.assertEqual(turkish.json['plain']['headline'], 'Bu şifre kolay tahmin edilir')
        self.assertEqual(turkish.json['plain']['label'], 'ZAYIF')
        self.assertEqual(turkish.json['plain']['tone'], 'caution')
        self.assertEqual(turkish.json['local_strength'], english.json['local_strength'])  # only the summary changes
        self.assertEqual(int(turkish.headers['Content-Length']), len(turkish.get_data()))
        self.assertIn('Accept-Language', turkish.headers.get('Vary', ''))
        self.assertEqual(self.check(token, **{'Accept-Language': 'en-GB'}).json['plain']['headline'], 'This password is easy to guess')

    def test_errors_are_left_alone(self):
        token = self.token()
        response = self.client.post('/api/mobile/v1/tools/password', headers={**self.auth(token), 'Accept-Language': 'tr'},
                                    json={'password': ''})
        self.assertEqual(response.status_code, 400)


if __name__ == '__main__':
    unittest.main()
