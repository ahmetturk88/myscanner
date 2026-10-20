"""Plain-language summaries for the password, certificate and website/QR checks."""
import logging
import unittest
from pathlib import Path
from types import SimpleNamespace

from bs4 import BeautifulSoup
from jinja2 import Environment, FileSystemLoader

from services.password_analyzer import PasswordAnalyzer
from services.simple_report_view import plain_password_report, plain_ssl_report, plain_web_report


def checks(plain):
    return {c['name']: (c['state'], c['result']) for c in plain['checks']}


def password(value):
    logging.disable(logging.CRITICAL)
    try:
        return PasswordAnalyzer().comprehensive_analysis(value, check_breaches=False)
    finally:
        logging.disable(logging.NOTSET)


class PasswordTests(unittest.TestCase):
    def test_weak_password_never_echoed_or_shareable(self):
        result = password('Summer2024!')
        plain = plain_password_report(result)
        self.assertEqual((plain['tone'], plain['label']), ('caution', 'WEAK'))
        self.assertNotIn('Summer', str(plain))
        self.assertEqual(plain['share_text'], '')
        self.assertIn('It uses common words or names', [r['title'] for r in plain['reasons']])
        self.assertEqual(checks(plain)['Data leaks'], ('na', 'Not checked'))
        self.assertEqual(plain['url'], {'prefix': '', 'host': 'Your password', 'rest': ' · 11 characters'})

    def test_strong_password_without_leak_check_says_so(self):
        plain = plain_password_report(password('violet-anchor-quartz-meadow-71'))
        self.assertEqual(plain['tone'], 'safe')
        self.assertIn('didn’t check whether it has leaked', plain['summary'])
        self.assertEqual(plain['reasons'][0]['title'], 'Leaks weren’t checked')

    def test_leaked_password(self):
        result = password('violet-anchor-quartz-meadow-71')
        result['pwned'] = {'status': 'found', 'count': 52341}
        plain = plain_password_report(result)
        self.assertEqual((plain['tone'], plain['headline']), ('danger', 'Stop using this password'))
        self.assertEqual(checks(plain)['Data leaks'], ('bad', 'Found 52,341 times'))
        self.assertIn('52,341', plain['reasons'][0]['detail'])

    def test_estimator_unavailable(self):
        plain = plain_password_report({'local_strength': {'status': 'unavailable'}, 'pwned': {'status': 'skipped'}})
        self.assertEqual(plain['tone'], 'unknown')
        self.assertEqual(checks(plain)['Strength'], ('na', 'Not measured'))


def ssl(**changes):
    data = {'domain': 'example.com', 'valid': True, 'issuer': 'DigiCert Inc', 'days_remaining': 120, 'tls_version': 'TLSv1.3',
            'checks': [{'name': n, 'status': 'completed'} for n in ('Public target', 'Verified handshake', 'Chain trust', 'Hostname identity', 'Validity period', 'Negotiated TLS', 'Certificate details')],
            'findings': []}
    data.update(changes)
    return data


class SSLTests(unittest.TestCase):
    def test_valid_certificate_is_not_called_a_safe_site(self):
        plain = plain_ssl_report(ssl())
        self.assertEqual((plain['tone'], plain['headline']), ('safe', 'The connection is private'))
        self.assertIn('says nothing about whether the site itself is honest', plain['summary'])
        self.assertIn('This checks the connection only', [r['title'] for r in plain['reasons']])
        self.assertEqual(checks(plain)['Encryption'], ('ok', 'TLS 1.3'))

    def test_expired_certificate(self):
        failed = ssl(valid=False, days_remaining=-4209, tls_version='TLSv1.2', reason_code='expired',
                     findings=[{'severity': 'danger', 'title': 'Certificate has expired'}])
        failed['checks'][2]['status'] = 'unavailable'
        failed['checks'][4]['status'] = 'invalid'
        plain = plain_ssl_report(failed)
        # Browsers block the page, so a failed certificate is red, and it is counted once.
        self.assertEqual((plain['tone'], plain['label']), ('danger', 'NOT SECURE'))
        self.assertEqual(plain['reasons'][0]['title'], 'Certificate has expired')
        self.assertIn('It ran out 11 years ago.', plain['reasons'][0]['detail'])
        self.assertNotIn('This checks the connection only', [r['title'] for r in plain['reasons']])
        self.assertEqual(checks(plain)['Valid until'], ('bad', 'Expired 11 years ago'))
        self.assertNotIn('In date', checks(plain))
        self.assertEqual(checks(plain)['Trusted issuer'], ('na', 'Couldn’t confirm'))
        self.assertEqual(plain['tally'], '1 bad · 2 fine · 1 not checked')
        self.assertIn('example[.]com', plain['share_text'])

    def test_each_failure_has_its_own_explanation(self):
        details = {plain_ssl_report(ssl(valid=False, reason_code=code))['reasons'][0]['detail']
                   for code in ('self_signed', 'self_signed_chain', 'hostname_mismatch', 'untrusted_issuer')}
        self.assertEqual(len(details), 4)

    def test_old_protocol(self):
        plain = plain_ssl_report(ssl(tls_version='TLSv1'))
        self.assertEqual(plain['label'], 'OUTDATED')
        self.assertEqual(checks(plain)['Encryption'], ('warn', 'TLS 1'))

    def test_no_connection(self):
        plain = plain_ssl_report({'domain': 'nope.example', 'valid': None, 'reason_code': 'dns_unavailable', 'checks': []})
        self.assertEqual(plain['tone'], 'unknown')
        self.assertIn('doesn’t resolve', plain['reasons'][0]['detail'])


class WebTests(unittest.TestCase):
    def test_qr_link_with_unsafe_password_form(self):
        result = {'url': 'http://pay-parking.example/pay', 'verdict': 'suspicious', 'assessment_status': 'completed',
                  'tls': {'status': 'unavailable'}, 'http': {'chain': [{}, {}], 'final_url': 'https://other.example/'},
                  'provider': {'status': 'not_requested'},
                  'findings': [{'code': 'password_http'}, {'code': 'unencrypted_entry'}, {'code': 'host_change'}]}
        plain = plain_web_report(result, source='qr')
        self.assertEqual((plain['tone'], plain['headline']), ('caution', 'Be careful with this QR code’s link'))
        self.assertTrue(any('instead of using the QR code' in a for a in plain['actions']))
        self.assertEqual(checks(plain)['Password forms'], ('warn', 'Unsafe'))
        self.assertEqual(checks(plain)['Threat lists'], ('na', 'Not requested'))
        self.assertIn('It ends at other.example.', [r['detail'] for r in plain['reasons'] if r['title'] == 'It lands on a different site'][0])
        self.assertIn('hxxp://pay-parking[.]example/pay', plain['share_text'])

    def test_malicious_qr_link_mentions_sticker_scams(self):
        plain = plain_web_report({'url': 'https://bad.example/', 'verdict': 'malicious', 'provider': {'status': 'completed'}}, source='qr')
        self.assertEqual(plain['tone'], 'danger')
        self.assertTrue(any('stickers' in a for a in plain['actions']))

    def test_clean_and_unknown(self):
        self.assertEqual(plain_web_report({'url': 'https://example.com/', 'verdict': 'clean', 'tls': {'status': 'completed'}, 'http': {'chain': [{}]}})['tone'], 'safe')
        plain = plain_web_report({'url': 'https://example.com/', 'verdict': 'unknown', 'assessment_status': 'partial'})
        self.assertEqual(plain['reasons'][0]['title'], 'Some checks couldn’t run')
        self.assertEqual(plain_web_report(None)['tone'], 'unknown')


class PageTests(unittest.TestCase):
    def test_summary_slots_and_evidence(self):
        env = Environment(loader=FileSystemLoader(Path(__file__).resolve().parents[1] / 'templates'))
        env.globals.update(csrf_token=lambda: 't', url_for=lambda e, **kw: '/static/' + kw.get('filename', e),
                           get_flashed_messages=lambda **kw: [], current_user=SimpleNamespace(is_authenticated=False),
                           request=SimpleNamespace(path='/'))
        for name, key in (('password_check.html', 'password'), ('ssl_checker.html', 'ssl')):
            with self.subTest(page=name):
                soup = BeautifulSoup(env.get_template(name).render(), 'html.parser')
                self.assertTrue(soup.select_one(f'#{key}-plain').has_attr('hidden'))
                tech = soup.select_one(f'details#{key}-tech')
                self.assertTrue(tech.has_attr('hidden'))
                self.assertIsNotNone(tech.select_one(f'#{key}-results'))
        soup = BeautifulSoup(env.get_template('qr_scanner.html').render(), 'html.parser')
        self.assertIsNotNone(soup.select_one('#result-card #qr-plain'))


if __name__ == '__main__':
    unittest.main()


class SiteAndSubdomainTests(unittest.TestCase):
    def test_site_wording(self):
        from services.simple_report_view import plain_web_report
        plain = plain_web_report({'url': 'https://shop.example/', 'verdict': 'suspicious', 'findings': [{'code': 'external_password_form'}]}, source='site')
        self.assertEqual(plain['headline'], 'Be careful with this website')
        self.assertEqual(plain['reasons'][0]['title'], 'It sends your password to another site')

    def test_discovery_is_information_not_a_verdict(self):
        from services.simple_report_view import plain_subdomain_report
        result = {'domain': 'example.com', 'assessment_status': 'partial', 'total_found': 7, 'active_count': 4, 'redirect_count': 2,
                  'total_checked': 60, 'dns_error_count': 1, 'wildcard': {'detected': False},
                  'subdomains': {'dns_only': [{}], 'http_error': [{}, {}]},
                  'sources': [{'name': 'Certificate Transparency (crt.sh)', 'status': 'completed'}]}
        plain = plain_subdomain_report(result)
        self.assertEqual((plain['tone'], plain['label'], plain['headline']), ('info', 'DISCOVERY', '7 subdomains found'))
        self.assertEqual(plain['share_text'], '')
        self.assertEqual(plain['reasons'][0]['title'], 'This is a sample')
        self.assertIn('2 show an error page', [r['title'] for r in plain['reasons']])
        self.assertEqual(plain['why_title'], 'What we found')
        self.assertEqual(checks(plain)['Certificate history'], ('ok', 'Used'))
        self.assertEqual(plain['tally'], '60 names checked')

    def test_wildcard_domain(self):
        from services.simple_report_view import plain_subdomain_report
        plain = plain_subdomain_report({'domain': 'example.com', 'assessment_status': 'completed', 'total_found': 1, 'wildcard': {'detected': True}})
        self.assertEqual(plain['headline'], '1 subdomain found')
        self.assertEqual(checks(plain)['Wildcard'], ('warn', 'Yes'))
        self.assertTrue(plain['actions'][0].startswith('Treat the list with care'))
        self.assertEqual(plain_subdomain_report(None)['headline'], '0 subdomains found')
