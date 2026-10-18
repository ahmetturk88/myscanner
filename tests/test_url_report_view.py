"""The plain-language summary at the top of a URL report says only what the evidence shows."""
import unittest

from services.url_assessment import assess_url
from services.url_report_view import defang, plain_report, url_parts

VET = {'verdict': 'safe', 'phishing': {'in_database': False, 'verified': False}, 'content': {}, 'typosquatting': {},
       'url_features': {}, 'ssl_info': {'chain_valid': True}, 'analysis': {'chain_length': 1}}


def evidence(vet=None, https=True, age=9000, urlhaus=False, content_risk=0, login=False, reputation_only=False):
    vet = {**VET, **(vet or {})}
    local = {'structure': {'is_https': https, 'contains_ip': False}, 'security_headers': {'score': 80},
             'phishing': {'risk_score': 0}, 'urlvet': vet}
    if https:
        local['ssl'] = {'valid': True}
    if reputation_only:
        local['reputation_only'] = True
    deep = {'structure': {'is_https': https}, 'urlvet': dict(vet),
            'page_content': {'title': 'x', 'content_risk_score': content_risk, 'has_login_form': login},
            'behavior': {'behavior_risk_score': 0, 'error': None},
            'whois': {'age_days': age, 'whois_risk_score': 30 if age < 30 else 0},
            'osint': {'urlhaus': urlhaus, 'urlhaus_status': 'matched' if urlhaus else 'not_found'}}
    if https:
        deep['ssl'] = {'valid': True}
    return local, deep


def report(url='https://example.org/', **kw):
    local, deep = evidence(**kw)
    assessment = assess_url(local, deep)
    return assessment, plain_report(assessment, local, deep, url)


class PlainReportTests(unittest.TestCase):
    def checks(self, plain):
        return {c['name']: (c['state'], c['result']) for c in plain['checks']}

    def test_malware_link(self):
        assessment, plain = report('http://update-chrome-free.top/setup.exe', https=False, age=12, urlhaus=True)
        self.assertEqual(assessment['verdict'], 'malicious')
        self.assertEqual((plain['tone'], plain['label']), ('danger', 'DANGEROUS'))
        self.assertIn('malware', plain['summary'])
        self.assertEqual(plain['reasons'][0]['title'], 'Reported for spreading malware')  # the worst finding leads
        self.assertTrue(any('virus scan' in a for a in plain['actions']))
        self.assertEqual(self.checks(plain)['Threat lists'], ('bad', 'Listed'))
        self.assertEqual(self.checks(plain)['Secure connection'], ('warn', 'No HTTPS'))
        self.assertIn('hxxp://update-chrome-free[.]top/setup[.]exe', plain['share_text'])
        self.assertNotIn('http://update', plain['share_text'])

    def test_fake_login_page(self):
        assessment, plain = report('https://secure-paypa1-login.com/verify', age=3, content_risk=40, login=True,
                                   vet={'content': {'brand_found': 'PayPal', 'brand_mismatch': True, 'has_login_form': True},
                                        'typosquatting': {'is_suspicious': True}})
        self.assertEqual(assessment['verdict'], 'suspicious')
        self.assertEqual(plain['tone'], 'caution')
        titles = [r['title'] for r in plain['reasons']]
        self.assertIn('It pretends to be PayPal', titles)
        self.assertIn('It asks for your password', titles)
        self.assertIn('A very new site', titles)
        self.assertIn('To reach PayPal, type its address yourself or use its official app.', plain['actions'])
        checks = self.checks(plain)
        self.assertEqual(checks['Look-alike or fake brand'], ('warn', 'PayPal'))
        self.assertEqual(checks['Site age'], ('warn', '3 days'))
        self.assertEqual(checks['Page content'], ('warn', 'Asks for password'))
        self.assertEqual(checks['Threat lists'], ('ok', 'Not listed'))
        self.assertEqual(plain['tally'], '3 warnings · 4 fine')

    def test_safe_site_lists_only_true_positives(self):
        assessment, plain = report('https://www.wikipedia.org/')
        self.assertEqual(assessment['verdict'], 'harmless')
        self.assertEqual(plain['tone'], 'safe')
        self.assertEqual([r['tone'] for r in plain['reasons']], ['ok', 'ok', 'ok'])
        self.assertIn('A long-established site', [r['title'] for r in plain['reasons']])
        self.assertTrue(all(state == 'ok' for state, _ in self.checks(plain).values()))
        self.assertTrue(plain['share_text'].startswith('MyScanner checked this link and found no warning signs'))

    def test_missing_checks_never_read_as_safe(self):
        local, deep = evidence()
        deep['osint'] = {}  # URLhaus not recorded
        del deep['page_content']
        assessment = assess_url(local, deep)
        plain = plain_report(assessment, local, deep, 'https://example.org/')
        self.assertEqual(assessment['verdict'], 'unknown')
        self.assertEqual(plain['tone'], 'unknown')
        self.assertEqual(plain['reasons'][0]['title'], 'Some checks couldn’t run')
        self.assertIn('can’t say it’s safe', plain['summary'])
        self.assertEqual(self.checks(plain)['Page content'], ('na', 'Not checked'))

    def test_reputation_only_says_the_page_was_not_opened(self):
        local, deep = evidence(reputation_only=True)
        assessment = {'verdict': 'unknown', 'reasons': [], 'components': {'reputation': {'status': 'assessed'}},
                      'missing_checks': ['x']}
        plain = plain_report(assessment, local, deep, 'http://1.2.3.4:8080/x')
        self.assertIn('didn’t open the page', plain['summary'])
        self.assertEqual(plain['reasons'][0]['title'], 'We didn’t open the page')
        self.assertEqual(self.checks(plain)['Redirects'], ('na', 'Not opened'))

    def test_bad_input_is_handled(self):
        plain = plain_report(None, None, None, None)
        self.assertEqual(plain['tone'], 'unknown')
        self.assertEqual(plain['url'], {'prefix': '', 'host': '', 'rest': ''})
        plain = plain_report({'verdict': 'evil', 'reasons': ['x', {'code': 'nope'}]}, {}, {}, 'https://a.example/')
        self.assertEqual(plain['tone'], 'unknown')

    def test_brand_text_is_bounded(self):
        local, deep = evidence(vet={'content': {'brand_found': 'x' * 200, 'brand_mismatch': True}})
        plain = plain_report(assess_url(local, deep), local, deep, 'https://a.example/')
        self.assertFalse(any('x' * 41 in r['title'] for r in plain['reasons']))


class HelperTests(unittest.TestCase):
    def test_url_parts_keep_the_original_text(self):
        self.assertEqual(url_parts('https://WWW.Example.com:8443/a?b=1'),
                         {'prefix': 'https://', 'host': 'WWW.Example.com', 'rest': ':8443/a?b=1'})
        self.assertEqual(url_parts('not a url')['host'], 'not a url')
        self.assertEqual(url_parts('http://[::1')['host'], 'http://[::1')

    def test_defang(self):
        self.assertEqual(defang('HTTPS://a.b.c/x.exe'), 'hxxps://a[.]b[.]c/x[.]exe')
        self.assertEqual(defang(None), '')


if __name__ == '__main__':
    unittest.main()
