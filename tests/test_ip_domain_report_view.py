"""Plain-language summaries for the IP and domain lookups say only what their sources returned."""
import unittest
from pathlib import Path
from types import SimpleNamespace

from bs4 import BeautifulSoup
from jinja2 import Environment, FileSystemLoader

from services.domain_report_view import plain_domain_report
from services.ip_report_view import plain_ip_report


def checks(plain):
    return {c['name']: (c['state'], c['result']) for c in plain['checks']}


def ip(status='not_found', score=0, reports=0, **reputation):
    return {'ip': '203.0.113.9', 'ip_version': 4, 'org': 'Example Hosting', 'asn': 64500, 'country': 'Germany',
            'reputation': {'status': status, 'score': score, 'reports': reports, 'distinct_reporters': 7, **reputation}}


class IPSummaryTests(unittest.TestCase):
    def test_clean_address(self):
        plain = plain_ip_report(ip(is_tor=False, usage_type='Fixed Line ISP'))
        self.assertEqual((plain['tone'], plain['headline']), ('safe', 'No warning signs found'))
        self.assertEqual(plain['reasons'][0]['title'], 'No abuse reports')
        self.assertEqual(checks(plain)['Abuse reports'], ('ok', 'None'))
        self.assertEqual(checks(plain)['Network type'], ('info', 'Fixed Line ISP'))
        self.assertIn('never points to a person', [r for r in plain['reasons'] if r['title'].startswith('Run by')][0]['detail'])

    def test_heavily_reported_address(self):
        plain = plain_ip_report(ip('matched', 87, 412, usage_type='Data Center/Web Hosting/Transit'))
        self.assertEqual((plain['tone'], plain['label']), ('danger', 'BAD REPUTATION'))
        self.assertEqual(plain['reasons'][0]['title'], 'Reported for abuse 412 times')
        self.assertIn('7 different reporters', plain['reasons'][0]['detail'])
        self.assertEqual(checks(plain)['Abuse confidence'], ('bad', '87/100'))
        self.assertIn('A server, not a home connection', [r['title'] for r in plain['reasons']])
        self.assertTrue(any('block it' in a for a in plain['actions']))

    def test_discounted_reports_on_shared_infrastructure(self):
        plain = plain_ip_report(ip('matched', 0, 35, is_whitelisted=True))
        self.assertEqual(plain['tone'], 'safe')
        self.assertEqual(plain['reasons'][0]['title'], 'Reports, but discounted')
        self.assertEqual(checks(plain)['Abuse reports'], ('info', '35 in 90 days'))

    def test_tor_exit_is_a_caution(self):
        plain = plain_ip_report(ip(is_tor=True))
        self.assertEqual(plain['tone'], 'caution')
        self.assertIn('Tor', plain['summary'])
        self.assertEqual(checks(plain)['Tor network'], ('warn', 'Yes'))

    def test_unavailable_reputation_is_not_safe(self):
        plain = plain_ip_report({'ip': '203.0.113.9', 'reputation': {'status': 'unavailable'}})
        self.assertEqual(plain['tone'], 'unknown')
        self.assertEqual(checks(plain)['Abuse reports'], ('na', 'Not checked'))
        self.assertEqual(plain_ip_report(None)['tone'], 'unknown')


def domain(**changes):
    data = {'domain': 'example.com', 'verdict': 'unknown', 'coverage': {'whois': 'assessed'}, 'age_days': 9000,
            'days_until_expiry': 200, 'status': ['client transfer prohibited'], 'registrar': 'Example Registrar',
            'dns': [{'type': 'A', 'value': '93.184.216.34'}, {'type': 'MX', 'value': 'mx.example.com'}],
            'spf_observation': {'status': 'published'}}
    data.update(changes)
    return data


class DomainSummaryTests(unittest.TestCase):
    def test_established_domain_says_the_site_was_not_checked(self):
        plain = plain_domain_report(domain())
        self.assertEqual(plain['tone'], 'safe')
        self.assertIn('doesn’t open the website', plain['summary'])
        self.assertTrue(any('link scanner' in a for a in plain['actions']))
        self.assertEqual(checks(plain)['Registration status'], ('ok', 'Active'))
        self.assertEqual(checks(plain)['Age'], ('ok', '24 years'))
        self.assertIn('example[.]com', plain['share_text'])

    def test_brand_new_domain(self):
        plain = plain_domain_report(domain(age_days=4))
        self.assertEqual(plain['tone'], 'caution')
        self.assertEqual(plain['reasons'][0]['title'], 'A brand-new domain')
        self.assertEqual(checks(plain)['Age'], ('warn', '4 days'))

    def test_suspended_domain(self):
        plain = plain_domain_report(domain(status=['client hold']))
        self.assertEqual(plain['tone'], 'caution')
        self.assertEqual(plain['summary'], 'The registry has suspended it.')
        self.assertEqual(checks(plain)['Registration status'], ('warn', 'On hold'))

    def test_missing_domain(self):
        plain = plain_domain_report({'domain': 'gogle.cm', 'verdict': 'no_domain', 'dns': [], 'coverage': {'whois': 'not_found'}})
        self.assertEqual((plain['tone'], plain['label']), ('danger', 'NOT A REAL DOMAIN'))
        self.assertEqual(checks(plain), {'Domain exists': ('bad', 'No')})

    def test_registration_unavailable_is_not_safe(self):
        plain = plain_domain_report(domain(coverage={'whois': 'unavailable'}, age_days=None, days_until_expiry=None))
        self.assertEqual(plain['tone'], 'unknown')
        self.assertEqual(plain['reasons'][0]['title'], 'Registration data unavailable')
        self.assertEqual(checks(plain)['Age'], ('na', 'Unknown'))

    def test_bad_input(self):
        plain = plain_domain_report(None)
        self.assertEqual(plain['tone'], 'unknown')
        self.assertTrue(plain['share_text'].startswith('MyScanner couldn’t fully check the domain .'))  # an empty name is not substituted everywhere


class PageTests(unittest.TestCase):
    def render(self, name):
        env = Environment(loader=FileSystemLoader(Path(__file__).resolve().parents[1] / 'templates'))
        env.globals.update(csrf_token=lambda: 't', url_for=lambda e, **kw: '/static/' + kw.get('filename', e),
                           get_flashed_messages=lambda **kw: [], current_user=SimpleNamespace(is_authenticated=False),
                           request=SimpleNamespace(path='/'))
        html = env.get_template(name).render()
        return html, BeautifulSoup(html, 'html.parser')

    def test_summary_first_and_all_evidence_kept(self):
        for name, key, inside in (('ip_check.html', 'ip', ('#stats-grid', '#ip-source-cards', '#ip-findings')),
                                  ('domain_lookup.html', 'domain', ('#stats-grid', '#domain-findings', '#dns-list'))):
            with self.subTest(page=name):
                html, soup = self.render(name)
                self.assertTrue(soup.select_one(f'#{key}-plain').has_attr('hidden'))
                tech = soup.select_one(f'#result-card details#{key}-tech')
                for selector in inside:
                    self.assertIsNotNone(tech.select_one(selector), selector)
                self.assertLess(html.index('plain_report.js'), html.index(f'{key}_workspace.js'))


if __name__ == '__main__':
    unittest.main()
