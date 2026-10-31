"""The plain-language summary at the top of an email report says only what the checks recorded."""
import unittest

from services.email_assessment import assess_email
from services.email_report_view import plain_email_report


def report(**changes):
    data = {'email': 'anna@example.com', 'domain': 'example.com',
            'dns': {'mx': {'status': 'found', 'records': [{'exchange': 'mx.example.com'}], 'infrastructure': []},
                    'spf': {'status': 'found', 'audit': {'configuration_valid': True}},
                    'dmarc': {'status': 'found', 'policy': 'reject', 'audit': {'configuration_valid': True}}},
            'smtp': {'coverage_status': 'skipped'},
            'blacklist': {'coverage_status': 'completed', 'clean_on': ['zen.spamhaus.org'], 'is_blacklisted': False},
            'domain_info': {'age_days': 9000}, 'is_disposable': False, 'is_free': False}
    data.update(changes)
    data['assessment'] = assess_email(data)
    return data


def checks(plain):
    return {c['name']: (c['state'], c['result']) for c in plain['checks']}


class PlainEmailReportTests(unittest.TestCase):
    def test_well_configured_domain(self):
        plain = plain_email_report(report())
        self.assertEqual((plain['tone'], plain['headline']), ('safe', 'No warning signs found'))
        self.assertIn('doesn’t prove who is behind', plain['summary'])
        self.assertTrue(all(state == 'ok' for state, _ in checks(plain).values()))
        self.assertNotIn('Mailbox', checks(plain))  # the probe was not run, so it is not listed
        self.assertEqual(plain['url'], {'prefix': 'anna@', 'host': 'example.com', 'rest': ''})

    def test_free_provider_and_monitoring_dmarc_are_information(self):
        dns = report()['dns']
        dns['dmarc'] = {'status': 'found', 'policy': 'none', 'audit': {'configuration_valid': True}}
        data = report(email='x@gmail.com', domain='gmail.com', is_free=True, dns=dns)
        plain = plain_email_report(data)
        self.assertEqual(data['assessment']['verdict'], 'no_indicators')
        self.assertEqual(plain['tone'], 'safe')
        self.assertEqual(checks(plain)['Fake-mail protection'], ('info', 'Monitoring only'))
        self.assertIn('A free email service', [r['title'] for r in plain['reasons']])

    def test_throwaway_new_domain(self):
        plain = plain_email_report(report(is_disposable=True, domain_info={'age_days': 10}))
        self.assertEqual(plain['tone'], 'caution')
        self.assertEqual([r['title'] for r in plain['reasons']], ['A throwaway address', 'A brand-new domain'])
        self.assertIn('throwaway', plain['summary'])
        self.assertEqual(checks(plain)['Domain age'], ('warn', '10 days'))

    def test_spoofable_domain(self):
        dns = report()['dns']
        dns['dmarc'] = {'status': 'not_found'}
        dns['spf'] = {'status': 'not_found'}
        plain = plain_email_report(report(dns=dns))
        self.assertEqual(plain['tone'], 'caution')
        self.assertEqual(plain['reasons'][0]['title'], 'Email from this domain is easy to fake')
        self.assertIn('SPF or DMARC', plain['reasons'][0]['detail'])
        self.assertEqual(checks(plain)['Fake-mail protection'], ('warn', 'None'))
        self.assertTrue(any('may be faked' in a for a in plain['actions']))

    def test_blocklisted_server_is_not_called_a_scammer(self):
        plain = plain_email_report(report(blacklist={'coverage_status': 'completed', 'is_blacklisted': True, 'blacklisted_on': ['zen.spamhaus.org']}))
        reason = plain['reasons'][0]
        self.assertEqual(reason['title'], 'Its mail server is on a spam blocklist')
        self.assertIn('zen.spamhaus.org', reason['detail'])
        self.assertIn('not proof', reason['detail'])

    def test_domain_that_does_not_exist(self):
        plain = plain_email_report(report(email='a@gmial.co', domain='gmial.co', dns={'domain_status': 'not_found'}))
        self.assertEqual((plain['tone'], plain['label']), ('danger', 'NOT A REAL ADDRESS'))
        self.assertEqual(checks(plain), {'Domain exists': ('bad', 'No'), 'Receives email': ('bad', 'No')})
        self.assertIn('typo', plain['actions'][0])
        # A domain that doesn't exist has no SPF or DMARC, but "easy to fake" would contradict "not a real address".
        missing = report(email='destek@garanti-bbva-guvenlik.com', domain='garanti-bbva-guvenlik.com',
                         dns={'domain_status': 'not_found', 'spf': {'status': 'not_found'}, 'dmarc': {'status': 'not_found'}})
        titles = [r['title'] for r in plain_email_report(missing)['reasons']]
        self.assertNotIn('Email from this domain is easy to fake', titles)

    def test_missing_checks_never_read_as_fine(self):
        plain = plain_email_report(report(blacklist={'coverage_status': 'unavailable'}, domain_info={'error': 'x'}))
        self.assertEqual(plain['tone'], 'unknown')
        self.assertEqual(plain['reasons'][0]['title'], 'Some checks couldn’t run')
        self.assertEqual(checks(plain)['Spam blocklists'], ('na', 'Not checked'))
        self.assertEqual(checks(plain)['Domain age'], ('na', 'Unknown'))

    def test_rejected_mailbox_probe(self):
        plain = plain_email_report(report(smtp={'coverage_status': 'checked', 'valid': False}))
        self.assertEqual(checks(plain)['Mailbox'], ('warn', 'Rejected'))
        self.assertIn('The mail server rejected this address', [r['title'] for r in plain['reasons']])

    def test_bad_input(self):
        plain = plain_email_report(None)
        self.assertEqual(plain['tone'], 'unknown')
        plain = plain_email_report({'assessment': {'verdict': 'evil'}, 'email': 7})
        self.assertEqual(plain['url']['host'], '')


class EmailPageTests(unittest.TestCase):
    def test_summary_first_and_all_evidence_kept(self):
        from pathlib import Path
        from types import SimpleNamespace
        from bs4 import BeautifulSoup
        from jinja2 import Environment, FileSystemLoader
        env = Environment(loader=FileSystemLoader(Path(__file__).resolve().parents[1] / 'templates'))
        env.globals.update(csrf_token=lambda: 't', url_for=lambda e, **kw: '/static/' + kw.get('filename', e),
                           get_flashed_messages=lambda **kw: [], current_user=SimpleNamespace(is_authenticated=False),
                           request=SimpleNamespace(path='/email-check'))
        html = env.get_template('email_check.html').render(smtp_probe_enabled=False)
        soup = BeautifulSoup(html, 'html.parser')
        self.assertTrue(soup.select_one('#email-plain').has_attr('hidden'))
        tech = soup.select_one('details#email-tech')
        for selector in ('#verdict-banner', '#blocklist-status', '#quality-items', '#dns-evidence', '#details-table'):
            self.assertIsNotNone(tech.select_one(selector), selector)
        self.assertIn('plain_report.js', html)


if __name__ == '__main__':
    unittest.main()
