"""email-evidence-v5: naming signals need review; supported source evidence can escalate."""
import unittest
from unittest.mock import patch

from services.email_assessment import assess_email
from services.email_checker import AdvancedEmailChecker
from services.email_report_view import plain_email_report
from services.report_i18n import translate_plain


def report(domain, age=9000, web_risk=None, registrar='Example Registrar', local='destek', free=False):
    checker = AdvancedEmailChecker(None)
    data = {'email': local + '@' + domain, 'domain': domain,
            'dns': {'mx': {'status': 'found', 'records': [{'exchange': 'mx.' + domain}], 'infrastructure': []},
                    'spf': {'status': 'found', 'audit': {'configuration_valid': True}},
                    'dmarc': {'status': 'found', 'policy': 'reject', 'audit': {'configuration_valid': True}}},
            'smtp': {'coverage_status': 'skipped'},
            'blacklist': {'coverage_status': 'completed', 'clean_on': ['bl.spamcop.net'], 'is_blacklisted': False},
            'domain_info': {'age_days': age, 'registrar': registrar}, 'is_disposable': False, 'is_free': free,
            'local_signals': checker.check_local(local, domain),
            'name_signals': checker.check_name(domain), 'web_risk': web_risk or {'status': 'not_found', 'threat_types': []}}
    data['assessment'] = assess_email(data)
    return data


def verdict(domain, **kwargs):
    return report(domain, **kwargs)['assessment']['verdict']


class NameTests(unittest.TestCase):
    def test_tricks_in_the_name_require_review_even_when_set_up_properly(self):
        for domain in ('garanti.com.tr.giris-dogrula.com', 'paypa1.com', 'xn--pple-43d.com', 'httpsgaranti-guvenlik.com'):
            self.assertEqual(verdict(domain, age=900), 'review', domain)

    def test_a_brand_name_on_a_new_or_cheap_domain(self):
        self.assertEqual(verdict('ptt-kargo-odeme.com', age=20), 'review')
        self.assertEqual(verdict('yurticikargo-takip.xyz', age=900), 'review')
        self.assertEqual(verdict('ptt-kargo-odeme.com', age=900), 'review')
        self.assertEqual(verdict('ptt-kargo-odeme.com', age=None), 'review')
        self.assertEqual(verdict('hepsiburda.com', age=900), 'review')      # one letter off
        self.assertEqual(verdict('hepsiburda.com', age=40), 'review')

    def test_real_and_long_established_domains(self):
        for domain in ('garantibbva.com.tr', 'gmail.com', 'turkiye.gov.tr', 'trendyol.com', 'example.com'):
            self.assertEqual(verdict(domain, age=40), 'no_indicators', domain)
        self.assertEqual(verdict('garantiemeklilik.com.tr', age=9000), 'no_indicators')  # an old group company
        self.assertEqual(report('gmail.com')['name_signals'], [])

    def test_new_cheap_domain_alone_needs_care_not_alarm(self):
        self.assertEqual(verdict('kahve-dukkani.shop', age=60), 'review')
        self.assertEqual(verdict('kahve-dukkani.shop', age=900), 'no_indicators')

    def test_google_web_risk_listing(self):
        listed = {'status': 'matched', 'threat_types': ['SOCIAL_ENGINEERING']}
        data = report('example-shop.com', web_risk=listed)
        self.assertEqual(data['assessment']['verdict'], 'dangerous')
        self.assertLessEqual(data['assessment']['score'], 20)
        plain = plain_email_report(data)
        self.assertEqual(plain['tone'], 'danger')
        self.assertEqual(plain['reasons'][0]['title'], 'Google lists this domain as dangerous')
        self.assertIn(('Google Web Risk', 'bad', 'Listed'), [(c['name'], c['state'], c['result']) for c in plain['checks']])


class LocalPartTests(unittest.TestCase):
    """Real phishing mail (phishing_pot, Oct 2026) puts the disguise before the @."""

    def test_a_bank_or_cargo_name_on_a_free_address_needs_review(self):
        data = report('gmail.com', local='garanti.destek', free=True)
        self.assertEqual(data['assessment']['verdict'], 'review')
        plain = plain_email_report(data)
        self.assertEqual(plain['reasons'][0]['title'], 'A company name appears before @')
        self.assertIn('free email address', plain['reasons'][0]['detail'])
        self.assertEqual(plain['tone'], 'caution')
        self.assertNotIn('scam', plain['summary'])
        turkish = translate_plain(plain, 'tr')
        self.assertIn('ücretsiz bir e-posta adresi', turkish['reasons'][0]['detail'])
        self.assertEqual(turkish['label'], 'DİKKATLİ OL')
        for local in ('netflixfan', 'ahmet88x', 'john.appleseed'):
            self.assertEqual(report('gmail.com', local=local, free=True)['assessment']['verdict'], 'no_indicators', local)

    def test_a_brand_name_before_the_at_on_someone_elses_domain(self):
        self.assertEqual(report('hustle.com.sg', local='paypal-support', age=4000)['assessment']['verdict'], 'review')
        self.assertEqual(report('fresh-mailer.com', local='paypal-support', age=20)['assessment']['verdict'], 'review')
        self.assertEqual(report('garantibbva.com.tr', local='garanti.destek')['assessment']['verdict'], 'no_indicators')

    def test_machine_made_sender_names(self):
        local = 'amendes-gouv-nepasrepondree.5635cbb6-f12a-6a35-1314b814cd19947b'
        data = report('quantumexchanger.com', local=local, age=4000)
        self.assertEqual(data['assessment']['verdict'], 'review')
        self.assertIn('words such as bank or government', str(data['assessment']['findings']))
        self.assertEqual(plain_email_report(data)['reasons'][0]['title'], 'A machine-made sender name')
        self.assertEqual(report('example-shop.com', local='orders', age=4000)['assessment']['verdict'], 'no_indicators')


class GuardDomainTests(unittest.TestCase):
    def test_registrar_and_age_do_not_prove_ownership_or_suppress_lookalikes(self):
        for registrar in ('MarkMonitor Inc.', 'Example Registrar', 'CSC Corporate'):
            data = report('paypa1.com', age=9503, registrar=registrar)
            self.assertEqual(data['assessment']['verdict'], 'review')
            self.assertIsNone(data['assessment']['guard_domain'])
            plain = plain_email_report(data)
            self.assertEqual(plain['tone'], 'caution')
            self.assertNotIn('belongs to', plain['summary'])
            self.assertIn('It copies a well-known name', [r['title'] for r in plain['reasons']])

    def test_malformed_source_match_does_not_confirm_a_threat(self):
        for types in ([], ['unrecognized']):
            data = report('example.com', web_risk={'status': 'matched', 'threat_types': types})
            self.assertEqual(data['assessment']['verdict'], 'unknown')
            self.assertIn('Google Web Risk lookup unavailable', str(data['assessment']['missing_checks']))
            self.assertFalse(any(r['tone'] == 'bad' for r in plain_email_report(data)['reasons']))


class ReportTests(unittest.TestCase):
    def test_heuristic_report_in_both_languages(self):
        plain = plain_email_report(report('ptt-kargo-odeme.com', age=20))
        self.assertEqual((plain['tone'], plain['label']), ('caution', 'BE CAREFUL'))
        self.assertNotIn('as a scam', plain['summary'])
        self.assertEqual(plain['reasons'][0]['title'], 'It copies a well-known name')
        self.assertIn('isn’t one of PTT Kargo’s known domains', plain['reasons'][0]['detail'])
        self.assertIn(('Copies a brand’s name', 'warn', 'Yes'), [(c['name'], c['state'], c['result']) for c in plain['checks']])
        turkish = translate_plain(plain, 'tr')
        self.assertEqual(turkish['label'], 'DİKKATLİ OL')
        self.assertIn('PTT Kargo adını kullanıyor', turkish['reasons'][0]['detail'])
        self.assertNotIn('TEHLİKELİ', turkish['share_text'])
        for action in turkish['actions']:
            self.assertNotIn('Don’t', action)

    def test_one_letter_off_is_a_warning(self):
        plain = plain_email_report(report('hepsiburda.com', age=900))
        self.assertEqual(plain['tone'], 'caution')
        self.assertIn('one letter away from Hepsiburada', plain['reasons'][0]['detail'])


class CheckerTests(unittest.TestCase):
    def test_reputation_outage_is_not_cached(self):
        checker = AdvancedEmailChecker(None)
        stored = []
        with patch('services.web_risk.check_web_risk', return_value={'status': 'unavailable', 'threat_types': []}), \
                patch.object(checker, '_cache_set', side_effect=lambda *a, **k: stored.append(a)):
            self.assertEqual(checker.check_reputation('example.com')['status'], 'unavailable')
        self.assertEqual(stored, [])

    def test_free_mail_domains_skip_name_and_reputation_checks(self):
        checker = AdvancedEmailChecker(None)
        dns = {'domain_status': 'found', 'mx': {'status': 'found', 'records': [], 'infrastructure': []}, 'spf': {}, 'dmarc': {}}
        with patch.object(checker, 'check_dns_records', return_value=dns), \
                patch.object(checker, 'check_blacklists', return_value={}), \
                patch.object(checker, 'check_domain_info', return_value={'age_days': 9000}), \
                patch.object(checker, 'check_reputation', side_effect=AssertionError('no lookup for gmail')):
            result = checker.check_all('someone@gmail.com')
        self.assertEqual(result['name_signals'], [])
        self.assertEqual(result['web_risk']['reason'], 'not_applicable')


if __name__ == '__main__':
    unittest.main()
