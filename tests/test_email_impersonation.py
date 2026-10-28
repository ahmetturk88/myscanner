"""email-evidence-v4: a copied brand name or a Web Risk listing decides on its own (scam domains set up SPF too)."""
import unittest
from unittest.mock import patch

from services.email_assessment import assess_email
from services.email_checker import AdvancedEmailChecker
from services.email_report_view import plain_email_report
from services.report_i18n import translate_plain


def report(domain, age=9000, web_risk=None, registrar='Example Registrar'):
    checker = AdvancedEmailChecker(None)
    data = {'email': 'destek@' + domain, 'domain': domain,
            'dns': {'mx': {'status': 'found', 'records': [{'exchange': 'mx.' + domain}], 'infrastructure': []},
                    'spf': {'status': 'found', 'audit': {'configuration_valid': True}},
                    'dmarc': {'status': 'found', 'policy': 'reject', 'audit': {'configuration_valid': True}}},
            'smtp': {'coverage_status': 'skipped'},
            'blacklist': {'coverage_status': 'completed', 'clean_on': ['bl.spamcop.net'], 'is_blacklisted': False},
            'domain_info': {'age_days': age, 'registrar': registrar}, 'is_disposable': False, 'is_free': False,
            'name_signals': checker.check_name(domain), 'web_risk': web_risk or {'status': 'not_found', 'threat_types': []}}
    data['assessment'] = assess_email(data)
    return data


def verdict(domain, **kwargs):
    return report(domain, **kwargs)['assessment']['verdict']


class NameTests(unittest.TestCase):
    def test_tricks_in_the_name_are_dangerous_even_when_set_up_properly(self):
        for domain in ('garanti.com.tr.giris-dogrula.com', 'paypa1.com', 'xn--pple-43d.com', 'httpsgaranti-guvenlik.com'):
            self.assertEqual(verdict(domain, age=900), 'dangerous', domain)

    def test_a_brand_name_on_a_new_or_cheap_domain(self):
        self.assertEqual(verdict('ptt-kargo-odeme.com', age=20), 'dangerous')
        self.assertEqual(verdict('yurticikargo-takip.xyz', age=900), 'dangerous')
        self.assertEqual(verdict('ptt-kargo-odeme.com', age=900), 'review')
        self.assertEqual(verdict('ptt-kargo-odeme.com', age=None), 'review')
        self.assertEqual(verdict('hepsiburda.com', age=900), 'review')      # one letter off
        self.assertEqual(verdict('hepsiburda.com', age=40), 'dangerous')

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


class GuardDomainTests(unittest.TestCase):
    def test_an_old_look_alike_held_by_a_brand_protection_registrar(self):
        # paypa1.com: 26 years old, MarkMonitor, SPF -all. It is PayPal's own guard domain.
        data = report('paypa1.com', age=9503, registrar='MarkMonitor Inc.')
        self.assertEqual(data['assessment']['verdict'], 'review')
        self.assertEqual(data['assessment']['guard_domain'], 'PayPal')
        plain = plain_email_report(data)
        self.assertEqual(plain['tone'], 'caution')
        self.assertEqual(plain['reasons'][0]['title'], 'Probably a brand’s guard domain')
        self.assertIn('belongs to PayPal', plain['summary'])
        self.assertIn(('Copies a brand’s name', 'warn', 'Guard domain'), [(c['name'], c['state'], c['result']) for c in plain['checks']])
        turkish = translate_plain(plain, 'tr')
        self.assertIn('PayPal şirketine ait', turkish['summary'])
        self.assertIn('marka koruma', turkish['reasons'][0]['detail'])

    def test_a_new_domain_or_an_ordinary_registrar_stays_dangerous(self):
        self.assertEqual(verdict('paypa1.com', age=9503), 'dangerous')
        self.assertEqual(report('paypa1.com', age=100, registrar='MarkMonitor Inc.')['assessment']['verdict'], 'dangerous')


class ReportTests(unittest.TestCase):
    def test_dangerous_report_in_both_languages(self):
        plain = plain_email_report(report('ptt-kargo-odeme.com', age=20))
        self.assertEqual((plain['tone'], plain['label']), ('danger', 'DANGEROUS'))
        self.assertIn('PTT Kargo', plain['summary'])
        self.assertEqual(plain['reasons'][0]['title'], 'It copies a well-known name')
        self.assertIn('isn’t one of PTT Kargo’s known domains', plain['reasons'][0]['detail'])
        self.assertIn(('Copies a brand’s name', 'bad', 'Yes'), [(c['name'], c['state'], c['result']) for c in plain['checks']])
        turkish = translate_plain(plain, 'tr')
        self.assertEqual(turkish['label'], 'TEHLİKELİ')
        self.assertIn('PTT Kargo adını kullanıyor', turkish['reasons'][0]['detail'])
        self.assertIn('dolandırıcılık', turkish['summary'])
        self.assertIn('dolandırıcılıkta', turkish['share_text'])
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
