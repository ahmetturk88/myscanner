import unittest
from unittest.mock import Mock
from services.domain_analyzer import DomainAnalyzer

class DomainWorkspaceTests(unittest.TestCase):
    def analyzer(self):
        a=DomainAnalyzer();a.session=Mock();return a
    def test_invalid_inputs_never_fetch_and_close(self):
        for value in ['127.0.0.1','localhost','example.com/path','https://u:p@example.com','example.com?x=1','a.local','example.com#x']:
            a=self.analyzer();self.assertIn('error',a.analyze_domain(value));a.session.get.assert_not_called();a.session.close.assert_called_once()
    def test_dns_actual_record_type_and_empty_state(self):
        a=self.analyzer();a._json=Mock(side_effect=[{'Status':0,'Answer':[{'type':5,'data':'alias.example.net','TTL':60}] }]+[{'Status':0}]*6)
        rows,status=a._get_dns_records('example.com');self.assertEqual(rows[0]['type'],'CNAME');self.assertEqual(a.dns_evidence['AAAA']['status'],'no_record');self.assertEqual(status,'assessed')
    def test_failure_is_not_absence_or_safe(self):
        a=self.analyzer();a._json=Mock(side_effect=RuntimeError('private-secret'));r=a.analyze_domain('example.com');self.assertEqual(r['assessment']['score'],0);self.assertEqual(r['verdict'],'unknown');self.assertNotIn('private-secret',str(r));self.assertEqual(r['dns_evidence']['A']['status'],'unavailable')
    def test_rdap_dates_and_identity(self):
        a=self.analyzer();a._json=Mock(side_effect=[{'services':[[['com'],['https://registry.example/']]]},{'objectClassName':'domain','ldhName':'example.com','events':[{'eventAction':'registration','eventDate':'2000-01-01T00:00:00Z'}]}]);r=a._get_whois_info('example.com');self.assertGreater(r['age_days'],9000);self.assertIsNone(r['days_until_expiry'])
    def test_rdap_wrong_identity_is_unavailable(self):
        a=self.analyzer();a._json=Mock(side_effect=[{'services':[[['com'],['https://registry.example/']]]},{'objectClassName':'domain','ldhName':'other.com'}]);self.assertEqual(a._get_whois_info('example.com')['_whois_status'],'unavailable')
    def test_responses_closed_on_bad_json(self):
        a=self.analyzer();response=a.session.get.return_value;response.status_code=200;response.json.return_value=[]
        with self.assertRaises(ValueError):a._json('https://dns.google/resolve',{})
        response.close.assert_called_once()
    def test_unicode_normalization(self):
        self.assertEqual(DomainAnalyzer.normalize('bücher.de'),'xn--bcher-kva.de')
if __name__=='__main__':unittest.main()
