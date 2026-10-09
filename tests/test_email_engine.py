import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch, MagicMock
import dns.resolver
from services.email_checker import AdvancedEmailChecker
from services.email_policy_audit import audit_spf, audit_dmarc

class EngineTests(unittest.TestCase):
    def setUp(self):
        self.c=AdvancedEmailChecker();self.addCleanup(self.c.executor.shutdown,wait=False)
    def test_known_provider_never_gets_a_different_provider_suggestion(self):
        for address in ('user@gmail.com','USER@GMAIL.COM','person@mail.com'):
            valid,normalized,details=self.c.validate_format(address)
            self.assertTrue(valid);self.assertEqual(details['suggestions'],[])
    def test_exact_typo_preserves_local_part(self):
        valid,_,details=self.c.validate_format('gmial.com@gmial.com')
        self.assertTrue(valid);self.assertEqual(details['suggestions'][0]['suggested'],'gmial.com@gmail.com')
    def test_aware_and_naive_whois_dates_preserve_metadata(self):
        for date in (datetime(1995,8,13),datetime(1995,8,13,tzinfo=timezone.utc)):
            data=SimpleNamespace(creation_date=date,expiration_date=datetime(2030,1,1),registrar='Example registrar',name_servers=['ns.example.org'])
            with patch.dict('sys.modules',{'whois':SimpleNamespace(whois=lambda _,**kwargs:data)}):r=self.c.check_domain_info('gmail.com')
            self.assertNotIn('error',r);self.assertGreater(r['age_days'],10000);self.assertEqual(r['registrar'],'Example registrar');self.assertEqual(r['expiration_date'],'2030-01-01')
    def test_unavailable_control_query_cannot_claim_clean(self):
        with patch('services.email_checker.dns.resolver.resolve',side_effect=dns.resolver.NXDOMAIN):r=self.c.check_blacklists('example.org',ip='8.8.8.8')
        self.assertFalse(r['clean_on']);self.assertEqual(r['coverage_status'],'partial')
    def test_dnsbl_uses_real_zones_and_sampled_mx_addresses(self):
        queries=[]
        def resolve(name,*args,**kwargs):
            queries.append(name)
            if name.startswith('2.0.0.127.'):return ['127.0.0.2']
            raise dns.resolver.NXDOMAIN
        with patch('services.email_checker.dns.resolver.resolve',side_effect=resolve):r=self.c.check_blacklists('example.org',mx_records=[{'addresses':['8.8.8.8','2001:4860:4860::8888']}])
        self.assertEqual(r['coverage_status'],'completed');self.assertEqual(r['queried_ips'],['8.8.8.8'])
        self.assertIn('8.8.8.8.zen.spamhaus.org',queries);self.assertIn('8.8.8.8.bl.spamcop.net',queries)
    def test_no_starttls_never_discloses_recipient(self):
        smtp=MagicMock();smtp.ehlo.return_value=(250,b'OK');smtp.has_extn.return_value=False
        mx=SimpleNamespace(preference=5,exchange='mx.example.org.')
        with patch('services.email_checker.dns.resolver.resolve',return_value=[mx]),patch('services.email_checker.PublicSMTP',return_value=smtp):r=self.c.check_smtp('user@example.org')
        self.assertIsNone(r['valid']);smtp.rcpt.assert_not_called();smtp.mail.assert_not_called();smtp.close.assert_called_once()
    def test_tls_failure_never_discloses_recipient(self):
        smtp=MagicMock();smtp.ehlo.return_value=(250,b'OK');smtp.has_extn.return_value=True;smtp.starttls.side_effect=OSError('secret')
        mx=SimpleNamespace(preference=5,exchange='mx.example.org.')
        with patch('services.email_checker.dns.resolver.resolve',return_value=[mx]),patch('services.email_checker.PublicSMTP',return_value=smtp):r=self.c.check_smtp('user@example.org')
        self.assertIsNone(r['valid']);smtp.rcpt.assert_not_called();self.assertNotIn('secret',str(r))
    def test_unified_contract_has_no_legacy_safe_or_deliverable_claim(self):
        with patch.object(self.c,'validate_format',return_value=(True,'u@example.org',{})),patch.object(self.c,'check_dns_records',return_value={}),patch.object(self.c,'check_blacklists',return_value={}),patch.object(self.c,'check_domain_info',return_value={}),patch.object(self.c,'check_smtp',return_value={'valid':True,'coverage_status':'checked'}):r=self.c.check_all('u@example.org',verify_smtp=True)
        self.assertEqual(r['quality_score'],r['assessment']['score']);self.assertEqual(r['verdict'],r['assessment']['verdict']);self.assertEqual(r['deliverability'],'PROBE_ACCEPTED');self.assertNotEqual(r['verdict'],'safe')

class PolicyTests(unittest.TestCase):
    def test_nested_spf_and_cycles(self):
        records={'a.example':['v=spf1 include:b.example -all'],'b.example':['v=spf1 ip4:8.8.8.0/24 -all']}
        lookup=lambda name,kind:(records[name],'found')
        r=audit_spf('a.example',records['a.example'],lookup);self.assertTrue(r['configuration_valid']);self.assertEqual(r['dns_terms'],1)
        records['b.example']=['v=spf1 include:a.example -all'];r=audit_spf('a.example',records['a.example'],lookup);self.assertFalse(r['configuration_valid']);self.assertIn('cycle',str(r['issues']))
    def test_spf_budget_caps_dns_work(self):
        calls=[]
        def lookup(name,kind):calls.append(name);return ['v=spf1 include:next'+str(len(calls))+'.example -all'],'found'
        r=audit_spf('example.org',['v=spf1 include:next.example -all'],lookup,budget=3)
        self.assertLessEqual(len(calls),3);self.assertIn('budget',str(r['issues']))
    def test_spf_failure_macro_duplicate_and_permissive_records(self):
        r=audit_spf('example.org',['v=spf1 include:other.example -all'],lambda *args:([],'unavailable'));self.assertEqual(r['status'],'partial');self.assertIsNone(r['configuration_valid'])
        for values in (['v=spf1 +all'],['v=spf1 ip4:bad -all'],['v=spf1 -all','v=spf1 ~all']):self.assertFalse(audit_spf('example.org',values,lambda *args:([],'found'))['configuration_valid'])
        self.assertEqual(audit_spf('example.org',['v=spf1 include:%{d}.example -all'],lambda *args:([],'found'))['status'],'partial')
    def test_dmarc_valid_duplicate_invalid_and_current_default(self):
        self.assertTrue(audit_dmarc(['v=DMARC1; p=reject; adkim=s; aspf=r'])['configuration_valid'])
        self.assertEqual(audit_dmarc(['v=DMARC1; rua=mailto:reports@example.org'])['policy'],'none')
        for records in (['v=DMARC1; p=reject; p=none'],['v=DMARC1; p=bogus'],['v=DMARC1; p=reject; adkim=z'],['v=DMARC1; p=reject','v=DMARC1; p=none']):self.assertFalse(audit_dmarc(records)['configuration_valid'])
        self.assertTrue(audit_dmarc(['v=DMARC1; p=reject; t=y'])['test_mode'])

if __name__=='__main__':unittest.main()
