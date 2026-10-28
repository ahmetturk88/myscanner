import copy
import unittest
from unittest.mock import patch
from services.email_assessment import assess_email
from services.email_checker import AdvancedEmailChecker

class AssessmentTests(unittest.TestCase):
    def baseline(self):
        return {'dns': {'mx': {'status':'found','records':[{'exchange':'mx.example.org'}]}, 'spf':{'status':'found'}, 'dmarc':{'status':'found','policy':'reject'}}, 'smtp':{'coverage_status':'checked','valid':True}, 'blacklist':{'coverage_status':'completed','is_blacklisted':False}, 'domain_info':{'age_days':100}}
    def test_full_evidence_has_bounded_index_and_explicit_unchecked_features(self):
        r=self.baseline();before=copy.deepcopy(r);a=assess_email(r)
        self.assertEqual(a['score'],100);self.assertEqual(sum(c['weight'] for c in a['categories']),100)
        self.assertEqual(r,before);self.assertIn('DKIM',str(a['not_checked']))
    def test_missing_checks_reduce_index_without_becoming_risk(self):
        r=self.baseline();r['smtp']={'coverage_status':'skipped','valid':None};r['blacklist']['coverage_status']='partial'
        a=assess_email(r);self.assertEqual((a['score'],a['risk_deduction'],a['coverage_penalty']),(95,0,5));self.assertEqual(a['verdict'],'unknown')
        self.assertIn('SMTP',str(a['not_checked']))
    def test_disabled_probe_and_one_answering_blocklist_can_be_clean(self):
        # The live server: SMTP probing off, Spamhaus refuses shared resolvers, SpamCop answers.
        r=self.baseline();r['smtp']={'coverage_status':'skipped','valid':None}
        r['blacklist']={'coverage_status':'partial','is_blacklisted':False,'clean_on':['bl.spamcop.net'],'unavailable_on':['zen.spamhaus.org']}
        a=assess_email(r);self.assertEqual(a['verdict'],'no_indicators');self.assertEqual(a['coverage'],'completed')
        self.assertIn('zen.spamhaus.org',str(a['not_checked']))
    def test_requested_probe_that_failed_is_still_a_gap(self):
        r=self.baseline();r['smtp']={'coverage_status':'unavailable','valid':None}
        self.assertEqual(assess_email(r)['verdict'],'unknown')
    def test_risk_and_coverage_are_separate_and_category_deductions_capped(self):
        r=self.baseline();r['blacklist']={'is_blacklisted':True};r['is_disposable']=True;r['smtp']['valid']=False
        a=assess_email(r);self.assertEqual(a['score'],60);self.assertEqual(a['risk_deduction'],40);self.assertEqual(a['verdict'],'review')
        for c in a['categories']:self.assertLessEqual(c['risk_deduction']+c['coverage_deduction'],c['weight'])
    def test_null_mx_and_monitoring_policy_have_explanations(self):
        r=self.baseline();r['dns']['mx']['records']=[{'exchange':'.'}];r['dns']['dmarc']['policy']='none'
        a=assess_email(r);self.assertEqual(a['score'],80);self.assertIn('null MX',str(a['findings']))
        self.assertIn('p=none',str(a['findings']))
    def test_spf_ptr_is_a_note_not_a_risk(self):
        # turkcell.com.tr uses ptr; RFC 7208 discourages it but the policy still works.
        from services.email_policy_audit import audit_spf
        audit=audit_spf('example.org',['v=spf1 ptr -all'],lambda name,kind:([],'not_found'))
        self.assertTrue(audit['configuration_valid']);self.assertIn('ptr',str(audit['notes']))
        r=self.baseline();r['dns']['spf']['audit']=audit
        a=assess_email(r);self.assertEqual(a['verdict'],'no_indicators');self.assertIn('ptr mechanism',str(a['findings']))
    def test_monitoring_dmarc_alone_is_a_note_not_a_risk(self):
        # gmail.com publishes p=none; its addresses must not need review for that alone.
        r=self.baseline();r['dns']['dmarc']['policy']='none'
        a=assess_email(r);self.assertEqual(a['verdict'],'no_indicators');self.assertEqual(a['risk_deduction'],0)
        self.assertIn('p=none',str(a['findings']))
    def test_malformed_records_and_nonfinite_age_never_confirm_full_coverage(self):
        for records in (None,{},'bad'):
            r=self.baseline();r['dns']['mx']['records']=records;r['domain_info']['age_days']=float('nan')
            self.assertEqual(assess_email(r)['coverage'],'partial')
    def test_smtp_is_opt_in_and_invalid_consent_is_rejected(self):
        c=AdvancedEmailChecker();self.addCleanup(c.executor.shutdown,wait=False)
        with patch.object(c,'validate_format',return_value=(True,'user@example.org',{})),patch.object(c,'check_dns_records',return_value={}),patch.object(c,'check_blacklists',return_value={}),patch.object(c,'check_domain_info',return_value={}),patch.object(c,'check_smtp',return_value={'valid':True,'coverage_status':'checked'}) as smtp:
            self.assertEqual(c.check_all('user@example.org')['smtp']['coverage_status'],'skipped');smtp.assert_not_called()
            c.check_all('user@example.org',verify_smtp=True);smtp.assert_called_once_with('user@example.org')
            with self.assertRaises(ValueError):c.check_all('user@example.org',verify_smtp='true')
    def test_nonexistent_domain_scores_zero_with_full_coverage(self):
        r=self.baseline();r['dns']={'domain_status':'not_found','mx':{'status':'not_found','records':[]}}
        r['blacklist']={'coverage_status':'not_applicable'};r['smtp']={'coverage_status':'not_applicable'};r['domain_info']={}
        a=assess_email(r)
        self.assertEqual((a['score'],a['verdict'],a['coverage'],a['missing_checks']),(0,'no_domain','completed',[]))
        self.assertIn('NXDOMAIN',a['findings'][0]['message'])
        self.assertEqual(sum(c['risk_deduction'] for c in a['categories']),100)
    def test_nxdomain_stops_lookups_and_skips_network_checks(self):
        import dns.resolver
        c=AdvancedEmailChecker();self.addCleanup(c.executor.shutdown,wait=False)
        with patch('services.email_checker.dns.resolver.resolve',side_effect=dns.resolver.NXDOMAIN()) as resolve:
            r=c.check_dns_records('missing.example')
        self.assertEqual(r['domain_status'],'not_found');resolve.assert_called_once()
        self.assertEqual([r[k]['status'] for k in ('mx','spf','dmarc')],['not_found']*3)
        with patch.object(c,'validate_format',return_value=(True,'a@missing.example',{})),patch.object(c,'check_dns_records',return_value=r),patch.object(c,'check_blacklists') as bl,patch.object(c,'check_domain_info') as whois,patch.object(c,'check_smtp') as smtp:
            report=c.check_all('a@missing.example',verify_smtp=True)
        bl.assert_not_called();whois.assert_not_called();smtp.assert_not_called()
        self.assertEqual((report['verdict'],report['quality_score']),('no_domain',0))
    def test_missing_mx_on_existing_domain_is_not_nxdomain(self):
        import dns.resolver
        c=AdvancedEmailChecker();self.addCleanup(c.executor.shutdown,wait=False)
        with patch('services.email_checker.dns.resolver.resolve',side_effect=dns.resolver.NoAnswer()):r=c.check_dns_records('example.org')
        self.assertEqual((r['domain_status'],r['mx']['status']),('found','not_found'))
    def test_dns_failure_is_unavailable_and_dkim_is_not_checked(self):
        c=AdvancedEmailChecker();self.addCleanup(c.executor.shutdown,wait=False)
        with patch('services.email_checker.dns.resolver.resolve',side_effect=TimeoutError()):r=c.check_dns_records('example.org')
        self.assertEqual([r[k]['status'] for k in ('mx','spf','dmarc')],['unavailable']*3)
        self.assertIsNone(r['dkim']['exists']);self.assertEqual(r['dkim']['status'],'not_checked')
    def test_blocklist_error_codes_are_not_malicious_listings(self):
        c=AdvancedEmailChecker();self.addCleanup(c.executor.shutdown,wait=False)
        with patch('services.email_checker.BLACKLISTS',['source.example']),patch('services.email_checker.dns.resolver.resolve',return_value=['127.255.255.254']):
            r=c.check_blacklists('example.org',ip='8.8.8.8')
        self.assertFalse(r['is_blacklisted']);self.assertEqual(r['coverage_status'],'partial');self.assertEqual(r['unavailable_on'],['source.example'])

if __name__=='__main__':unittest.main()
