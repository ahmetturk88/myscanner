import copy
import unittest
from services.url_assessment import assess_url
from services.url_failure_diagnostic import failure_diagnostic


def reports():
    provider={'verdict':'harmless','trust_score':100,'phishing':{'in_database':False,'verified':False,'valid':False}}
    local={'urlvet':copy.deepcopy(provider),'structure':{'is_https':True},'ssl':{'valid':True},'security_headers':{'score':100},'phishing':{'risk_score':0}}
    deep={'urlvet':copy.deepcopy(provider),'structure':{'is_https':True},'ssl':{'valid':True},'page_content':{'title':'Example','content_risk_score':0},'behavior':{'behavior_risk_score':0},'osint':{'urlhaus_status':'not_found'}}
    return local,deep


class AssessmentTests(unittest.TestCase):
    def test_complete_evidence_and_input_purity(self):
        local,deep=reports();before=copy.deepcopy((local,deep));r=assess_url(local,deep)
        self.assertEqual((r['score'],r['verdict'],r['coverage']),(100,'harmless','completed'))
        self.assertEqual((local,deep),before)
        self.assertEqual(r,assess_url(local,deep))
    def test_content_affects_overall_without_provider_score_change(self):
        local,deep=reports();deep['page_content']['content_risk_score']=80
        self.assertEqual(assess_url(local,deep)['score'],80)
    def test_source_scores_are_not_averaged(self):
        local,deep=reports();baseline=assess_url(local,deep)
        local['urlvet']['trust_score']=1;deep['urlvet']['trust_score']=37
        self.assertEqual(assess_url(local,deep),baseline)
    def test_duplicate_certificate_finding_counts_once(self):
        local,deep=reports();local['ssl']['valid']=False;deep['ssl']['valid']=False
        deep['urlvet']['ssl_info']={'chain_valid':False}
        r=assess_url(local,deep);self.assertEqual(r['score'],80)
        self.assertEqual([x['code'] for x in r['reasons']],['tls_invalid'])
    def test_invalid_certificate_is_never_clean(self):
        local,deep=reports();local['ssl']={'valid':False,'verification_error':'certificate has expired'}
        r=assess_url(local,deep);self.assertEqual(r['verdict'],'suspicious')
        self.assertIn('tls_invalid',[x['code'] for x in r['reasons']])
    def test_plain_http_destination_is_never_clean(self):
        local,deep=reports()
        for data in (local,deep):data['structure']['is_https']=False;data.pop('ssl')
        deep['behavior'].update(original_url='http://example.org/',final_url='http://example.org/',error=None)
        r=assess_url(local,deep);self.assertEqual(r['verdict'],'suspicious')
        self.assertIn('no_https',[x['code'] for x in r['reasons']])
    def test_http_that_upgrades_to_https_on_the_same_site_is_not_penalized(self):
        local,deep=reports()
        for data in (local,deep):data['structure']['is_https']=False;data.pop('ssl')
        deep['behavior'].update(original_url='http://github.com/',final_url='https://github.com/',error=None)
        r=assess_url(local,deep);self.assertEqual(r['verdict'],'harmless')
        self.assertNotIn('no_https',[x['code'] for x in r['reasons']])
        deep['behavior'].update(final_url='https://evil.example/')
        self.assertIn('no_https',[x['code'] for x in assess_url(local,deep)['reasons']])
    def test_shortener_is_removed_from_behavior_subtotal(self):
        local,deep=reports();local['is_shortened']=True;deep['behavior'].update(is_shortened=True,behavior_risk_score=15)
        self.assertEqual(assess_url(local,deep)['score'],95)
    def test_provider_content_and_redirect_evidence_affect_overall(self):
        local,deep=reports();deep['urlvet']['content']={'brand_mismatch':True,'has_hidden_iframe':True}
        deep['urlvet']['analysis']={'chain_length':5}
        r=assess_url(local,deep);self.assertEqual(r['score'],82)
        self.assertEqual({x['code'] for x in r['reasons']},{'brand_mismatch','hidden_iframe','redirect_behavior'})
    def test_urlhaus_match_overrides_clean_provider_score(self):
        local,deep=reports();deep['osint']={'urlhaus':True,'urlhaus_status':'matched'}
        self.assertEqual(assess_url(local,deep)['verdict'],'malicious')
    def test_verified_phishing_overrides_high_scores(self):
        local,deep=reports();deep['urlvet']['phishing']={'in_database':True,'verified':True,'valid':True}
        r=assess_url(local,deep);self.assertEqual(r['verdict'],'malicious');self.assertLessEqual(r['score'],10)
        self.assertTrue(r['threat_override'])
    def test_unverified_report_alone_is_noted_but_not_a_threat(self):
        local,deep=reports();deep['urlvet']['phishing']={'in_database':True,'verified':False,'valid':False}
        r=assess_url(local,deep);self.assertEqual(r['verdict'],'harmless');self.assertEqual(r['coverage'],'completed')
        self.assertIn('unverified_report',[x['code'] for x in r['reasons']]);self.assertFalse(r['threat_override'])
    def test_unverified_report_with_a_look_alike_signal_needs_review(self):
        local,deep=reports();deep['urlvet']['phishing']={'in_database':True,'verified':False,'valid':False}
        deep['urlvet']['typosquatting']={'is_suspicious':True}
        r=assess_url(local,deep);self.assertEqual(r['verdict'],'suspicious');self.assertFalse(r['threat_override'])
    def test_look_alike_signal_without_a_report_is_unchanged(self):
        local,deep=reports();deep['urlvet']['typosquatting']={'is_suspicious':True}
        self.assertEqual(assess_url(local,deep)['verdict'],'harmless')
    def test_missing_or_failed_content_cannot_confirm_safety(self):
        for content in ({},{'content_risk_score':0},{'title':'','content_risk_score':0,'error':'timeout'}):
            local,deep=reports();deep['page_content']=content;r=assess_url(local,deep)
            self.assertEqual(r['verdict'],'unknown');self.assertTrue(r['provisional'])
    def test_no_evidence_has_no_numeric_score(self):
        r=assess_url({},{});self.assertIsNone(r['score']);self.assertEqual(r['verdict'],'unknown')
    def test_invalid_numeric_and_nested_provider_data(self):
        for value in (True,float('nan'),float('inf'),-1,101,'0'):
            local,deep=reports();deep['page_content']['content_risk_score']=value
            self.assertEqual(assess_url(local,deep)['coverage'],'partial')
        local,deep=reports();deep['urlvet']['url_features']='bad';deep['behavior']='bad';deep['osint']='bad'
        self.assertEqual(assess_url(local,deep)['coverage'],'partial')
    def test_legacy_false_urlhaus_does_not_mean_checked(self):
        local,deep=reports();deep['osint']={'urlhaus':False}
        r=assess_url(local,deep);self.assertEqual(r['verdict'],'unknown');self.assertEqual(r['score'],95);self.assertEqual(r['coverage_penalty'],5);self.assertEqual(r['evidence_score'],100)
    def test_unconfirmed_analyzer_threat_is_not_a_verdict(self):
        # v5: a heuristic analyzer verdict never confirms a threat by itself.
        local,deep=reports();local.update(verdict='malicious',urlvet={'error':'offline'})
        r=assess_url(local,deep);self.assertEqual((r['verdict'],r['coverage']),('unknown','partial'));self.assertFalse(r['threat_override'])
    def test_saved_verdict_is_not_rescored_silently(self):
        from services.url_assessment import saved_assessment
        local,deep=reports()
        stored={'policy_version':'url-evidence-v4','verdict':'malicious','score':10,'coverage':'completed'}
        r=saved_assessment({'aggregate_assessment':stored},local,deep)
        self.assertEqual((r['verdict'],r['score'],r['policy_version']),('malicious',10,'url-evidence-v4'))
        self.assertEqual(r['current_policy']['policy_version'],'url-evidence-v7')
        self.assertEqual(r['current_policy']['verdict'],assess_url(local,deep)['verdict'])
        current=saved_assessment({'aggregate_assessment':assess_url(local,deep)},local,deep)
        self.assertNotIn('current_policy',current)
        legacy=saved_assessment({},local,deep)
        self.assertTrue(legacy['assessed_at_read_time'])
    def test_plain_http_is_a_finding_not_a_threat(self):
        local,deep=reports();local.update(verdict='malicious',structure={'is_https':False,'contains_ip':False},ssl={'valid':False,'error':'Not using HTTPS'})
        r=assess_url(local,deep)
        self.assertEqual(r['policy_version'],'url-evidence-v7');self.assertNotIn(r['verdict'],('malicious','high_risk'))
        self.assertIn('no_https',[x['code'] for x in r['reasons']])
    def test_unconfirmed_provider_threat_requests_review(self):
        local,deep=reports();deep['urlvet']['verdict']='malicious'
        r=assess_url(local,deep);self.assertEqual(r['verdict'],'suspicious');self.assertFalse(r['threat_override'])
        self.assertIn('A provider reports a threat; confirmation details require review',r['missing_checks'])
    def test_missing_content_loses_its_category_weight(self):
        local,deep=reports();deep['page_content']={}
        r=assess_url(local,deep);self.assertEqual(r['score'],75);self.assertEqual(r['coverage_deductions']['content'],25)
    def test_risk_and_coverage_deductions_are_both_applied(self):
        local,deep=reports();deep['osint']={};deep['page_content']['content_risk_score']=80
        r=assess_url(local,deep);self.assertEqual(r['score'],75);self.assertEqual(r['evidence_score'],80);self.assertEqual(r['coverage_penalty'],5)
    def test_duplicated_source_gap_counts_once(self):
        local,deep=reports();local['urlvet']=deep['urlvet']={'error':'offline'}
        r=assess_url(local,deep);self.assertEqual(r['coverage_penalty'],5)
    def test_whois_only_failure_retains_other_evidence_and_deduplicates_gap(self):
        local,deep=reports()
        for report in (local,deep):
            report['urlvet'].update(incomplete=True,errors=['whois_lookup: private SECRET'],
                                    content={'brand_mismatch':True})
        before=copy.deepcopy((local,deep))
        r=assess_url(local,deep)
        self.assertEqual(r['score'],85)
        self.assertEqual(r['coverage_deductions']['identity'],5)
        self.assertEqual(r['coverage_deductions']['reputation'],0)
        self.assertEqual(r['components']['content']['deduction'],10)
        self.assertEqual(r['missing_checks'],['URLVet domain registration (WHOIS) check unavailable'])
        self.assertNotIn('SECRET',str(r))
        self.assertEqual((local,deep),before)
    def test_whois_failure_does_not_discard_verified_phishing(self):
        local,deep=reports()
        deep['urlvet'].update(incomplete=True,errors=['whois_lookup: invalid'])
        deep['urlvet']['phishing']={'in_database':True,'verified':True,'valid':True}
        r=assess_url(local,deep)
        self.assertEqual(r['verdict'],'malicious');self.assertTrue(r['threat_override'])
    def test_unknown_or_mixed_provider_failure_is_not_treated_as_whois_only(self):
        for errors in (['whois_lookup: invalid','unknown: timeout'], 'whois_lookup: invalid', [None], []):
            local,deep=reports()
            deep['urlvet'].update(incomplete=True,errors=errors,content={'brand_mismatch':True})
            r=assess_url(local,deep)
            self.assertEqual(r['components']['content']['deduction'],0)
            self.assertIn('deep URLVet assessment unavailable or incomplete',r['missing_checks'])
    def test_failure_diagnostic_does_not_contain_exception_text(self):
        try:raise RuntimeError('postgresql://user:SECRET@host/private?token=SECRET')
        except RuntimeError as error:r=failure_diagnostic(error,'local_analysis')
        self.assertEqual(r,{'stage':'local_analysis','type':'RuntimeError','locations':[]})

if __name__=='__main__':unittest.main()
