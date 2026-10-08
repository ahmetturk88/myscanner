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
    def test_unverified_is_not_confirmation(self):
        local,deep=reports();deep['urlvet']['phishing']={'in_database':True,'verified':False,'valid':False}
        r=assess_url(local,deep);self.assertEqual(r['verdict'],'unknown');self.assertEqual(r['coverage'],'partial')
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
        self.assertEqual(assess_url(local,deep)['verdict'],'unknown')
    def test_reported_threat_survives_unavailable_source(self):
        local,deep=reports();local.update(verdict='malicious',urlvet={'error':'offline'})
        r=assess_url(local,deep);self.assertEqual((r['verdict'],r['coverage']),('malicious','partial'))
    def test_failure_diagnostic_does_not_contain_exception_text(self):
        try:raise RuntimeError('postgresql://user:SECRET@host/private?token=SECRET')
        except RuntimeError as error:r=failure_diagnostic(error,'local_analysis')
        self.assertEqual(r,{'stage':'local_analysis','type':'RuntimeError','locations':[]})

if __name__=='__main__':unittest.main()
