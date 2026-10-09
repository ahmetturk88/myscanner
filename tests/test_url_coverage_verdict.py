import unittest
from services.url_assessment import assess_url

class CoverageVerdictTests(unittest.TestCase):
    def test_unavailable_checks_do_not_turn_legacy_suspicion_into_evidence(self):
        local={'verdict':'suspicious','structure':{'is_https':True,'contains_ip':False},'ssl':{'error':'DNS unavailable'},'security_headers':{'error':'DNS unavailable'},'urlvet':{'error':'unavailable'}}
        deep={'verdict':'suspicious','structure':local['structure'],'page_content':{'error':'DNS unavailable'},'behavior':{'error':'DNS unavailable'},'urlvet':{'error':'unavailable'}}
        result=assess_url(local,deep)
        self.assertEqual(result['verdict'],'unknown')
        self.assertEqual(result['coverage'],'partial')
        self.assertEqual(result['reasons'],[])
