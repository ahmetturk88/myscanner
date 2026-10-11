import unittest
from services.file_assessment import assess_file

class AssessmentTests(unittest.TestCase):
    def test_partial_evidence_deducted_and_threat_preserved(self):
        r={'security_score':100,'coverage_status':'partial','missing_checks':['provider unavailable'],'malwarebazaar':{'status':'unavailable'}}
        self.assertEqual(assess_file(r)['score'],75)
        self.assertEqual(assess_file({**r,'malwarebazaar':{'status':'matched','is_malicious':True}})['score'],0)
    def test_missing_index_never_receives_credit(self):
        for value in (None,True,'100',float('nan'),101):
            self.assertEqual(assess_file({'security_score':value})['score'],0)
    def test_complete_and_risk_caps(self):
        r={'security_score':100,'coverage_status':'completed','malwarebazaar':{'status':'not_found'}}
        self.assertEqual(assess_file(r)['score'],100)
        self.assertEqual(assess_file({**r,'verdict':'high_risk'})['score'],29)


class FileVerdictPolicyTests(unittest.TestCase):
    """file-evidence-v3: only a hash-reputation match confirms a threat."""
    def merge(self, local, mb):
        from services.file_threat_intel import FileThreatIntel
        intel = FileThreatIntel.__new__(FileThreatIntel)
        intel.mb_client = None
        return intel._merge_results(local, mb, 'build.py', b'fixture')

    def test_low_local_score_is_never_malicious(self):
        for score in (0, 10, 29, 45):
            result = self.merge({'security_score': score, 'verdict': 'high_risk'}, {'status': 'not_found', 'is_malicious': False})
            self.assertEqual(result['verdict'], 'suspicious')
            self.assertFalse(assess_file(result)['confirmed'])

    def test_hash_match_still_confirms(self):
        result = self.merge({'security_score': 95, 'verdict': 'safe'}, {'status': 'matched', 'is_malicious': True})
        self.assertEqual(result['verdict'], 'malicious')
        self.assertEqual(assess_file(result)['score'], 0)
        self.assertTrue(assess_file(result)['confirmed'])
        self.assertEqual(assess_file(result)['policy_version'], 'file-evidence-v3')
