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
