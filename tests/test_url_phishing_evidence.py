"""Offline checks for contradictory phishing evidence, fresh and saved reports."""
import copy
import unittest
from services.url_scan_coverage import apply_phishing_evidence, apply_url_coverage, url_scan_outcome
from services.urlvet_client import URLVetClient


def provider(listed=True, verified=False, verdict='harmless'):
    return {'verdict': verdict, 'trust_score': 100, 'final_score': 98,
            'phishing': {'in_database': listed, 'verified': verified}}


class EvidenceTests(unittest.TestCase):
    def test_reported_unverified_entry_cannot_confirm_safety(self):
        p=apply_phishing_evidence(provider())
        self.assertEqual(p['verdict'],'unknown');self.assertEqual(p['verdict_reported'],'harmless')
        self.assertEqual(p['phishing_status'],'unverified');self.assertEqual(p['trust_score'],100)
    def test_verified_entry_overrides_high_score(self):
        p=apply_phishing_evidence(provider(verified=True))
        self.assertEqual(p['verdict'],'malicious');self.assertEqual(p['phishing_status'],'verified')
    def test_known_threat_is_preserved_when_entry_is_unverified(self):
        for verdict in ['suspicious','malicious']:
            self.assertEqual(apply_phishing_evidence(provider(verdict=verdict))['verdict'],verdict)
    def test_missing_and_malformed_booleans_are_not_negative_matches(self):
        for listed,verified in [(None,None),('false','false'),(True,None),(False,True)]:
            p=apply_phishing_evidence(provider(listed,verified))
            self.assertNotEqual(p['phishing_status'],'not_found')
            if listed is not None or verified is not None:self.assertEqual(p['verdict'],'unknown')
    def test_negative_match_is_limited_to_reported_dataset(self):
        self.assertEqual(apply_phishing_evidence(provider(False,False))['phishing_status'],'not_found')
    def test_saved_report_is_corrected_idempotently(self):
        result={'verdict':'safe','summary':{'level':'Low Risk'},'urlvet':provider(),'recommendations':[]}
        apply_url_coverage(result);first=copy.deepcopy(result);apply_url_coverage(result)
        self.assertEqual(result,first);self.assertEqual(result['verdict'],'unknown')
        self.assertEqual(result['assessment_status'],'partial')
        self.assertIn('Conflicting',result['assessment_warning'])
    def test_queue_outcome_preserves_verified_deep_threat_with_missing_local_provider(self):
        self.assertEqual(url_scan_outcome({'verdict':'safe','urlvet':{}},{'verdict':'safe','urlvet':provider(verified=True)}),('partial','malicious'))
    def test_queue_outcome_never_saves_conflict_as_harmless(self):
        r={'verdict':'safe','urlvet':provider()}
        self.assertEqual(url_scan_outcome(r,copy.deepcopy(r)),('partial','unknown'))
    def test_real_provider_parser_preserves_missing_evidence_and_normalizes_conflict(self):
        client=URLVetClient()
        try:
            p=client._parse_response('https://example.invalid',{'result':{'verdict':'Safe','trust_score':100},'phishing':{'in_database':True,'verified':False}})
            self.assertEqual(p['verdict'],'unknown')
            empty=client._parse_response('https://example.invalid',{'result':{'verdict':'Safe','trust_score':100}})
            self.assertIsNone(empty['phishing']['in_database']);self.assertEqual(empty['phishing_status'],'unavailable')
        finally:client.session.close()

if __name__=='__main__':unittest.main()
