import unittest
from unittest.mock import Mock,patch
import ssl
from services.ip_analyzer import IPAnalyzer
from services.domain_analyzer import DomainAnalyzer
from services.ssl_analyzer import SSLAnalyzer
from services.malwarebazaar_client import MalwareBazaarClient
from services.file_threat_intel import FileThreatIntel
from services.file_deep_analyzer import FileDeepAnalyzer

HASH='a'*64

def response(data,code=200):
    r=Mock(status_code=code);r.json.return_value=data
    if code>=400:r.raise_for_status.side_effect=RuntimeError('provider failure')
    return r

class EvidenceTests(unittest.TestCase):
    def test_ip_metadata_is_not_safety_and_missing_key_is_unknown(self):
        analyzer=IPAnalyzer();analyzer.session=Mock();analyzer.session.get.return_value=response({'success':True,'ip':'8.8.8.8'})
        result=analyzer.analyze_ip('8.8.8.8')
        self.assertEqual(result['verdict'],'unknown');self.assertIsNone(result['blacklist_count']);self.assertEqual(result['reputation_status'],'not_configured');analyzer.session.close.assert_called_once()
    def test_ip_reputation_failure_and_malformed_data_are_not_clean(self):
        for payload in ({},{'data':{}},{'data':{'ipAddress':'8.8.8.8','abuseConfidenceScore':False,'totalReports':0}},{'data':{'ipAddress':'1.1.1.1','abuseConfidenceScore':0,'totalReports':0}}):
            analyzer=IPAnalyzer();analyzer.session=Mock();analyzer.session.get.side_effect=[response({'success':True,'ip':'8.8.8.8'}),response(payload)]
            result=analyzer.analyze_ip('8.8.8.8','key');self.assertEqual(result['verdict'],'unknown');self.assertEqual(result['reputation_status'],'unavailable')
    def test_ip_valid_negative_is_dataset_only_and_positive_is_preserved(self):
        for score,verdict in [(0,'not_found'),(75,'reported')]:
            analyzer=IPAnalyzer();analyzer.session=Mock();analyzer.session.get.side_effect=[response({},503),response({'data':{'ipAddress':'8.8.8.8','abuseConfidenceScore':score,'totalReports':5 if score else 0}})]
            result=analyzer.analyze_ip('8.8.8.8','key');self.assertEqual(result['verdict'],verdict);self.assertEqual(result['coverage_status'],'partial')
    def test_ip_inputs_cannot_change_provider_request_path(self):
        for value in ('127.0.0.1','169.254.169.254','8.8.8.8/../../admin','::ffff:127.0.0.1'):
            analyzer=IPAnalyzer();analyzer.session=Mock();self.assertIn('error',analyzer.analyze_ip(value));analyzer.session.get.assert_not_called()
    def test_domain_failure_has_coverage_and_no_demo_key(self):
        with patch.dict('os.environ',{},clear=True):
            analyzer=DomainAnalyzer();analyzer.session=Mock();analyzer.session.get.side_effect=RuntimeError('secret')
            result=analyzer.analyze_domain('example.com');self.assertEqual(result['verdict'],'unknown');self.assertEqual(result['coverage']['whois'],'unavailable');self.assertEqual(result['coverage_status'],'partial');self.assertNotIn('secret',str(result));analyzer.session.close.assert_called_once()
    def test_domain_query_uses_encoded_params_and_invalid_input_never_fetches(self):
        for target in ('example.com/?name=localhost','example.com/path','https://user:key@example.com'):
            analyzer=DomainAnalyzer();analyzer.session=Mock();self.assertIn('error',analyzer.analyze_domain(target));analyzer.session.get.assert_not_called()
        analyzer=DomainAnalyzer();analyzer.session=Mock();analyzer.session.get.return_value=response({'Status':0})
        self.assertEqual(analyzer._get_dns_records('example.com')[1],'assessed')
        self.assertEqual(analyzer.session.get.call_args.args[0],'https://dns.google/resolve')
        self.assertEqual(analyzer.session.get.call_args.kwargs['params']['name'],'example.com')
    def test_tls_connection_failure_is_unknown_but_verification_failure_is_invalid(self):
        with patch('services.ssl_analyzer.validate_public_url',return_value=Mock(hostname='example.com')):
            for error,expected in [(TimeoutError(),'unavailable'),(ssl.SSLCertVerificationError(),'invalid')]:
                with patch('services.ssl_analyzer.public_connection',side_effect=error):
                    result=SSLAnalyzer().analyze_certificate('example.com');self.assertEqual(result['status'],expected);self.assertIs(result['valid'],False if expected=='invalid' else None)
    def test_malwarebazaar_failures_never_become_negative_matches(self):
        for data,code in [({},200),({'query_status':'ok','data':[]},200),({'query_status':'ok','data':[{'sha256_hash':'b'*64}]},200),({'query_status':'hash_not_found'},503),({'query_status':'hash_not_found'},302)]:
            client=MalwareBazaarClient(auth_key='test-private-key-value');client.session=Mock();client.session.post.return_value=response(data,code)
            result=client.check_hash(HASH);self.assertEqual(result['status'],'unavailable');self.assertIsNone(result['is_malicious'])
    def test_malwarebazaar_valid_results_are_specific_to_hash(self):
        for data,state in [({'query_status':'hash_not_found'},'not_found'),({'query_status':'ok','data':[{'sha256_hash':HASH,'signature':'test'}]},'matched')]:
            client=MalwareBazaarClient(auth_key='test-private-key-value');client.session=Mock();client.session.post.return_value=response(data)
            self.assertEqual(client.check_hash(HASH)['status'],state);self.assertFalse(client.session.post.call_args.kwargs['allow_redirects'])
    def test_file_merge_preserves_threat_and_does_not_infer_safety(self):
        scanner=FileThreatIntel.__new__(FileThreatIntel);scanner.mb_client=None
        cases=[({'security_score':100,'verdict':'not_found'},{'status':'unavailable'},'unknown'),({'security_score':100,'verdict':'not_found'},{'status':'not_found','is_malicious':False},'not_found'),({'security_score':10,'verdict':'malicious'},{'status':'unavailable'},'malicious'),({'error':'failed','verdict':'unknown'},{'status':'not_found'},'unknown'),({'security_score':100,'verdict':'not_found'},{'status':'matched','is_malicious':True},'malicious')]
        for local,provider,expected in cases:
            result=scanner._merge_results(local,provider,'test.txt',b'test');self.assertEqual(result['verdict'],expected)
    def test_site_dns_failure_is_not_record_absence_and_reputation_is_not_clean(self):
        from services.site_analyzer import SiteAnalyzer
        analyzer=SiteAnalyzer.__new__(SiteAnalyzer)
        with patch('services.site_analyzer.dns.resolver.resolve',side_effect=TimeoutError):
            result=analyzer.check_dns_records('example.com')
        self.assertIsNone(result['has_spf']);self.assertIsNone(result['has_dmarc']);self.assertEqual(result['risk_score'],0);self.assertEqual(result['coverage_status'],'partial')
        self.assertIsNone(analyzer.check_reputation('example.com')['is_blacklisted'])
    def test_confirmed_hash_match_overrides_benign_heuristics(self):
        analyzer=FileDeepAnalyzer(use_exiftool=False)
        with patch.object(analyzer,'_is_likely_benign',return_value=(True,['text'])),patch.object(analyzer,'check_hash_reputation',return_value={'status':'matched','is_malicious':True,'risk_score':80,'sources':['MalwareBazaar']}):
            result=analyzer.comprehensive_analysis(b'hello','test.txt')
        self.assertEqual(result['verdict'],'malicious');self.assertLessEqual(result['security_score'],20)
    def test_local_file_missing_provider_never_claims_clean(self):
        analyzer=FileDeepAnalyzer(use_exiftool=False)
        with patch.object(analyzer,'check_hash_reputation',return_value={'status':'unavailable','is_malicious':None,'risk_score':0,'sources':[]}):
            result=analyzer.comprehensive_analysis(b'hello','test.txt')
        self.assertNotEqual(result['verdict'],'safe');self.assertEqual(result['coverage_status'],'partial');self.assertIn('Hash reputation unavailable',result['missing_checks'])

if __name__=='__main__':unittest.main()


