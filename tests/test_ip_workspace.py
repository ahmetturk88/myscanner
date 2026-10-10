import unittest
from unittest.mock import Mock
from services.ip_analyzer import IPAnalyzer

def response(data,code=200):
    r=Mock(status_code=code);r.json.return_value=data;return r
class IPWorkspaceTests(unittest.TestCase):
    def analyzer(self):
        a=IPAnalyzer();a.session=Mock();return a
    def test_public_addresses_only_and_close(self):
        for value in ['127.0.0.1','10.0.0.1','169.254.169.254','::1','::ffff:127.0.0.1','8.8.8.8/x','fe80::1%eth0',None,{},True]:
            a=self.analyzer();self.assertIn('error',a.analyze_ip(value));a.session.get.assert_not_called();a.session.close.assert_called_once()
    def test_metadata_https_identity_and_missing_flags(self):
        a=self.analyzer();a.session.get.return_value=response({'success':True,'ip':'8.8.8.8','country':'US','connection':{'asn':15169,'org':'Google'},'timezone':{'id':'America/New_York'}});r=a.analyze_ip('8.8.8.8');self.assertEqual(r['asn'],15169);self.assertEqual(r['assessment']['score'],50);self.assertEqual(r['verdict'],'unknown');self.assertIsNone(r['is_proxy']);self.assertTrue(a.session.get.call_args.args[0].startswith('https://'));self.assertIsNone(r['blacklist_count'])
    def test_ipv6_canonical_identity(self):
        a=self.analyzer();a.session.get.return_value=response({'success':True,'ip':'2606:4700:4700:0:0:0:0:1111'});r=a.analyze_ip('2606:4700:4700::1111');self.assertEqual(r['coverage']['metadata'],'assessed');self.assertEqual(r['ip_version'],6)
    def test_report_with_zero_confidence_is_still_reported(self):
        a=self.analyzer();a.session.get.side_effect=[response({},503),response({'data':{'ipAddress':'8.8.8.8','abuseConfidenceScore':0,'totalReports':5}})];r=a.analyze_ip('8.8.8.8','private-key');self.assertEqual(r['verdict'],'reported');self.assertEqual(r['reputation_status'],'matched');self.assertTrue(r['findings']);self.assertIsNone(r['blacklist_count'])
    def test_zero_reports_only_means_no_reports(self):
        a=self.analyzer();a.session.get.side_effect=[response({'success':True,'ip':'8.8.8.8'}),response({'data':{'ipAddress':'8.8.8.8','abuseConfidenceScore':0,'totalReports':0}})];r=a.analyze_ip('8.8.8.8','key');self.assertEqual(r['assessment']['score'],100);self.assertEqual(r['verdict'],'not_found');self.assertIn('do not establish safety',r['summary'][-1]);self.assertFalse(r['findings'])
    def test_wrong_identity_and_malformed_are_unknown(self):
        for data in [{'data':{'ipAddress':'1.1.1.1','abuseConfidenceScore':99,'totalReports':2}}, {'data':{'ipAddress':'8.8.8.8','abuseConfidenceScore':True,'totalReports':2}}, {'data':{'ipAddress':'8.8.8.8','abuseConfidenceScore':0,'totalReports':-1}}]:
            a=self.analyzer();a.session.get.side_effect=[response({},503),response(data)];r=a.analyze_ip('8.8.8.8','key');self.assertEqual(r['verdict'],'unknown');self.assertEqual(r['assessment']['score'],0)
    def test_rate_limit_and_secret_redaction(self):
        a=self.analyzer();a.session.get.side_effect=[response({},429),RuntimeError('secret-token')];r=a.analyze_ip('8.8.8.8','secret-token');self.assertEqual(r['metadata_reason'],'rate_limited');self.assertNotIn('secret-token',str(r));self.assertEqual(r['reputation_status'],'unavailable')
    def test_coordinates_and_types_not_coerced(self):
        a=self.analyzer();a.session.get.return_value=response({'success':True,'ip':'8.8.8.8','latitude':True,'longitude':float('nan'),'connection':{'asn':True}});r=a.analyze_ip('8.8.8.8');self.assertIsNone(r['lat']);self.assertIsNone(r['lon']);self.assertIsNone(r['asn'])
    def test_metadata_mismatch_rejected_and_responses_closed(self):
        a=self.analyzer();r=response({'success':True,'ip':'1.1.1.1'});a.session.get.return_value=r;result=a.analyze_ip('8.8.8.8');self.assertEqual(result['coverage']['metadata'],'unavailable');r.close.assert_called_once()
if __name__=='__main__':unittest.main()
