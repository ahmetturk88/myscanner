import unittest
from unittest.mock import Mock, patch
from services import ip_location
from services.ip_analyzer import IPAnalyzer

LOOKUP=ip_location.lookup
FIELDS=dict.fromkeys(('country','country_code','city','region','continent','timezone','asn','org','isp','network_domain','lat','lon'))

def response(data,code=200):
    r=Mock(status_code=code);r.json.return_value=data;return r
class IPWorkspaceTests(unittest.TestCase):
    def setUp(self):
        # Location comes from the local DB-IP files; no file is installed in tests.
        patcher=patch.object(ip_location,'lookup',return_value=None);self.lookup=patcher.start();self.addCleanup(patcher.stop)
    def analyzer(self):
        a=IPAnalyzer();a.session=Mock();return a
    def test_public_addresses_only_and_close(self):
        for value in ['127.0.0.1','10.0.0.1','169.254.169.254','::1','::ffff:127.0.0.1','8.8.8.8/x','fe80::1%eth0',None,{},True]:
            a=self.analyzer();self.assertIn('error',a.analyze_ip(value));a.session.get.assert_not_called();a.session.close.assert_called_once()
    def test_local_metadata_never_contacts_the_network_and_flags_stay_missing(self):
        self.lookup.return_value={**FIELDS,'country':'United States','asn':15169,'org':'Google'}
        a=self.analyzer();r=a.analyze_ip('8.8.8.8');self.assertEqual(r['asn'],15169);self.assertEqual(r['assessment']['score'],50);self.assertEqual(r['verdict'],'unknown');self.assertIsNone(r['is_proxy']);a.session.get.assert_not_called();self.assertIsNone(r['blacklist_count'])
    def test_ipv6_canonical_identity(self):
        self.lookup.return_value=FIELDS
        a=self.analyzer();r=a.analyze_ip('2606:4700:4700:0:0:0:0:1111');self.lookup.assert_called_with('2606:4700:4700::1111');self.assertEqual(r['coverage']['metadata'],'assessed');self.assertEqual(r['ip_version'],6)
    def test_report_with_zero_confidence_is_still_reported(self):
        a=self.analyzer();a.session.get.side_effect=[response({'data':{'ipAddress':'8.8.8.8','abuseConfidenceScore':0,'totalReports':5}})];r=a.analyze_ip('8.8.8.8','private-key');self.assertEqual(r['verdict'],'reported');self.assertEqual(r['reputation_status'],'matched');self.assertTrue(r['findings']);self.assertIsNone(r['blacklist_count'])
    def test_zero_reports_only_means_no_reports(self):
        a=self.analyzer();self.lookup.return_value=FIELDS;a.session.get.side_effect=[response({'data':{'ipAddress':'8.8.8.8','abuseConfidenceScore':0,'totalReports':0}})];r=a.analyze_ip('8.8.8.8','key');self.assertEqual(r['assessment']['score'],100);self.assertEqual(r['verdict'],'not_found');self.assertIn('do not establish safety',r['summary'][-1]);self.assertFalse(r['findings'])
    def test_wrong_identity_and_malformed_are_unknown(self):
        for data in [{'data':{'ipAddress':'1.1.1.1','abuseConfidenceScore':99,'totalReports':2}}, {'data':{'ipAddress':'8.8.8.8','abuseConfidenceScore':True,'totalReports':2}}, {'data':{'ipAddress':'8.8.8.8','abuseConfidenceScore':0,'totalReports':-1}}]:
            a=self.analyzer();a.session.get.side_effect=[response(data)];r=a.analyze_ip('8.8.8.8','key');self.assertEqual(r['verdict'],'unknown');self.assertEqual(r['assessment']['score'],0)
    def test_rate_limit_and_secret_redaction(self):
        a=self.analyzer();a.session.get.side_effect=[response({},429)];r=a.analyze_ip('8.8.8.8','secret-token');self.assertEqual(r['reputation']['reason'],'rate_limited');self.assertNotIn('secret-token',str(r));self.assertEqual(r['reputation_status'],'unavailable')
        a=self.analyzer();a.session.get.side_effect=RuntimeError('secret-token');r=a.analyze_ip('8.8.8.8','secret-token');self.assertNotIn('secret-token',str(r));self.assertEqual(r['reputation_status'],'unavailable')
    def test_coordinates_and_types_not_coerced(self):
        city=Mock(get=Mock(return_value={'location':{'latitude':True,'longitude':float('nan')}}));asn=Mock(get=Mock(return_value={'autonomous_system_number':True}))
        with patch.object(ip_location,'_reader',side_effect=lambda name:city if name==ip_location.CITY_FILE else asn):
            r=LOOKUP('8.8.8.8')
        self.assertIsNone(r['lat']);self.assertIsNone(r['lon']);self.assertIsNone(r['asn'])
    def test_damaged_database_is_unavailable_not_an_error(self):
        self.lookup.side_effect=ValueError('damaged')
        a=self.analyzer();result=a.analyze_ip('8.8.8.8');self.assertEqual(result['coverage']['metadata'],'unavailable');self.assertEqual(result['metadata_reason'],'source_response_invalid')
    def test_report_severity_tracks_confidence_not_count(self):
        for score, severity in [(0,'info'),(1,'warning'),(49,'warning'),(50,'high'),(100,'high')]:
            a=self.analyzer();a.session.get.side_effect=[response({'data':{'ipAddress':'8.8.8.8','abuseConfidenceScore':score,'totalReports':235}})]
            r=a.analyze_ip('8.8.8.8','key');self.assertEqual(r['findings'][0]['severity'],severity);self.assertEqual(r['total_reports'],235);self.assertEqual(r['verdict'],'reported')
    def test_whitelisted_reports_are_discounted_but_still_reported(self):
        a=self.analyzer();a.session.get.side_effect=[response({'data':{'ipAddress':'8.8.8.8','abuseConfidenceScore':12,'totalReports':131,'isWhitelisted':True}})]
        r=a.analyze_ip('8.8.8.8','key');f=r['findings'][0]
        self.assertEqual((f['severity'],f['code'],r['verdict'],r['reputation']['is_whitelisted']),('info','abuse_reports_discounted','reported',True));self.assertIn('whitelisted',f['detail'])
if __name__=='__main__':unittest.main()


class PrivateAddressTests(unittest.TestCase):
    def test_private_address_is_explained_not_looked_up(self):
        from unittest.mock import patch
        from services.ip_analyzer import IPAnalyzer
        with patch.object(IPAnalyzer, '_get_ip_info') as lookup:
            for value in ('192.168.1.1', '10.0.0.5', '127.0.0.1', 'fe80::1'):
                result = IPAnalyzer().analyze_ip(value, 'key')
                self.assertIn('private address inside a local network', result['error'], value)
            lookup.assert_not_called()
        self.assertEqual(IPAnalyzer().analyze_ip('not-an-ip', 'key')['error'], 'A public IPv4 or IPv6 address is required')
