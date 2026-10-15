"""Offline verified TLS, scope, failure, endpoint and public-target boundary tests."""
import ast
import socket
import ssl
import unittest
from pathlib import Path
from datetime import datetime,timezone,timedelta
from types import SimpleNamespace
from unittest.mock import Mock,MagicMock,patch
from flask import Flask,request,jsonify,render_template
from jinja2 import ChoiceLoader,DictLoader,FileSystemLoader
from bs4 import BeautifulSoup
from services.ssl_analyzer import SSLAnalyzer
from services.safe_http import UnsafeTargetError,TargetResolutionError
ROOT=Path(__file__).resolve().parents[1]

class TLSObservationTests(unittest.TestCase):
    def setUp(self):
        self.validate=patch('services.ssl_analyzer.validate_public_url',return_value=SimpleNamespace(hostname='example.com',port=443)).start()
        self.context=patch('services.ssl_analyzer.ssl.create_default_context').start().return_value
        self.connection=patch('services.ssl_analyzer.public_connection').start().return_value
        self.tls=self.context.wrap_socket.return_value.__enter__.return_value
        now=datetime.now(timezone.utc)
        self.cert={'notBefore':(now-timedelta(days=1)).strftime('%b %d %H:%M:%S %Y GMT'),
                   'notAfter':(now+timedelta(days=90)).strftime('%b %d %H:%M:%S %Y GMT'),
                   'issuer':((('organizationName','Test CA'),),),'subject':((('commonName','example.com'),),),
                   'subjectAltName':(('DNS','example.com'),),'serialNumber':'123'}
        self.tls.getpeercert.side_effect=lambda binary_form=False:b'certbytes' if binary_form else self.cert
        self.tls.version.return_value='TLSv1.3';self.tls.cipher.return_value=('TLS_AES_256_GCM_SHA384','TLSv1.3',256)
        self.addCleanup(patch.stopall)
    def test_verified_handshake_preserves_sni_and_reports_actual_evidence(self):
        r=SSLAnalyzer().analyze_certificate('example.com')
        self.assertTrue(r['valid']);self.assertIsNone(r['grade']);self.assertEqual(r['assessment']['score'],100)
        self.context.wrap_socket.assert_called_once_with(self.connection.__enter__.return_value,server_hostname='example.com')
        self.assertEqual(r['tls_version'],'TLSv1.3');self.assertEqual(len(r['certificate_sha256']),64)
        self.assertEqual(r['subject_names'],['example.com'])
    def test_short_lifetime_warns_without_lowering_coverage_or_fabricating_grade(self):
        self.cert['notAfter']=(datetime.now(timezone.utc)+timedelta(days=5)).strftime('%b %d %H:%M:%S %Y GMT')
        r=SSLAnalyzer().analyze_certificate('example.com');self.assertTrue(r['valid']);self.assertEqual(r['assessment']['score'],100)
        self.assertIsNone(r['grade']);self.assertEqual(r['findings'][0]['severity'],'warning')
    def test_verification_failure_is_invalid_and_never_leaks_details(self):
        self.context.wrap_socket.side_effect=ssl.SSLCertVerificationError('private details')
        r=SSLAnalyzer().analyze_certificate('example.com');self.assertFalse(r['valid']);self.assertEqual(r['status'],'invalid')
        self.assertNotIn('private details',str(r));self.assertNotIn('details_unverified',r)
    def expired_der(self,names=('example.com',),self_signed=True):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key=ec.generate_private_key(ec.SECP256R1());subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,names[0])])
        issuer=subject if self_signed else x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME,'Other CA')])
        now=datetime.now(timezone.utc)
        cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(255)
              .not_valid_before(now-timedelta(days=400)).not_valid_after(now-timedelta(days=10))
              .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]),critical=False).sign(key,hashes.SHA256()))
        return cert.public_bytes(serialization.Encoding.DER)
    def untrusted_handshake(self,code,der):
        error=ssl.SSLCertVerificationError('private details');error.verify_code=code
        second=MagicMock();tls=second.__enter__.return_value
        tls.getpeercert.return_value=der;tls.version.return_value='TLSv1.2';tls.cipher.return_value=('ECDHE-RSA-AES128-GCM-SHA256','TLSv1.2',128)
        self.context.wrap_socket.side_effect=[error,second]
        return SSLAnalyzer().analyze_certificate('example.com')
    def test_expired_certificate_is_named_and_details_marked_untrusted(self):
        r=self.untrusted_handshake(10,self.expired_der(self_signed=False))
        self.assertEqual((r['valid'],r['status'],r['reason_code'],r['details_unverified']),(False,'invalid','expired',True))
        self.assertEqual(r['findings'][0]['title'],'Certificate has expired');self.assertLess(r['days_remaining'],0)
        checks={c['name']:c['status'] for c in r['checks']}
        self.assertEqual((checks['Validity period'],checks['Hostname identity'],checks['Verified handshake']),('invalid','completed','invalid'))
        self.assertEqual(self.context.verify_mode,ssl.CERT_NONE);self.assertNotIn('private details',str(r))
    def test_self_signed_and_hostname_mismatch_are_named(self):
        r=self.untrusted_handshake(18,self.expired_der(('other.example',)))
        checks={c['name']:c['status'] for c in r['checks']}
        self.assertEqual((r['reason_code'],checks['Chain trust'],checks['Hostname identity']),('self_signed','invalid','invalid'))
        r=self.untrusted_handshake(62,self.expired_der(('*.example.org',),self_signed=False))
        self.assertEqual((r['reason_code'],r['findings'][0]['title']),('hostname_mismatch','Hostname does not match'))
    def test_network_failures_are_unknown_not_invalid(self):
        for error,code in [(socket.timeout(),'connection_timeout'),(OSError('secret'),'tls_unavailable')]:
            self.context.wrap_socket.side_effect=error;r=SSLAnalyzer().analyze_certificate('example.com')
            self.assertIsNone(r['valid']);self.assertEqual(r['reason_code'],code);self.assertNotIn('secret',str(r))
    def test_dns_failure_has_no_socket_and_zero_coverage(self):
        self.validate.side_effect=TargetResolutionError('secret')
        r=SSLAnalyzer().analyze_certificate('example.com');self.assertEqual(r['reason_code'],'dns_unavailable')
        self.context.wrap_socket.assert_not_called();self.assertEqual(r['assessment']['score'],0)
    def test_private_target_propagates_and_no_handshake(self):
        self.validate.side_effect=UnsafeTargetError('blocked')
        with self.assertRaises(UnsafeTargetError):SSLAnalyzer().analyze_certificate('example.com')
        self.context.wrap_socket.assert_not_called()
    def test_malformed_inputs_and_custom_ports_rejected(self):
        for value in (None,'','x'*2049,'https://example.com:444/','ftp://example.com','https://user:pass@example.com'):
            with self.assertRaises((ValueError,UnsafeTargetError)):SSLAnalyzer().analyze_certificate(value)
    def test_missing_or_malformed_certificate_never_claims_valid(self):
        for cert in ({},{'notBefore':'bad','notAfter':'bad'}):
            self.cert=cert;r=SSLAnalyzer().analyze_certificate('example.com');self.assertIsNone(r['valid'])
    def test_private_mixed_addresses_block_before_socket(self):
        with patch('services.ssl_analyzer.validate_public_url', wraps=__import__('services.safe_http',fromlist=['validate_public_url']).validate_public_url),patch('services.safe_http.socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443)),(socket.AF_INET,socket.SOCK_STREAM,6,'',('10.0.0.1',443))]):
            with self.assertRaises(UnsafeTargetError):SSLAnalyzer().analyze_certificate('example.com')
        self.context.wrap_socket.assert_not_called()

class EndpointTests(unittest.TestCase):
    def setUp(self):
        tree=ast.parse((ROOT/'app.py').read_text());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='api_ssl_checker');fn.decorator_list=[]
        self.app=Flask(__name__);self.factory=Mock();ns={'request':request,'jsonify':jsonify,'SSLAnalyzer':self.factory,'UnsafeTargetError':UnsafeTargetError,'log_activity':Mock(),'current_user':SimpleNamespace(username='tester'),'app':self.app}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),'endpoint','exec'),ns)
        self.app.add_url_rule('/api/ssl-checker',view_func=ns['api_ssl_checker'],methods=['POST']);self.client=self.app.test_client()
    def test_bad_payload_cannot_start(self):
        for data in ({},[],{'domain':3},{'domain':'x'*2049}):self.assertEqual(self.client.post('/api/ssl-checker',json=data).status_code,400)
        self.factory.assert_not_called()
    def test_no_store_result_and_private_policy_error(self):
        self.factory.return_value.analyze_certificate.return_value={'valid':None,'status':'unavailable'}
        r=self.client.post('/api/ssl-checker',json={'domain':'example.com'});self.assertEqual(r.status_code,200);self.assertEqual(r.headers['Cache-Control'],'no-store')
        self.factory.return_value.analyze_certificate.side_effect=UnsafeTargetError('secret')
        r=self.client.post('/api/ssl-checker',json={'domain':'example.com'});self.assertEqual(r.status_code,400);self.assertNotIn('secret',r.get_data(as_text=True))
    def test_template_renders_native_assets(self):
        self.app.jinja_loader=ChoiceLoader([DictLoader({'base.html':'{% block head_extra %}{% endblock %}{% block content %}{% endblock %}'}),FileSystemLoader(str(ROOT/'templates'))])
        with self.app.test_request_context('/'):soup=BeautifulSoup(render_template('ssl_checker.html'),'html.parser')
        self.assertTrue(soup.find('script',src=lambda s:s and s.split('?')[0]=='/static/ssl_workspace.js'));self.assertFalse(soup.select('[onclick]'))

if __name__=='__main__':unittest.main()
