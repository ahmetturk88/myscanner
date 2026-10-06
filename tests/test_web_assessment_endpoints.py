"""Production route tests using disposable databases and mocked analyzers."""
import unittest
from unittest.mock import patch
import test_task_ownership
from services.safe_http import UnsafeTargetError

class WebEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_task_ownership.TaskOwnershipTests.setUpClass()
        cls.production=test_task_ownership.TaskOwnershipTests.production
    @classmethod
    def tearDownClass(cls):test_task_ownership.TaskOwnershipTests.tearDownClass()
    def setUp(self):
        test_task_ownership.TaskOwnershipTests.setUp(self)
        self.app.register_error_handler(UnsafeTargetError,self.production.unsafe_scan_target)
        for path,name in [('/api/subdomain-finder','api_subdomain_finder'),('/api/scan-subdomain','api_scan_subdomain'),('/api/scan-qr-url','api_scan_qr_url')]:
            self.app.add_url_rule(path,name,getattr(self.production,name),methods=['POST'])
    def tearDown(self):test_task_ownership.TaskOwnershipTests.tearDown(self)
    def login(self):test_task_ownership.TaskOwnershipTests.sign_in(self,self.admin)

    def test_anonymous_cannot_start_any_analysis(self):
        for path in ['/api/subdomain-finder','/api/scan-subdomain','/api/scan-qr-url']:
            self.assertEqual(self.client.post(path,json={}).status_code,401)

    def test_bad_payloads_and_non_boolean_external_options_are_400(self):
        self.login()
        from extensions import db
        from models import User
        before=db.session.get(User,self.admin).subdomain_finder_remaining
        for path,field in [('/api/subdomain-finder','domain'),('/api/scan-subdomain','domain'),('/api/scan-qr-url','url')]:
            for payload in [None,[],{}, {field:99},{field:'example.com','include_ct':'true'} if path.endswith('finder') else {field:'example.com','include_provider':'false'}]:
                with self.subTest(path=path,payload=payload):self.assertEqual(self.client.post(path,json=payload).status_code,400)

        self.assertEqual(db.session.get(User,self.admin).subdomain_finder_remaining,before)

    def test_discovery_passes_source_choice_and_is_not_cached(self):
        self.login()
        with patch.object(self.production,'SubdomainFinder') as finder:
            finder.return_value.find_subdomains.return_value={'schema_version':2,'results':[]}
            r=self.client.post('/api/subdomain-finder',json={'domain':'example.com','include_ct':False})
            finder.return_value.find_subdomains.assert_called_once_with('example.com',include_ct=False)
        self.assertEqual(r.status_code,200);self.assertEqual(r.headers['Cache-Control'],'no-store')

    def test_qr_opt_in_is_explicit_and_response_not_cached(self):
        self.login()
        with patch.object(self.production,'QRAnalyzer') as qr:
            qr.return_value.scan_url.return_value={'schema_version':2,'verdict':'unknown'}
            r=self.client.post('/api/scan-qr-url',json={'url':'https://example.com'})
            qr.return_value.scan_url.assert_called_once_with('https://example.com',include_provider=False)
        self.assertEqual(r.status_code,200);self.assertEqual(r.headers['Cache-Control'],'no-store')

    def test_hostname_inspection_normalizes_and_preserves_deep_report(self):
        self.login()
        with patch('services.web_assessment.WebAssessment') as analyzer:
            analyzer.return_value.analyze.return_value={'schema_version':2,'tls':{'status':'completed'}}
            r=self.client.post('/api/scan-subdomain',json={'domain':'WWW.EXAMPLE.com','include_provider':True})
            analyzer.return_value.analyze.assert_called_once_with('https://www.example.com/',include_provider=True)
        self.assertEqual(r.status_code,200);self.assertEqual(r.json['tls']['status'],'completed')

    def test_analysis_error_has_generic_503_and_does_not_expose_raw_error(self):
        self.login()
        with patch.object(self.production,'QRAnalyzer') as qr:
            qr.return_value.scan_url.side_effect=RuntimeError('sensitive-private-value')
            with patch.object(self.production.app.logger,'exception'):
                r=self.client.post('/api/scan-qr-url',json={'url':'https://example.com'})
        self.assertEqual(r.status_code,503);self.assertNotIn('sensitive',r.json['error'])
