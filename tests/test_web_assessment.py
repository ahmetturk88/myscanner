"""Offline evidence, failure and network-boundary tests; never contact targets."""
import ast
import os
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
import requests
from services.safe_http import UnsafeTargetError, PublicHTTPSession
from services.web_assessment import WebAssessment, dns_records, response_chain
from services.subdomain_finder import SubdomainFinder, normalize_domain

ROOT=Path(__file__).resolve().parents[1]

def page(code=200, location=None, body=b'<html><title>Example</title></html>'):
    r=requests.Response(); r.status_code=code; r._content=body; r._content_consumed=True; r.headers['Content-Type']='text/html'
    if location: r.headers['Location']=location
    return r

def records(host, types=('A','AAAA','CNAME','MX','NS','TXT'), deadline=None):
    return {kind:{'status':'completed' if kind=='A' else 'no_record','values':['8.8.8.8'] if kind=='A' else []} for kind in types}

class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.patches=[patch('services.web_assessment.validate_public_url'),patch('services.web_assessment.dns_records',side_effect=records),
                      patch('services.web_assessment.certificate_details',return_value={'status':'completed','verified':True,'days_remaining':80}),
                      patch.object(PublicHTTPSession,'get',return_value=page())]
        self.mocks=[p.start() for p in self.patches]
        self.addCleanup(lambda:[p.stop() for p in reversed(self.patches)])

    def test_local_success_is_not_safe_or_fake_engine_count(self):
        r=WebAssessment().analyze('https://example.com')
        self.assertEqual(r['verdict'],'unknown');self.assertEqual(r['assessment_status'],'completed')
        self.assertEqual(r['assessment_scope'],'local')
        self.assertEqual(r['stats']['checks_completed'],5)
        self.assertEqual(r['stats']['checks_total'],5)
        self.assertEqual(r['stats']['checks_not_requested'],1)
        self.assertEqual(r['provider']['status'],'not_requested');self.assertNotIn('harmless',r['stats'])
        self.assertEqual(r['content']['title'],'Example')

    def test_provider_is_never_called_without_explicit_opt_in(self):
        with patch('services.urlvet_client.URLVetClient') as provider,patch.dict(os.environ,{'URLVET_URL':'http://configured.invalid'}):
            WebAssessment().analyze('https://example.com')
            provider.assert_not_called()

    def test_configured_provider_closes_session_and_preserves_malicious(self):
        with patch('services.urlvet_client.URLVetClient') as provider,patch.dict(os.environ,{'URLVET_URL':'http://configured.invalid'}):
            provider.return_value.analyze_url.return_value={'verdict':'malicious','trust_score':0,'red_flags':['Threat evidence']}
            r=WebAssessment().analyze('https://example.com',True)
            self.assertEqual(r['verdict'],'malicious'); self.assertEqual(r['provider']['trust_score'],0)
            provider.return_value.session.close.assert_called_once()

    def test_provider_failure_does_not_erase_local_password_warning(self):
        self.mocks[3].return_value=page(body=b'<form action="http://example.com/submit"><input type="password"></form>')
        with patch('services.urlvet_client.URLVetClient') as provider,patch.dict(os.environ,{'URLVET_URL':'http://configured.invalid'}):
            provider.return_value.analyze_url.return_value={'verdict':'error','trust_score':0}
            r=WebAssessment().analyze('https://example.com',True)
            self.assertEqual(r['verdict'],'suspicious');self.assertEqual(r['assessment_status'],'partial')
            self.assertTrue(any(f['code']=='password_http' for f in r['findings']))

    def test_unconfigured_provider_reports_unavailable(self):
        with patch.dict(os.environ,{},clear=True):
            r=WebAssessment().analyze('https://example.com',True)
            self.assertEqual(r['provider']['status'],'unavailable')
            self.assertEqual(r['assessment_status'],'partial')
            self.assertEqual(r['stats']['checks_total'],6)

    def test_completed_http_inspection_preserves_transport_warning(self):
        r=WebAssessment().analyze('http://example.com')
        self.assertEqual(r['assessment_status'],'completed')
        self.assertEqual(r['verdict'],'suspicious')
        self.assertTrue(any(f['code']=='unencrypted_entry' for f in r['findings']))

    def test_failed_requested_local_check_remains_partial(self):
        self.mocks[3].side_effect=requests.ConnectionError()
        r=WebAssessment().analyze('https://example.com')
        self.assertEqual(r['assessment_status'],'partial')
        self.assertLess(r['stats']['checks_completed'],r['stats']['checks_total'])

    def test_http_failure_has_no_synthetic_safety_score(self):
        self.mocks[3].side_effect=requests.ConnectionError()
        r=WebAssessment().analyze('https://example.com')
        self.assertEqual(r['http']['status'],'unavailable');self.assertEqual(r['verdict'],'unknown')
        self.assertNotIn('security_score',r)

    def test_private_preflight_stops_local_and_external_requests(self):
        self.mocks[0].side_effect=UnsafeTargetError('blocked')
        with patch('services.urlvet_client.URLVetClient') as provider,self.assertRaises(UnsafeTargetError):
            WebAssessment().analyze('https://example.com',True)
        self.mocks[3].assert_not_called();provider.assert_not_called()

    def test_private_redirect_becomes_blocked_never_clean(self):
        self.mocks[3].side_effect=[page(302,'http://127.0.0.1/'),UnsafeTargetError('blocked')]
        r=WebAssessment().analyze('https://example.com')
        self.assertEqual(r['http']['status'],'blocked');self.assertEqual(r['verdict'],'unknown')
        self.assertEqual(len(r['http']['chain']),1)

    def test_redirect_loop_limit_and_http_errors_are_observations(self):
        session=Mock();session.get.return_value=page(302,'/loop')
        response,chain,reason=response_chain(session,'https://example.com/loop',float('inf'))
        self.assertIsNone(response);self.assertIn('loop',reason);session.get.assert_called_once()
        self.mocks[3].return_value=page(403)
        r=WebAssessment().analyze('https://example.com');self.assertEqual(r['http']['status_code'],403)
        self.assertEqual(r['verdict'],'unknown');self.assertEqual(r['content']['status'],'not_applicable')

    def test_deadline_does_not_dispatch_next_redirect(self):
        with patch('services.web_assessment.time.monotonic',return_value=20):
            session=Mock();r=response_chain(session,'https://example.com',10)
            session.get.assert_not_called();self.assertIn('Time budget',r[2])

    def test_malicious_page_title_is_data_and_forms_are_not_submitted(self):
        self.mocks[3].return_value=page(body=b'<title>&lt;img onerror=alert(1)&gt;</title><form action="https://other.example/submit"><input type=password></form>')
        r=WebAssessment().analyze('https://example.com')
        self.assertEqual(r['content']['title'],'<img onerror=alert(1)>')
        self.assertTrue(r['content']['forms'][0]['external_host']);self.mocks[3].assert_called_once()

    def test_blocked_destination_skips_opted_in_external_analysis(self):
        self.mocks[3].side_effect=[page(302,'http://127.0.0.1/'),UnsafeTargetError('blocked')]
        with patch('services.urlvet_client.URLVetClient') as provider:
            r=WebAssessment().analyze('https://example.com',True)
            provider.assert_not_called()
        self.assertEqual(r['provider']['status'],'not_requested')

    def test_malformed_form_does_not_discard_other_evidence(self):
        self.mocks[3].return_value=page(body=b'<form action="http://[bad"><input type=password></form>')
        r=WebAssessment().analyze('https://example.com')
        self.assertEqual(r['content']['status'],'completed')
        self.assertTrue(any(f['code']=='invalid_form_action' for f in r['findings']))

    def test_invalid_and_oversized_input_rejected(self):
        for value in [None, {}, 'x'*2049]:
            with self.subTest(value=str(value)[:20]),self.assertRaises(ValueError):WebAssessment().analyze(value)

class DiscoveryTests(unittest.TestCase):
    def test_hostname_validation(self):
        self.assertEqual(normalize_domain('https://EXAMPLE.com'),'example.com')
        for value in ['https://user:password@example.com','example.com/path','example.com?x=1','127.0.0.1','example.com:443','https://example.com/#section']:
            with self.subTest(value=value),self.assertRaises((ValueError,UnsafeTargetError)):normalize_domain(value)

    def test_dns_absolute_bounded_and_failure_distinguished(self):
        import dns.resolver
        with patch('services.web_assessment.dns.resolver.resolve',side_effect=dns.resolver.NoAnswer()) as lookup:
            r=dns_records('example.com',('A',));self.assertEqual(r['A']['status'],'no_record')
            self.assertEqual(lookup.call_args.args[0],'example.com.');self.assertFalse(lookup.call_args.kwargs['search'])
        with patch('services.web_assessment.dns.resolver.resolve',side_effect=dns.resolver.LifetimeTimeout()):
            self.assertEqual(dns_records('example.com',('A',))['A']['status'],'unavailable')

    def test_certificate_index_filters_foreign_wildcards_and_duplicates(self):
        finder=SubdomainFinder();r=page();r._content=b'[{"name_value":"api.example.com\\napi.example.com\\n*.example.com\\nevil-example.com\\nexample.com.evil.com"}]'
        with patch.object(PublicHTTPSession,'get',return_value=r) as get:
            names,source=finder.certificate_names('example.com',float('inf'))
        self.assertEqual(names,{'api.example.com'});self.assertEqual(source['status'],'completed')
        self.assertEqual(get.call_args.args[0],'https://crt.sh/');self.assertFalse(get.call_args.kwargs['allow_redirects'])

    def test_ct_outage_does_not_block_dns_discovery_and_is_explicit(self):
        finder=SubdomainFinder();finder.COMMON_SUBDOMAINS=['www','www','mail']
        with patch.object(finder,'certificate_names',return_value=(set(),{'name':'CT','status':'unavailable'})),patch('services.subdomain_finder.dns_records',side_effect=records),patch.object(finder,'probe_web',side_effect=lambda row,deadline:row):
            r=finder.find_subdomains('example.com')
        self.assertEqual(r['total_found'],2);self.assertEqual(r['candidates_selected'],2);self.assertEqual(r['assessment_status'],'partial')
        self.assertEqual(len(r['all_subdomains']),2)

    def test_wildcard_and_dns_only_results_are_preserved(self):
        finder=SubdomainFinder();finder.COMMON_SUBDOMAINS=['www']
        with patch('services.subdomain_finder.dns_records',side_effect=records),patch.object(finder,'probe_web',side_effect=lambda row,deadline:row):
            r=finder.find_subdomains('example.com',include_ct=False)
        self.assertTrue(r['wildcard']['detected']);self.assertTrue(r['results'][0]['possible_wildcard'])
        self.assertEqual(r['results'][0]['verdict'],'dns_only');self.assertEqual(r['inactive_count'],0)

    def test_private_mixed_addresses_never_probe_http(self):
        finder=SubdomainFinder()
        def mixed(host,types,deadline):
            r=records(host,types,deadline);r['A']['values']=['8.8.8.8','127.0.0.1'];return r
        with patch('services.subdomain_finder.dns_records',side_effect=mixed):
            row=finder.resolve_candidate(('www.example.com',['common_name']),'example.com',float('inf'),{'detected':False,'addresses':[]})
        with patch.object(PublicHTTPSession,'head') as head:
            r=finder.probe_web(row,float('inf'));head.assert_not_called()
        self.assertEqual(r['http']['status'],'blocked')

    def test_redirects_are_observed_without_following_and_cert_has_metadata(self):
        finder=SubdomainFinder();row={'full_domain':'www.example.com','public_addresses':True}
        with patch.object(PublicHTTPSession,'head',return_value=page(302,'http://127.0.0.1/')) as head,patch('services.subdomain_finder.certificate_details',return_value={'status':'completed','issuer':'Test CA'}):
            result=finder.probe_web(row,float('inf'))
        self.assertEqual(result['verdict'],'redirect');self.assertEqual(result['tls']['issuer'],'Test CA')
        self.assertFalse(head.call_args.kwargs['allow_redirects']);self.assertEqual(head.call_count,1)

    def test_dns_errors_not_reported_as_nonexistent(self):
        finder=SubdomainFinder();finder.COMMON_SUBDOMAINS=['www']
        def error(host,types,deadline):return {k:{'status':'unavailable','values':[]} for k in types}
        with patch('services.subdomain_finder.dns_records',side_effect=error),patch.object(finder,'certificate_names') as ct:
            result=finder.find_subdomains('example.com',include_ct=False);ct.assert_not_called()
        self.assertEqual(result['dns_error_count'],1);self.assertEqual(result['not_found_count'],0)
        self.assertEqual(result['unresolved'][0]['dns_status'],'unavailable')

    def test_candidate_limits_and_web_probe_subset(self):
        finder=SubdomainFinder();finder.COMMON_SUBDOMAINS=['host'+str(i) for i in range(30)]
        with patch('services.subdomain_finder.dns_records',side_effect=records),patch.object(finder,'probe_web',side_effect=lambda row,deadline:row) as probe:
            r=finder.find_subdomains('example.com',max_subdomains=25,include_ct=False)
        self.assertEqual(r['total_found'],25);self.assertEqual(probe.call_count,20)
        for limit in [0,101,True,'100']:
            with self.assertRaises(ValueError):finder.find_subdomains('example.com',limit,False)

    def test_no_virustotal_endpoint_or_import_in_runtime_python(self):
        for folder in ['services','routes','utils','config']:
            directory=ROOT/folder
            paths=list(directory.rglob('*.py')) if directory.exists() else []
            if folder=='services':paths.extend(ROOT.glob('*.py'))
            for path in paths:
                tree=ast.parse(path.read_text(encoding='utf-8-sig'))
                for node in ast.walk(tree):
                    if isinstance(node,ast.Constant) and isinstance(node.value,str):
                        self.assertNotIn('virustotal.com',node.value.lower(),str(path))
                        self.assertNotIn('vtapi',node.value.lower(),str(path))
                    if isinstance(node,(ast.Import,ast.ImportFrom)):
                        name=node.module if isinstance(node,ast.ImportFrom) else ','.join(a.name for a in node.names)
                        self.assertNotIn('virustotal',(name or '').lower(),str(path))

class ResponseBudgetTests(unittest.TestCase):
    def test_custom_body_cap_closes_transport(self):
        from test_ssrf_protection import response, records as addresses
        raw=response(body=b'x'*1025)
        with PublicHTTPSession(response_limit=1024) as session:
            pool=Mock();pool.urlopen.return_value=raw
            with patch.object(session.get_adapter('https://').poolmanager,'connection_from_host',return_value=pool),patch('services.safe_http.socket.getaddrinfo',return_value=addresses('8.8.8.8')):
                with self.assertRaises(UnsafeTargetError):session.get('https://example.com')
        self.assertTrue(raw.closed)

    def test_response_budget_closes_transport_without_disabling_tls(self):
        from test_ssrf_protection import response, records as addresses
        raw=response(body=b'body')
        with PublicHTTPSession(deadline=1) as session:
            pool=Mock();pool.urlopen.return_value=raw
            with patch.object(session.get_adapter('https://').poolmanager,'connection_from_host',return_value=pool),patch('services.safe_http.socket.getaddrinfo',return_value=addresses('8.8.8.8')),patch('services.safe_http.time.monotonic',return_value=2):
                with self.assertRaises(UnsafeTargetError):session.get('https://example.com')
        self.assertTrue(raw.closed)

if __name__=='__main__':unittest.main()

