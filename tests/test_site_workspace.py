"""Offline Site Scanner report and discovery boundary regression tests."""
import copy
import unittest
from unittest.mock import patch, Mock
import requests
from services.site_evidence import assess_site, header_observations, discovery_documents
from services.safe_http import UnsafeTargetError, TargetResolutionError
from services.site_analyzer import SiteAnalyzer

def fixture():
    return {'url':'https://example.com/','structure':{'hostname':'example.com'},
      'http':{'status':'completed','status_code':200,'final_url':'https://example.com/','security_headers':{},'chain':[]},
      'tls':{'status':'completed'},'content':{'status':'completed'},'provider':{'status':'not_requested'},
      'dns':{},'findings':[],'verdict':'unknown','stats':{'redirect_count':0},
      'checks':[{'name':n,'status':'completed'} for n in ('Structure','DNS','HTTP','TLS','Static page')]+[{'name':'url.vet','status':'not_requested'}]}
def response(body=b'',code=200):
    r=requests.Response();r.status_code=code;r._content=body;r._content_consumed=True;return r

class SiteReportTests(unittest.TestCase):
    def assess(self,r=None,**options):
        with patch('services.site_evidence.WebAssessment') as factory:
            factory.return_value.analyze.return_value=copy.deepcopy(r or fixture())
            result=assess_site('example.com',**options)
            factory.return_value.analyze.assert_called_once_with('example.com',include_provider=options.get('include_provider',False))
            return result
    def test_complete_local_checks_do_not_claim_safety(self):
        r=self.assess();self.assertEqual(r['assessment']['score'],100);self.assertEqual(r['verdict'],'unknown')
        self.assertIsNone(r['security_score']);self.assertFalse(r['active_scan_performed'])
        self.assertEqual(r['vulnerabilities']['dynamic']['status'],'not_performed')
        self.assertEqual(r['assessment']['checks_total'],6)
    def test_unavailable_source_reduces_coverage_without_safe_verdict(self):
        r=fixture();r['checks'][-1]['status']='unavailable'
        result=self.assess(r,include_provider=True)
        self.assertEqual(result['assessment']['score'],86);self.assertIn('url.vet',result['missing_checks'])
    def test_optional_documents_are_counted_only_when_requested(self):
        with patch('services.site_evidence.discovery_documents',return_value={'robots':{'status':'not_found'},'sitemap':{'status':'unavailable'}}):
            result=self.assess(include_discovery=True)
        self.assertEqual(result['assessment']['checks_total'],8);self.assertEqual(result['assessment']['score'],88)
    def test_blocked_http_does_not_request_documents(self):
        r=fixture();r['http']['status']='blocked'
        with patch('services.site_evidence.discovery_documents') as discovery:
            result=self.assess(r,include_discovery=True)
        discovery.assert_not_called();self.assertEqual(result['header_observations'][0]['status'],'unavailable')
    def test_strict_boolean_flags(self):
        for flag in ('true',1,None):
            with self.assertRaises(ValueError):assess_site('example.com',include_provider=flag)
    def test_hsts_http_and_frame_ancestors_alternative(self):
        h={'status':'completed','final_url':'http://example.com','security_headers':{'Content-Security-Policy':"default-src 'self'; frame-ancestors 'none'"}}
        rows=header_observations(h);self.assertEqual(rows[0]['status'],'not_applicable');self.assertEqual(rows[-1]['status'],'alternative_present')
        h['security_headers']['Content-Security-Policy']="report-uri /frame-ancestors"
        self.assertEqual(header_observations(h)[-1]['status'],'missing')
    def test_adapter_closes_legacy_session_without_active_scanner(self):
        a=SiteAnalyzer.__new__(SiteAnalyzer);a.session=Mock()
        with patch('services.site_evidence.assess_site',return_value=fixture()) as assess:
            self.assertEqual(a.comprehensive_analysis('example.com')['verdict'],'unknown')
        a.session.close.assert_called_once();assess.assert_called_once_with('example.com',False,False)
    def test_adapter_closes_session_after_failure(self):
        a=SiteAnalyzer.__new__(SiteAnalyzer);a.session=Mock()
        with patch('services.site_evidence.assess_site',side_effect=UnsafeTargetError('blocked')):
            with self.assertRaises(UnsafeTargetError):a.comprehensive_analysis('example.com')
        a.session.close.assert_called_once()

class DiscoveryTests(unittest.TestCase):
    def check(self,side_effect):
        with patch('services.site_evidence.response_chain',side_effect=side_effect) as call:
            result=discovery_documents('https://example.com/ignored?q=secret')
        self.assertEqual([c.args[1] for c in call.call_args_list],['https://example.com/robots.txt','https://example.com/sitemap.xml'])
        return result
    def test_documents_do_not_follow_listed_paths(self):
        r=self.check([(response(b'User-agent: *\nDisallow: /private\nSitemap: http://127.0.0.1/a'),[{'url':'https://example.com/robots.txt'}],None),
                      (response(b'<urlset><url><loc>http://127.0.0.1/</loc></url></urlset>'),[{'url':'https://example.com/sitemap.xml'}],None)])
        self.assertEqual(r['robots']['status'],'observed');self.assertEqual(r['sitemap']['entries_observed'],1)
    def test_xml_entities_are_rejected(self):
        r=self.check([(response(code=404),[{'url':'https://example.com/robots.txt'}],None),
                      (response(b'<!DOCTYPE urlset [<!ENTITY x SYSTEM "file:///etc/passwd">]><urlset/>'),[{'url':'https://example.com/sitemap.xml'}],None)])
        self.assertEqual(r['robots']['status'],'not_found');self.assertEqual(r['sitemap']['status'],'unavailable')
    def test_private_redirect_and_resolution_failure_are_distinct(self):
        r=self.check([UnsafeTargetError('secret'),TargetResolutionError('secret')])
        self.assertEqual(r['robots']['status'],'blocked');self.assertEqual(r['sitemap']['status'],'unavailable');self.assertNotIn('secret',str(r))

if __name__=='__main__':unittest.main()

class EndpointTests(unittest.TestCase):
    def setUp(self):
        import ast
        from pathlib import Path
        from flask import Flask, request, jsonify
        from types import SimpleNamespace
        tree=ast.parse(Path(__file__).resolve().parents[1].joinpath('app.py').read_text())
        fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='api_site_scan')
        fn.decorator_list=[]
        self.factory=Mock()
        self.app=Flask(__name__)
        ns={'request':request,'jsonify':jsonify,'SiteAnalyzer':self.factory,'log_activity':Mock(),'current_user':SimpleNamespace(username='tester'),'UnsafeTargetError':UnsafeTargetError,'app':self.app}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),'endpoint','exec'),ns)
        self.app.add_url_rule('/api/site-scan',view_func=ns['api_site_scan'],methods=['POST'])
        self.client=self.app.test_client()
    def test_malformed_options_cannot_start_a_scan(self):
        for data in (None,[],{}, {'domain':3},{'domain':'example.com','include_provider':'true'}):
            self.assertEqual(self.client.post('/api/site-scan',json=data).status_code,400)
        self.factory.assert_not_called()
    def test_options_are_queued_and_analysis_runs_in_the_worker(self):
        from services.evidence_jobs import run_evidence_job
        with patch('services.evidence_jobs.queue_evidence_job',return_value=({'task_id':'t'},202)) as queued:
            r=self.client.post('/api/site-scan',json={'domain':'example.com','include_discovery':True})
        self.assertEqual(r.status_code,202)
        kind,params=queued.call_args.args
        self.assertEqual((kind,params),('site',{'domain':'example.com','include_provider':False,'include_discovery':True}))
        self.factory.assert_not_called()
        with self.app.app_context(),patch('services.site_analyzer.SiteAnalyzer') as analyzer:
            analyzer.return_value.comprehensive_analysis.return_value={'verdict':'unknown'}
            self.assertEqual(run_evidence_job(kind,params,1),{'status':'completed','result':{'verdict':'unknown'}})
            analyzer.return_value.comprehensive_analysis.assert_called_once_with('example.com',include_provider=False,include_discovery=True)
    def test_dns_policy_and_internal_failures_are_distinct(self):
        from services.evidence_jobs import run_evidence_job,DNS_UNAVAILABLE,POLICY_BLOCKED,UNAVAILABLE
        params={'domain':'example.com','include_provider':False,'include_discovery':False}
        for error,message in [(TargetResolutionError('secret'),DNS_UNAVAILABLE),(UnsafeTargetError('secret'),POLICY_BLOCKED),(RuntimeError('secret'),UNAVAILABLE['site'])]:
            with self.app.app_context(),patch('services.site_analyzer.SiteAnalyzer') as analyzer:
                analyzer.return_value.comprehensive_analysis.side_effect=error
                result=run_evidence_job('site',params,1)
            self.assertEqual(result,{'status':'failed','user_error':message});self.assertNotIn('secret',str(result))

class TemplateAndBoundaryTests(unittest.TestCase):
    def test_template_loads_assets_and_optional_checks_start_unselected(self):
        from flask import Flask,render_template
        from jinja2 import ChoiceLoader,DictLoader,FileSystemLoader
        from pathlib import Path
        from bs4 import BeautifulSoup
        app=Flask(__name__)
        root=Path(__file__).resolve().parents[1]
        app.jinja_loader=ChoiceLoader([DictLoader({'base.html':'{% block head_extra %}{% endblock %}{% block content %}{% endblock %}'}),FileSystemLoader(str(root/'templates'))])
        with app.test_request_context('/'):
            soup=BeautifulSoup(render_template('site_scanner.html'),'html.parser')
        self.assertTrue(soup.find('script',src=lambda value:value and value.split('?')[0]=='/static/site_workspace.js'))
        self.assertFalse(soup.select_one('#site-provider').has_attr('checked'))
        self.assertFalse(soup.select_one('#site-discovery').has_attr('checked'))
        self.assertFalse(soup.select('[onclick]'))
    def test_private_and_mixed_targets_never_reach_http_or_provider(self):
        import socket
        public=(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443))
        private=(socket.AF_INET,socket.SOCK_STREAM,6,'',('10.0.0.1',443))
        for value,rows in [('http://127.0.0.1/',[private]),('https://example.com/',[public,private])]:
            with patch('services.safe_http.socket.getaddrinfo',return_value=rows),patch('services.safe_http.PublicHTTPSession.get') as get:
                with self.assertRaises(UnsafeTargetError):assess_site(value,include_provider=True,include_discovery=True)
                get.assert_not_called()
    def test_static_description_and_heading_evidence(self):
        from services.web_assessment import WebAssessment
        r=response(b'<html><title>Title</title><meta name="description" content="Description"><meta name="viewport" content="width=device-width"><h1>Heading</h1><img src="/image"><script>bad()</script></html>')
        r.headers['Content-Type']='text/html'
        records={k:{'status':'no_record','values':[]} for k in ('A','AAAA','CNAME','MX','NS','TXT')}
        with patch('services.web_assessment.validate_public_url'),patch('services.web_assessment.dns_records',return_value=records),patch('services.web_assessment.certificate_details',return_value={'status':'completed'}),patch('services.safe_http.PublicHTTPSession.get',return_value=r):
            result=WebAssessment().analyze('https://example.com/')
        self.assertEqual(result['content']['description'],'Description')
        self.assertEqual(result['content']['headings'],['Heading'])
        self.assertEqual(result['content']['images_missing_alt'],1)
        self.assertEqual(result['verdict'],'unknown')

class ProviderObservationTests(unittest.TestCase):
    def test_unverified_phishing_entry_is_usable_unknown_not_outage(self):
        from services.web_assessment import provider_observation
        r=provider_observation({'verdict':'harmless','trust_score':100,'phishing':{'in_database':True,'verified':False,'valid':False}})
        self.assertEqual(r['status'],'completed');self.assertEqual(r['verdict'],'unknown')
        self.assertEqual(r['phishing_status'],'unverified');self.assertTrue(r['evidence_warning'])
    def test_partial_source_keeps_threat_and_sanitizes_errors(self):
        from services.web_assessment import provider_observation
        r=provider_observation({'verdict':'malicious','trust_score':5,'errors':['secret raw error'],'incomplete':True})
        self.assertEqual(r['status'],'partial');self.assertEqual(r['verdict'],'malicious');self.assertEqual(r['error_count'],1)
        self.assertNotIn('secret',str(r))
    def test_request_failure_and_malformed_score_stay_unavailable(self):
        from services.web_assessment import provider_observation
        for value in ({'error':'Request timeout'}, {'error':'API error: 401'}, {'verdict':'harmless','trust_score':float('nan')}, {'verdict':'harmless','trust_score':True},None):
            self.assertEqual(provider_observation(value)['status'],'unavailable')
    def test_header_observations_and_optional_counts_are_consistent(self):
        with patch('services.site_evidence.WebAssessment') as web:
            web.return_value.analyze.return_value=fixture()
            r=assess_site('example.com')
        self.assertEqual(r['stats']['checks_not_requested'],3)
        self.assertEqual(len(r['findings']),5)
        self.assertEqual(r['stats']['observation_count'],5)
        self.assertEqual(r['stats']['warning_count'],0)
        self.assertIn('5 review observations',r['report_brief'][3])
