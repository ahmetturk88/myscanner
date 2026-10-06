"""Contain unverified active scanning; no real target requests are sent."""
import hashlib
import json
import pathlib
import tempfile
import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import Mock, patch
from flask import render_template
from jinja2 import ChoiceLoader, DictLoader, FileSystemLoader
from bs4 import BeautifulSoup
from services.site_analyzer import SiteAnalyzer
from services.active_scan_policy import TargetAuthorizationRequired
from services.vulnerability_scanner.scan_orchestrator import ScanOrchestrator
from models.vulnerability import VulnerabilityScan
import test_scan_stop_permissions as stop_tests

class ActiveBoundaryTests(unittest.TestCase):
    setUp = stop_tests.StopScanPermissionsTests.setUp
    tearDown = stop_tests.StopScanPermissionsTests.tearDown
    sign_in = stop_tests.StopScanPermissionsTests.sign_in

    def test_user_and_admin_cannot_dispatch_any_scan_type(self):
        for user_id in [self.owner_id, self.admin_id]:
            self.sign_in(user_id)
            for scan_type in ['web_application', 'network', 'full']:
                for active in [True, False]:
                    response = self.client.post('/vulnerability/start', json={'target': 'https://example.invalid', 'scan_type': scan_type, 'active_scan': active, 'verified': True})
                    self.assertEqual(response.status_code, 403)
                    self.assertEqual(response.get_json()['code'], 'target_authorization_required')
        self.orchestrator.assert_not_called()
        self.assertEqual(VulnerabilityScan.query.count(), 1)

    def test_malformed_and_missing_payload_do_not_dispatch(self):
        self.sign_in(self.owner_id)
        for kwargs in [{}, {'json': {}}, {'data': '{', 'content_type': 'application/json'}]:
            self.assertEqual(self.client.post('/vulnerability/start', **kwargs).status_code, 403)
        self.orchestrator.assert_not_called()

    def test_anonymous_cannot_dispatch(self):
        self.assertIn(self.client.post('/vulnerability/start', json={}).status_code, [302, 401])
        self.orchestrator.assert_not_called()

    def test_direct_orchestrator_call_cannot_write_or_queue(self):
        orchestrator = object.__new__(ScanOrchestrator)
        orchestrator._executor = Mock()
        with patch('services.vulnerability_scanner.scan_orchestrator.db.session.add') as add:
            with self.assertRaises(TargetAuthorizationRequired):
                orchestrator.start_scan('https://example.invalid', 'full', self.admin_id, {'verified': True})
            add.assert_not_called()
        orchestrator._executor.submit.assert_not_called()

    def test_owner_can_still_stop_existing_scan(self):
        self.sign_in(self.owner_id)
        self.assertEqual(self.client.post('/vulnerability/stop/test-scan').status_code, 200)
        self.orchestrator.return_value.stop_scan.assert_called_once_with('test-scan')

    def test_dashboard_explains_disabled_form(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        self.app.jinja_loader = ChoiceLoader([DictLoader({'base.html': '{% block head_extra %}{% endblock %}{% block content %}{% endblock %}{% block body_extra %}{% endblock %}'}), FileSystemLoader(str(root / 'templates'))])
        self.app.add_url_rule('/site-scanner', endpoint='site_scanner', view_func=lambda: 'site')
        with self.app.test_request_context('/'):
            html = render_template('vuln_scan.html', stats={'total_scans': 0, 'total_vulnerabilities': 0, 'critical_count': 0}, recent_scans=[], scanners_status={'zap': {'available': False, 'status': 'unavailable'}, 'openvas': {'available': False, 'status': 'unavailable'}})
        soup = BeautifulSoup(html, 'html.parser')
        self.assertTrue(soup.select_one('#scanForm fieldset').has_attr('disabled'))
        self.assertIn('temporarily unavailable', soup.get_text())
        self.assertEqual(soup.find('a', href='/site-scanner').get_text().strip(), 'Open Site Scanner for general analysis →')

class PassiveSiteTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.analyzer = SiteAnalyzer(cache_dir=self.temporary.name)

    def test_dynamic_compatibility_method_never_sends_requests(self):
        with patch.object(self.analyzer.session, 'get') as get:
            result = self.analyzer.scan_vulnerabilities_dynamic('https://example.invalid/?id=1')
        get.assert_not_called()
        self.assertEqual(result['status'], 'not_performed')
        self.assertEqual(result['tested_endpoints'], [])
        self.assertNotIn('sql_injection_suspected', result)
        self.assertNotIn('risk_score', result)

    def test_comprehensive_analysis_does_not_call_dynamic_scanner(self):
        with patch('services.site_analyzer.validate_public_url', return_value=SimpleNamespace(url='https://example.invalid/')), patch.object(self.analyzer.session, 'get', return_value=SimpleNamespace(status_code=200, url='https://example.invalid/', text='<html><title>Example Site Title</title></html>')), patch.object(self.analyzer, 'scan_vulnerabilities_dynamic', side_effect=AssertionError('Must not dispatch active analysis')):
            patches = [patch.object(self.analyzer, name, return_value={}) for name in ['check_security_headers', 'check_ssl_advanced', 'analyze_robots_txt', 'analyze_sitemap', 'check_dns_records', 'check_phishing_indicators', 'check_reputation', 'analyze_performance']]
            for item in patches:
                item.start()
                self.addCleanup(item.stop)
            result = self.analyzer.comprehensive_analysis('https://example.invalid/')
        self.assertNotIn('error', result)
        self.assertEqual(result['analysis_mode'], 'passive')
        self.assertFalse(result['active_scan_performed'])
        self.assertEqual(result['vulnerabilities']['dynamic']['status'], 'not_performed')

    def test_cache_from_previous_active_analysis_is_not_reused(self):
        domain = 'https://example.invalid/'
        old_key = hashlib.md5(domain.encode()).hexdigest()
        pathlib.Path(self.temporary.name, old_key + '.json').write_text(json.dumps({'cached_at': datetime.now().isoformat(), 'result': {'old_active': True}}), encoding='utf-8')
        self.assertIsNone(self.analyzer._get_cached_result(domain))
        result = {'analysis_mode': 'passive'}
        self.analyzer._save_cached_result(domain, result)
        self.assertEqual(self.analyzer._get_cached_result(domain), result)
