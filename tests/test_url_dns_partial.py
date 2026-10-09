import socket
import unittest
from unittest.mock import patch, Mock
from services.safe_http import TargetResolutionError, UnsafeTargetError, validate_public_url
from services.url_analyzer import URLDeepAnalyzer, dns_partial

class DNSPartialTests(unittest.TestCase):
    def test_dns_failure_is_typed_and_never_opens_connection(self):
        with patch('services.safe_http.socket.getaddrinfo', side_effect=socket.gaierror(-5, 'unavailable')):
            with self.assertRaises(TargetResolutionError):
                validate_public_url('https://example.com')
    def test_private_target_is_not_reclassified_as_dns_failure(self):
        with self.assertRaises(UnsafeTargetError) as caught:
            validate_public_url('http://127.0.0.1')
        self.assertNotIsInstance(caught.exception, TargetResolutionError)
    def test_unavailable_check_has_no_clean_or_risk_score(self):
        result=dns_partial(Mock(side_effect=TargetResolutionError('hidden')))()
        self.assertEqual(result['reason'], 'target_dns_unavailable')
        self.assertNotIn('score',result)
        self.assertNotIn('hidden',str(result))
    def test_policy_rejection_still_propagates(self):
        with self.assertRaises(UnsafeTargetError):
            dns_partial(Mock(side_effect=UnsafeTargetError('blocked')))()
    def test_local_dns_failure_retains_structure_and_provider_threat(self):
        analyzer=URLDeepAnalyzer()
        try:
            with patch('services.url_analyzer.validate_public_url',side_effect=TargetResolutionError('DNS')), \
                 patch.object(analyzer,'check_ssl_certificate',return_value={'error':'DNS unavailable'}), \
                 patch.object(analyzer,'check_dns_records',return_value={'error':'DNS unavailable'}), \
                 patch.object(analyzer,'check_security_headers',return_value={'error':'DNS unavailable'}), \
                 patch.object(analyzer,'analyze_with_urlvet',return_value={'verdict':'malicious','trust_score':0}):
                result=analyzer.comprehensive_analysis('https://example.com')
            self.assertTrue(result['structure']['is_https'])
            self.assertEqual(result['verdict'],'malicious')
            self.assertIn('error',result['security_headers'])
            from services.url_assessment import assess_url
            assessment=assess_url(result, {})
            self.assertEqual(assessment['coverage'],'partial')
            self.assertEqual(assessment['verdict'],'malicious')
        finally:
            analyzer.session.close()

class WorkerIsolationTests(unittest.TestCase):
    def test_runtime_workers_consume_disjoint_queues(self):
        from scripts import vps_runtime
        commands={}
        for role in ('worker','tip-worker'):
            with patch.object(vps_runtime,'configure'), patch.object(vps_runtime.os,'execvp') as launch:
                vps_runtime.run(role)
                commands[role]=launch.call_args.args[1]
        def queues(role):
            command=commands[role]
            return set(command[command.index('-Q')+1].split(','))
        self.assertEqual(queues('worker'),{'scans','celery'})
        self.assertEqual(queues('tip-worker'),{'tip'})
        self.assertNotEqual(commands['worker'][-1],commands['tip-worker'][-1])
