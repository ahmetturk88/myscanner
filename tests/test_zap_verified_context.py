"""ZAP context preparation only: HTTP API and target DNS are mocked."""
import re
from contextlib import nullcontext
import time
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
from extensions import db
from services.target_verification import issue_challenge
from services.active_scan_policy import TargetAuthorizationRequired
from services.verified_target_scope import VerifiedTargetScope, TargetScopeError
from services.vulnerability_scanner.zap_client import ZAPClient, ZAPTargetContext, context_origin_regex
from services.vulnerability_scanner.scan_orchestrator import ScanOrchestrator
import test_target_verification as fixtures

class ZAPContextTests(unittest.TestCase):
    setUp = fixtures.VerificationTests.setUp
    tearDown = fixtures.VerificationTests.tearDown
    sign_in = fixtures.VerificationTests.sign_in

    def zap_client(self):
        client = object.__new__(ZAPClient)
        client._contexts = {}
        client.api_key = 'test-only'
        client.base_url = 'http://zap.internal:8080'
        client._session = Mock()
        client._session.get.return_value = Mock(status_code=200, json=lambda: {'Result':'OK', 'contextId':'7'})
        return client

    def scope(self):
        target = issue_challenge(self.owner_id, 'example.com')
        target.verified_until = time.time()+3600
        db.session.commit()
        return VerifiedTargetScope.for_target(self.owner_id, 'example.com')

    def public(self):
        return patch('services.safe_http.socket.getaddrinfo', return_value=[(2,1,6,'',('93.184.216.34',443))])

    def zap_context(self, client):
        with self.public():
            return client.create_verified_context(self.scope())

    def test_regex_rejects_sibling_prefix_credentials_port_and_scheme(self):
        # ZAP uses Java's strict end anchor; Python equivalent for this test.
        pattern = context_origin_regex('https://example.com').replace(r'\z', r'\Z')
        for url in ['https://example.com', 'https://example.com/a?q=1', 'https://example.com:443/a']:
            self.assertIsNotNone(re.fullmatch(pattern,url))
        for url in ['http://example.com/a','https://example.com:80/a','https://example.com.evil.com/a','https://sub.example.com','https://user@example.com','https://exampleXcom/a','https://example.com/\n']:
            self.assertIsNone(re.fullmatch(pattern,url),url)

    def test_context_is_unique_and_exact_and_configured_before_in_scope(self):
        client = self.zap_client()
        first = self.zap_context(client)
        second = self.zap_context(client)
        self.assertNotEqual(first.name,second.name)
        calls = client._session.get.call_args_list[:4]
        self.assertEqual([c.args[0].split('/')[-2] for c in calls], ['newContext','setContextInScope','includeInContext','setContextInScope'])
        self.assertEqual(calls[1].kwargs['params']['booleanInScope'],'false')
        self.assertEqual(calls[2].kwargs['params']['regex'],context_origin_regex('https://example.com'))
        self.assertEqual(calls[3].kwargs['params']['booleanInScope'],'true')
        self.assertTrue(all(c.kwargs['allow_redirects'] is False for c in calls))

    def test_unverified_and_private_target_do_not_configure_zap(self):
        client = self.zap_client()
        with self.assertRaises(TargetScopeError):
            client.create_verified_context(SimpleNamespace(origin='https://example.com'))
        scope = self.scope()
        with patch('services.safe_http.socket.getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',443))]):
            with self.assertRaises(Exception):
                client.create_verified_context(scope)
        client._session.get.assert_not_called()

    def test_context_error_cleans_only_new_context_and_does_not_register_it(self):
        client = self.zap_client()
        responses = [Mock(status_code=200, json=lambda:{'contextId':'7'}), Mock(status_code=200, json=lambda:{'Result':'FAIL'}), Mock(status_code=200, json=lambda:{'Result':'OK'})]
        client._session.get.side_effect = responses
        with self.public(), self.assertRaises(RuntimeError):
            client.create_verified_context(self.scope())
        calls = client._session.get.call_args_list
        self.assertIn('/removeContext/',calls[-1].args[0])
        self.assertEqual(calls[0].kwargs['params']['contextName'],calls[-1].kwargs['params']['contextName'])
        self.assertFalse(client._contexts)

    def test_api_error_payload_and_malformed_ids_are_not_success(self):
        for data in [{'contextId':'bad'}, {'contextId':'7','code':'error'}, [], {'contextId':'\u0667'}]:
            client=self.zap_client()
            client._session.get.return_value.json=lambda:data
            with self.public(), self.assertRaises(RuntimeError):
                client.create_verified_context(self.scope())
            self.assertFalse(client._contexts)

    def test_direct_target_requests_remain_closed_without_any_api_call(self):
        client=self.zap_client()
        for method in [client.access_url,client.start_active_scan]:
            with self.assertRaises(TargetAuthorizationRequired):
                method('https://example.com')
        client._session.get.assert_not_called()
        orchestrator=object.__new__(ScanOrchestrator)
        with self.assertRaises(TargetAuthorizationRequired):
            orchestrator._run_zap_scan('https://example.com',SimpleNamespace(user_id=self.owner_id))

    def test_prepared_spider_and_active_calls_use_their_own_context(self):
        client=self.zap_client();context=self.zap_context(client)
        client._session.get.reset_mock()
        client._session.get.return_value=Mock(status_code=200, json=lambda:{'scan':'3'})
        # Test future gated code with local mocks; no production bypass exists.
        with self.public(), patch('services.vulnerability_scanner.zap_client.require_verified_target'):
            client.access_url('https://example.com/a',context=context)
            client.start_active_scan('https://example.com/a',context=context)
        calls=client._session.get.call_args_list
        self.assertEqual(len(calls),2)
        self.assertTrue(all('/accessUrl/' not in c.args[0] for c in calls))
        self.assertEqual(calls[0].kwargs['params']['contextName'],context.name)
        self.assertEqual(calls[0].kwargs['params']['subtreeOnly'],'true')
        self.assertEqual(calls[1].kwargs['params']['contextId'],context.context_id)
        self.assertEqual(calls[1].kwargs['params']['inScopeOnly'],'true')

    def test_forged_context_and_different_target_fail_before_scan_call(self):
        client=self.zap_client();context=self.zap_context(client);client._session.get.reset_mock()
        forged=ZAPTargetContext(context.name,context.context_id,context.scope)
        with patch('services.vulnerability_scanner.zap_client.require_verified_target'):
            for ctx,url in [(forged,'https://example.com'),(context,'https://evil.com')]:
                with self.assertRaises(TargetScopeError):
                    client.access_url(url,context=ctx)
        client._session.get.assert_not_called()

    def test_alerts_are_exact_origin_and_empty_results_do_not_fallback(self):
        client=self.zap_client();context=self.zap_context(client)
        client._session.get.reset_mock()
        client._session.get.return_value=Mock(status_code=200, json=lambda:{'alerts':[{'url':'https://example.com/a','name':'owned'},{'url':'https://example.com.evil.com/a'},{'url':'http://example.com/a'},{'url':'https://other.com/a'}]})
        with self.public():
            alerts=client.get_alerts('https://example.com',context=context)
        self.assertEqual([a['name'] for a in alerts],['owned'])
        client._session.get.return_value=Mock(status_code=200, json=lambda:{'alerts':[]})
        with self.public():
            self.assertEqual(client.get_alerts('https://example.com',context=context),[])
        with self.assertRaises(TargetScopeError):
            client.get_all_alerts_no_filter()

    def test_context_removal_does_not_allow_reuse(self):
        client=self.zap_client();context=self.zap_context(client)
        client.remove_verified_context(context)
        client._session.get.reset_mock()
        with self.assertRaises(TargetScopeError):
            client._verified_context_url(context,'https://example.com')
        client._session.get.assert_not_called()

    def test_orchestrator_timeout_propagates_and_cleans_context(self):
        orchestrator=object.__new__(ScanOrchestrator)
        client=Mock()
        client.access_url.return_value={'scan_id':'3'}
        client.wait_for_completion.return_value=False
        orchestrator.zap_client=client
        record=SimpleNamespace(id=1,user_id=self.owner_id)
        with patch('services.vulnerability_scanner.scan_orchestrator.require_verified_target'), patch('services.active_scan_policy.prepare_verified_target',return_value=Mock()), patch('services.vulnerability_scanner.zap_job.isolated_zap_job', return_value=nullcontext(client)):
            with self.assertRaises(RuntimeError):
                orchestrator._run_zap_scan('https://example.com',record,{'active_scan':False})
        client.get_alerts.assert_not_called()
        client.get_all_alerts_no_filter.assert_not_called()
        client.remove_verified_context.assert_called_once_with(client.create_verified_context.return_value)

    def test_orchestrator_empty_scoped_results_never_read_other_targets(self):
        orchestrator=object.__new__(ScanOrchestrator)
        client=Mock()
        client.access_url.return_value={'scan_id':'3'}
        client.wait_for_completion.return_value=True
        client.wait_for_passive_scan.return_value=True
        client.get_alerts.return_value=[]
        orchestrator.zap_client=client
        record=SimpleNamespace(id=1,user_id=self.owner_id)
        with patch('services.vulnerability_scanner.scan_orchestrator.require_verified_target'), patch('services.active_scan_policy.prepare_verified_target',return_value=Mock()), patch('services.vulnerability_scanner.zap_job.isolated_zap_job', return_value=nullcontext(client)):
            self.assertEqual(orchestrator._run_zap_scan('https://example.com',record,{'active_scan':False}),[])
        client.get_all_alerts_no_filter.assert_not_called()
        client.remove_verified_context.assert_called_once()

    def test_api_redirect_is_rejected_without_following_it(self):
        client=self.zap_client()
        client._session.get.return_value=Mock(status_code=302,json=lambda:{'contextId':'7'})
        with self.public(), self.assertRaises(RuntimeError):
            client.create_verified_context(self.scope())
        self.assertFalse(client._contexts)
        self.assertFalse(client._session.get.call_args.kwargs['allow_redirects'])
