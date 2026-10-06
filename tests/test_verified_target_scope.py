"""Scope and redirect checks use mocked HTTP/DNS; no live scan traffic."""
import time
import unittest
from unittest.mock import patch, Mock
import requests
from extensions import db
from models import VerifiedTarget
from services.target_verification import issue_challenge
from services.verified_target_scope import VerifiedTargetScope, VerifiedTargetSession, TargetScopeError
from services.safe_http import UnsafeTargetError
import test_target_verification as fixtures

class ScopeTests(unittest.TestCase):
    setUp = fixtures.VerificationTests.setUp
    tearDown = fixtures.VerificationTests.tearDown
    sign_in = fixtures.VerificationTests.sign_in

    def grant(self):
        target = issue_challenge(self.owner_id, 'https://example.com')
        target.verified_until = time.time() + 3600
        db.session.commit()
        return target

    def test_owner_paths_queries_and_default_port_are_allowed(self):
        self.grant()
        scope = VerifiedTargetScope.for_target(self.owner_id, 'https://EXAMPLE.com:443/')
        self.assertEqual(scope.validate_url('https://example.com:443/a?q=1#part'), 'https://example.com/a?q=1')

    def test_admin_and_unverified_email_cannot_use_grant(self):
        self.grant()
        with self.assertRaises(TargetScopeError):
            VerifiedTargetScope.for_target(self.other_id, 'https://example.com')
        self.owner.is_verified = False
        db.session.commit()
        with self.assertRaises(TargetScopeError):
            VerifiedTargetScope.for_target(self.owner_id, 'https://example.com')

    def test_out_of_scope_urls_fail_before_network(self):
        self.grant()
        scope = VerifiedTargetScope.for_target(self.owner_id, 'example.com')
        for value in ['https://sub.example.com/a', 'https://example.net', 'http://example.com',
                      'https://example.com:8080', 'https://example.com:80', '//example.com/a',
                      '/path', 'https://user@example.com', 'https://example.com\\@evil.com',
                      'https://127.0.0.1', 'file:///etc/passwd', 'https://example.com/' + 'a'*2048]:
            with self.subTest(value=value), patch('services.safe_http.socket.getaddrinfo') as dns:
                with self.assertRaises((UnsafeTargetError, ValueError)):
                    scope.authorize_url(value)
                dns.assert_not_called()

    def test_expiry_revocation_rotation_are_checked_again(self):
        target = self.grant()
        scope = VerifiedTargetScope.for_target(self.owner_id, 'example.com')
        for field, value in [('verified_until', time.time()-1), ('revoked', True)]:
            setattr(target, field, value)
            db.session.commit()
            with self.assertRaises(TargetScopeError):
                scope.validate_url('https://example.com/a')
            target.verified_until = time.time()+3600
            target.revoked = False
            db.session.commit()
        issue_challenge(self.owner_id, 'example.com')
        with self.assertRaises(TargetScopeError):
            scope.validate_url('https://example.com/a')

    def test_independent_database_revocation_is_not_hidden_by_identity_map(self):
        target = self.grant()
        scope = VerifiedTargetScope.for_target(self.owner_id, 'example.com')
        with db.engine.begin() as connection:
            connection.execute(VerifiedTarget.__table__.update().where(VerifiedTarget.id == target.id).values(revoked=True))
        with self.assertRaises(TargetScopeError):
            scope.validate_url('https://example.com/a')

    def test_private_mixed_and_failed_dns_are_rejected(self):
        self.grant()
        scope = VerifiedTargetScope.for_target(self.owner_id, 'example.com')
        for ips in [['127.0.0.1'], ['93.184.216.34', '10.0.0.1'], ['::1'], []]:
            records = [(2, 1, 6, '', (ip, 443)) for ip in ips]
            with self.subTest(ips=ips), patch('services.safe_http.socket.getaddrinfo', return_value=records):
                with self.assertRaises(UnsafeTargetError):
                    scope.authorize_url('https://example.com/a')

    def test_public_preflight_returns_validated_addresses(self):
        self.grant()
        scope = VerifiedTargetScope.for_target(self.owner_id, 'example.com')
        records = [(2, 1, 6, '', ('93.184.216.34', 443))]
        with patch('services.safe_http.socket.getaddrinfo', return_value=records):
            self.assertEqual(scope.authorize_url('https://example.com/a').addresses, tuple(records))

    def response(self, request, location=None):
        response = requests.Response()
        response.request = request
        response.url = request.url
        response.status_code = 302 if location else 200
        response._content = b''
        response._content_consumed = True
        if location:
            response.headers['Location'] = location
        return response

    def test_cross_origin_redirect_never_reaches_transport(self):
        self.grant()
        scope = VerifiedTargetScope.for_target(self.owner_id, 'example.com')
        for destination in ['https://evil.com/a', 'http://example.com/a', 'https://sub.example.com/a', 'https://example.com:80/a']:
            with self.subTest(destination=destination), VerifiedTargetSession(scope) as session:
                with patch('services.safe_http.PublicHTTPAdapter.send', side_effect=lambda request, **kw: self.response(request, destination)) as transport:
                    with self.assertRaises(TargetScopeError):
                        session.get('https://example.com/a')
                    self.assertEqual(transport.call_count, 1)

    def test_same_origin_redirect_allowed_but_rechecks_revocation(self):
        target = self.grant()
        scope = VerifiedTargetScope.for_target(self.owner_id, 'example.com')
        def send(request, **kwargs):
            return self.response(request, '/b' if request.url.endswith('/a') else None)
        with VerifiedTargetSession(scope) as session, patch('services.safe_http.PublicHTTPAdapter.send', side_effect=send) as transport:
            self.assertEqual(session.get('https://example.com/a').status_code, 200)
            self.assertEqual(transport.call_count, 2)
        def revoke(request, **kwargs):
            target.revoked = True
            db.session.commit()
            return self.response(request, '/b')
        with VerifiedTargetSession(scope) as session, patch('services.safe_http.PublicHTTPAdapter.send', side_effect=revoke) as transport:
            with self.assertRaises(TargetScopeError):
                session.get('https://example.com/a')
            self.assertEqual(transport.call_count, 1)

    def test_scoped_adapter_retains_pinned_public_connection(self):
        self.grant()
        scope = VerifiedTargetScope.for_target(self.owner_id, 'example.com')
        records = [(2, 1, 6, '', ('93.184.216.34', 443))]
        with VerifiedTargetSession(scope) as session:
            self.assertFalse(session.trust_env)
            adapter = session.get_adapter('https://example.com')
            with patch('services.safe_http.socket.getaddrinfo', return_value=records), patch.object(adapter.poolmanager, 'connection_from_host', return_value=Mock()) as pool:
                adapter._pool('https://example.com/a')
                self.assertEqual(pool.call_args.args[0], '93.184.216.34')
                self.assertEqual(pool.call_args.kwargs['pool_kwargs']['assert_hostname'], 'example.com')

    def test_pending_and_storage_failure_do_not_grant(self):
        issue_challenge(self.owner_id, 'example.com')
        with self.assertRaises(TargetScopeError):
            VerifiedTargetScope.for_target(self.owner_id, 'example.com')
        with patch.object(db.session, 'execute', side_effect=RuntimeError('storage unavailable')):
            with self.assertRaises(RuntimeError):
                VerifiedTargetScope.for_target(self.owner_id, 'example.com')

    def test_policy_preparation_checks_public_dns_without_enabling_dispatch(self):
        from services.active_scan_policy import prepare_verified_target, require_verified_target, TargetAuthorizationRequired
        self.grant()
        records = [(2, 1, 6, '', ('93.184.216.34', 443))]
        with patch('services.safe_http.socket.getaddrinfo', return_value=records):
            self.assertEqual(prepare_verified_target(self.owner_id, 'example.com').origin, 'https://example.com')
        with self.assertRaises(TargetAuthorizationRequired):
            require_verified_target()

    def test_connection_selection_rejects_rebinding_after_public_preflight(self):
        self.grant()
        scope = VerifiedTargetScope.for_target(self.owner_id, 'example.com')
        public = [(2, 1, 6, '', ('93.184.216.34', 443))]
        private = [(2, 1, 6, '', ('127.0.0.1', 443))]
        with VerifiedTargetSession(scope) as session, patch('services.safe_http.socket.getaddrinfo', side_effect=[public, private]):
            scope.authorize_url(scope.origin)
            adapter = session.get_adapter(scope.origin)
            with patch.object(adapter.poolmanager, 'connection_from_host') as pool:
                with self.assertRaises(UnsafeTargetError):
                    adapter._pool(scope.origin)
                pool.assert_not_called()
