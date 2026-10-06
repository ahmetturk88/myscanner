"""Account-bound DNS proof tests, without real DNS queries or active scans."""
import importlib.util
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import dns.exception
from flask import Flask, jsonify
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect, generate_csrf
from jinja2 import ChoiceLoader, DictLoader, FileSystemLoader
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import inspect
from extensions import db
from models import User, VerifiedTarget
from routes.vuln_routes import vuln_bp
from services.target_verification import (normalize_origin, issue_challenge,
    verify_challenge, has_verified_origin, challenge_value, serialize_target,
    lookup_txt, TargetProofError)

class OriginTests(unittest.TestCase):
    def test_exact_origin_normalization(self):
        for value, expected in [('EXAMPLE.com', 'https://example.com'), ('https://example.com:443/', 'https://example.com'), ('http://example.com:80', 'http://example.com'), ('https://example.com.', 'https://example.com'), ('https://bücher.de', 'https://xn--bcher-kva.de')]:
            self.assertEqual(normalize_origin(value)[0], expected)

    def test_unsafe_or_ambiguous_inputs_are_rejected(self):
        for value in [None, [], '', ' localhost', '127.0.0.1', '8.8.8.8', '[::1]', '2130706433', 'example.local', 'a.internal', 'example.com..', 'https://user:pass@example.com', 'https://example.com:8080', 'http://example.com:443', 'ftp://example.com', 'https://example.com/path', 'https://example.com?x=1', 'https://example.com#x', 'https://example.com\\evil', 'https://example.com\n', 'https://*.example.com', 'a..com']:
            with self.subTest(value=value), self.assertRaises(TargetProofError):
                normalize_origin(value)

class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.app = Flask(__name__)
        self.app.config.update(TESTING=True, SECRET_KEY='target-tests-only', SQLALCHEMY_DATABASE_URI='sqlite:///' + str(pathlib.Path(self.temporary.name, 'targets.db')))
        db.init_app(self.app)
        login = LoginManager(self.app)
        @login.user_loader
        def load_user(user_id):
            return db.session.get(User, int(user_id))
        CSRFProtect(self.app)
        @self.app.get('/token')
        def token():
            return jsonify(token=generate_csrf())
        self.app.register_blueprint(vuln_bp)
        root = pathlib.Path(__file__).resolve().parents[1]
        self.app.jinja_loader = ChoiceLoader([DictLoader({'base.html': '{% block head_extra %}{% endblock %}{% block content %}{% endblock %}'}), FileSystemLoader(str(root / 'templates'))])
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()
        self.owner = User(username='owner', email='owner@example.com', password_hash='unused', is_verified=True)
        self.other = User(username='other', email='other@example.com', password_hash='unused', is_verified=True, is_admin=True)
        db.session.add_all([self.owner, self.other])
        db.session.commit()
        self.owner_id, self.other_id = self.owner.id, self.other.id
        self.client = self.app.test_client()
        self.sign_in(self.owner_id)

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        db.engine.dispose()
        self.context.pop()
        self.temporary.cleanup()

    def sign_in(self, user_id):
        with self.client.session_transaction() as session:
            session['_user_id'] = str(user_id)
            session['_fresh'] = True

    def post(self, path, data=None):
        token = self.client.get('/token').get_json()['token']
        return self.client.post(path, json=data or {}, headers={'X-CSRFToken': token})

    def target(self, origin='example.com', now=100):
        return issue_challenge(self.owner_id, origin, now=now)

    def test_challenge_has_random_account_specific_value(self):
        first = self.target()
        second = issue_challenge(self.other_id, 'example.com', now=100)
        self.assertNotEqual(challenge_value(first), challenge_value(second))
        self.assertEqual(len(first.token), 64)
        self.assertFalse(has_verified_origin(self.owner_id, 'example.com', now=101))

    def test_matching_dns_proof_is_exact_and_account_bound(self):
        target = self.target()
        verify_challenge(target, self.owner_id, lookup=lambda host: [challenge_value(target)], now=101)
        self.assertTrue(has_verified_origin(self.owner_id, 'https://example.com:443', now=102))
        for origin in ['http://example.com', 'https://sub.example.com', 'https://example.net']:
            self.assertFalse(has_verified_origin(self.owner_id, origin, now=102))
        self.assertFalse(has_verified_origin(self.other_id, 'example.com', now=102))

    def test_dns_error_wrong_token_and_missing_record_never_verify(self):
        target = self.target()
        for values in [[], ['wrong'], ['é'], ['x' * 1000]]:
            with self.assertRaises(TargetProofError):
                verify_challenge(target, self.owner_id, lookup=lambda host: values, now=101)
        with self.assertRaises(TargetProofError):
            verify_challenge(target, self.owner_id, lookup=lambda host: (_ for _ in ()).throw(dns.exception.Timeout()), now=101)
        self.assertIsNone(target.verified_until)

    def test_other_account_and_expired_challenge_do_not_lookup(self):
        target = self.target()
        for owner, now in [(self.other_id, 101), (self.owner_id, 86500)]:
            with patch('services.target_verification.lookup_txt') as lookup:
                with self.assertRaises(TargetProofError):
                    verify_challenge(target, owner, now=now)
                lookup.assert_not_called()

    def test_rotation_and_revocation_invalidate_proof(self):
        target = self.target()
        old_value = challenge_value(target)
        verify_challenge(target, self.owner_id, lookup=lambda host: [old_value], now=101)
        target = issue_challenge(self.owner_id, 'example.com', now=102)
        self.assertNotEqual(challenge_value(target), old_value)
        self.assertFalse(has_verified_origin(self.owner_id, 'example.com', now=103))
        with self.assertRaises(TargetProofError):
            verify_challenge(target, self.owner_id, lookup=lambda host: [old_value], now=103)
        target.revoked = True
        db.session.commit()
        with self.assertRaises(TargetProofError):
            verify_challenge(target, self.owner_id, lookup=lambda host: [challenge_value(target)], now=104)

    def test_concurrent_revocation_cannot_be_undone_by_dns_result(self):
        target = self.target()
        expected = challenge_value(target)
        def lookup(host):
            # Change through a separate DB transaction while DNS is in flight.
            with db.engine.begin() as connection:
                connection.execute(VerifiedTarget.__table__.update().where(VerifiedTarget.id == target.id).values(revoked=True))
            return [expected]
        with self.assertRaises(TargetProofError):
            verify_challenge(target, self.owner_id, lookup=lookup, now=101)
        db.session.refresh(target)
        self.assertTrue(target.revoked)
        self.assertIsNone(target.verified_until)

    def test_verified_proof_expires(self):
        target = self.target()
        verify_challenge(target, self.owner_id, lookup=lambda host: [challenge_value(target)], now=101)
        self.assertFalse(has_verified_origin(self.owner_id, 'example.com', now=86501))
        self.assertNotEqual(serialize_target(target, now=86501)['status'], 'verified')

    def test_api_round_trip_and_scanner_remains_closed(self):
        response = self.post('/vulnerability/targets', {'origin': 'example.com', 'user_id': self.other_id})
        self.assertEqual(response.status_code, 201)
        data = response.get_json()['target']
        target = db.session.get(VerifiedTarget, data['id'])
        self.assertEqual(target.user_id, self.owner_id)
        with patch('services.target_verification.lookup_txt', return_value=[data['record_value']]):
            self.assertEqual(self.post('/vulnerability/targets/' + data['id'] + '/verify').status_code, 200)
        self.assertEqual(self.post('/vulnerability/start', {'target': 'https://example.com', 'target_id': data['id']}).status_code, 403)
        self.assertEqual(self.post('/vulnerability/targets/' + data['id'] + '/revoke').status_code, 200)
        self.assertFalse(has_verified_origin(self.owner_id, 'example.com'))

    def test_admin_cannot_read_verify_or_revoke_another_accounts_target(self):
        target = self.target()
        self.sign_in(self.other_id)
        for suffix in ['verify', 'revoke']:
            with patch('services.target_verification.lookup_txt') as lookup:
                self.assertEqual(self.post('/vulnerability/targets/' + target.id + '/' + suffix).status_code, 404)
                lookup.assert_not_called()
        self.assertNotIn(target.id.encode(), self.client.get('/vulnerability/targets').data)

    def test_anonymous_is_denied_and_target_pages_are_not_cached(self):
        response = self.client.get('/vulnerability/targets')
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        with self.client.session_transaction() as session:
            session.clear()
        from flask import g
        g.pop('_login_user', None)
        g.pop('csrf_token', None)
        self.assertIn(self.client.get('/vulnerability/targets').status_code, [302, 401])
        self.assertIn(self.post('/vulnerability/targets', {'origin': 'example.com'}).status_code, [302, 401])
        self.assertEqual(VerifiedTarget.query.count(), 0)

    def test_challenge_quota_prevents_creation(self):
        for _ in range(10):
            self.assertEqual(self.post('/vulnerability/targets', {'origin': 'example.com'}).status_code, 201)
        response = self.post('/vulnerability/targets', {'origin': 'other.com'})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(VerifiedTarget.query.count(), 1)

    def test_storage_failure_does_not_create_a_proof(self):
        from sqlalchemy.exc import SQLAlchemyError
        with patch('routes.vuln_routes.issue_challenge', side_effect=SQLAlchemyError('private error')):
            response = self.post('/vulnerability/targets', {'origin': 'example.com'})
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b'private error', response.data)
        self.assertEqual(VerifiedTarget.query.count(), 0)

    def test_unverified_account_is_denied(self):
        self.owner.is_verified = False
        db.session.commit()
        self.assertEqual(self.post('/vulnerability/targets', {'origin': 'example.com'}).status_code, 403)
        self.assertEqual(self.client.get('/vulnerability/targets').status_code, 403)
        self.assertEqual(VerifiedTarget.query.count(), 0)

    def test_missing_csrf_is_rejected_before_quota_or_dns(self):
        target = self.target()
        for path in ['/vulnerability/targets', '/vulnerability/targets/' + target.id + '/verify', '/vulnerability/targets/' + target.id + '/revoke']:
            with patch('routes.vuln_routes.consume_limit') as limit, patch('services.target_verification.lookup_txt') as lookup:
                self.assertEqual(self.client.post(path, json={}).status_code, 400)
                limit.assert_not_called()
                lookup.assert_not_called()

    def test_verification_quota_prevents_dns_lookup(self):
        response = self.post('/vulnerability/targets', {'origin': 'example.com'})
        target_id = response.get_json()['target']['id']
        with patch('services.target_verification.lookup_txt', return_value=[]) as lookup:
            for _ in range(5):
                self.assertEqual(self.post('/vulnerability/targets/' + target_id + '/verify').status_code, 400)
            response = self.post('/vulnerability/targets/' + target_id + '/verify')
            self.assertEqual(response.status_code, 429)
            self.assertIn('Retry-After', response.headers)
            self.assertEqual(lookup.call_count, 5)

    def test_page_renders_owner_record_and_post_forms(self):
        target = self.target(now=__import__('time').time())
        html = self.client.get('/vulnerability/targets').data.decode('utf-8')
        self.assertIn(challenge_value(target), html)
        self.assertIn('Active scanning remains temporarily unavailable', html)
        self.assertEqual(html.count('name="csrf_token"'), 3)
        self.assertIn('method="post"', html)

    def test_migration_creates_table_and_tolerates_create_all(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location('target_migration', root / 'migrations/versions/c291ed857a40_add_verified_targets.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with db.engine.begin() as connection:
            operations = Operations(MigrationContext.configure(connection))
            with patch.object(module, 'op', operations):
                module.downgrade()
                self.assertFalse(inspect(connection).has_table('verified_target'))
                module.upgrade()
                module.upgrade()
                self.assertTrue(inspect(connection).has_table('verified_target'))
                self.assertEqual({c['name'] for c in inspect(connection).get_columns('verified_target')}, set(VerifiedTarget.__table__.columns.keys()))

class DNSLookupTests(unittest.TestCase):
    def test_dns_query_is_absolute_bounded_and_joins_txt_chunks(self):
        with patch('services.target_verification.dns.resolver.Resolver') as factory:
            resolver = factory.return_value
            resolver.resolve.return_value = [SimpleNamespace(strings=(b'myscanner-', b'value')), SimpleNamespace(strings=(b'\xff',))]
            self.assertEqual(lookup_txt('example.com'), ['myscanner-value'])
            resolver.resolve.assert_called_once_with('_myscanner-verification.example.com.', 'TXT', search=False, lifetime=4)
            self.assertEqual(resolver.timeout, 2)
            self.assertEqual(resolver.lifetime, 4)
