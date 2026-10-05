"""Offline WSGI tests, without trusting real local or hosted proxy headers."""
import unittest
from flask import Flask, jsonify, request
from services.trusted_proxy import configure_trusted_proxy


class TrustedProxyTests(unittest.TestCase):
    def app(self, config=None):
        app = Flask(__name__)
        @app.get('/')
        def info():
            return jsonify(ip=request.remote_addr, scheme=request.scheme, host=request.host,
                           applied=request.environ.get('myscanner.proxy_applied', False))
        configure_trusted_proxy(app, {} if config is None else config)
        return app.test_client()

    def config(self, hops='1'):
        return {'TRUSTED_PROXY_CIDRS': '10.0.0.0/24,::1/128', 'TRUSTED_PROXY_HOPS': hops}

    def get(self, client, chain='198.51.100.7', peer='10.0.0.2', proto='https'):
        return client.get('/', environ_overrides={'REMOTE_ADDR': peer},
                          headers={'X-Forwarded-For': chain, 'X-Forwarded-Proto': proto,
                                   'X-Forwarded-Host': 'evil.invalid', 'X-Forwarded-Port': '666',
                                   'X-Forwarded-Prefix': '/evil'}).get_json()

    def test_default_does_not_trust_forwarded_headers(self):
        result = self.get(self.app())
        self.assertEqual(result['ip'], '10.0.0.2')
        self.assertEqual(result['scheme'], 'http')

    def test_trusted_peer_sets_client_ip_and_https_without_host_changes(self):
        result = self.get(self.app(self.config()))
        self.assertEqual(result['ip'], '198.51.100.7')
        self.assertEqual(result['scheme'], 'https')
        self.assertEqual(result['host'], 'localhost')
        self.assertTrue(result['applied'])

    def test_untrusted_direct_peer_cannot_spoof(self):
        result = self.get(self.app(self.config()), peer='203.0.113.8')
        self.assertEqual(result['ip'], '203.0.113.8')
        self.assertEqual(result['scheme'], 'http')
        self.assertFalse(result['applied'])

    def test_spoofed_prefix_is_ignored(self):
        result = self.get(self.app(self.config()), chain='203.0.113.99,198.51.100.7')
        self.assertEqual(result['ip'], '198.51.100.7')

    def test_two_hops_require_trusted_intermediate(self):
        client = self.app(self.config('2'))
        self.assertEqual(self.get(client, chain='198.51.100.7,10.0.0.3')['ip'], '198.51.100.7')
        self.assertFalse(self.get(client, chain='198.51.100.7,203.0.113.8')['applied'])

    def test_invalid_short_and_oversized_chains_are_ignored(self):
        client = self.app(self.config('2'))
        for chain in ['198.51.100.7', 'bad,10.0.0.3', 'fe80::1%eth0,10.0.0.3', '1' * 2049]:
            with self.subTest(chain=chain[:40]):
                self.assertFalse(self.get(client, chain=chain)['applied'])

    def test_invalid_scheme_is_not_applied(self):
        self.assertFalse(self.get(self.app(self.config()), proto='javascript')['applied'])

    def test_ipv6_and_mapped_ipv4_are_supported(self):
        client = self.app(self.config())
        self.assertEqual(self.get(client, peer='::1', chain='2001:db8::8')['ip'], '2001:db8::8')
        self.assertEqual(self.get(client, peer='::ffff:10.0.0.2', chain='::ffff:198.51.100.7')['ip'], '198.51.100.7')

    def test_unsafe_incomplete_or_mistyped_config_is_rejected(self):
        for config in [
            {'TRUSTED_PROXY_HOPS': '1'},
            {'TRUSTED_PROXY_CIDRS': '10.0.0.0/24'},
            {'TRUSTED_PROXY_CIDRS': '0.0.0.0/0', 'TRUSTED_PROXY_HOPS': '1'},
            {'TRUSTED_PROXY_CIDRS': '::/0', 'TRUSTED_PROXY_HOPS': '1'},
            {'TRUSTED_PROXY_CIDRS': 'bad', 'TRUSTED_PROXY_HOPS': '1'},
            self.config('0'), self.config('11'), self.config('abc'),
        ]:
            with self.subTest(config=config), self.assertRaises(RuntimeError):
                self.app(config)


class ProxyRateLimitIntegrationTests(unittest.TestCase):
    def test_clients_have_separate_quotas_and_spoofed_prefix_cannot_reset_one(self):
        from extensions import db
        from services.auth_rate_limit import consume_limit, AuthRateLimited
        app = Flask(__name__)
        app.config.update(SECRET_KEY='test-proxy', SQLALCHEMY_DATABASE_URI='sqlite:///:memory:')
        db.init_app(app)
        configure_trusted_proxy(app, {'TRUSTED_PROXY_CIDRS': '10.0.0.2/32', 'TRUSTED_PROXY_HOPS': '1'})
        @app.post('/attempt')
        def attempt():
            try:
                consume_limit('proxy-integration', request.remote_addr, 1, 60, now=100)
                return 'accepted'
            except AuthRateLimited:
                return 'limited', 429
        with app.app_context():
            db.create_all()
        client = app.test_client()
        def post(chain):
            return client.post('/attempt', environ_overrides={'REMOTE_ADDR': '10.0.0.2'},
                               headers={'X-Forwarded-For': chain, 'X-Forwarded-Proto': 'https'})
        self.assertEqual(post('198.51.100.1').status_code, 200)
        self.assertEqual(post('198.51.100.2').status_code, 200)
        self.assertEqual(post('203.0.113.77,198.51.100.1').status_code, 429)
        with app.app_context():
            db.drop_all()
            db.engine.dispose()


class ProxyDiagnosticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import test_task_ownership
        cls.helper = test_task_ownership.TaskOwnershipTests
        cls.helper.setUpClass()
        cls.app = cls.helper.production.app

    @classmethod
    def tearDownClass(cls):
        cls.helper.tearDownClass()

    def setUp(self):
        from pathlib import Path
        from extensions import db
        from models import User
        self.assertEqual(self.app.config['SQLALCHEMY_DATABASE_URI'], 'sqlite:///' + str(Path(self.helper.temporary.name, 'import.db')))
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            user = User(username='proxy-admin', email='proxy@example.invalid', password_hash='unused', is_admin=True)
            db.session.add(user)
            db.session.commit()
            self.user_id = user.id
        self.client = self.app.test_client()

    def tearDown(self):
        from extensions import db
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_anonymous_and_non_admin_are_denied(self):
        from extensions import db
        from models import User
        self.assertEqual(self.client.get('/admin/proxy-info').status_code, 302)
        with self.app.app_context():
            user = db.session.get(User, self.user_id)
            user.is_admin = False
            db.session.commit()
        with self.client.session_transaction() as session:
            session['_user_id'] = str(self.user_id)
            session['_fresh'] = True
        self.assertEqual(self.client.get('/admin/proxy-info').status_code, 403)

    def test_admin_can_inspect_only_proxy_metadata_without_caching(self):
        with self.client.session_transaction() as session:
            session['_user_id'] = str(self.user_id)
            session['_fresh'] = True
        response = self.client.get('/admin/proxy-info', headers={'X-Forwarded-For': '198.51.100.8'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(set(response.get_json()), {'peer_ip','client_ip','scheme','forwarded_for','forwarded_proto','configured','applied'})
        self.assertFalse(response.get_json()['applied'])
