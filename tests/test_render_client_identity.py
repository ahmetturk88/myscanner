"""Offline tests of the explicit public Render ingress profile."""
import unittest
from flask import Flask, jsonify, request
from services.trusted_proxy import configure_trusted_proxy

class RenderClientIdentityTests(unittest.TestCase):
    def config(self):
        return {'RENDER': 'true', 'RENDER_CLIENT_IP_SOURCE': 'cloudflare'}

    def app(self, config=None):
        app = Flask(__name__)
        @app.get('/')
        def info():
            return jsonify(ip=request.remote_addr, scheme=request.scheme, host=request.host,
                           path=request.path, prefix=request.script_root,
                           peer=request.environ.get('myscanner.proxy_peer'),
                           applied=request.environ.get('myscanner.proxy_applied', False),
                           source=request.environ.get('myscanner.identity_source', 'direct'))
        configure_trusted_proxy(app, self.config() if config is None else config)
        return app.test_client()

    def get(self, candidate='8.8.8.8', peer='127.0.0.1', extra=None, config=None):
        headers = {'CF-Connecting-IP': candidate, 'X-Forwarded-For': '198.51.100.77,1.1.1.1',
                   'X-Forwarded-Proto': 'https', 'X-Forwarded-Host': 'evil.invalid',
                   'X-Forwarded-Port': '666', 'X-Forwarded-Prefix': '/evil'}
        headers.update(extra or {})
        return self.app(config).get('/', headers=headers, environ_overrides={'REMOTE_ADDR': peer}).get_json()

    def test_public_address_applies_with_original_peer_retained(self):
        result = self.get()
        self.assertEqual(result['ip'], '8.8.8.8')
        self.assertEqual(result['peer'], '127.0.0.1')
        self.assertTrue(result['applied'])
        self.assertEqual(result['source'], 'render-cloudflare')

    def test_host_scheme_port_and_prefix_are_unchanged(self):
        result = self.get()
        self.assertEqual((result['host'], result['scheme'], result['prefix'], result['path']), ('localhost', 'http', '', '/'))

    def test_forwarded_for_prefix_never_selects_client(self):
        for chain in ['198.51.100.77', '198.51.100.77,1.1.1.1,10.25.1.2', 'bad']:
            self.assertEqual(self.get(extra={'X-Forwarded-For': chain})['ip'], '8.8.8.8')

    def test_render_environment_alone_does_not_trust_headers(self):
        result = self.get(config={'RENDER': 'true'})
        self.assertEqual(result['ip'], '127.0.0.1')
        self.assertFalse(result['applied'])

    def test_local_default_ignores_cloudflare_headers(self):
        self.assertEqual(self.get(config={})['ip'], '127.0.0.1')

    def test_non_loopback_and_other_loopback_peers_cannot_apply(self):
        for peer in ['1.1.1.1', '10.25.170.135', '127.0.0.2', 'bad', '']:
            with self.subTest(peer=peer):
                result = self.get(peer=peer)
                self.assertEqual(result['ip'], peer)
                self.assertFalse(result['applied'])

    def test_missing_malformed_private_reserved_candidates_fall_back(self):
        for value in ['', 'bad', '8.8.8.8,1.1.1.1', '198.51.100.77', '127.0.0.1', '10.0.0.1', '224.0.0.1', 'ff02::1', 'fe80::1%eth0', ' ' * 101 + '8.8.8.8']:
            with self.subTest(value=value):
                result = self.get(value)
                self.assertEqual(result['ip'], '127.0.0.1')
                self.assertFalse(result['applied'])
                self.assertEqual(result['source'], 'direct')

    def test_ipv6_and_mapped_addresses_are_normalized(self):
        for candidate, peer, expected in [('2606:4700::1111', '::1', '2606:4700::1111'), ('::ffff:8.8.8.8', '::ffff:127.0.0.1', '8.8.8.8')]:
            self.assertEqual(self.get(candidate, peer)['ip'], expected)

    def test_pseudo_ipv4_requires_valid_ipv6_companion(self):
        self.assertEqual(self.get('240.1.2.3', extra={'CF-Connecting-IPv6': '2606:4700::1111'})['ip'], '2606:4700::1111')
        for companion in ['', '8.8.8.8', '2001:db8::77', 'bad', 'ff02::1']:
            self.assertFalse(self.get('240.1.2.3', extra={'CF-Connecting-IPv6': companion})['applied'])

    def test_ipv6_companion_cannot_override_normal_ipv4(self):
        self.assertEqual(self.get(extra={'CF-Connecting-IPv6': '2606:4700::1111'})['ip'], '8.8.8.8')
        self.assertFalse(self.get(extra={'CF-Connecting-IPv6': 'x' * 101})['applied'])

    def test_invalid_environment_profile_and_mixed_config_fail_startup(self):
        configurations = [
            {'RENDER_CLIENT_IP_SOURCE': 'cloudflare'},
            {'RENDER': 'false', 'RENDER_CLIENT_IP_SOURCE': 'cloudflare'},
            {'RENDER': 'true', 'RENDER_CLIENT_IP_SOURCE': 'cloudflrae'},
            {**self.config(), 'TRUSTED_PROXY_CIDRS': '127.0.0.1/32'},
            {**self.config(), 'TRUSTED_PROXY_HOPS': '1'},
        ]
        for config in configurations:
            with self.subTest(config=config), self.assertRaises(RuntimeError):
                self.app(config)

    def test_clients_have_separate_database_quotas_and_prefix_cannot_reset_one(self):
        from extensions import db
        from services.auth_rate_limit import consume_limit, AuthRateLimited
        app = Flask(__name__)
        app.config.update(SECRET_KEY='render-test', SQLALCHEMY_DATABASE_URI='sqlite:///:memory:')
        db.init_app(app)
        configure_trusted_proxy(app, self.config())
        @app.post('/attempt')
        def attempt():
            try:
                consume_limit('render-profile-test', request.remote_addr, 1, 60, now=100)
                return 'accepted'
            except AuthRateLimited:
                return 'limited', 429
        with app.app_context():
            db.create_all()
        try:
            client = app.test_client()
            def post(candidate, forwarded=''):
                return client.post('/attempt', environ_overrides={'REMOTE_ADDR': '127.0.0.1'},
                                   headers={'CF-Connecting-IP': candidate, 'X-Forwarded-For': forwarded})
            self.assertEqual(post('8.8.8.8').status_code, 200)
            self.assertEqual(post('1.1.1.1').status_code, 200)
            self.assertEqual(post('8.8.8.8', '198.51.100.77').status_code, 429)
            self.assertEqual(post('').status_code, 200)
            self.assertEqual(post('bad', '1.0.0.1').status_code, 429)
        finally:
            with app.app_context():
                db.session.remove()
                db.drop_all()
                db.engine.dispose()
