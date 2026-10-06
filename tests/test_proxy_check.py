"""Candidate parsing never activates proxy trust; browser checks are diagnostic."""
import pathlib
import shutil
import subprocess
import unittest
from flask import Flask, request
from services.trusted_proxy import render_edge_candidate, configure_trusted_proxy

class EdgeDiagnosticTests(unittest.TestCase):
    def candidate(self, value, ipv6=''):
        return render_edge_candidate({'HTTP_CF_CONNECTING_IP': value, 'HTTP_CF_CONNECTING_IPV6': ipv6})

    def test_public_and_mapped_addresses(self):
        for value, expected in [('8.8.8.8', '8.8.8.8'), ('::ffff:8.8.8.8', '8.8.8.8'), ('2606:4700::1111', '2606:4700::1111')]:
            self.assertEqual(self.candidate(value), expected)

    def test_invalid_private_reserved_and_multicast_are_rejected(self):
        for value in ['', 'bad', '8.8.8.8,1.1.1.1', '127.0.0.1', '10.0.0.1', '198.51.100.77', '224.0.0.1', 'ff02::1', 'fe80::1%eth0', '::1']:
            with self.subTest(value=value):
                self.assertIsNone(self.candidate(value))

    def test_ipv6_companion_only_used_for_pseudo_ipv4(self):
        self.assertEqual(self.candidate('240.1.2.3', '2606:4700::1111'), '2606:4700::1111')
        self.assertIsNone(self.candidate('240.1.2.3', '8.8.8.8'))
        self.assertIsNone(self.candidate('240.1.2.3', '2001:db8::77'))
        self.assertEqual(self.candidate('8.8.8.8', '2606:4700::1111'), '8.8.8.8')

    def test_render_headers_do_not_activate_trust(self):
        app = Flask(__name__)
        self.assertIsNone(configure_trusted_proxy(app, {'RENDER': 'true'}))
        @app.get('/')
        def info():
            return {'ip': request.remote_addr, 'candidate': render_edge_candidate(request.environ)}
        result = app.test_client().get('/', environ_overrides={'REMOTE_ADDR': '127.0.0.1'}, headers={'CF-Connecting-IP': '8.8.8.8'}).get_json()
        self.assertEqual(result, {'ip': '127.0.0.1', 'candidate': '8.8.8.8'})

    @unittest.skipUnless(shutil.which('node'), 'Node.js is needed for the diagnostic button tests')
    def test_browser_diagnostic_logic(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        result = subprocess.run(['node', str(root / 'tests/test_proxy_check.cjs')], capture_output=True, text=True, encoding='utf-8')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
