"""Offline QR workspace regression checks. No real target is contacted."""
from pathlib import Path
import shutil
import subprocess
import unittest
ROOT = Path(__file__).resolve().parents[1]
class WorkspaceTests(unittest.TestCase):
    def test_decoder_is_local_and_optional_provider_is_off(self):
        template = (ROOT/'templates/qr_scanner.html').read_text()
        self.assertIn('vendor/jsQR-1.4.0.js', template)
        self.assertNotIn('cdn.jsdelivr.net', template)
        self.assertIn('id="include-provider"', template)
        self.assertNotIn('id="include-provider" checked', template)
        self.assertNotIn('onclick=', template)
    def test_reduced_motion_and_literal_dom(self):
        css = (ROOT/'static/qr_workspace.css').read_text()
        self.assertIn('prefers-reduced-motion:no-preference', css)
        js = (ROOT/'static/qr_workspace.js').read_text()
        for sink in ('innerHTML', 'insertAdjacentHTML', 'window.open', 'localStorage'):
            self.assertNotIn(sink, js)
        self.assertIn('textContent', js)
        self.assertIn('AbortController', js)
    @unittest.skipUnless(shutil.which('node'), 'Node.js required for actual QR decoding and workflow tests')
    def test_real_qr_decode_and_classification(self):
        subprocess.run([shutil.which('node'), str(ROOT/'tests/test_qr_workspace.cjs')], check=True)
    @unittest.skipUnless(shutil.which('node'), 'Node.js required for QR workflow tests')
    def test_explicit_inspection_recovery_and_privacy(self):
        subprocess.run([shutil.which('node'), str(ROOT/'tests/test_qr_workspace_flow.cjs')], check=True)
