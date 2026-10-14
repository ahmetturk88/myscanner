"""The email key can come from a mounted secret file (VPS) or the environment (Render)."""
import os
import tempfile
import unittest
from unittest.mock import patch

from services.provider_credentials import resend_key

KEY = 're_' + 'a' * 30


class ResendKeyTests(unittest.TestCase):
    def test_file_wins_and_empty_file_means_disabled(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, 'resend_api_key')
            with open(path, 'w') as handle:
                handle.write(KEY + '\n')
            with patch.dict(os.environ, {'RESEND_API_KEY_FILE': path, 'RESEND_API_KEY': 're_' + 'b' * 30}, clear=True):
                self.assertEqual(resend_key(), KEY)
            open(path, 'w').close()
            with patch.dict(os.environ, {'RESEND_API_KEY_FILE': path}, clear=True):
                self.assertIsNone(resend_key())

    def test_environment_fallback_and_rejects_bad_values(self):
        with patch.dict(os.environ, {'RESEND_API_KEY': KEY}, clear=True):
            self.assertEqual(resend_key(), KEY)
        with patch.dict(os.environ, {'RESEND_API_KEY': 'short'}, clear=True):
            self.assertIsNone(resend_key())
        with patch.dict(os.environ, {'RESEND_API_KEY_FILE': '/nonexistent/key'}, clear=True):
            self.assertIsNone(resend_key())


if __name__ == '__main__':
    unittest.main()
