"""A certificate that fails verification is reported as invalid evidence, not as a failed check."""
import contextlib
import ssl
import unittest
from unittest import mock

from services.url_analyzer import URLDeepAnalyzer


class TlsCheckTests(unittest.TestCase):
    def check(self, error):
        context = mock.Mock()
        context.wrap_socket.side_effect = error
        with mock.patch('services.url_analyzer.public_connection', return_value=contextlib.nullcontext(mock.Mock())), \
                mock.patch('ssl.create_default_context', return_value=context):
            return URLDeepAnalyzer().check_ssl_certificate('expired.example')

    def test_verification_failure_is_evidence(self):
        error = ssl.SSLCertVerificationError(1, 'certificate verify failed')
        error.verify_message = 'certificate has expired'
        result = self.check(error)
        self.assertEqual(result, {'valid': False, 'verification_error': 'certificate has expired'})

    def test_connection_failure_stays_unavailable(self):
        result = self.check(TimeoutError('timed out'))
        self.assertFalse(result['valid']);self.assertIn('error', result)


if __name__ == '__main__':
    unittest.main()
