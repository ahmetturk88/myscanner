"""Error reporting is off without a DSN and never sends request data or secrets."""
import unittest
from unittest import mock

from services import error_reporting


class ErrorReportingTests(unittest.TestCase):
    def test_off_without_a_valid_dsn(self):
        with mock.patch.dict('os.environ', {}, clear=True):
            self.assertIsNone(error_reporting.sentry_dsn())
        with mock.patch.dict('os.environ', {'SENTRY_DSN': 'http://not-https.example/1'}, clear=True):
            self.assertIsNone(error_reporting.sentry_dsn())
        with mock.patch.object(error_reporting, '_started', False), mock.patch.dict('os.environ', {}, clear=True):
            self.assertFalse(error_reporting.init_error_reporting('web'))
            error_reporting.report_exception(RuntimeError('ignored'))  # no-op, no crash

    def test_scrub_keeps_only_method_and_path(self):
        event = {'request': {'method': 'POST', 'url': 'https://myscanners.com/api/x?url=https://victim.example',
                             'data': {'password': 'p'}, 'cookies': {'session': 's'}, 'headers': {'Authorization': 'Bearer t'}},
                 'user': {'email': 'a@b.c'}, 'breadcrumbs': {'values': [1]}, 'extra': {'k': 'v'}, 'exception': {}}
        cleaned = error_reporting.scrub(event)
        self.assertEqual(cleaned['request'], {'method': 'POST', 'url': 'https://myscanners.com/api/x'})
        for key in ('user', 'breadcrumbs', 'extra'):
            self.assertNotIn(key, cleaned)
        self.assertIn('exception', cleaned)

    def test_sensitive_reports_never_include_the_message(self):
        sdk = mock.Mock()
        with mock.patch.object(error_reporting, '_started', True), mock.patch.dict('sys.modules', {'sentry_sdk': sdk}):
            try:
                raise ValueError('hunter2-password')
            except ValueError as error:
                error_reporting.report_exception(error, sensitive=True)
        message = sdk.capture_message.call_args.args[0]
        self.assertIn('ValueError', message)
        self.assertNotIn('hunter2', message)
        sdk.capture_exception.assert_not_called()


if __name__ == '__main__':
    unittest.main()
