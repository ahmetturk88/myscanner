"""The all-tools benchmark grades results correctly and its cases are well formed."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts'))
import tools_check  # noqa: E402

TOOLS = {'email', 'password', 'ip', 'domain', 'ssl', 'subdomain', 'site', 'file'}


class ToolsCheckTests(unittest.TestCase):
    def test_every_tool_has_cases(self):
        self.assertEqual({case[0] for case in tools_check.CASES}, TOOLS)
        for tool, label, value, check in tools_check.CASES:
            self.assertTrue(label and callable(check))

    def test_graders(self):
        self.assertEqual(tools_check.one_of('verdict', ('clean',), ('unknown',))({'verdict': 'unknown'})[0], 'WARN')
        self.assertEqual(tools_check.refused({'error': 'private'})[0], 'PASS')
        self.assertEqual(tools_check.password_exposed({'verdict': 'weak', 'pwned': {'status': 'unavailable'}})[0], 'WARN')
        self.assertEqual(tools_check.ip_clean({'abuse_score': 0, 'reputation_status': 'not_found'})[0], 'PASS')
        self.assertEqual(tools_check.tls_failed('expired')({'verdict': 'verification_failed', 'reason_code': 'expired'})[0], 'PASS')
        self.assertEqual(tools_check.finds_www({'results': [{'full_domain': 'www.example.com'}]})[0], 'PASS')

    def test_errors_are_failures_and_exit_code_reflects_them(self):
        with mock.patch.object(tools_check, 'run', side_effect=RuntimeError('down')), mock.patch('builtins.print'):
            self.assertEqual(tools_check.main(['--only', 'ip', '--workers', '2']), 1)
        with mock.patch.object(tools_check, 'run', return_value={'verdict': 'no_domain', 'error': 'x', 'abuse_score': 0,
                                                                  'reputation_status': 'not_found'}), mock.patch('builtins.print'):
            self.assertEqual(tools_check.main(['--only', 'ip']), 0)


if __name__ == '__main__':
    unittest.main()
