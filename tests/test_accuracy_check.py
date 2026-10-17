"""The accuracy benchmark grades verdicts correctly and never touches the database."""
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'scripts'))
import accuracy_check  # noqa: E402


class GradeTests(unittest.TestCase):
    def test_clean_sites(self):
        self.assertEqual(accuracy_check.grade('clean', 'harmless'), 'PASS')
        self.assertEqual(accuracy_check.grade('clean', 'unknown'), 'WARN')
        for verdict in ('suspicious', 'high_risk', 'malicious', 'error'):
            self.assertEqual(accuracy_check.grade('clean', verdict), 'FAIL', verdict)

    def test_sites_that_should_be_flagged(self):
        for verdict in ('suspicious', 'high_risk', 'malicious'):
            self.assertEqual(accuracy_check.grade('flag', verdict), 'PASS', verdict)
        self.assertEqual(accuracy_check.grade('flag', 'unknown'), 'WARN')
        self.assertEqual(accuracy_check.grade('flag', 'harmless'), 'FAIL')

    def test_threats(self):
        for verdict in ('high_risk', 'malicious'):
            self.assertEqual(accuracy_check.grade('threat', verdict), 'PASS', verdict)
        self.assertEqual(accuracy_check.grade('threat', 'suspicious'), 'WARN')
        for verdict in ('unknown', 'harmless', None):
            self.assertEqual(accuracy_check.grade('threat', verdict), 'FAIL', verdict)

    def test_script_is_shipped_in_the_worker_image(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, '.dockerignore'), encoding='utf-8') as ignore:
            self.assertIn('!scripts/accuracy_check.py', ignore.read().splitlines())
        with open(os.path.join(root, 'Dockerfile.vps'), encoding='utf-8') as dockerfile:
            self.assertIn('scripts/accuracy_check.py', dockerfile.read())

    def test_every_case_has_a_known_group_and_a_web_url(self):
        for expect, url, note in accuracy_check.CASES:
            self.assertIn(expect, ('clean', 'flag', 'threat'))
            self.assertTrue(url.startswith(('http://', 'https://')), url)
            self.assertTrue(note)


class RunTests(unittest.TestCase):
    def fake_scan(self, url):
        verdict = 'harmless' if 'google' in url else 'unknown'
        return {'verdict': verdict, 'score': 90, 'reasons': [{'code': 'headers_weak'}], 'missing_checks': [],
                'seconds': 1, 'provider_verdict': 'safe', 'urlhaus': 'not_found'}

    def test_report_written_and_exit_code_reflects_failures(self):
        with mock.patch.object(accuracy_check, 'scan', side_effect=self.fake_scan), \
                mock.patch('builtins.print'), mock.patch('builtins.open', mock.mock_open()) as opened:
            self.assertEqual(accuracy_check.main(['--only', 'clean', '--workers', '2']), 0)
            written = ''.join(call.args[0] for call in opened().write.call_args_list)
        rows = json.loads(written)
        self.assertEqual(len(rows), sum(c[0] == 'clean' for c in accuracy_check.CASES))
        self.assertEqual({r['grade'] for r in rows}, {'PASS', 'WARN'})
        with mock.patch.object(accuracy_check, 'scan', side_effect=RuntimeError), \
                mock.patch('builtins.print'), mock.patch('builtins.open', mock.mock_open()):
            self.assertEqual(accuracy_check.main(['--only', 'threat']), 1)


if __name__ == '__main__':
    unittest.main()
