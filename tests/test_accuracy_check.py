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
            lines = ignore.read().splitlines()
        self.assertIn('!scripts/accuracy_check.py', lines)
        self.assertIn('!scripts/tools_check.py', lines)
        self.assertIn('!scripts/email_bench.py', lines)  # it was left out once and the run printed nothing
        self.assertIn('!scripts/file_samples.py', lines)
        with open(os.path.join(root, 'Dockerfile.vps'), encoding='utf-8') as dockerfile:
            source = dockerfile.read()
        for script in ('accuracy_check.py', 'tools_check.py', 'email_bench.py', 'file_samples.py'):
            self.assertIn('scripts/' + script, source)

    def test_shipped_scripts_bring_the_scripts_they_import(self):
        # benchmark_metrics.py was left out once: email_bench.py failed in the container with ModuleNotFoundError.
        import re
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        dockerfile = open(os.path.join(root, 'Dockerfile.vps'), encoding='utf-8').read()
        ignore = open(os.path.join(root, '.dockerignore'), encoding='utf-8').read().splitlines()
        shipped = re.findall(r'scripts/(\w+)\.py', dockerfile.split('./scripts/')[0])
        for name in shipped:
            source = open(os.path.join(root, 'scripts', name + '.py'), encoding='utf-8').read()
            for needed in set(re.findall(r'from scripts\.(\w+) import', source)):
                with self.subTest(script=name, imports=needed):
                    self.assertIn(needed, shipped)
                    self.assertIn(f'!scripts/{needed}.py', ignore)

    def test_standard_port_detection(self):
        self.assertTrue(accuracy_check.standard_port('http://a.example/x'))
        self.assertTrue(accuracy_check.standard_port('https://a.example:443/'))
        self.assertFalse(accuracy_check.standard_port('http://1.2.3.4:38141/bin.sh'))

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


class BlindGradeTests(unittest.TestCase):
    def test_blind_mode_counts_any_flag_as_caught(self):
        try:
            accuracy_check.BLIND = True
            self.assertEqual(accuracy_check.grade('threat', 'suspicious'), 'PASS')
            self.assertEqual(accuracy_check.grade('threat', 'harmless'), 'FAIL')
        finally:
            accuracy_check.BLIND = False
        self.assertEqual(accuracy_check.grade('threat', 'suspicious'), 'WARN')


class EvasionCaseTests(unittest.TestCase):
    def test_every_address_trick_case_is_caught_from_the_address_alone(self):
        EVASION_CASES = accuracy_check.EVASION_CASES
        from services.url_tricks import address_signals, unmask
        for expect, url, note in EVASION_CASES:
            if expect != 'threat' or 'eicar' in url:
                continue
            clean, tricks = unmask(url)
            strong = tricks or [s for s in address_signals(clean) if s['strong']]
            self.assertTrue(strong, f'{url}: {note}')
        for expect, url, note in EVASION_CASES:
            if expect == 'clean':
                clean, tricks = unmask(url)
                self.assertEqual((tricks, [s for s in address_signals(clean) if s['strong']]), ([], []), url)


class FileInputTests(unittest.TestCase):
    def test_links_are_read_once_each_without_blanks_or_comments(self):
        import tempfile
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False, encoding='utf-8') as handle:
            handle.write('# phishing\nhttps://a.example/\n\nhttps://b.example/x \nhttps://a.example/\n')
        self.assertEqual(accuracy_check.read_links(handle.name), ['https://a.example/', 'https://b.example/x'])
        os.unlink(handle.name)
