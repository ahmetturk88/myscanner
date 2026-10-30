"""Offline regressions for evidence strength, new fetch paths, and benchmark integrity."""
import io
import json
import socket
import unittest
from unittest.mock import Mock, patch

from scripts.benchmark_metrics import classification_metrics
from scripts import email_bench, load_test
from services import site_crawl, site_trust
from services.url_screenshot import rendered_text
from services.web_risk import validated_observation


class MetricsTests(unittest.TestCase):
    def test_always_review_does_not_pass_clean_controls(self):
        metrics = classification_metrics([('clean', 'review'), ('threat', 'review')])
        self.assertEqual(metrics['false_positive_rate'], 1)
        self.assertEqual(metrics['precision'], .5)
        with patch.object(email_bench, 'check', return_value=('a@b.com', 'review', '-')), patch('builtins.print'):
            self.assertFalse(email_bench.bench('control', ['a@b.com'], email_bench.LEGIT_OK))

    def test_unknown_and_dead_domains_are_not_correct_detections(self):
        result = classification_metrics([('clean', 'unknown'), ('threat', 'no_domain'), ('threat', 'invalid'), ('threat', 'error')])
        self.assertEqual(result['inconclusive'], 4)
        self.assertEqual(result['decision_coverage'], 0)
        self.assertIsNone(result['precision'])
        self.assertEqual(result['true_positive'], 0)

    def test_failure_in_threat_batch_fails_cli_even_when_controls_pass(self):
        with patch.object(email_bench, 'bench', side_effect=[True, False]), patch.object(email_bench, 'scam_addresses', return_value=['a@b.com']):
            self.assertEqual(email_bench.main(['fixtures']), 1)

    def test_empty_batch_is_not_a_pass(self):
        with patch('builtins.print'):
            self.assertFalse(email_bench.bench('empty', [], email_bench.SCAM_OK))

    def test_independent_dataset_requires_both_labels_and_provenance(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'holdout.jsonl'
            rows = [dict(id='control', email='a@control.example', label='clean', provenance='independent-owner-record', observed_at='2026-10-30'),
                    dict(id='threat', email='a@threat.example', label='threat', provenance='independently-reviewed-domain', observed_at='2026-10-30')]
            path.write_text('\n'.join(json.dumps(r) for r in rows))
            self.assertEqual(len(email_bench.labeled_dataset(path)), 2)
            import logging
            def check_private(email):
                self.assertTrue(logging.root.manager.disable >= logging.CRITICAL)
                return email, 'unknown', '-'
            previous_logging = logging.root.manager.disable
            with patch.object(email_bench, 'check', side_effect=check_private), patch('builtins.print'):
                self.assertEqual(email_bench.benchmark_dataset(path), 2)
            self.assertEqual(logging.root.manager.disable, previous_logging)
            rows[1]['email'] = rows[0]['email']
            path.write_text('\n'.join(json.dumps(r) for r in rows))
            with self.assertRaises(ValueError):
                email_bench.labeled_dataset(path)


class SourceStateTests(unittest.TestCase):
    def test_malformed_and_mixed_source_states_never_become_clean(self):
        for value in (None, [], {'status': 'matched', 'threat_types': []}, {'status': 'mystery'}, {'status': 'not_found', 'threat_types': ['MALWARE']}):
            self.assertEqual(validated_observation(value)['status'], 'unavailable')
            self.assertEqual(site_trust.reputation(['https://a.example/'], lookup=lambda _: value)['status'], 'unavailable')
        with_types = {'status': 'matched', 'threat_types': ['MALWARE']}
        self.assertEqual(site_trust.reputation(['https://a.example/'], lookup=lambda _: with_types)['status'], 'matched')
        self.assertEqual(site_trust.reputation(['a', 'b'], lookup=lambda u: {'status': 'not_found' if u == 'a' else 'not_configured'})['status'], 'unavailable')

    def test_http_200_malformed_provider_body_is_not_a_negative_match(self):
        from services.web_risk import check_web_risk
        session = Mock()
        for payload in ({'error': 'denied'}, {'threat': None}, {'threat': {}}, {'threat': 'wrong'}):
            session.get.return_value = Mock(status_code=200)
            session.get.return_value.json.return_value = payload
            self.assertEqual(check_web_risk('https://a.example/', session, key='test-key')['status'], 'unavailable')


class NewFetchPathsTests(unittest.TestCase):
    def test_download_never_contacts_private_or_mixed_dns_target(self):
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443)),
                     (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]
        for url in ('http://127.0.0.1/a.exe', 'https://mixed.example/a.exe'):
            with patch('services.safe_http.socket.getaddrinfo', return_value=addresses), patch('services.safe_http.socket.socket') as connect:
                scan = Mock()
                self.assertEqual(site_crawl._download(url, scan)['status'], 'unavailable')
                scan.assert_not_called()
                connect.assert_not_called()

    def test_antivirus_outage_is_never_described_as_clean(self):
        found = {'skipped_by_robots': 0, 'stopped': None, 'external': {}, 'pages': [], 'downloads': [{'url': 'https://public.example/setup.exe', 'extension': 'exe'}], 'contacts': {}, 'text': ''}
        with patch('services.site_crawl._download', return_value={'status': 'unavailable'}):
            evidence, findings = site_crawl.assess(found, lookup=lambda _: {'status': 'not_found'})
        self.assertEqual(evidence['downloads'][0]['antivirus']['status'], 'unavailable')
        self.assertNotIn('Antivirus found nothing', str(findings))

    def test_rendered_text_stops_stream_early_closes_response_and_disables_redirects(self):
        class Stream:
            status_code = 200
            closed = False
            def __enter__(self): return self
            def __exit__(self, *args): self.closed = True
            def iter_content(self, _):
                yield b'x' * 65537
                raise AssertionError('Must stop reading at limit')
        stream = Stream()
        with patch('services.url_screenshot.requests.get', return_value=stream) as get:
            self.assertIsNone(rendered_text('https://target.example', 'http://urlvet:8080'))
        self.assertTrue(stream.closed)
        self.assertTrue(get.call_args.kwargs['stream'])
        self.assertFalse(get.call_args.kwargs['allow_redirects'])



class LoadProtocolTests(unittest.TestCase):
    def test_pending_is_not_a_finished_scan_and_result_is_checked(self):
        recorder = load_test.Recorder()
        replies = [(202, {'scan_id': 1}), (200, {'status': 'pending'}), (200, {'status': 'completed'}), (200, {'plain': {'tone': 'unknown'}})]
        with patch.object(load_test, 'request', side_effect=replies) as request, patch('scripts.load_test.time.sleep'):
            load_test.url_scan('https://ours.example', 'token', 'ours.example', recorder, float('inf'))
        self.assertEqual(request.call_count, 4)
        self.assertFalse(recorder.failures)

    def test_unknown_terminal_status_is_a_failure(self):
        recorder = load_test.Recorder()
        with patch.object(load_test, 'request', side_effect=[(202, {'scan_id': 1}), (200, {'status': 'mystery'})]), patch('scripts.load_test.time.sleep'):
            load_test.url_scan('https://ours.example', 'token', 'ours.example', recorder, float('inf'))
        self.assertTrue(recorder.failures)
