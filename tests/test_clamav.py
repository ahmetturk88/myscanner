"""ClamAV client protocol and how an antivirus result shapes the file verdict."""
import os
import socket
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch

from services import clamav_client
from services.file_threat_intel import FileThreatIntel

NOT_FOUND = {'status': 'not_found', 'is_malicious': False}


class FakeClamd:
    """Answers zVERSION and zINSTREAM like clamd; records what it received."""

    def __init__(self, verdict=b'stream: OK'):
        self.verdict, self.received = verdict, b''
        self.server = socket.create_server(('127.0.0.1', 0))
        self.port = self.server.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            with conn:
                command = b''
                while not command.endswith(b'\0'):
                    command += conn.recv(1)
                if command == b'zVERSION\0':
                    conn.sendall(b'ClamAV 1.5.4/27800/Wed Oct 22 08:00:00 2026\0')
                    continue
                data = b''
                while True:
                    header = b''
                    while len(header) < 4:
                        header += conn.recv(4 - len(header))
                    size = struct.unpack('!L', header)[0]
                    if not size:
                        break
                    while size:
                        piece = conn.recv(size)
                        data, size = data + piece, size - len(piece)
                self.received = data
                conn.sendall(self.verdict + b'\0')

    def close(self):
        self.server.close()


class ClientTests(unittest.TestCase):
    def run_scan(self, verdict, content=b'hello'):
        fake = FakeClamd(verdict)
        self.addCleanup(fake.close)
        with patch.dict(os.environ, {'CLAMAV_HOST': '127.0.0.1', 'CLAMAV_PORT': str(fake.port)}):
            return clamav_client.scan_bytes(content), fake

    def test_clean_stream_sends_every_byte_in_chunks(self):
        content = os.urandom(clamav_client.CHUNK * 2 + 17)
        result, fake = self.run_scan(b'stream: OK', content)
        self.assertEqual(fake.received, content)
        self.assertEqual((result['status'], result['engine'], result['database_version']), ('clean', 'ClamAV 1.5.4', '27800'))

    def test_detections_split_known_malware_from_heuristics(self):
        result, _ = self.run_scan(b'stream: Win.Trojan.Agent-123 FOUND')
        self.assertEqual((result['status'], result['kind'], result['signature']), ('found', 'malware', 'Win.Trojan.Agent-123'))
        result, _ = self.run_scan(b'stream: Heuristics.OLE2.ContainsMacros FOUND')
        self.assertEqual(result['kind'], 'heuristic')

    def test_errors_and_missing_service_are_reported_not_hidden(self):
        result, _ = self.run_scan(b'INSTREAM size limit exceeded. ERROR')
        self.assertEqual(result['status'], 'unavailable')
        with patch.dict(os.environ, {'CLAMAV_HOST': '127.0.0.1', 'CLAMAV_PORT': '1'}):
            self.assertEqual(clamav_client.scan_bytes(b'x')['status'], 'unavailable')
        with patch.dict(os.environ, {'CLAMAV_HOST': ''}):
            self.assertEqual(clamav_client.scan_bytes(b'x'), {'status': 'not_configured'})


class VerdictTests(unittest.TestCase):
    def scan(self, antivirus, content=b'plain text for the antivirus test', name='notes.txt'):
        with tempfile.TemporaryDirectory() as folder, \
             patch('services.clamav_client.scan_bytes', return_value=antivirus), \
             patch('services.file_deep_analyzer.FileDeepAnalyzer.check_hash_reputation', return_value=NOT_FOUND):
            intel = FileThreatIntel(use_exiftool=False)
            intel.local_analyzer.cache_dir = folder
            with patch.object(intel, '_run_malwarebazaar_scan', return_value={**NOT_FOUND, 'found': False}):
                return intel.comprehensive_file_scan(content, name)

    def row(self, report):
        return next((c for c in report['plain']['checks'] if c['name'] == 'Antivirus'), None)

    def test_known_malware_is_dangerous(self):
        report = self.scan({'status': 'found', 'kind': 'malware', 'signature': 'Win.Trojan.Agent-123'})
        self.assertEqual(report['verdict'], 'malicious')
        self.assertEqual(report['plain']['tone'], 'danger')
        self.assertEqual(self.row(report)['state'], 'bad')
        self.assertIn('Win.Trojan.Agent-123', report['plain']['reasons'][0]['detail'])

    def test_heuristic_is_caution_not_danger(self):
        report = self.scan({'status': 'found', 'kind': 'heuristic', 'signature': 'Heuristics.OLE2.ContainsMacros'})
        self.assertEqual(report['verdict'], 'suspicious')
        self.assertEqual(self.row(report)['state'], 'warn')

    def test_clean_is_shown_and_unavailable_is_a_missing_check(self):
        clean = self.scan({'status': 'clean'})
        self.assertEqual(clean['verdict'], 'not_found')
        self.assertEqual(self.row(clean)['result'], 'Clean')
        self.assertIn('Antivirus found nothing', [r['title'] for r in clean['plain']['reasons']])
        down = self.scan({'status': 'unavailable'})
        self.assertIn('Antivirus scan unavailable', down['missing_checks'])
        self.assertEqual(down['verdict'], 'unknown')
        # When ClamAV is off, the report says so instead of leaving the row out.
        self.assertEqual(self.row(self.scan({'status': 'not_configured'}))['result'], 'Not checked')


if __name__ == '__main__':
    unittest.main()
