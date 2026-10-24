"""The app's file scan, end to end on the server: the multipart upload the app sends, the job it
queues, and the report it gets back must carry the same plain-language summary as the website."""
import io
import unittest
from unittest.mock import patch

from pypdf import PdfWriter

import test_mobile_api
from services.evidence_jobs import run_evidence_job


def pdf_bytes():
    writer = PdfWriter(); writer.add_blank_page(width=100, height=100)
    out = io.BytesIO(); writer.write(out); return out.getvalue()


_base = test_mobile_api.MobileApiTests


class MobileFileScanTests(unittest.TestCase):
    # Reuse the mobile API fixtures without re-running that suite's own tests.
    setUpClass = classmethod(_base.setUpClass.__func__)
    tearDownClass = classmethod(_base.tearDownClass.__func__)
    setUp, login, token, auth = _base.setUp, _base.login, _base.token, _base.auth

    def test_app_upload_queues_the_websites_file_scan(self):
        token = self.token()
        queued = []

        def fake_queue(kind, params):
            from flask import jsonify
            queued.append((kind, params['filename']))
            from services.upload_validation import remove_temporary_upload
            remove_temporary_upload(params['path'])  # the real job deletes it when it finishes
            return jsonify(task_id='t-1', status='started'), 202
        with patch('services.evidence_jobs.queue_evidence_job', side_effect=fake_queue):
            # Exactly what the app's XMLHttpRequest sends: multipart field "file" with an ASCII name.
            response = self.client.post('/api/mobile/v1/tools/file', headers=self.auth(token),
                                        data={'file': (io.BytesIO(pdf_bytes()), 'file.pdf', 'application/pdf')},
                                        content_type='multipart/form-data')
        self.assertEqual(response.status_code, 202, response.get_data(as_text=True))
        self.assertEqual(response.json['task_id'], 't-1')
        self.assertEqual(queued, [('file_scan', 'file.pdf')])

    def test_the_finished_job_carries_the_plain_summary_the_app_shows(self):
        import tempfile, os
        handle, path = tempfile.mkstemp(suffix='.pdf')
        with os.fdopen(handle, 'wb') as out:
            out.write(pdf_bytes())
        with self.app.app_context(), \
             patch('services.clamav_client.scan_bytes', return_value={'status': 'clean', 'engine': 'ClamAV'}), \
             patch('services.file_deep_analyzer.FileDeepAnalyzer.check_hash_reputation',
                   return_value={'status': 'not_found', 'risk_score': 0, 'is_malicious': False}), \
             patch('services.pdf_structure.pdf_observations', side_effect=__import__('services.pdf_structure', fromlist=['inspect_pdf']).inspect_pdf):
            job = run_evidence_job('file_scan', {'path': path, 'filename': 'Hesap_Hareketleri.pdf'}, self.owner)
        self.assertEqual(job['status'], 'completed', job)
        plain = job['result']['plain']
        # The app's reportOf() unwraps result when result.plain has a headline.
        self.assertTrue(plain['headline'])
        self.assertTrue(plain['label'] and plain['reasons'])


del _base  # keep pytest from collecting the borrowed suite a second time

if __name__ == '__main__':
    unittest.main()
