"""Evidence jobs run in workers and expose only fixed messages (S-08)."""
import os
import unittest
from unittest.mock import patch

import test_task_ownership
from extensions import db
from models import AsyncScanTask


class EvidenceJobTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_task_ownership.TaskOwnershipTests.setUpClass()
        cls.production = test_task_ownership.TaskOwnershipTests.production

    @classmethod
    def tearDownClass(cls):
        test_task_ownership.TaskOwnershipTests.tearDownClass()

    def setUp(self):
        test_task_ownership.TaskOwnershipTests.setUp(self)

    def tearDown(self):
        test_task_ownership.TaskOwnershipTests.tearDown(self)

    def upload(self):
        from services.upload_validation import save_temporary_upload
        return save_temporary_upload(b'fixture', 'sample.pdf', 'temp_uploads')

    def test_file_jobs_always_remove_the_upload(self):
        from services.evidence_jobs import run_evidence_job
        for side_effect in (None, RuntimeError('private parser detail')):
            path = self.upload()
            with patch('services.file_deep_analyzer.FileDeepAnalyzer.comprehensive_analysis',
                       side_effect=side_effect, return_value={'verdict': 'unknown'}):
                result = run_evidence_job('file_deep', {'path': path, 'filename': 'sample.pdf'}, self.owner)
            self.assertFalse(os.path.exists(path))
            self.assertNotIn('private', str(result))

    def test_file_scan_binds_pdf_receipt_to_owner(self):
        from services.evidence_jobs import run_evidence_job
        from services.file_pdf_receipts import signer
        path = self.upload()
        with patch('services.file_threat_intel.FileThreatIntel.comprehensive_file_scan', return_value={'verdict': 'unknown', 'filename': 'sample.pdf'}):
            result = run_evidence_job('file_scan', {'path': path, 'filename': 'sample.pdf'}, self.owner)
        receipt = signer(self.production.app.config['SECRET_KEY']).loads(result['result']['_pdf_receipt'])
        self.assertEqual(receipt['owner'], str(self.owner))

    def test_unknown_job_and_long_messages_are_not_echoed(self):
        from services.evidence_jobs import run_evidence_job
        self.assertEqual(run_evidence_job('shell', {}, self.owner)['status'], 'failed')
        with patch('services.subdomain_finder.SubdomainFinder') as finder:
            finder.return_value.find_subdomains.side_effect = ValueError('x' * 500)
            result = run_evidence_job('subdomain_discovery', {'domain': 'example.com', 'include_ct': False}, self.owner)
        self.assertLess(len(result['user_error']), 200)

    def test_queue_failure_is_generic_and_removes_upload(self):
        from flask_login import login_user
        from services.evidence_jobs import queue_evidence_job
        path = self.upload()
        with self.app.test_request_context(), \
             patch('celery_app.require_broker'), \
             patch('services.task_dispatch.enqueue_owned_task', side_effect=RuntimeError('broker password')):
            from models import User
            login_user(db.session.get(User, self.owner))
            response, status = queue_evidence_job('file_scan', {'path': path, 'filename': 'sample.pdf'})
        self.assertEqual(status, 503)
        self.assertNotIn('password', response.get_data(as_text=True))
        self.assertFalse(os.path.exists(path))

    def test_task_status_shows_only_bounded_user_messages_and_is_not_cached(self):
        db.session.add(AsyncScanTask(task_id='job', user_id=self.owner))
        db.session.commit()
        test_task_ownership.TaskOwnershipTests.sign_in(self, self.owner)
        for payload, expected in [({'status': 'failed', 'user_error': 'Target DNS is temporarily unavailable; please retry'},
                                   'Target DNS is temporarily unavailable; please retry'),
                                  ({'status': 'failed', 'user_error': 'x' * 500}, 'Analysis failed. Please retry.'),
                                  ({'status': 'failed', 'user_error': {'nested': 'value'}}, 'Analysis failed. Please retry.')]:
            self.result.return_value.state = 'SUCCESS'
            self.result.return_value.result = payload
            response = self.client.get('/api/task-status/job')
            self.assertEqual(response.json['error'], expected)
            self.assertEqual(response.headers['Cache-Control'], 'no-store')


if __name__ == '__main__':
    unittest.main()
