"""Sandbox file and URL analysis run in workers, not in web requests (S-08)."""
from io import BytesIO
import os
import unittest
from unittest.mock import patch

import test_task_ownership


class SandboxQueueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_task_ownership.TaskOwnershipTests.setUpClass()
        cls.production = test_task_ownership.TaskOwnershipTests.production

    @classmethod
    def tearDownClass(cls):
        test_task_ownership.TaskOwnershipTests.tearDownClass()

    def setUp(self):
        test_task_ownership.TaskOwnershipTests.setUp(self)
        from routes.sandbox_routes import sandbox_bp
        from services.upload_validation import UploadValidationError
        self.app.register_blueprint(sandbox_bp)
        self.app.register_error_handler(UploadValidationError, self.production.invalid_upload)
        test_task_ownership.TaskOwnershipTests.sign_in(self, self.owner)

    def tearDown(self):
        test_task_ownership.TaskOwnershipTests.tearDown(self)

    def upload(self, environment='300'):
        return self.client.post('/api/sandbox/analyze-file', data={
            'file': (BytesIO(b'MZ fixture'), 'sample.exe'), 'environment_id': environment,
        }, content_type='multipart/form-data')

    def test_file_analysis_is_queued_with_a_temporary_copy(self):
        with patch('routes.sandbox_routes.HybridAnalysisService') as provider, \
             patch('tasks.sandbox_file_task.apply_async') as published:
            result = self.upload()
        self.assertEqual(result.status_code, 202)
        from models import AsyncScanTask
        from extensions import db
        self.assertEqual(db.session.get(AsyncScanTask, result.json['task_id']).user_id, self.owner)
        provider.assert_not_called()
        path, filename, owner, environment = published.call_args.kwargs['args']
        self.assertEqual((filename, owner, environment), ('sample.exe', self.owner, '300'))
        self.assertTrue(os.path.exists(path))
        os.remove(path)

    def test_unknown_environment_is_rejected_before_charging(self):
        with patch('routes.sandbox_routes.reserve_request_quota') as charge:
            result = self.upload(environment='../../etc')
        self.assertEqual(result.status_code, 400)
        charge.assert_not_called()

    def test_queue_failure_removes_the_temporary_copy(self):
        saved = []
        from services import upload_validation
        original = upload_validation.save_temporary_upload
        def save(*args):
            saved.append(original(*args))
            return saved[-1]
        with patch('services.upload_validation.save_temporary_upload', side_effect=save), \
             patch('services.task_dispatch.enqueue_owned_task', side_effect=RuntimeError('broker detail')):
            result = self.upload()
        self.assertEqual(result.status_code, 503)
        self.assertNotIn('broker', result.json['error'])
        self.assertFalse(os.path.exists(saved[0]))

    def test_worker_builds_report_and_always_removes_the_upload(self):
        from tasks import sandbox_file_task
        from services.upload_validation import save_temporary_upload
        for outcome in ({'verdict': 'unknown'}, RuntimeError('private parser detail')):
            path = save_temporary_upload(b'fixture', 'sample.exe', 'temp_uploads')
            with patch('routes.sandbox_routes.sandbox_file_report', side_effect=[outcome] if isinstance(outcome, Exception) else None,
                       return_value=outcome), patch.object(sandbox_file_task, 'update_state'):
                result = sandbox_file_task.apply(args=(path, 'sample.exe', self.owner, '300')).result
            self.assertFalse(os.path.exists(path))
            if isinstance(outcome, Exception):
                self.assertEqual(result['status'], 'failed')
                self.assertNotIn('private', str(result))
            else:
                self.assertEqual(result, {'status': 'completed', 'result': outcome})

    def test_url_sandbox_uses_the_queued_url_pipeline(self):
        with patch('celery_app.require_broker'), \
             patch('services.url_scan_storage.enqueue_url_scan', return_value=9) as enqueue, \
             patch('services.safe_http.socket.socket') as network:
            result = self.client.post('/api/sandbox/analyze-url', json={'url': 'https://example.com', 'environment_id': '300'})
        self.assertEqual(result.status_code, 202)
        self.assertEqual(result.json['result_url'], '/result/9')
        enqueue.assert_called_once()
        network.assert_not_called()


if __name__ == '__main__':
    unittest.main()
