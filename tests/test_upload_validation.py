"""Run: python -m unittest discover -s tests -p test_upload_validation.py -v"""

from io import BytesIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from werkzeug.datastructures import FileStorage

import test_task_ownership
from services.upload_validation import (
    UploadValidationError, read_validated_upload, save_temporary_upload,
)


class UploadHelperTests(unittest.TestCase):
    def upload(self, content=b'test', filename='sample.pdf'):
        return FileStorage(stream=BytesIO(content), filename=filename)

    def test_exact_limit_and_uppercase_extension_accepted(self):
        self.assertEqual(read_validated_upload(self.upload(filename='sample.PDF'), {'pdf'}, 4), ('sample.pdf', b'test'))

    def test_reads_at_most_limit_plus_one(self):
        file = self.upload(b'123456789')
        with self.assertRaises(UploadValidationError) as error:
            read_validated_upload(file, {'pdf'}, 4)
        self.assertEqual(error.exception.status_code, 413)
        self.assertEqual(file.stream.tell(), 5)

    def test_missing_empty_and_disallowed_files_rejected(self):
        for file in [None, self.upload(filename=''), self.upload(filename='sample.txt'), self.upload(b'')]:
            with self.subTest(file=file), self.assertRaises(UploadValidationError):
                read_validated_upload(file, {'pdf'}, 4)

    def test_path_traversal_name_never_enters_storage_path(self):
        name, content = read_validated_upload(self.upload(filename='../../secret.PDF'), {'pdf'}, 4)
        self.assertNotIn('/', name)
        with tempfile.TemporaryDirectory() as folder:
            first = Path(save_temporary_upload(content, name, folder))
            second = Path(save_temporary_upload(content, name, folder))
            self.assertEqual(first.parent, Path(folder).resolve())
            self.assertNotEqual(first, second)
            self.assertEqual(first.read_bytes(), b'test')
            self.assertEqual(first.suffix, '.pdf')


class UploadEndpointTests(test_task_ownership.TaskOwnershipTests):
    def setUp(self):
        super().setUp()
        from services.upload_validation import UploadValidationError
        from werkzeug.exceptions import RequestEntityTooLarge
        from routes.sandbox_routes import sandbox_bp
        self.app.register_error_handler(UploadValidationError, self.production.invalid_upload)
        self.app.register_error_handler(RequestEntityTooLarge, self.production.oversized_request)
        self.app.config['MAX_CONTENT_LENGTH'] = self.production.app.config['MAX_CONTENT_LENGTH']
        self.app.register_blueprint(sandbox_bp)
        for rule, name in [('/api/scan-file', 'api_scan_file'), ('/api/file-deep-analysis', 'api_file_deep_analysis')]:
            self.app.add_url_rule(rule, name, getattr(self.production, name), methods=['POST'])

    def post_file(self, path, content=b'test', filename='sample.pdf'):
        self.sign_in(self.owner)
        return self.client.post(path, data={'file': (BytesIO(content), filename)})

    def test_all_file_routes_reject_disallowed_extension(self):
        for path in ['/api/scan-file', '/api/file-deep-analysis', '/api/async-scan-file', '/api/sandbox/analyze-file']:
            with self.subTest(path=path):
                self.assertEqual(self.post_file(path, filename='sample.txt').status_code, 400)

    def test_all_standard_file_routes_enforce_size_limit(self):
        with patch.object(self.production, 'MAX_FILE_SIZE', 4):
            for path in ['/api/scan-file', '/api/file-deep-analysis', '/api/async-scan-file']:
                with self.subTest(path=path):
                    self.assertEqual(self.post_file(path, b'12345').status_code, 413)

    def test_sandbox_uses_its_own_larger_limit(self):
        with patch('routes.sandbox_routes.MAX_SIZE', 4):
            self.assertEqual(self.post_file('/api/sandbox/analyze-file', b'12345').status_code, 413)

    def test_request_size_cap_returns_json(self):
        self.app.config['MAX_CONTENT_LENGTH'] = 4
        response = self.post_file('/api/async-scan-file')
        self.assertEqual(response.status_code, 413)
        self.assertIn('error', response.get_json())

    def test_queue_failure_deletes_saved_file(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(self.production, 'UPLOAD_FOLDER', folder), patch('app.enqueue_owned_task', side_effect=RuntimeError('broker unavailable')):
            response = self.post_file('/api/async-scan-file')
            self.assertEqual(response.status_code, 503)
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_worker_deletes_file_after_analysis_failure(self):
        from tasks import scan_file_task
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'sample.pdf')
            path.write_bytes(b'test')
            with patch.object(scan_file_task, 'update_state'), patch('services.file_deep_analyzer.FileDeepAnalyzer.comprehensive_analysis', side_effect=RuntimeError('analysis failed')):
                result = scan_file_task.run(str(path), 'sample.pdf', self.owner)
            self.assertEqual(result['status'], 'failed')
            self.assertFalse(path.exists())

    def test_worker_deletes_file_after_success(self):
        from tasks import scan_file_task
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, 'sample.pdf')
            path.write_bytes(b'test')
            with patch.object(scan_file_task, 'update_state'), patch('services.file_deep_analyzer.FileDeepAnalyzer.comprehensive_analysis', return_value={'verdict':'unknown'}):
                result = scan_file_task.run(str(path), 'sample.pdf', self.owner)
            self.assertEqual(result['status'], 'completed')
            self.assertFalse(path.exists())

    def test_deep_analysis_accepts_valid_file(self):
        with patch('services.file_deep_analyzer.FileDeepAnalyzer.comprehensive_analysis', return_value={'verdict':'unknown'}):
            response = self.post_file('/api/file-deep-analysis')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['verdict'], 'unknown')


if __name__ == '__main__':
    unittest.main()
