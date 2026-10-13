"""Page previews: bounded worker capture and owner-only serving."""
import io
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from PIL import Image

from services import url_screenshot

import test_task_ownership


def png(width=40, height=30):
    output = io.BytesIO()
    Image.new('RGB', (width, height), (10, 120, 200)).save(output, 'PNG')
    return output.getvalue()


def provider_response(body, status=200):
    response = MagicMock(status_code=status)
    response.iter_content.return_value = [body[i:i+1000] for i in range(0, len(body), 1000)]
    response.__enter__.return_value = response
    return response


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp());self.addCleanup(shutil.rmtree, self.directory)
        patcher = patch.dict(os.environ, {'SCREENSHOT_DIR': str(self.directory)});patcher.start();self.addCleanup(patcher.stop)

    def capture(self, body, status=200):
        with patch('services.url_screenshot.requests.get', return_value=provider_response(body, status)) as get:
            stored = url_screenshot.capture_screenshot('https://example.com/a?b=1', 7, base_url='http://urlvet:8080')
        return stored, get

    def test_png_is_reencoded_as_jpeg_and_url_is_a_query_parameter(self):
        stored, get = self.capture(png())
        self.assertTrue(stored)
        self.assertEqual(get.call_args.args[0], 'http://urlvet:8080/api/v1/screenshot')
        self.assertEqual(get.call_args.kwargs['params'], {'url': 'https://example.com/a?b=1'})
        self.assertFalse(get.call_args.kwargs['allow_redirects'])
        self.assertTrue((self.directory/'7.jpg').read_bytes().startswith(b'\xff\xd8'))

    def test_rejected_bodies_store_nothing(self):
        cases = [(b'<svg onload=alert(1)>', 200), (png(), 500), (b'GIF89a' + b'x' * 50, 200)]
        for body, status in cases:
            self.assertFalse(self.capture(body, status)[0])
        with patch.object(url_screenshot, 'MAX_DOWNLOAD_BYTES', 100):
            self.assertFalse(self.capture(png(200, 200))[0])
        with patch.object(url_screenshot, 'MAX_SOURCE_PIXELS', 100):
            self.assertFalse(self.capture(png())[0])
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_provider_failure_never_raises(self):
        with patch('services.url_screenshot.requests.get', side_effect=OSError('provider detail')):
            self.assertFalse(url_screenshot.capture_screenshot('https://example.com', 8, base_url='http://urlvet:8080'))

    def test_no_provider_means_no_network(self):
        with patch.dict(os.environ, {'URLVET_URL': ''}), patch('services.url_screenshot.requests.get') as get:
            self.assertFalse(url_screenshot.capture_screenshot('https://example.com', 9))
        get.assert_not_called()

    def test_prune_removes_only_old_previews(self):
        old, new, other = self.directory/'1.jpg', self.directory/'2.jpg', self.directory/'notes.txt'
        for path in (old, new, other):
            path.write_bytes(b'x')
        os.utime(old, (0, 0));os.utime(other, (0, 0))
        self.assertEqual(url_screenshot.prune_screenshots(days=30), 1)
        self.assertEqual(sorted(p.name for p in self.directory.iterdir()), ['2.jpg', 'notes.txt'])

    def test_scan_task_captures_before_saving(self):
        from tasks import scan_url_task
        order = []
        analyzer = MagicMock()
        with patch('services.url_scan_storage.claim_url_scan', return_value=True), \
             patch('services.url_analyzer.URLDeepAnalyzer', return_value=analyzer), \
             patch('services.url_screenshot.capture_screenshot', side_effect=lambda *a: order.append('capture')) as capture, \
             patch('services.url_scan_storage.save_url_scan', side_effect=lambda *a: order.append('save') or {'status': 'completed'}):
            scan_url_task.apply(args=('https://example.com', 1, 5, 'task')).get()
        capture.assert_called_once_with('https://example.com', 5)
        self.assertEqual(order, ['capture', 'save'])


class ServingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_task_ownership.TaskOwnershipTests.setUpClass()
        cls.production = test_task_ownership.TaskOwnershipTests.production

    @classmethod
    def tearDownClass(cls):
        test_task_ownership.TaskOwnershipTests.tearDownClass()

    def setUp(self):
        test_task_ownership.TaskOwnershipTests.setUp(self)
        for rule, name in [('/api/scan_screenshot/<int:scan_id>', 'api_scan_screenshot'), ('/api/scan_result/<int:scan_id>', 'api_scan_result')]:
            self.app.add_url_rule(rule, name, getattr(self.production, name))
        from models import Scan
        from extensions import db
        scan = Scan(url='https://example.com', status='completed', verdict='harmless', user_id=self.owner)
        db.session.add(scan);db.session.commit();self.scan_id = scan.id
        self.directory = Path(tempfile.mkdtemp());self.addCleanup(shutil.rmtree, self.directory)
        patcher = patch.dict(os.environ, {'SCREENSHOT_DIR': str(self.directory)});patcher.start();self.addCleanup(patcher.stop)

    def tearDown(self):
        test_task_ownership.TaskOwnershipTests.tearDown(self)

    def sign_in(self, user_id):
        # The pushed app context keeps Flask-Login's cached user in g.
        from flask import g
        g.pop('_login_user', None)
        test_task_ownership.TaskOwnershipTests.sign_in(self, user_id)

    def test_owner_and_admin_see_the_preview_others_do_not(self):
        (self.directory/f'{self.scan_id}.jpg').write_bytes(b'\xff\xd8preview')
        for user, expected in ((self.owner, 200), (self.admin, 200), (self.other, 404)):
            self.sign_in(user)
            response = self.client.get(f'/api/scan_screenshot/{self.scan_id}')
            self.assertEqual(response.status_code, expected)
            if expected == 200:
                self.assertEqual(response.mimetype, 'image/jpeg')
                self.assertIn('no-store', response.headers['Cache-Control'])

    def test_result_links_the_preview_only_when_stored(self):
        self.sign_in(self.owner)
        self.assertIsNone(self.client.get(f'/api/scan_result/{self.scan_id}').json['screenshot_url'])
        self.assertEqual(self.client.get(f'/api/scan_screenshot/{self.scan_id}').status_code, 404)
        (self.directory/f'{self.scan_id}.jpg').write_bytes(b'\xff\xd8preview')
        self.assertEqual(self.client.get(f'/api/scan_result/{self.scan_id}').json['screenshot_url'], f'/api/scan_screenshot/{self.scan_id}')


if __name__ == '__main__':
    unittest.main()
