"""Run: python -m unittest discover -s tests -p test_task_ownership.py -v"""

import importlib.util
from io import BytesIO
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from flask import Flask
from flask_login import LoginManager

from extensions import db
from models import User, AsyncScanTask
from services.task_dispatch import enqueue_owned_task


class TaskOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Import the production endpoint functions using a disposable DB, not
        # a developer's configured DATABASE_URL or local .env database.
        cls.temporary = tempfile.TemporaryDirectory()
        with patch.dict(os.environ, {
            'DATABASE_URL': 'sqlite:///' + str(Path(cls.temporary.name, 'import.db')),
            'SECRET_KEY': 'test-only', 'IS_RENDER': '1',
        }):
            import app
            cls.production = app

    @classmethod
    def tearDownClass(cls):
        with cls.production.app.app_context():
            db.session.remove()
            db.engine.dispose()
        cls.temporary.cleanup()

    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(TESTING=True, SECRET_KEY='test-only', SQLALCHEMY_DATABASE_URI='sqlite:///:memory:')
        db.init_app(self.app)
        login = LoginManager(self.app)

        @login.user_loader
        def load_user(user_id):
            return db.session.get(User, int(user_id))

        for rule, name, methods in [
            ('/api/task-status/<task_id>', 'task_status', ['GET']),
            ('/api/async-scan-file', 'async_scan_file', ['POST']),
            ('/api/async-scan-site', 'async_scan_site', ['POST']),
            ('/api/batch-scan', 'batch_scan', ['POST']),
        ]:
            self.app.add_url_rule(rule, name, getattr(self.production, name), methods=methods)
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()
        users = [User(username=name, email=name+'@example.invalid', password_hash='unused', is_admin=name=='admin') for name in ['owner', 'other', 'admin']]
        db.session.add_all(users)
        db.session.flush()
        self.owner, self.other, self.admin = [u.id for u in users]
        db.session.add(AsyncScanTask(task_id='owned-task', user_id=self.owner))
        db.session.commit()
        self.client = self.app.test_client()
        self.patch_result = patch('app.AsyncResult')
        self.result = self.patch_result.start()
        self.addCleanup(self.patch_result.stop)
        self.result.return_value.state = 'SUCCESS'
        self.result.return_value.result = {'private': 'owner-result'}

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.context.pop()

    def sign_in(self, user_id):
        with self.client.session_transaction() as session:
            session['_user_id'] = str(user_id)
            session['_fresh'] = True

    def test_owner_can_read_result(self):
        self.sign_in(self.owner)
        response = self.client.get('/api/task-status/owned-task')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['result'], {'private': 'owner-result'})

    def test_admin_can_read_result(self):
        self.sign_in(self.admin)
        self.assertEqual(self.client.get('/api/task-status/owned-task').status_code, 200)

    def test_other_user_cannot_access_backend(self):
        self.sign_in(self.other)
        response = self.client.get('/api/task-status/owned-task')
        self.assertEqual(response.status_code, 403)
        self.result.assert_not_called()
        self.assertNotIn('result', response.get_json())

    def test_unknown_or_legacy_task_is_denied(self):
        self.sign_in(self.admin)
        self.assertEqual(self.client.get('/api/task-status/legacy-task').status_code, 404)
        self.result.assert_not_called()

    def test_anonymous_is_denied(self):
        self.assertEqual(self.client.get('/api/task-status/owned-task').status_code, 401)
        self.result.assert_not_called()

    def test_pending_response_is_preserved(self):
        self.sign_in(self.owner)
        self.result.return_value.state = 'PENDING'
        response = self.client.get('/api/task-status/owned-task')
        self.assertEqual(response.get_json()['progress'], 0)
        self.assertEqual(response.get_json()['state'], 'PENDING')

    def test_dispatch_persists_owner_before_publishing(self):
        task = Mock()
        def publish(*, args, task_id):
            self.assertEqual(db.session.get(AsyncScanTask, task_id).user_id, self.owner)
            self.assertEqual(args, ('input', self.owner))
        task.apply_async.side_effect = publish
        task_id = enqueue_owned_task(task, ('input', self.owner), self.owner)
        db.session.remove()
        self.assertEqual(db.session.get(AsyncScanTask, task_id).user_id, self.owner)

    def test_broker_failure_removes_registration(self):
        task = Mock()
        task.apply_async.side_effect = RuntimeError('broker unavailable')
        with self.assertRaises(RuntimeError):
            enqueue_owned_task(task, (), self.owner)
        self.assertEqual(AsyncScanTask.query.count(), 1)

    def check_created_task(self, response, published):
        self.assertEqual(response.status_code, 200)
        task_id = response.get_json()['task_id']
        self.assertEqual(db.session.get(AsyncScanTask, task_id).user_id, self.owner)
        self.assertEqual(published.call_args.kwargs['task_id'], task_id)

    def test_batch_endpoint_registers_owner(self):
        self.sign_in(self.owner)
        with patch.object(self.production.batch_scan_task, 'apply_async') as published:
            self.check_created_task(self.client.post('/api/batch-scan', json={'urls':['https://example.invalid']}), published)

    def test_site_endpoint_registers_owner(self):
        self.sign_in(self.owner)
        with patch.object(self.production.scan_site_task, 'apply_async') as published:
            self.check_created_task(self.client.post('/api/async-scan-site', json={'domain':'example.invalid'}), published)

    def test_file_endpoint_registers_owner(self):
        self.sign_in(self.owner)
        with tempfile.TemporaryDirectory() as uploads, patch.object(self.production, 'UPLOAD_FOLDER', uploads), patch.object(self.production.scan_file_task, 'apply_async') as published:
            self.check_created_task(self.client.post('/api/async-scan-file', data={'file':(BytesIO(b'test-only'), 'sample.pdf')}), published)

    def test_migration_creates_table_and_tolerates_startup_create_all(self):
        from alembic.migration import MigrationContext
        from alembic.operations import Operations
        import sqlalchemy as sa
        path = Path(__file__).resolve().parents[1] / 'migrations/versions/7c4e29a1b603_add_async_task_ownership.py'
        spec = importlib.util.spec_from_file_location('task_ownership_migration', path)
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)
        with db.engine.begin() as connection:
            operations = Operations(MigrationContext.configure(connection))
            with patch.object(migration, 'op', operations):
                migration.upgrade()
                migration.downgrade()
                self.assertFalse(sa.inspect(connection).has_table('async_scan_task'))
                migration.upgrade()
                self.assertTrue(sa.inspect(connection).has_table('async_scan_task'))


if __name__ == '__main__':
    unittest.main()
