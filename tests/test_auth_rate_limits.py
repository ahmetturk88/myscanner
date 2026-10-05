"""Offline authentication throttling tests with a disposable database."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
import unittest
import time
from bs4 import BeautifulSoup
from sqlalchemy.exc import OperationalError
from extensions import db
from models import User, AuthRateLimit
from services.auth_rate_limit import consume_limit, AuthRateLimited, check_verification_send
import test_task_ownership


class AuthRateLimitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_task_ownership.TaskOwnershipTests.setUpClass()
        cls.production = test_task_ownership.TaskOwnershipTests.production

    @classmethod
    def tearDownClass(cls):
        test_task_ownership.TaskOwnershipTests.tearDownClass()

    def setUp(self):
        self.app = self.production.app
        self.assertEqual(self.app.config['SQLALCHEMY_DATABASE_URI'], 'sqlite:///' + str(Path(test_task_ownership.TaskOwnershipTests.temporary.name, 'import.db')))
        with self.app.app_context():
            db.drop_all()
            db.create_all()
            db.session.add(User(username='limited-user', email='limited@example.invalid', password_hash='unused', is_verified=False))
            db.session.commit()
        self.client = self.app.test_client()
        page = self.client.get('/login')
        self.token = BeautifulSoup(page.data, 'html.parser').find('meta', {'name': 'csrf-token'})['content']

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def post(self, path='/login', email='limited@example.invalid', ip='127.0.0.1'):
        return self.client.post(path, data={'email': email, 'password': 'unused', 'csrf_token': self.token},
                                environ_overrides={'REMOTE_ADDR': ip})

    def test_account_limit_blocks_rotating_ips_before_password_verification(self):
        with patch.object(User, 'check_password', return_value=False) as check:
            for i in range(20):
                self.assertEqual(self.post(ip='192.0.2.' + str(i + 1)).status_code, 302)
            response = self.post(ip='198.51.100.1')
            self.assertEqual(response.status_code, 429)
            self.assertEqual(check.call_count, 20)
            self.assertIn('Retry-After', response.headers)
            self.assertIn(b'Please try again shortly', response.data)

    def test_ip_limit_blocks_rotating_accounts_and_ignores_forwarded_headers(self):
        with patch('services.auth_rate_limit.time.time', return_value=time.time()):
            for i in range(60):
                self.assertEqual(self.post(email=str(i) + '@example.invalid').status_code, 302)
            response = self.client.post('/login', data={'csrf_token': self.token, 'email': 'other@example.invalid'},
                                        headers={'X-Forwarded-For': '203.0.113.99'})
            self.assertEqual(response.status_code, 429)

    def test_registration_limit_blocks_before_user_creation_and_email(self):
        with patch.object(self.production, 'send_verification_email') as send:
            for _ in range(5):
                self.assertEqual(self.post('/register').status_code, 302)
            self.assertEqual(self.post('/register').status_code, 429)
            send.assert_not_called()
        with self.app.app_context():
            self.assertEqual(User.query.count(), 1)

    def test_unverified_login_does_not_repeat_email_within_cooldown(self):
        with patch.object(User, 'check_password', return_value=True), patch.object(self.production, 'send_verification_email') as send:
            self.assertEqual(self.post().status_code, 302)
            self.assertEqual(self.post().status_code, 429)
            self.assertEqual(send.call_count, 1)

    def test_expired_window_allows_new_attempt(self):
        with self.app.app_context():
            consume_limit('test', 'person@example.invalid', 1, 60, now=100)
            with self.assertRaises(AuthRateLimited) as error:
                consume_limit('test', 'person@example.invalid', 1, 60, now=130)
            self.assertEqual(error.exception.retry_after, 30)
            consume_limit('test', 'person@example.invalid', 1, 60, now=160)
            row = AuthRateLimit.query.one()
            self.assertEqual(row.hits, 1)
            self.assertEqual(row.expires_at, 220)
            self.assertNotIn('person', row.key)

    def test_verification_hour_limit_survives_minute_resets(self):
        with self.app.app_context():
            for now in [100, 161, 222]:
                with patch('services.auth_rate_limit.time.time', return_value=now):
                    check_verification_send(1)
            with patch('services.auth_rate_limit.time.time', return_value=283), self.assertRaises(AuthRateLimited):
                check_verification_send(1)

    def test_missing_csrf_does_not_consume_limits(self):
        self.assertEqual(self.client.post('/login', data={'email': 'limited@example.invalid'}).status_code, 400)
        with self.app.app_context():
            self.assertEqual(AuthRateLimit.query.count(), 0)

    def test_storage_failure_blocks_authentication(self):
        with patch.object(self.production, 'check_auth_request', side_effect=OperationalError('counter', {}, Exception('offline'))), patch.object(User, 'check_password') as check:
            self.assertEqual(self.post().status_code, 503)
            check.assert_not_called()

    def test_migration_creates_table_and_tolerates_startup_create_all(self):
        import importlib.util
        from alembic.migration import MigrationContext
        from alembic.operations import Operations
        path = Path(__file__).resolve().parents[1] / 'migrations/versions/a6b738de2104_add_auth_rate_limits.py'
        spec = importlib.util.spec_from_file_location('auth_migration', path)
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)
        with self.app.app_context(), db.engine.begin() as connection:
            AuthRateLimit.__table__.drop(connection)
            operations = Operations(MigrationContext.configure(connection))
            with patch.object(migration, 'op', operations):
                migration.upgrade()
                migration.upgrade()
                connection.execute(AuthRateLimit.__table__.insert().values(key='test', hits=1, expires_at=100))

    def test_concurrent_consumption_cannot_exceed_limit(self):
        def attempt(_):
            with self.app.app_context():
                try:
                    consume_limit('concurrent', 'same', 5, 60, now=100)
                    return True
                except AuthRateLimited:
                    return False
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(sum(pool.map(attempt, range(12))), 5)
