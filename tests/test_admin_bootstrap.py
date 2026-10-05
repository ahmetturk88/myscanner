"""Admin promotion tests run only against a disposable in-memory database."""
import unittest
from contextlib import redirect_stderr
from io import StringIO
from flask import Flask
from extensions import db
from models import User
from make_admin import promote_existing_user, main
from services.permissions import DAILY_LIMITS


class AdminBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(SQLALCHEMY_DATABASE_URI='sqlite:///:memory:')
        db.init_app(self.app)
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()
        db.session.add_all([
            User(username='target', email='target@example.invalid', password_hash='unchanged', is_verified=True),
            User(username='other', email='other@example.invalid', password_hash='other', is_verified=True),
            User(username='pending', email='pending@example.invalid', password_hash='pending', is_verified=False),
        ])
        db.session.commit()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        db.engine.dispose()
        self.context.pop()

    def test_promotes_only_requested_verified_account(self):
        user_id, changed = promote_existing_user(' TARGET@example.invalid ')
        self.assertTrue(changed)
        target = db.session.get(User, user_id)
        self.assertTrue(target.is_admin)
        self.assertEqual(target.role, 'admin')
        self.assertEqual(target.password_hash, 'unchanged')
        self.assertTrue(target.is_verified)
        self.assertEqual(target.remaining_scans, 999999)
        for service, limit in DAILY_LIMITS['admin'].items():
            field = 'sandbox_remaining' if service == 'sandbox_analysis' else service + '_remaining'
            if hasattr(User, field):
                self.assertEqual(getattr(target, field), limit)
        other = User.query.filter_by(email='other@example.invalid').one()
        self.assertFalse(other.is_admin)
        self.assertEqual(other.role, 'user')

    def test_unknown_account_is_not_created(self):
        with self.assertRaises(ValueError):
            promote_existing_user('missing@example.invalid')
        self.assertEqual(User.query.count(), 3)
        self.assertEqual(User.query.filter_by(is_admin=True).count(), 0)

    def test_unverified_account_is_not_promoted(self):
        with self.assertRaises(ValueError):
            promote_existing_user('pending@example.invalid')
        self.assertEqual(User.query.filter_by(is_admin=True).count(), 0)

    def test_empty_email_is_rejected(self):
        with self.assertRaises(ValueError):
            promote_existing_user(' ')

    def test_repeated_command_is_idempotent(self):
        user_id, _ = promote_existing_user('target@example.invalid')
        self.assertEqual(promote_existing_user('target@example.invalid'), (user_id, False))

    def test_admin_flag_alone_also_gets_admin_service_role(self):
        user = User.query.filter_by(email='target@example.invalid').one()
        user.is_admin = True
        db.session.commit()
        self.assertTrue(promote_existing_user(user.email)[1])
        self.assertEqual(user.role, 'admin')

    def test_cli_requires_explicit_email_without_importing_application(self):
        import sys
        before = sys.modules.get('app')
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit) as error:
            main([])
        self.assertEqual(error.exception.code, 2)
        self.assertIs(sys.modules.get('app'), before)
        self.assertEqual(User.query.filter_by(is_admin=True).count(), 0)


if __name__ == '__main__':
    unittest.main()
