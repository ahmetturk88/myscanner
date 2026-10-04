"""Run with: python -m unittest discover -s tests -p test_scan_stop_permissions.py"""

import unittest
from unittest.mock import patch

from flask import Flask
from flask_login import LoginManager

from extensions import db
from models import User
from models.vulnerability import VulnerabilityScan
from routes.vuln_routes import vuln_bp


class StopScanPermissionsTests(unittest.TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config.update(
            TESTING=True,
            SECRET_KEY='test-only',
            SQLALCHEMY_DATABASE_URI='sqlite:///:memory:',
        )
        db.init_app(self.app)
        login = LoginManager(self.app)

        @login.user_loader
        def load_user(user_id):
            return db.session.get(User, int(user_id))

        self.app.register_blueprint(vuln_bp)
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()
        owner = User(username='owner', email='owner@example.invalid', password_hash='unused')
        other = User(username='other', email='other@example.invalid', password_hash='unused')
        admin = User(username='admin', email='admin@example.invalid', password_hash='unused', is_admin=True)
        db.session.add_all([owner, other, admin])
        db.session.flush()
        self.owner_id, self.other_id, self.admin_id = owner.id, other.id, admin.id
        scan = VulnerabilityScan(
            scan_uuid='test-scan', user_id=owner.id,
            target='https://example.invalid', scan_type='web_application', status='running',
        )
        db.session.add(scan)
        db.session.commit()
        self.client = self.app.test_client()
        self.mock = patch('routes.vuln_routes.get_orchestrator')
        self.orchestrator = self.mock.start()
        self.addCleanup(self.mock.stop)
        self.orchestrator.return_value.stop_scan.return_value = True

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.context.pop()

    def sign_in(self, user_id):
        with self.client.session_transaction() as session:
            session['_user_id'] = str(user_id)
            session['_fresh'] = True

    def test_other_user_is_rejected_before_orchestrator_is_called(self):
        self.sign_in(self.other_id)
        response = self.client.post('/vulnerability/stop/test-scan')
        self.assertEqual(response.status_code, 403)
        self.orchestrator.assert_not_called()
        self.assertEqual(VulnerabilityScan.query.one().status, 'running')

    def test_owner_can_stop_scan(self):
        self.sign_in(self.owner_id)
        response = self.client.post('/vulnerability/stop/test-scan')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()['success'])
        self.orchestrator.return_value.stop_scan.assert_called_once_with('test-scan')

    def test_admin_can_stop_another_users_scan(self):
        self.sign_in(self.admin_id)
        self.assertEqual(self.client.post('/vulnerability/stop/test-scan').status_code, 200)
        self.orchestrator.return_value.stop_scan.assert_called_once_with('test-scan')

    def test_missing_scan_returns_404_without_calling_orchestrator(self):
        self.sign_in(self.owner_id)
        self.assertEqual(self.client.post('/vulnerability/stop/missing').status_code, 404)
        self.orchestrator.assert_not_called()

    def test_anonymous_user_cannot_stop_scan(self):
        self.assertEqual(self.client.post('/vulnerability/stop/test-scan').status_code, 401)
        self.orchestrator.assert_not_called()

    def test_authorized_stop_failure_keeps_existing_error_response(self):
        self.sign_in(self.owner_id)
        self.orchestrator.return_value.stop_scan.return_value = False
        self.assertEqual(self.client.post('/vulnerability/stop/test-scan').status_code, 400)


if __name__ == '__main__':
    unittest.main()
