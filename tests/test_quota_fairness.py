"""Failures on our side return the user's daily allowance; the user's own errors do not."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from flask import Flask, jsonify
from flask_login import LoginManager, login_user
from sqlalchemy import select
from extensions import db
from models import User
from services.daily_quota import consume_quota, refund_after_failure
from services.quota_policy import DAILY_LIMITS
from services.safe_http import TargetResolutionError, UnsafeTargetError


class QuotaFairnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = Flask(__name__)
        self.app.config.update(SQLALCHEMY_DATABASE_URI='sqlite:///' + str(Path(self.tmp.name, 'q.db')),
                               SECRET_KEY='test', TESTING=True)
        db.init_app(self.app)
        login = LoginManager(self.app)
        login.user_loader(lambda uid: db.session.get(User, int(uid)))
        self.context = self.app.app_context()
        self.context.push()
        db.create_all()
        user = User(username='owner', email='fair@example.invalid', password_hash='unused',
                    scans_reset_date=datetime.now(timezone.utc).replace(tzinfo=None))
        db.session.add(user)
        db.session.commit()
        self.uid = user.id

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        db.engine.dispose()
        self.context.pop()
        self.tmp.cleanup()

    def balance(self, service):
        with db.engine.connect() as connection:
            return connection.execute(select(getattr(User, service + '_remaining')).where(User.id == self.uid)).scalar_one()

    def call_checked(self, service, view):
        from services.permissions import check_permission
        checked = check_permission(service)(view)
        with self.app.test_request_context('/', method='POST', json={'domain': 'example.com'}):
            login_user(db.session.get(User, self.uid))
            return checked()

    def test_free_link_checks_are_ten_a_day(self):
        self.assertEqual(DAILY_LIMITS['user']['url_analyzer'], 10)

    def test_server_error_response_refunds(self):
        response = self.call_checked('ssl_check', lambda: (jsonify(error='down'), 503))
        self.assertEqual(response[1], 503)
        self.assertEqual(self.balance('ssl_check'), 15)

    def test_raised_error_refunds_and_propagates(self):
        def broken():
            raise RuntimeError('provider crashed')
        with self.assertRaises(RuntimeError):
            self.call_checked('ssl_check', broken)
        self.assertEqual(self.balance('ssl_check'), 15)

    def test_completed_and_rejected_work_is_charged(self):
        self.call_checked('ssl_check', lambda: jsonify(ok=True))
        self.call_checked('ssl_check', lambda: (jsonify(error='bad domain'), 400))
        self.assertEqual(self.balance('ssl_check'), 13)

    def test_worker_failure_refunds_but_blocked_target_does_not(self):
        from services.evidence_jobs import run_evidence_job
        params = {'domain': 'example.com', 'include_provider': False, 'include_discovery': False}
        for error, refunded in [(RuntimeError('x'), True), (TargetResolutionError('x'), True), (UnsafeTargetError('x'), False)]:
            consume_quota(self.uid, 'site_scan')
            before = self.balance('site_scan')
            with patch('services.site_analyzer.SiteAnalyzer') as analyzer:
                analyzer.return_value.comprehensive_analysis.side_effect = error
                self.assertEqual(run_evidence_job('site', params, self.uid)['status'], 'failed')
            self.assertEqual(self.balance('site_scan'), before + 1 if refunded else before)

    def test_failed_url_job_refunds_exactly_once(self):
        from services.url_scan_storage import enqueue_url_scan, fail_url_scan
        consume_quota(self.uid, 'url_analyzer')
        scan_id = enqueue_url_scan(Mock(), 'https://example.invalid', self.uid)
        self.assertTrue(fail_url_scan(scan_id, self.uid, 'https://example.invalid'))
        self.assertFalse(fail_url_scan(scan_id, self.uid, 'https://example.invalid'))
        self.assertEqual(self.balance('url_analyzer'), 10)

    def test_refund_never_exceeds_limit_or_crosses_a_day(self):
        refund_after_failure(self.uid, 'file_scan')
        self.assertEqual(self.balance('file_scan'), 5)
        consume_quota(self.uid, 'file_scan')
        db.session.get(User, self.uid).scans_reset_date = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=1)
        db.session.commit()
        refund_after_failure(self.uid, 'file_scan')
        self.assertEqual(self.balance('file_scan'), 4)

    def test_refund_problem_is_logged_not_raised(self):
        with patch('services.daily_quota.refund_quota', side_effect=RuntimeError('db gone')):
            refund_after_failure(self.uid, 'file_scan')


if __name__ == '__main__':
    unittest.main()
