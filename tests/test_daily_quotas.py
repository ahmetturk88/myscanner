"""UTC daily reservation races and real endpoint dispatch boundaries."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from threading import Barrier
import tempfile
import unittest
from unittest.mock import Mock, patch
from flask import Flask
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from extensions import db
from models import User, AsyncScanTask
from services.daily_quota import (consume_quota, remaining_quota, reset_expired_quotas,
    DailyQuotaExceeded, DailyQuotaUnavailable, QuotaUserMissing, SERVICES)
import test_task_ownership

class AtomicDailyQuotaTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.app=Flask(__name__)
        self.app.config.update(SQLALCHEMY_DATABASE_URI='sqlite:///'+str(Path(self.tmp.name,'quota.db')),SQLALCHEMY_ENGINE_OPTIONS={'connect_args':{'timeout':30}})
        db.init_app(self.app);self.context=self.app.app_context();self.context.push();db.create_all()
        self.now=datetime.now(timezone.utc)
        user=User(username='owner',email='quota@example.invalid',password_hash='unused',scans_reset_date=self.now,url_analyzer_remaining=3)
        db.session.add(user);db.session.commit();self.uid=user.id
    def tearDown(self):
        db.session.remove();db.drop_all();db.engine.dispose();self.context.pop();self.tmp.cleanup()
    def balance(self, service='url_analyzer'):
        with db.engine.connect() as c:return c.execute(select(getattr(User,service+'_remaining')).where(User.id==self.uid)).scalar_one()
    def test_concurrent_workers_cannot_exceed_last_three_units(self):
        barrier=Barrier(12)
        def worker(_):
            with self.app.app_context():
                barrier.wait()
                try:consume_quota(self.uid,'url_analyzer',now=self.now);return True
                except DailyQuotaExceeded:return False
        with ThreadPoolExecutor(max_workers=12) as pool:accepted=list(pool.map(worker,range(12)))
        self.assertEqual(sum(accepted),3);self.assertEqual(self.balance(),0)
    def test_concurrent_first_requests_reset_only_once(self):
        db.session.get(User,self.uid).scans_reset_date=self.now-timedelta(days=1);db.session.get(User,self.uid).url_analyzer_remaining=0;db.session.commit()
        barrier=Barrier(8)
        def worker(_):
            with self.app.app_context():
                barrier.wait()
                try:consume_quota(self.uid,'url_analyzer',now=self.now);return True
                except DailyQuotaExceeded:return False
        with ThreadPoolExecutor(max_workers=8) as pool:accepted=list(pool.map(worker,range(8)))
        self.assertEqual(sum(accepted),3);self.assertEqual(self.balance(),0)
    def test_bulk_cost_is_all_or_nothing(self):
        with self.assertRaises(DailyQuotaExceeded):consume_quota(self.uid,'url_analyzer',4,now=self.now)
        self.assertEqual(self.balance(),3);self.assertEqual(consume_quota(self.uid,'url_analyzer',2,now=self.now),1)
    def test_reset_hooks_do_not_replenish_today(self):
        consume_quota(self.uid,'url_analyzer',now=self.now)
        self.assertEqual(reset_expired_quotas(now=self.now),0)
        self.assertEqual(reset_expired_quotas(now=self.now),0);self.assertEqual(self.balance(),2)
    def test_rollover_refreshes_all_services_and_uses_utc_day(self):
        user=db.session.get(User,self.uid);user.scans_reset_date=datetime(2026,10,5,23,59);user.email_check_remaining=0;user.file_scan_remaining=0;db.session.commit()
        now=datetime(2026,10,6,3,0,tzinfo=timezone(timedelta(hours=3)))
        consume_quota(self.uid,'url_analyzer',now=now)
        self.assertEqual(self.balance(),2);self.assertEqual(self.balance('email_check'),15);self.assertEqual(self.balance('file_scan'),5)
        self.assertEqual(reset_expired_quotas(now=now),0)
    def test_reading_remaining_rolls_over_without_scheduler(self):
        db.session.get(User,self.uid).scans_reset_date=self.now-timedelta(days=2);db.session.commit()
        self.assertEqual(remaining_quota(self.uid,'email_check',now=self.now),15)
        consume_quota(self.uid,'email_check',now=self.now);self.assertEqual(remaining_quota(self.uid,'email_check',now=self.now),14)
    def test_legacy_excess_negative_and_null_balance_are_bounded(self):
        for stored,expected in [(20,2),(-5,None),(None,2)]:
            user=db.session.get(User,self.uid);user.url_analyzer_remaining=stored;db.session.commit()
            if expected is None:
                with self.assertRaises(DailyQuotaExceeded):consume_quota(self.uid,'url_analyzer',now=self.now)
            else:self.assertEqual(consume_quota(self.uid,'url_analyzer',now=self.now),expected)
    def test_user_and_service_boundaries_and_invalid_cost(self):
        with self.assertRaises(QuotaUserMissing):consume_quota(99999,'url_analyzer',now=self.now)
        for service,cost in [('typo',1),('sandbox_analysis',1),('url_analyzer',0),('url_analyzer',True),('url_analyzer',1.5)]:
            with self.assertRaises(ValueError):consume_quota(self.uid,service,cost,now=self.now)
        self.assertEqual(self.balance(),3)
    def test_unknown_roles_use_basic_limits_and_admin_flags_apply_on_reset(self):
        user=db.session.get(User,self.uid);user.role='typo';user.scans_reset_date=self.now-timedelta(days=1);db.session.commit()
        self.assertEqual(consume_quota(self.uid,'url_analyzer',now=self.now),2)
        db.session.expire_all();user=db.session.get(User,self.uid);user.is_admin=True;user.scans_reset_date=self.now-timedelta(days=1);db.session.commit()
        self.assertIsNone(consume_quota(self.uid,'url_analyzer',now=self.now))
    def test_admin_has_no_daily_limit_even_when_existing_balance_is_zero(self):
        from services.daily_quota import SERVICES
        for privileges in [{'is_admin':True,'role':'user'},{'is_admin':False,'role':'admin'}]:
            user=db.session.get(User,self.uid)
            for key,value in privileges.items():setattr(user,key,value)
            for service in SERVICES:setattr(user,service+'_remaining',0)
            user.scans_reset_date=self.now;db.session.commit()
            for service in SERVICES:
                self.assertIsNone(consume_quota(self.uid,service,2000000,now=self.now))
                self.assertIsNone(remaining_quota(self.uid,service,now=self.now))
                self.assertEqual(self.balance(service),0)
    def test_demoted_admin_is_limited_immediately_even_with_cached_user(self):
        user=db.session.get(User,self.uid);user.is_admin=True;user.url_analyzer_remaining=0;db.session.commit()
        self.assertIsNone(consume_quota(self.uid,'url_analyzer',now=self.now))
        from sqlalchemy import update
        with db.engine.begin() as conn:conn.execute(update(User).where(User.id==self.uid).values(is_admin=False,role='user'))
        with self.assertRaises(DailyQuotaExceeded):consume_quota(self.uid,'url_analyzer',now=self.now)
    def test_database_failure_blocks_reservation(self):
        with patch.object(db.engine,'begin',side_effect=SQLAlchemyError('private-db-error')):
            with self.assertRaises(DailyQuotaUnavailable):consume_quota(self.uid,'url_analyzer',now=self.now)
    def test_later_orm_commit_cannot_undo_committed_reservation(self):
        user=db.session.get(User,self.uid);self.assertEqual(user.url_analyzer_remaining,3)
        consume_quota(self.uid,'url_analyzer',now=self.now);user.last_login=self.now;db.session.commit();self.assertEqual(self.balance(),2)

class DailyQuotaEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_task_ownership.TaskOwnershipTests.setUpClass();cls.production=test_task_ownership.TaskOwnershipTests.production
    @classmethod
    def tearDownClass(cls):test_task_ownership.TaskOwnershipTests.tearDownClass()
    def setUp(self):
        test_task_ownership.TaskOwnershipTests.setUp(self)
        for path,name in [('/api/bulk-email-check','api_bulk_email_check'),('/api/file-deep-analysis','api_file_deep_analysis'),('/api/check-password','api_check_password'),('/api/scan-file','api_scan_file'),('/dashboard','dashboard')]:self.app.add_url_rule(path,name,getattr(self.production,name),methods=['POST','GET'] if path=='/dashboard' else ['POST'])
        from services.upload_validation import UploadValidationError
        self.app.register_error_handler(UploadValidationError,self.production.invalid_upload)
        test_task_ownership.TaskOwnershipTests.sign_in(self,self.owner)
    def tearDown(self):test_task_ownership.TaskOwnershipTests.tearDown(self)
    def balance(self,service):
        db.session.expire_all();return getattr(db.session.get(User,self.owner),service+'_remaining')
    def test_url_batch_charges_each_url_before_dispatch_and_cannot_bypass(self):
        with patch.object(self.production,'enqueue_owned_task',return_value='task') as enqueue:
            r=self.client.post('/api/batch-scan',json={'urls':['https://example.invalid/a','https://example.invalid/b']});self.assertEqual(r.status_code,200);self.assertEqual(self.balance('url_analyzer'),1)
            r=self.client.post('/api/batch-scan',json={'urls':['https://example.invalid/a','https://example.invalid/b']});self.assertEqual(r.status_code,429);self.assertEqual(self.balance('url_analyzer'),1);self.assertEqual(enqueue.call_count,1)
    def test_bulk_email_processes_and_charges_entire_validated_batch(self):
        with patch.object(self.production,'AdvancedEmailChecker') as checker:
            checker.return_value.check_all.return_value={'valid':True,'quality_score':50}
            r=self.client.post('/api/bulk-email-check',json={'emails':['a@example.invalid','b@example.invalid']});self.assertEqual(r.status_code,200);self.assertEqual(checker.return_value.check_all.call_count,2);self.assertEqual(self.balance('email_check'),13)
            r=self.client.post('/api/bulk-email-check',json={'emails':['a@example.invalid']*14});self.assertEqual(r.status_code,429);self.assertEqual(checker.return_value.check_all.call_count,2);self.assertEqual(self.balance('email_check'),13)
    def test_malformed_batches_do_not_reserve_or_dispatch(self):
        with patch.object(self.production,'enqueue_owned_task') as enqueue,patch.object(self.production,'AdvancedEmailChecker') as checker:
            for path,field in [('/api/batch-scan','urls'),('/api/bulk-email-check','emails')]:
                for value in [None,'text',[],[None],[''],['x']*21]:self.assertEqual(self.client.post(path,json={field:value}).status_code,400)
            enqueue.assert_not_called();checker.assert_not_called()
        self.assertEqual(self.balance('url_analyzer'),3);self.assertEqual(self.balance('email_check'),15)
    def test_async_site_and_all_file_routes_enforce_shared_allowances(self):
        user=db.session.get(User,self.owner);user.site_scan_remaining=0;user.file_scan_remaining=0;db.session.commit()
        with patch.object(self.production,'enqueue_owned_task') as enqueue,patch.object(self.production,'FileDeepAnalyzer') as analyzer,patch.object(self.production,'get_file_threat_intel') as intel:
            self.assertEqual(self.client.post('/api/async-scan-site',json={'domain':'example.invalid'}).status_code,429)
            for path in ['/api/scan-file','/api/file-deep-analysis','/api/async-scan-file']:
                self.assertEqual(self.client.post(path,data={'file':(BytesIO(b'valid'),'a.pdf')},content_type='multipart/form-data').status_code,429)
            enqueue.assert_not_called();analyzer.assert_not_called();intel.assert_not_called()
    def test_invalid_upload_and_json_do_not_consume_quota(self):
        for path in ['/api/scan-file','/api/file-deep-analysis','/api/async-scan-file']:
            self.assertEqual(self.client.post(path,data={'file':(BytesIO(b'x'),'bad.xyz')},content_type='multipart/form-data').status_code,400)
        for payload in [None,[],{}, {'password':123},{'password':''}]:self.assertEqual(self.client.post('/api/check-password',json=payload).status_code,400)
        self.assertEqual(self.balance('file_scan'),5);self.assertEqual(self.balance('password_check'),3)
    def test_accepted_broker_failure_does_not_reset_reservation(self):
        with patch.object(self.production,'enqueue_owned_task',side_effect=RuntimeError('broker unavailable')):
            r=self.client.post('/api/async-scan-file',data={'file':(BytesIO(b'x'),'a.pdf')},content_type='multipart/form-data');self.assertEqual(r.status_code,503)
        self.assertEqual(self.balance('file_scan'),4)
    def test_storage_failure_returns_generic_503_before_analyzer(self):
        with patch('services.permissions.consume_quota',side_effect=DailyQuotaUnavailable('secret')),patch.object(self.production,'PasswordAnalyzer') as analyzer:
            r=self.client.post('/api/check-password',json={'password':'example'});self.assertEqual(r.status_code,503);self.assertNotIn('secret',r.json['error']);analyzer.assert_not_called()
    def test_dashboard_form_shares_url_allowance_with_batch(self):
        db.session.get(User,self.owner).url_analyzer_remaining=0;db.session.commit()
        with patch('services.url_scan_storage.enqueue_url_scan') as thread:
            r=self.client.post('/dashboard',data={'url':'https://example.invalid'});self.assertEqual(r.status_code,302);thread.assert_not_called()
    def test_report_reads_never_start_new_analysis_or_consume_quota(self):
        import json
        from models import Scan
        self.app.add_url_rule('/api/url-analysis/<int:scan_id>','api_url_analysis',self.production.api_url_analysis)
        self.app.add_url_rule('/report/pdf/<int:scan_id>','download_pdf',self.production.download_pdf)
        row=Scan(user_id=self.owner,url='https://example.invalid',verdict='unknown',status='completed',result='saved',raw_report=json.dumps({'local_analysis':{'security_score':50},'deep_analysis':{}}))
        db.session.add(row);db.session.commit();sid=row.id
        with patch.object(self.production,'URLDeepAnalyzer') as analyzer,patch.object(self.production,'generate_vulnerability_report',return_value=BytesIO(b'%PDF-test')) as pdf:
            for _ in range(2):
                self.assertEqual(self.client.get('/api/url-analysis/'+str(sid)).status_code,200)
                self.assertEqual(self.client.get('/report/pdf/'+str(sid)).status_code,200)
            analyzer.assert_not_called();self.assertEqual(pdf.call_count,2)
        self.assertEqual(self.balance('url_analyzer'),3)
    def test_missing_saved_report_requires_explicit_new_scan(self):
        from models import Scan
        self.app.add_url_rule('/api/url-analysis/<int:scan_id>','api_url_analysis',self.production.api_url_analysis)
        self.app.add_url_rule('/report/pdf/<int:scan_id>','download_pdf',self.production.download_pdf)
        row=Scan(user_id=self.owner,url='https://example.invalid',verdict='unknown',status='completed',result='legacy',raw_report='not-json');db.session.add(row);db.session.commit();sid=row.id
        with patch.object(self.production,'URLDeepAnalyzer') as analyzer:
            self.assertEqual(self.client.get('/api/url-analysis/'+str(sid)).status_code,409)
            self.assertEqual(self.client.get('/report/pdf/'+str(sid)).status_code,409)
            analyzer.assert_not_called()
        self.assertEqual(self.balance('url_analyzer'),3)
    def test_sandbox_hash_uses_file_allowance_after_hex_validation(self):
        from routes import sandbox_routes
        self.app.add_url_rule('/api/sandbox/hash-lookup','sandbox_hash',sandbox_routes.api_sandbox_hash_lookup,methods=['POST'])
        with patch.object(sandbox_routes,'HybridAnalysisService') as service:
            service.return_value.lookup_hash.return_value={'verdict':'unknown'}
            self.assertEqual(self.client.post('/api/sandbox/hash-lookup',json={'hash':'z'*64}).status_code,400)
            self.assertEqual(self.balance('file_scan'),5)
            self.assertEqual(self.client.post('/api/sandbox/hash-lookup',json={'hash':'a'*64}).status_code,200)
            self.assertEqual(self.balance('file_scan'),4)
            db.session.get(User,self.owner).file_scan_remaining=0;db.session.commit()
            self.assertEqual(self.client.post('/api/sandbox/hash-lookup',json={'hash':'a'*64}).status_code,429)
            self.assertEqual(service.call_count,1)
    def test_anonymous_batch_does_not_dispatch(self):
        with self.client.session_transaction() as session:session.clear()
        with patch.object(self.production,'enqueue_owned_task') as enqueue:
            self.assertEqual(self.client.post('/api/batch-scan',json={'urls':['https://example.invalid']}).status_code,401);enqueue.assert_not_called()
        self.assertEqual(self.balance('url_analyzer'),3)
