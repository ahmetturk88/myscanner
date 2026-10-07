"""URL delivery, durable reports, ownership and bounded crash failure."""
from datetime import datetime, timedelta
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
from extensions import db
from models import Scan, AsyncScanTask
from services.url_scan_storage import (enqueue_url_scan, claim_url_scan, save_url_scan,
    fail_url_scan, expire_url_scans, JOB_LIFETIME, JOB_MARKER, FAILURE)
import test_task_ownership

ROOT=Path(__file__).resolve().parents[1]

class URLQueueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_task_ownership.TaskOwnershipTests.setUpClass()
        cls.production = test_task_ownership.TaskOwnershipTests.production
    @classmethod
    def tearDownClass(cls):
        test_task_ownership.TaskOwnershipTests.tearDownClass()
    tearDown = test_task_ownership.TaskOwnershipTests.tearDown
    sign_in = test_task_ownership.TaskOwnershipTests.sign_in
    # Reuse the isolated Flask/database fixture without inheriting unrelated tests.
    def setUp(self):
        test_task_ownership.TaskOwnershipTests.setUp(self)
        self.sign_in(self.owner)
        self.app.add_url_rule('/dashboard','dashboard',self.production.dashboard,methods=['GET','POST'])
        self.app.add_url_rule('/result/<int:scan_id>','result_page',lambda scan_id: 'result')
        self.app.add_url_rule('/api/scan_status/<int:scan_id>','api_scan_status',self.production.api_scan_status)
        self.app.add_url_rule('/api/scan_result/<int:scan_id>','api_scan_result',self.production.api_scan_result)
    def job(self):
        task=Mock();sid=enqueue_url_scan(task,'https://example.invalid',self.owner)
        task_id=task.apply_async.call_args.kwargs['task_id']
        return sid,task_id
    def reports(self, available=True):
        provider={'verdict':'harmless','trust_score':100} if available else {'error':'unavailable'}
        return ({'urlvet':provider,'verdict':'safe','details':'العربية '*15000}, {'urlvet':provider,'verdict':'safe'})
    def test_publish_sees_committed_owner_scan_and_exact_id(self):
        task=Mock()
        def inspect(**kwargs):
            url,owner,sid,tid=kwargs['args']
            db.session.remove()
            row=db.session.get(Scan,sid)
            self.assertEqual((row.status,row.user_id,row.url),('queued',owner,url))
            self.assertEqual(db.session.get(AsyncScanTask,tid).user_id,owner)
            self.assertEqual(kwargs['task_id'],tid)
            self.assertEqual(kwargs['expires'],2700)
        task.apply_async.side_effect=inspect
        enqueue_url_scan(task,'https://example.invalid',self.owner)
    def test_duplicate_delivery_claims_once_and_wrong_identity_never_claims(self):
        sid,tid=self.job()
        for owner,url,taskid in [(self.other,'https://example.invalid',tid),(self.owner,'https://other.invalid',tid),(self.owner,'https://example.invalid','forged')]:
            self.assertFalse(claim_url_scan(sid,owner,url,taskid))
        self.assertTrue(claim_url_scan(sid,self.owner,'https://example.invalid',tid))
        self.assertFalse(claim_url_scan(sid,self.owner,'https://example.invalid',tid))
    def test_complete_large_report_survives_session_restart(self):
        sid,tid=self.job();self.assertTrue(claim_url_scan(sid,self.owner,'https://example.invalid',tid))
        local,deep=self.reports();save_url_scan(sid,self.owner,'https://example.invalid',local,deep)
        db.session.remove();row=db.session.get(Scan,sid)
        self.assertEqual(row.status,'completed');self.assertEqual(json.loads(row.raw_report)['local_analysis'],local)
        self.assertIn('scanned_at',json.loads(row.raw_report))
        self.assertFalse(fail_url_scan(sid,self.owner,row.url))
    def test_partial_preserves_threat_and_never_claims_safe(self):
        for verdict,expected in [('safe','unknown'),('malicious','malicious')]:
            sid,tid=self.job();claim_url_scan(sid,self.owner,'https://example.invalid',tid)
            local,deep=self.reports(False);local['verdict']=verdict
            result=save_url_scan(sid,self.owner,'https://example.invalid',local,deep)
            self.assertEqual(result,{'status':'partial','verdict':expected})
    def test_publish_failure_is_generic_durable_and_late_delivery_cannot_claim(self):
        task=Mock();task.apply_async.side_effect=RuntimeError('private broker credential')
        with self.assertRaises(RuntimeError):enqueue_url_scan(task,'https://example.invalid',self.owner)
        db.session.expire_all();row=Scan.query.one();tid=task.apply_async.call_args.kwargs['task_id']
        self.assertEqual(row.status,'error');self.assertEqual(json.loads(row.raw_report)['error'],FAILURE)
        self.assertIsNotNone(db.session.get(AsyncScanTask,tid))
        self.assertFalse(claim_url_scan(row.id,self.owner,row.url,tid))
    def test_database_failure_never_publishes(self):
        task=Mock()
        with patch.object(db.session,'commit',side_effect=RuntimeError('db failed')),self.assertRaises(RuntimeError):enqueue_url_scan(task,'https://example.invalid',self.owner)
        db.session.rollback();task.apply_async.assert_not_called();self.assertEqual(Scan.query.count(),0)
    def test_stale_queued_and_running_jobs_expire_but_other_scans_do_not(self):
        now=datetime.utcnow()
        for status in ['queued','running','completed','cancelled']:
            db.session.add(Scan(url='https://example.invalid',user_id=self.owner,status=status,result=JOB_MARKER,date_posted=now-JOB_LIFETIME-timedelta(seconds=1)))
        db.session.add(Scan(url='https://site.invalid',user_id=self.owner,status='running',result='Site analysis',date_posted=now-JOB_LIFETIME-timedelta(seconds=1)))
        db.session.commit();self.assertEqual(expire_url_scans(now),2)
        self.assertEqual(expire_url_scans(now),0)
        db.session.expire_all();self.assertEqual([s.status for s in Scan.query.order_by(Scan.id)],['error','error','completed','cancelled','running'])
    def test_expired_job_cannot_start_or_save_even_before_sweeper(self):
        sid,tid=self.job();row=db.session.get(Scan,sid);row.date_posted=datetime.utcnow()-JOB_LIFETIME-timedelta(seconds=1);db.session.commit()
        self.assertFalse(claim_url_scan(sid,self.owner,row.url,tid))
        row.status='running';db.session.commit()
        with self.assertRaises(ValueError):save_url_scan(sid,self.owner,row.url,*self.reports())
    def test_cancelled_or_changed_owner_cannot_be_overwritten(self):
        for change in [{'status':'cancelled'},{'user_id':self.other},{'url':'https://other.invalid'}]:
            sid,tid=self.job();claim_url_scan(sid,self.owner,'https://example.invalid',tid)
            db.session.expire_all();row=db.session.get(Scan,sid)
            for name,value in change.items():setattr(row,name,value)
            db.session.commit()
            with self.assertRaises(ValueError):save_url_scan(sid,self.owner,'https://example.invalid',*self.reports())
            self.assertFalse(fail_url_scan(sid,self.owner,'https://example.invalid') if 'status' not in change else fail_url_scan(sid,self.owner,row.url))
    def test_invalid_analysis_never_completes(self):
        for local,deep in [(None,{}),({'error':'secret'},{}),({'urlvet':None},{}),({'bad':float('nan')},{})]:
            sid,tid=self.job();claim_url_scan(sid,self.owner,'https://example.invalid',tid)
            with self.assertRaises((ValueError,AttributeError)):save_url_scan(sid,self.owner,'https://example.invalid',local,deep)
    def test_dashboard_dispatches_queue_without_thread_or_analyzer(self):
        with patch.object(self.production.scan_url_task,'apply_async') as dispatch,patch.object(self.production.threading,'Thread') as thread,patch.object(self.production,'URLDeepAnalyzer') as analyzer:
            response=self.client.post('/dashboard',data={'url':'https://example.invalid'})
            self.assertEqual(response.status_code,302);self.assertIn('/result/',response.location)
            dispatch.assert_called_once();thread.assert_not_called();analyzer.assert_not_called()
    def test_unconfigured_queue_does_not_create_job_or_consume_quota(self):
        from models import User
        before=db.session.get(User,self.owner).url_analyzer_remaining
        with patch('celery_app.require_broker',side_effect=RuntimeError('missing broker')),patch.object(self.production.scan_url_task,'apply_async') as dispatch:
            self.assertEqual(self.client.post('/dashboard',data={'url':'https://example.invalid'}).status_code,302)
            dispatch.assert_not_called()
        db.session.expire_all();self.assertEqual(db.session.get(User,self.owner).url_analyzer_remaining,before);self.assertEqual(Scan.query.count(),0)
    def test_invalid_url_never_publishes_or_creates_row(self):
        with patch.object(self.production.scan_url_task,'apply_async') as dispatch:
            for url in ['file:///etc/passwd','https://example.invalid/'+('a'*500)]:self.assertEqual(self.client.post('/dashboard',data={'url':url}).status_code,302)
            dispatch.assert_not_called();self.assertEqual(Scan.query.count(),0)
    def test_worker_saves_before_success_and_closes_session(self):
        import tasks
        sid,tid=self.job();analyzer=Mock();analyzer.comprehensive_analysis.return_value,analyzer.comprehensive_deep_analysis.return_value=self.reports()
        with patch.object(self.production,'app',self.app),patch('services.url_analyzer.URLDeepAnalyzer',return_value=analyzer):
            self.assertEqual(tasks.scan_url_task.run('https://example.invalid',self.owner,sid,tid)['status'],'completed')
            self.assertEqual(tasks.scan_url_task.run('https://example.invalid',self.owner,sid,tid)['status'],'failed')
        analyzer.comprehensive_analysis.assert_called_once();analyzer.session.close.assert_called_once()
    def test_worker_failure_persists_generic_error_and_closes(self):
        import tasks
        sid,tid=self.job();analyzer=Mock();analyzer.comprehensive_analysis.side_effect=RuntimeError('sensitive provider error')
        with patch.object(self.production,'app',self.app),patch('services.url_analyzer.URLDeepAnalyzer',return_value=analyzer):result=tasks.scan_url_task.run('https://example.invalid',self.owner,sid,tid)
        self.assertEqual(result['status'],'failed');db.session.expire_all();row=db.session.get(Scan,sid)
        self.assertEqual(row.status,'error');self.assertNotIn('sensitive',row.raw_report);analyzer.session.close.assert_called_once()
    def test_worker_storage_failure_cannot_report_success(self):
        import tasks
        sid,tid=self.job();analyzer=Mock();analyzer.comprehensive_analysis.return_value,analyzer.comprehensive_deep_analysis.return_value=self.reports()
        with patch.object(self.production,'app',self.app),patch('services.url_analyzer.URLDeepAnalyzer',return_value=analyzer),patch('services.url_scan_storage.save_url_scan',side_effect=RuntimeError('storage')):
            self.assertEqual(tasks.scan_url_task.run('https://example.invalid',self.owner,sid,tid)['status'],'failed')
        db.session.expire_all();self.assertEqual(db.session.get(Scan,sid).status,'error')
    def test_other_user_cannot_poll_or_read_report(self):
        sid,tid=self.job();self.sign_in(self.other)
        for endpoint in ['scan_status','scan_result']:self.assertEqual(self.client.get('/api/'+endpoint+'/'+str(sid)).status_code,404)
    def test_interface_has_queue_and_generic_failure_states(self):
        source=(ROOT/'templates/result.html').read_text(encoding='utf-8')
        self.assertIn('Your scan is queued.',source);self.assertIn("scanData.status === 'error'",source)
        self.assertNotIn('def scan_in_background',(ROOT/'app.py').read_text(encoding='utf-8'))

class URLClaimConcurrencyTests(unittest.TestCase):
    def test_concurrent_deliveries_claim_one_row_once(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        import tempfile
        from flask import Flask
        from models import User
        with tempfile.TemporaryDirectory() as temporary:
            app=Flask('claim-race')
            app.config.update(SQLALCHEMY_DATABASE_URI='sqlite:///'+str(Path(temporary,'race.db')),SQLALCHEMY_ENGINE_OPTIONS={'connect_args':{'timeout':30}})
            db.init_app(app)
            with app.app_context():
                db.create_all();user=User(username='race',email='race@example.invalid',password_hash='unused');db.session.add(user);db.session.commit();owner=user.id
                task=Mock();sid=enqueue_url_scan(task,'https://example.invalid',owner);tid=task.apply_async.call_args.kwargs['task_id'];db.session.remove()
            barrier=Barrier(8)
            def claim(_):
                with app.app_context():
                    barrier.wait();return claim_url_scan(sid,owner,'https://example.invalid',tid)
            with ThreadPoolExecutor(max_workers=8) as pool:self.assertEqual(sum(pool.map(claim,range(8))),1)
            with app.app_context():db.session.remove();db.drop_all();db.engine.dispose()

if __name__=='__main__':unittest.main()
