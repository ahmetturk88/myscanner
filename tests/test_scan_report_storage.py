"""Complete site report persistence, worker boundaries and non-destructive migration."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import importlib.util
import json
from pathlib import Path
import tempfile
from threading import Barrier
import unittest
from unittest.mock import patch
from alembic.migration import MigrationContext
from alembic.operations import Operations
from flask import Flask
import sqlalchemy as sa
from extensions import db
from models import Scan, User
from services.site_scan_storage import claim_site_scan, save_site_scan, fail_site_scan
import test_task_ownership

REPORT={'status':'success','verdict':'safe','security_score':86,'details':'معلومات '+'x'*120000}

class SiteStorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.app=Flask(__name__)
        self.app.config.update(SQLALCHEMY_DATABASE_URI='sqlite:///'+str(Path(self.tmp.name,'site.db')),SQLALCHEMY_ENGINE_OPTIONS={'connect_args':{'timeout':30}})
        db.init_app(self.app);self.context=self.app.app_context();self.context.push();db.create_all()
        user=User(username='owner',email='owner@example.invalid',password_hash='unused');db.session.add(user);db.session.flush();self.uid=user.id
        row=Scan(url='https://example.invalid',user_id=self.uid,status='queued',verdict='pending',result='pending');db.session.add(row);db.session.commit();self.sid=row.id
    def tearDown(self):
        db.session.remove();db.drop_all();db.engine.dispose();self.context.pop();self.tmp.cleanup()
    def claim(self):return claim_site_scan(self.sid,self.uid,'example.invalid')
    def row(self):db.session.expire_all();return db.session.get(Scan,self.sid)
    def test_large_unicode_report_round_trips_after_session_restart(self):
        self.assertTrue(self.claim());saved=save_site_scan(self.sid,self.uid,'example.invalid',REPORT)
        db.session.remove();row=self.row();raw=json.loads(row.raw_report)
        self.assertEqual(raw,saved);self.assertEqual(raw['details'],REPORT['details']);self.assertEqual(raw['security_score'],86);self.assertIsNotNone(datetime.fromisoformat(raw['completed_at']).tzinfo);self.assertEqual(row.status,'completed');self.assertLess(len(row.result),1000)
        self.assertFalse(hasattr(row,'security_score'));self.assertFalse(hasattr(row,'completed_at'))
    def test_wrong_owner_target_or_missing_record_cannot_claim(self):
        for sid,uid,domain in [(self.sid,self.uid+1,'example.invalid'),(self.sid,self.uid,'other.invalid'),(99999,self.uid,'example.invalid')]:self.assertFalse(claim_site_scan(sid,uid,domain))
        self.assertEqual(self.row().status,'queued')
    def test_concurrent_deliveries_claim_once(self):
        barrier=Barrier(8)
        def worker(_):
            with self.app.app_context():barrier.wait();return self.claim()
        with ThreadPoolExecutor(max_workers=8) as pool:self.assertEqual(sum(pool.map(worker,range(8))),1)
        self.assertEqual(self.row().status,'running')
    def test_terminal_record_cannot_be_claimed_again(self):
        self.claim();save_site_scan(self.sid,self.uid,'example.invalid',REPORT);self.assertFalse(self.claim())
    def test_completion_rechecks_owner_and_target(self):
        self.claim()
        for uid,domain in [(self.uid+1,'example.invalid'),(self.uid,'other.invalid')]:
            with self.assertRaises(ValueError):save_site_scan(self.sid,uid,domain,REPORT)
        self.assertEqual(self.row().status,'running');self.assertIsNone(self.row().raw_report)
    def test_cancelled_record_is_not_overwritten_by_success_or_failure(self):
        self.claim();row=self.row();row.status='cancelled';db.session.commit()
        with self.assertRaises(ValueError):save_site_scan(self.sid,self.uid,'example.invalid',REPORT)
        self.assertFalse(fail_site_scan(self.sid,self.uid,'example.invalid'));self.assertEqual(self.row().status,'cancelled')
    def test_partial_and_unavailable_do_not_claim_safe(self):
        for state in ['partial','unavailable']:
            row=self.row();row.status='running';db.session.commit();saved=save_site_scan(self.sid,self.uid,'example.invalid',dict(REPORT,status=state))
            self.assertEqual(saved['status'],state);self.assertEqual(saved['verdict'],'unknown');self.assertEqual(self.row().status,state)
    def test_partial_retains_detected_threat(self):
        self.claim();saved=save_site_scan(self.sid,self.uid,'example.invalid',dict(REPORT,status='partial',verdict='malicious'));self.assertEqual(saved['verdict'],'malicious')
    def test_invalid_report_never_completes(self):
        self.claim()
        for result in [None,[],{}, {'status':'failed'},dict(REPORT,error='failure'),dict(REPORT,status='invalid'),dict(REPORT,status=[])]:
            with self.subTest(type=type(result).__name__):
                with self.assertRaises(ValueError):save_site_scan(self.sid,self.uid,'example.invalid',result)
        self.assertEqual(self.row().status,'running')
    def test_score_bounds_and_verdict_are_normalized_without_markup(self):
        for score in [True,float('inf'),-1,101,'90']:
            row=self.row();row.status='running';db.session.commit();saved=save_site_scan(self.sid,self.uid,'example.invalid',dict(REPORT,security_score=score,verdict='<script>alert(1)</script>'))
            self.assertIsNone(saved['security_score']);self.assertEqual(saved['verdict'],'unknown');self.assertNotIn('<script>',self.row().result)
    def test_zero_score_is_preserved(self):
        self.claim();self.assertEqual(save_site_scan(self.sid,self.uid,'example.invalid',dict(REPORT,security_score=0))['security_score'],0)
    def test_serialization_failure_cannot_mark_completed(self):
        self.claim()
        with self.assertRaises(ValueError):save_site_scan(self.sid,self.uid,'example.invalid',dict(REPORT,extra=float('nan')))
        self.assertEqual(self.row().status,'running')
    def test_failure_is_durable_generic_and_does_not_overwrite_completed(self):
        self.claim();self.assertTrue(fail_site_scan(self.sid,self.uid,'example.invalid'));row=self.row();self.assertEqual(row.status,'error');self.assertEqual(json.loads(row.raw_report)['status'],'failed');self.assertFalse(self.claim())
        row.status='completed';row.raw_report='saved';db.session.commit();self.assertFalse(fail_site_scan(self.sid,self.uid,'example.invalid'));self.assertEqual(self.row().raw_report,'saved')

class SiteWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):test_task_ownership.TaskOwnershipTests.setUpClass();cls.production=test_task_ownership.TaskOwnershipTests.production
    @classmethod
    def tearDownClass(cls):test_task_ownership.TaskOwnershipTests.tearDownClass()
    def setUp(self):
        test_task_ownership.TaskOwnershipTests.setUp(self)
        row=Scan(url='https://example.invalid',user_id=self.owner,status='queued');db.session.add(row);db.session.commit();self.sid=row.id
        self.app_patch=patch.object(self.production,'app',self.app);self.app_patch.start();self.addCleanup(self.app_patch.stop)
        import tasks
        self.task=tasks.scan_site_task
        self.state_patch=patch.object(self.task,'update_state');self.state_patch.start();self.addCleanup(self.state_patch.stop)
        self.analyzer_patch=patch('services.site_analyzer.SiteAnalyzer');self.analyzer=self.analyzer_patch.start();self.addCleanup(self.analyzer_patch.stop)
        self.analyzer.return_value.comprehensive_analysis.return_value=dict(REPORT)
    def tearDown(self):test_task_ownership.TaskOwnershipTests.tearDown(self)
    def row(self):db.session.expire_all();return db.session.get(Scan,self.sid)
    def test_success_is_returned_only_after_complete_report_is_saved(self):
        r=self.task.run('example.invalid',self.owner,self.sid);self.assertEqual(r['status'],'completed');self.assertEqual(json.loads(self.row().raw_report),r['result'])
    def test_other_owner_does_not_start_analyzer(self):
        self.assertEqual(self.task.run('example.invalid',self.other,self.sid)['status'],'failed');self.analyzer.assert_not_called();self.assertEqual(self.row().status,'queued')
    def test_duplicate_delivery_does_not_analyze_again(self):
        self.task.run('example.invalid',self.owner,self.sid);self.assertEqual(self.task.run('example.invalid',self.owner,self.sid)['status'],'failed');self.assertEqual(self.analyzer.return_value.comprehensive_analysis.call_count,1)
    def test_analyzer_failure_persists_error_without_exception_details(self):
        self.analyzer.return_value.comprehensive_analysis.side_effect=RuntimeError('private-provider-detail')
        r=self.task.run('example.invalid',self.owner,self.sid);self.assertEqual(r['status'],'failed');self.assertEqual(self.row().status,'error');self.assertNotIn('private-provider-detail',str(r)+self.row().raw_report)
    def test_analyzer_error_dict_cannot_be_success(self):
        self.analyzer.return_value.comprehensive_analysis.return_value={'error':'provider failed'}
        self.assertEqual(self.task.run('example.invalid',self.owner,self.sid)['status'],'failed');self.assertEqual(self.row().status,'error')
    def test_persistence_failure_cannot_be_success(self):
        with patch('services.site_scan_storage.save_site_scan',side_effect=RuntimeError('private-db-detail')):
            r=self.task.run('example.invalid',self.owner,self.sid)
        self.assertEqual(r['status'],'failed');self.assertEqual(self.row().status,'error');self.assertNotIn('private-db-detail',str(r))
    def test_task_api_does_not_call_returned_failure_success(self):
        test_task_ownership.TaskOwnershipTests.sign_in(self,self.owner)
        self.result.return_value.state='SUCCESS'
        for status in ['failed','error']:
            self.result.return_value.result={'status':status,'error':'private-detail'}
            r=self.client.get('/api/task-status/owned-task');self.assertEqual(r.status_code,200)
            self.assertEqual(r.json['state'],'FAILURE');self.assertEqual(r.json['outcome'],'failed');self.assertNotIn('private-detail',r.get_data(as_text=True))
    def test_task_api_distinguishes_partial_and_unavailable(self):
        test_task_ownership.TaskOwnershipTests.sign_in(self,self.owner)
        self.result.return_value.state='SUCCESS'
        for status in ['partial','unavailable']:
            self.result.return_value.result={'status':status,'result':{'verdict':'unknown'}}
            r=self.client.get('/api/task-status/owned-task');self.assertEqual(r.json['outcome'],status);self.assertNotIn('successfully',r.json['status'])
    def test_partial_worker_report_retains_partial_status(self):
        self.analyzer.return_value.comprehensive_analysis.return_value=dict(REPORT,status='partial',verdict='unknown')
        r=self.task.run('example.invalid',self.owner,self.sid);self.assertEqual(r['status'],'partial');self.assertEqual(self.row().status,'partial')
    def test_cancelled_during_analysis_stays_cancelled(self):
        def analyze(domain):
            row=self.row();row.status='cancelled';db.session.commit();return REPORT
        self.analyzer.return_value.comprehensive_analysis.side_effect=analyze
        self.assertEqual(self.task.run('example.invalid',self.owner,self.sid)['status'],'failed');self.assertEqual(self.row().status,'cancelled')

class ResultMigrationTests(unittest.TestCase):
    def migration(self):
        path=Path(__file__).resolve().parents[1]/'migrations/versions/d4e52098ab61_expand_scan_result_text.py'
        spec=importlib.util.spec_from_file_location('expand_result',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
    def test_widening_preserves_old_data_and_accepts_large_result(self):
        engine=sa.create_engine('sqlite:///:memory:');self.addCleanup(engine.dispose)
        with engine.begin() as connection:
            connection.exec_driver_sql('CREATE TABLE scan (id INTEGER PRIMARY KEY, result VARCHAR(1000))');connection.exec_driver_sql("INSERT INTO scan VALUES (1, 'existing report')")
            module=self.migration()
            with patch.object(module,'op',Operations(MigrationContext.configure(connection))):module.upgrade();module.upgrade();module.downgrade()
            self.assertIsInstance(sa.inspect(connection).get_columns('scan')[1]['type'],sa.Text)
            self.assertEqual(connection.exec_driver_sql('SELECT result FROM scan').scalar(),'existing report')
            connection.execute(sa.text('UPDATE scan SET result=:value'),{'value':'x'*120000});self.assertEqual(len(connection.exec_driver_sql('SELECT result FROM scan').scalar()),120000)
    def test_missing_schema_is_reported_instead_of_silently_skipped(self):
        engine=sa.create_engine('sqlite:///:memory:');self.addCleanup(engine.dispose)
        with engine.begin() as connection:
            module=self.migration()
            with patch.object(module,'op',Operations(MigrationContext.configure(connection))),self.assertRaisesRegex(RuntimeError,'scan table'):module.upgrade()

if __name__=='__main__':unittest.main()
