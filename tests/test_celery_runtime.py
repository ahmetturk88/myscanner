"""Offline configuration, shared app identity and actual in-memory message routing."""
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from celery_app import celery_settings, MyScannerCelery, require_broker, SCAN_TASKS, TIP_TASKS
ROOT=Path(__file__).resolve().parents[1]

class CeleryConfigurationTests(unittest.TestCase):
    def test_development_keeps_local_redis_default(self):
        c=celery_settings({});self.assertEqual(c['broker_url'],'redis://localhost:6379/0');self.assertTrue(c['myscanner_queue_enabled'])
    def test_redis_environment_is_shared_by_broker_and_backend(self):
        c=celery_settings({'APP_ENV':'production','REDIS_URL':'redis://redis.internal:6379/2'});self.assertEqual(c['broker_url'],c['result_backend']);self.assertTrue(c['myscanner_queue_enabled'])
    def test_explicit_celery_urls_override_shared_redis(self):
        c=celery_settings({'REDIS_URL':'redis://cache:6379/0','CELERY_BROKER_URL':'redis://jobs:6379/1','CELERY_RESULT_BACKEND':'redis://results:6379/2'});self.assertEqual(c['broker_url'],'redis://jobs:6379/1');self.assertEqual(c['result_backend'],'redis://results:6379/2')
    def test_tls_scheme_is_supported(self):
        c=celery_settings({'APP_ENV':'production','REDIS_URL':'rediss://user:encoded%20pass@jobs.internal:6380/0'});self.assertTrue(c['broker_url'].startswith('rediss://'));import ssl;self.assertEqual(c['broker_use_ssl']['ssl_cert_reqs'],ssl.CERT_REQUIRED);self.assertEqual(c['redis_backend_use_ssl']['ssl_cert_reqs'],ssl.CERT_REQUIRED)
    def test_missing_production_broker_disables_publishing_without_localhost(self):
        c=celery_settings({'APP_ENV':'production'});self.assertFalse(c['myscanner_queue_enabled']);self.assertEqual(c['broker_url'],'memory://');self.assertEqual(c['result_backend'],'cache+memory://')
        app=MyScannerCelery('disabled-test',set_as_current=False);app.conf.update(c);self.addCleanup(app.close)
        with patch.object(app,'connection_for_write') as connection,self.assertRaisesRegex(RuntimeError,'Background jobs'):app.send_task('scan_site_task')
        connection.assert_not_called()
    def test_render_defaults_to_production(self):self.assertFalse(celery_settings({'RENDER':'true'})['myscanner_queue_enabled'])
    def test_invalid_environments_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError,'APP_ENV'):celery_settings({'APP_ENV':'prodution'})
    def test_malformed_urls_are_rejected_without_credentials(self):
        for url in ['https://user:secret@example.com','redis://','redis://jobs:abc/0','redis://jobs:70000/0','redis://jobs:0/0','redis://jobs/not-a-db','redis://jobs/0#secret','redis://bad host/0','redis://jobs\n/0','rediss://jobs/0?ssl_cert_reqs=none']:
            with self.subTest(scheme=url.split(':')[0]),self.assertRaises(RuntimeError) as error:celery_settings({'REDIS_URL':url})
            self.assertNotIn('secret',str(error.exception))
    def test_explicit_empty_broker_does_not_fall_back_to_shared_redis(self):
        c=celery_settings({'APP_ENV':'production','REDIS_URL':'redis://cache/0','CELERY_BROKER_URL':''});self.assertFalse(c['myscanner_queue_enabled'])
    def test_backend_without_broker_is_rejected_in_production(self):
        with self.assertRaisesRegex(RuntimeError,'broker'):celery_settings({'APP_ENV':'production','CELERY_RESULT_BACKEND':'redis://results/0'})
    def test_memory_urls_only_allowed_in_testing(self):
        c=celery_settings({'APP_ENV':'testing','CELERY_BROKER_URL':'memory://','CELERY_RESULT_BACKEND':'cache+memory://'});self.assertTrue(c['myscanner_queue_enabled'])
        for mode in ['development','production']:
            with self.assertRaises(RuntimeError):celery_settings({'APP_ENV':mode,'REDIS_URL':'memory://'})
    def test_all_known_tasks_have_explicit_routes_and_declared_queues(self):
        c=celery_settings({});self.assertEqual({q.name for q in c['task_queues']},{'celery','scans','tip'});self.assertFalse(c['task_create_missing_queues'])
        for name in SCAN_TASKS:self.assertEqual(c['task_routes'][name]['queue'],'scans')
        for name in TIP_TASKS:self.assertEqual(c['task_routes'][name]['queue'],'tip')
    def test_schedule_uses_registered_tip_routes_and_has_no_quota_reset(self):
        c=celery_settings({});self.assertEqual(len(c['beat_schedule']),3)
        for entry in c['beat_schedule'].values():self.assertIn(entry['task'],TIP_TASKS);self.assertEqual(entry['options']['queue'],'tip')
        self.assertEqual(c['beat_schedule']['fetch-ioc-sources-hourly']['schedule'],3600)
        self.assertEqual(c['beat_schedule']['misp-pull-daily']['kwargs'],{'days_back':7})
    def test_serialization_limits_and_ack_policy_are_explicit(self):
        c=celery_settings({});self.assertEqual(c['accept_content'],['json']);self.assertEqual(c['result_serializer'],'json');self.assertEqual(c['timezone'],'UTC');self.assertEqual(c['worker_prefetch_multiplier'],1);self.assertFalse(c['task_acks_late']);self.assertLess(c['task_soft_time_limit'],c['task_time_limit']);self.assertGreater(c['broker_transport_options']['visibility_timeout'],c['task_time_limit'])
    def test_worker_and_beat_commands_consume_all_declared_queues(self):
        source=(ROOT/'render.yaml').read_text(encoding='utf-8');self.assertIn('-A celery_worker:celery worker',source);self.assertIn('-Q scans,tip,celery',source);self.assertIn('-A celery_worker:celery beat',source);self.assertNotIn('-A tasks',source);self.assertNotIn('worker -B',source)
    def test_only_one_celery_constructor_remains_in_runtime_modules(self):
        constructors=[]
        for file in ['celery_app.py','celery_config.py','celery_worker.py','tasks.py','app.py']:
            tree=ast.parse((ROOT/file).read_text(encoding='utf-8'))
            constructors.extend(file for node in ast.walk(tree) if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in {'Celery','MyScannerCelery'})
        self.assertEqual(constructors,['celery_app.py'])

class CeleryProcessTests(unittest.TestCase):
    def run_child(self,code,overrides):
        env=dict(os.environ)
        for key in ['APP_ENV','RENDER','REDIS_URL','CELERY_BROKER_URL','CELERY_RESULT_BACKEND']:env.pop(key,None)
        env.update(overrides)
        # Child tracebacks include Unicode Windows paths; match the parent's decoder.
        env['PYTHONIOENCODING'] = 'utf-8'
        env['PYTHONUTF8'] = '1'
        return subprocess.run([sys.executable,'-c',code],cwd=ROOT,env=env,capture_output=True,text=True,encoding='utf-8',timeout=20)
    def test_tasks_aliases_registry_and_compatibility_binding_share_identity(self):
        r=self.run_child("import celery_app,celery_config,tasks; from flask import Flask; c=celery_app.celery; c.finalize(); assert c is celery_config.celery is tasks.celery; app=Flask('test'); assert celery_app.make_celery(app) is c; assert app.extensions['celery'] is c; assert all(c.tasks[n].app is c for n in celery_app.SCAN_TASKS+celery_app.TIP_TASKS); print('shared')",{'APP_ENV':'testing','CELERY_BROKER_URL':'memory://','CELERY_RESULT_BACKEND':'cache+memory://'})
        self.assertEqual(r.returncode,0,r.stderr);self.assertIn('shared',r.stdout)
    def test_actual_task_messages_use_scan_and_tip_routes(self):
        code="""from celery_app import celery
import tasks
from kombu import Connection
for task,queue,args in [(tasks.scan_site_task,'scans',('example.invalid',1,9)),(tasks.fetch_ioc_source_task,'tip',(7,))]:
    result=task.apply_async(args=args)
    with celery.connection_for_read() as connection:
        q=connection.SimpleQueue(queue)
        message=q.get(block=False)
        assert message.headers['task']==task.name
        assert message.headers['id']==result.id
        assert message.payload[0]==list(args)
        assert message.content_type=='application/json'
        message.ack();q.close()
print('routed')
"""
        r=self.run_child(code,{'APP_ENV':'testing','CELERY_BROKER_URL':'memory://','CELERY_RESULT_BACKEND':'cache+memory://'});self.assertEqual(r.returncode,0,r.stderr);self.assertIn('routed',r.stdout)
    def test_unconfigured_production_web_configuration_imports_without_flask(self):
        r=self.run_child("import celery_app,celery_config;import sys;assert 'app' not in sys.modules;assert not celery_app.celery.conf.myscanner_queue_enabled;print('disabled')",{'APP_ENV':'production'});self.assertEqual(r.returncode,0,r.stderr);self.assertIn('disabled',r.stdout)
    def test_unconfigured_production_worker_entry_refuses_startup(self):
        r=self.run_child('import celery_worker',{'APP_ENV':'production'});self.assertNotEqual(r.returncode,0);self.assertIn('Background jobs require',r.stderr)
    def test_configured_worker_import_does_not_initialize_flask_database(self):
        r=self.run_child("import celery_worker,sys;assert 'app' not in sys.modules;assert celery_worker.celery.conf.broker_url=='redis://jobs.internal:6379/0';print('ready')",{'APP_ENV':'production','REDIS_URL':'redis://jobs.internal:6379/0'});self.assertEqual(r.returncode,0,r.stderr);self.assertIn('ready',r.stdout)

if __name__=='__main__':unittest.main()
