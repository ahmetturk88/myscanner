import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
from flask import Flask
from flask_login import LoginManager,UserMixin
from services.runtime_health import health_bp,collect_status,StatusCache,check_database,check_scan_worker

class User(UserMixin):
    def __init__(self,identity,admin=False):self.id=identity;self.is_admin=admin

class RuntimeHealthTests(unittest.TestCase):
    def setUp(self):
        root=Path(__file__).resolve().parents[1]
        self.app=Flask(__name__,template_folder=str(root/'templates'))
        self.app.secret_key='health-tests'
        login=LoginManager(self.app)
        users={'admin':User('admin',True),'user':User('user')}
        login.user_loader(lambda identity:users.get(identity))
        self.app.register_blueprint(health_bp)
        self.client=self.app.test_client()
    def login(self,identity):
        with self.client.session_transaction() as session:session['_user_id']=identity;session['_fresh']=True
    def test_liveness_does_not_contact_dependencies(self):
        with patch('services.runtime_health.cached_status') as probe:
            result=self.client.get('/health/live')
        self.assertEqual(result.status_code,200);self.assertEqual(result.json,{'status':'alive'});probe.assert_not_called()
    def test_public_readiness_redacts_all_details(self):
        with patch('services.runtime_health.cached_status',return_value={'status':'not_ready','secret':'private','reason':'database_unavailable'}):result=self.client.get('/health/ready')
        self.assertEqual(result.status_code,503);self.assertEqual(result.json,{'status':'not_ready'})
        self.assertEqual(result.headers['Cache-Control'],'no-store')
    def test_anonymous_and_regular_users_cannot_probe_admin_checks(self):
        with patch('services.runtime_health.cached_status') as probe:
            for route in ['/admin/runtime-info','/admin/runtime-status']:
                self.assertEqual(self.client.get(route).status_code,401)
            self.login('user')
            for route in ['/admin/runtime-info','/admin/runtime-status']:self.assertEqual(self.client.get(route).status_code,403)
        probe.assert_not_called()
    def test_admin_page_explains_queue_configuration(self):
        from jinja2 import ChoiceLoader,DictLoader
        self.app.jinja_loader=ChoiceLoader([DictLoader({'base.html':'{% block content %}{% endblock %}'}),self.app.jinja_loader])
        self.login('admin')
        report={'reason':'queue_not_configured','checks':{'broker':'not_configured'},'scope':'No provider probe.'}
        with patch('services.runtime_health.cached_status',return_value=report):result=self.client.get('/admin/runtime-status')
        self.assertEqual(result.status_code,200)
        self.assertIn(b'No production queue is configured.',result.data)
        self.assertEqual(result.headers['Cache-Control'],'no-store')
    def celery(self,enabled=True):return SimpleNamespace(conf=SimpleNamespace(myscanner_queue_enabled=enabled,broker_url='redis://private:credential@broker/0',result_backend='redis://private:credential@backend/1',broker_use_ssl=None))
    def test_missing_queue_is_explicit_and_has_no_network_probe(self):
        with patch('services.runtime_health.check_database',return_value='available'),patch('services.runtime_health.check_redis') as redis:
            result=collect_status('private',self.celery(False))
        self.assertEqual(result['reason'],'queue_not_configured');redis.assert_not_called();self.assertNotIn('credential',str(result))
    def test_database_broker_backend_and_worker_failures_are_distinct(self):
        cases=[('unavailable',['available','available'],'available','database_unavailable'),('available',['unavailable','available'],'available','broker_unavailable'),('available',['available','unavailable'],'available','result_backend_unavailable'),('available',['available','available'],'unavailable','scan_worker_unavailable'),('available',['available','available'],'available','ready')]
        for database,redis,worker,reason in cases:
            with self.subTest(reason=reason),patch('services.runtime_health.check_database',return_value=database),patch('services.runtime_health.check_redis',side_effect=redis),patch('services.runtime_health.check_scan_worker',return_value=worker):
                result=collect_status('private',self.celery())
            self.assertEqual(result['reason'],reason);self.assertEqual(result['status'],'ready' if reason=='ready' else 'not_ready')
    def test_database_error_is_generic_and_connection_is_closed(self):
        engine=Mock();engine.connect.side_effect=RuntimeError('password=private')
        with patch('services.runtime_health.sa.create_engine',return_value=engine):self.assertEqual(check_database('postgresql://user:secret@host/db'),'unavailable')
        engine.dispose.assert_called_once()
    def test_cache_limits_repeated_dependency_checks(self):
        collector=Mock(return_value={'status':'ready'});cache=StatusCache()
        with patch('services.runtime_health.time.monotonic',side_effect=[10,11,16,16]):
            cache.get(collector);cache.get(collector);cache.get(collector)
        self.assertEqual(collector.call_count,2)
    def test_worker_must_consume_scan_queue_and_closes_probe(self):
        for queues,expected in [({'worker':[{'name':'tip'}]},'unavailable'),({'worker':[{'name':'scans'}]},'available'),({},'unavailable')]:
            probe=Mock();probe.control.inspect.return_value.active_queues.return_value=queues
            with patch('services.runtime_health.Celery',return_value=probe):self.assertEqual(check_scan_worker(self.celery()),expected)
            probe.close.assert_called_once()
    def test_admin_json_explains_unavailable_queue_without_secrets(self):
        self.login('admin')
        value={'status':'not_ready','reason':'queue_not_configured','checks':{'broker':'not_configured'}}
        with patch('services.runtime_health.cached_status',return_value=value):result=self.client.get('/admin/runtime-info')
        self.assertEqual(result.status_code,200);self.assertEqual(result.json,value)

if __name__=='__main__':unittest.main()
