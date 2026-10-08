"""Read-only bounded dependency checks; never return connection strings or errors."""
import time
from threading import Lock
import sqlalchemy as sa
from redis import Redis
from celery import Celery
from flask import Blueprint, current_app, jsonify, render_template
from flask_login import current_user

health_bp=Blueprint('runtime_health',__name__)


def check_database(uri):
    engine=None
    try:
        url=sa.engine.make_url(uri)
        options={'connect_timeout':2,'options':'-c statement_timeout=1500'} if url.get_backend_name()=='postgresql' else {'timeout':2}
        engine=sa.create_engine(url,poolclass=sa.pool.NullPool,hide_parameters=True,connect_args=options)
        with engine.connect() as connection:
            connection.execute(sa.text('SELECT 1'))
        return 'available'
    except Exception:
        return 'unavailable'
    finally:
        if engine is not None:engine.dispose()


def check_redis(uri):
    client=None
    try:
        client=Redis.from_url(uri,socket_connect_timeout=1,socket_timeout=1,retry_on_timeout=False)
        return 'available' if client.ping() else 'unavailable'
    except Exception:
        return 'unavailable'
    finally:
        if client is not None:client.close()


def check_scan_worker(celery):
    probe=None
    try:
        # Separate transport with bounded I/O; do not alter publisher configuration.
        probe=Celery('readiness-probe',broker=celery.conf.broker_url)
        probe.conf.update(broker_transport_options={'socket_connect_timeout':1,'socket_timeout':1,'max_retries':0},
                          broker_connection_max_retries=0,broker_connection_timeout=1,
                          broker_use_ssl=celery.conf.broker_use_ssl)
        queues=probe.control.inspect(timeout=1).active_queues() or {}
        return 'available' if any(isinstance(items,list) and any(isinstance(item,dict) and item.get('name')=='scans' for item in items) for items in queues.values()) else 'unavailable'
    except Exception:
        return 'unavailable'
    finally:
        if probe is not None:probe.close()


def collect_status(uri,celery):
    checks={'database':check_database(uri),'broker':'not_configured','result_backend':'not_configured','scan_worker':'not_checked'}
    if celery.conf.myscanner_queue_enabled:
        checks['broker']=check_redis(celery.conf.broker_url)
        checks['result_backend']=check_redis(celery.conf.result_backend)
        if checks['broker']=='available':checks['scan_worker']=check_scan_worker(celery)
    ready=all(value=='available' for value in checks.values())
    if checks['database']!='available':reason='database_unavailable'
    elif checks['broker']=='not_configured':reason='queue_not_configured'
    elif checks['broker']!='available':reason='broker_unavailable'
    elif checks['result_backend']!='available':reason='result_backend_unavailable'
    elif checks['scan_worker']!='available':reason='scan_worker_unavailable'
    else:reason='ready'
    return {'status':'ready' if ready else 'not_ready','checks':checks,'reason':reason,
            'scope':'Database, Redis connectivity and a worker consuming scans; not a provider or end-to-end scan test.'}


class StatusCache:
    def __init__(self):self.lock=Lock();self.value=None;self.expires=0
    def get(self,collector):
        with self.lock:
            if self.value is None or time.monotonic()>=self.expires:
                self.value=collector();self.expires=time.monotonic()+5
            return self.value


def cached_status():
    from celery_app import celery
    cache=current_app.extensions.setdefault('runtime_health_cache',StatusCache())
    return cache.get(lambda:collect_status(current_app.config['SQLALCHEMY_DATABASE_URI'],celery))


def response(body,status=200):
    result=jsonify(body);result.status_code=status
    result.headers['Cache-Control']='no-store'
    return result


@health_bp.get('/health/live')
def live():return response({'status':'alive'})


@health_bp.get('/health/ready')
def ready():
    status=cached_status()['status']
    return response({'status':status},200 if status=='ready' else 503)


@health_bp.get('/admin/runtime-info')
def runtime_info():
    if not current_user.is_authenticated:return response({'error':'Unauthorized'},401)
    if not current_user.is_admin:return response({'error':'Forbidden'},403)
    return response(cached_status())


@health_bp.get('/admin/runtime-status')
def runtime_page():
    if not current_user.is_authenticated:return response({'error':'Unauthorized'},401)
    if not current_user.is_admin:return response({'error':'Forbidden'},403)
    result=current_app.make_response(render_template('runtime_status.html',report=cached_status()))
    result.headers['Cache-Control']='no-store'
    return result
