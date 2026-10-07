"""One Celery instance for publishers, workers, results and Beat."""
import os
import ssl
from urllib.parse import urlsplit, parse_qs
from celery import Celery
from kombu import Queue
from dotenv import load_dotenv


def production_mode(env):
    mode = env.get('APP_ENV', 'production' if env.get('RENDER', '').lower() == 'true' else 'development').lower()
    if mode not in {'development', 'testing', 'production'}:
        raise RuntimeError('APP_ENV must be development, testing, or production')
    return mode == 'production'


if not production_mode(os.environ):
    load_dotenv()

SCAN_TASKS = ('scan_url_task', 'expire_url_scan_jobs', 'scan_site_task', 'scan_file_task', 'batch_scan_task', 'scan_large_file_task')
TIP_TASKS = ('fetch_ioc_source_task', 'fetch_all_ioc_sources', 'cleanup_expired_iocs',
             'misp_pull_task', 'misp_push_task', 'initialize_tip_sources')


def _redis_url(value, setting, testing=False):
    if testing and value in {'memory://', 'cache+memory://'}:
        return value
    try:
        if any(ord(character) <= 32 for character in value):
            raise ValueError()
        parsed = urlsplit(value)
        if parsed.scheme not in {'redis', 'rediss'} or not parsed.hostname or parsed.fragment or parsed.port == 0:
            raise ValueError()
        if parsed.path not in {'', '/'} and not parsed.path[1:].isdigit():
            raise ValueError()
        _ = parsed.port
        if parsed.scheme == 'rediss':
            requirements = parse_qs(parsed.query).get('ssl_cert_reqs', ['required'])
            if requirements != ['required'] and requirements != ['CERT_REQUIRED']:
                raise ValueError()
    except (TypeError, ValueError):
        raise RuntimeError(setting + ' must be a valid Redis connection URL') from None
    return value


def celery_settings(environ=None):
    env = os.environ if environ is None else environ
    production = production_mode(env)
    testing = env.get('APP_ENV', '').lower() == 'testing'
    # Explicit Celery settings win over the shared Redis setting.
    broker = env.get('CELERY_BROKER_URL', env.get('REDIS_URL', '')).strip()
    enabled = bool(broker) or not production
    if not broker:
        broker = 'memory://' if production else 'redis://localhost:6379/0'
    backend = env.get('CELERY_RESULT_BACKEND', broker).strip()
    if enabled:
        broker = _redis_url(broker, 'CELERY_BROKER_URL/REDIS_URL', testing)
        backend = _redis_url(backend, 'CELERY_RESULT_BACKEND', testing)
    elif backend != 'memory://':
        # Reject a misleading backend-only configuration rather than ignoring it.
        raise RuntimeError('Configure a broker before setting CELERY_RESULT_BACKEND')
    else:
        backend = 'cache+memory://'
    settings = {
        'broker_url': broker, 'result_backend': backend,
        'myscanner_queue_enabled': enabled,
        'task_serializer': 'json', 'accept_content': ['json'], 'result_serializer': 'json',
        'timezone': 'UTC', 'enable_utc': True, 'task_track_started': True,
        'include': ['tasks'], 'task_default_queue': 'celery',
        'task_queues': (Queue('celery'), Queue('scans'), Queue('tip')),
        'task_create_missing_queues': False,
        'task_routes': {**{name: {'queue': 'scans'} for name in SCAN_TASKS},
                        **{name: {'queue': 'tip'} for name in TIP_TASKS}},
        'beat_schedule': {
            'expire-url-scan-jobs': {'task': 'expire_url_scan_jobs', 'schedule': 60, 'options': {'queue': 'scans'}},
            'fetch-ioc-sources-hourly': {'task': 'fetch_all_ioc_sources', 'schedule': 3600, 'options': {'queue': 'tip'}},
            'cleanup-expired-iocs-daily': {'task': 'cleanup_expired_iocs', 'schedule': 86400, 'options': {'queue': 'tip'}},
            'misp-pull-daily': {'task': 'misp_pull_task', 'schedule': 86400, 'kwargs': {'days_back': 7}, 'options': {'queue': 'tip'}},
        },
        'worker_prefetch_multiplier': 1,
        # Existing tasks are not universally retry/idempotency-safe yet.
        'task_acks_late': False,
        'task_time_limit': 1800, 'task_soft_time_limit': 1500,
        'broker_transport_options': {'visibility_timeout': 3600},
        'broker_connection_retry_on_startup': True,
        'task_publish_retry_policy': {'max_retries': 2, 'interval_start': 0, 'interval_step': 0.2, 'interval_max': 0.5},
    }

    if broker.startswith('rediss://'):
        settings['broker_use_ssl'] = {'ssl_cert_reqs': ssl.CERT_REQUIRED}
    if backend.startswith('rediss://'):
        settings['redis_backend_use_ssl'] = {'ssl_cert_reqs': ssl.CERT_REQUIRED}
    return settings


def require_broker(app):
    if not app.conf.myscanner_queue_enabled:
        raise RuntimeError('Background jobs require CELERY_BROKER_URL or REDIS_URL. No production localhost fallback is used.')


class MyScannerCelery(Celery):
    def send_task(self, *args, **kwargs):
        require_broker(self)
        return super().send_task(*args, **kwargs)


celery = MyScannerCelery('myscanner')
celery.conf.update(celery_settings())


def make_celery(app):
    """Compatibility binding; never create another application or task registry."""
    app.extensions['celery'] = celery
    return celery
