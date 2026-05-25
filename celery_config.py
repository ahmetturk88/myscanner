# celery_config.py
from celery import Celery

celery = Celery(
    'myscanner',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/0'
)

celery.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
)

# ================================================================
# TIP Tasks Schedule
# ================================================================

celery.conf.beat_schedule.update({
    'fetch-ioc-sources-hourly': {
        'task': 'fetch_all_ioc_sources',
        'schedule': 3600,  # كل ساعة
        'options': {'queue': 'tip'}
    },
    'cleanup-expired-iocs-daily': {
        'task': 'cleanup_expired_iocs',
        'schedule': 86400,  # يومياً
        'options': {'queue': 'tip'}
    },
    'misp-pull-daily': {
        'task': 'misp_pull_task',
        'schedule': 86400,  # يومياً
        'kwargs': {'days_back': 7},
        'options': {'queue': 'tip'}
    },
})

# إضافة queue مخصصة لـ TIP
celery.conf.task_queues = {
    'celery': {},
    'tip': {},
}