# celery_app.py
# ================================================================
# إعدادات Celery للمهام غير المتزامنة
# ================================================================

from celery import Celery
import os

def make_celery(app):
    """إنشاء Celery مع سياق Flask"""
    
    # إعداد Celery
    celery = Celery(
        app.import_name,
        backend=os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
        broker=os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    )
    
    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)
    
    celery.Task = ContextTask
    
    # إعدادات Celery
    celery.conf.update(
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        task_track_started=True,
        task_time_limit=30 * 60,  # 30 دقيقة كحد أقصى
        task_soft_time_limit=25 * 60,  # 25 دقيقة قبل الإنذار
        worker_prefetch_multiplier=1,
        task_acks_late=True,
    )
    
    return celery