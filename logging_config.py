# logging_config.py
import logging
import os
from logging.handlers import RotatingFileHandler
from datetime import datetime


def setup_logging(app):
    """إعداد نظام التسجيل للتطبيق"""

    if not os.path.exists('logs'):
        os.mkdir('logs')

    # ================================================================
    # Formatter موحد لجميع الملفات
    # ================================================================
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    )
    simple_formatter = logging.Formatter('%(asctime)s - %(message)s')

    # ================================================================
    # 1. myscanner.log — كل شيء (INFO+)
    # ================================================================
    file_handler = RotatingFileHandler(
        'logs/myscanner.log',
        maxBytes=10 * 1024 * 1024,   # 10 MB
        backupCount=10
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    # ================================================================
    # 2. errors.log — الأخطاء فقط (ERROR+)
    # ================================================================
    error_handler = RotatingFileHandler(
        'logs/errors.log',
        maxBytes=10 * 1024 * 1024,
        backupCount=5
    )
    error_handler.setFormatter(formatter)
    error_handler.setLevel(logging.ERROR)

    # ================================================================
    # 3. Flask app.logger
    # ================================================================
    # امسح الـ handlers القديمة لتجنب التكرار عند إعادة التشغيل
    app.logger.handlers.clear()
    app.logger.addHandler(file_handler)
    app.logger.addHandler(error_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.propagate = False

    # ================================================================
    # 4. services logger — يغطي كل ملفات services/
    #    (services.site_analyzer, services.url_analyzer, إلخ)
    # ================================================================
    services_logger = logging.getLogger('services')
    services_logger.handlers.clear()
    services_logger.setLevel(logging.INFO)
    services_logger.addHandler(file_handler)
    services_logger.addHandler(error_handler)
    services_logger.propagate = False

    # ================================================================
    # 5. tasks logger — يغطي Celery tasks
    # ================================================================
    tasks_logger = logging.getLogger('tasks')
    tasks_logger.handlers.clear()
    tasks_logger.setLevel(logging.INFO)
    tasks_logger.addHandler(file_handler)
    tasks_logger.addHandler(error_handler)
    tasks_logger.propagate = False

    # ================================================================
    # 6. activities.log — أنشطة المستخدمين
    # ================================================================
    activity_handler = RotatingFileHandler(
        'logs/activities.log',
        maxBytes=10 * 1024 * 1024,
        backupCount=5
    )
    activity_handler.setFormatter(simple_formatter)
    activity_handler.setLevel(logging.INFO)

    activity_logger = logging.getLogger('activity')
    activity_logger.handlers.clear()
    activity_logger.setLevel(logging.INFO)
    activity_logger.addHandler(activity_handler)
    activity_logger.propagate = False

    # ================================================================
    # 7. performance.log — أداء التطبيق
    # ================================================================
    performance_handler = RotatingFileHandler(
        'logs/performance.log',
        maxBytes=10 * 1024 * 1024,
        backupCount=5
    )
    performance_handler.setFormatter(simple_formatter)
    performance_handler.setLevel(logging.INFO)

    performance_logger = logging.getLogger('performance')
    performance_logger.handlers.clear()
    performance_logger.setLevel(logging.INFO)
    performance_logger.addHandler(performance_handler)
    performance_logger.propagate = False

    app.logger.info('[SUCCESS] Logging system initialized successfully')
    return app.logger


# ================================================================
# دوال مساعدة
# ================================================================

def log_activity(user, action, details=None):
    """تسجيل أنشطة المستخدمين في activities.log و myscanner.log معاً"""
    msg = f'Activity: {action} | User: {user} | Details: {details}'

    # activities.log
    logging.getLogger('activity').info(msg)

    # myscanner.log
    try:
        from flask import current_app
        current_app.logger.info(msg)
    except RuntimeError:
        # خارج سياق Flask (مثلاً Celery task)
        logging.getLogger('tasks').info(msg)


def log_performance(endpoint, duration_ms, user):
    """تسجيل أداء التطبيق في performance.log"""
    logging.getLogger('performance').info(
        f'Performance: {endpoint} took {duration_ms}ms | User: {user}'
    )


def log_error(error, user=None, details=None):
    """تسجيل الأخطاء في errors.log و myscanner.log معاً"""
    msg = f'Error: {error} | User: {user} | Details: {details}'
    try:
        from flask import current_app
        current_app.logger.error(msg, exc_info=True)
    except RuntimeError:
        logging.getLogger('tasks').error(msg, exc_info=True)