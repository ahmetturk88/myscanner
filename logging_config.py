# logging_config.py
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from datetime import datetime


def setup_logging(app):
    """إعداد نظام التسجيل - يدعم Local و Render"""

    IS_RENDER = os.getenv('RENDER') or os.getenv('IS_RENDER')

    formatter        = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    simple_formatter = logging.Formatter('%(asctime)s - %(message)s')

    # Console Handler - يشتغل دائماً
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)

    # File Handlers - Local فقط
    file_handler = error_handler = activity_handler = performance_handler = None

    if not IS_RENDER:
        if not os.path.exists('logs'):
            os.mkdir('logs')

        file_handler = RotatingFileHandler(
            'logs/myscanner.log', maxBytes=10 * 1024 * 1024, backupCount=10)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)

        error_handler = RotatingFileHandler(
            'logs/errors.log', maxBytes=10 * 1024 * 1024, backupCount=5)
        error_handler.setFormatter(formatter)
        error_handler.setLevel(logging.ERROR)

        activity_handler = RotatingFileHandler(
            'logs/activities.log', maxBytes=10 * 1024 * 1024, backupCount=5)
        activity_handler.setFormatter(simple_formatter)
        activity_handler.setLevel(logging.INFO)

        performance_handler = RotatingFileHandler(
            'logs/performance.log', maxBytes=10 * 1024 * 1024, backupCount=5)
        performance_handler.setFormatter(simple_formatter)
        performance_handler.setLevel(logging.INFO)

    # Flask app.logger
    app.logger.handlers.clear()
    app.logger.addHandler(console_handler)
    if file_handler:  app.logger.addHandler(file_handler)
    if error_handler: app.logger.addHandler(error_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.propagate = False

    # services logger
    services_logger = logging.getLogger('services')
    services_logger.handlers.clear()
    services_logger.addHandler(console_handler)
    if file_handler:  services_logger.addHandler(file_handler)
    if error_handler: services_logger.addHandler(error_handler)
    services_logger.setLevel(logging.INFO)
    services_logger.propagate = False

    # tasks logger
    tasks_logger = logging.getLogger('tasks')
    tasks_logger.handlers.clear()
    tasks_logger.addHandler(console_handler)
    if file_handler:  tasks_logger.addHandler(file_handler)
    if error_handler: tasks_logger.addHandler(error_handler)
    tasks_logger.setLevel(logging.INFO)
    tasks_logger.propagate = False

    # activity logger
    activity_logger = logging.getLogger('activity')
    activity_logger.handlers.clear()
    activity_logger.addHandler(console_handler)
    if activity_handler: activity_logger.addHandler(activity_handler)
    activity_logger.setLevel(logging.INFO)
    activity_logger.propagate = False

    # performance logger
    performance_logger = logging.getLogger('performance')
    performance_logger.handlers.clear()
    performance_logger.addHandler(console_handler)
    if performance_handler: performance_logger.addHandler(performance_handler)
    performance_logger.setLevel(logging.INFO)
    performance_logger.propagate = False

    env = "Render ☁️" if IS_RENDER else "Local 💻"
    app.logger.info(f'[SUCCESS] Logging system initialized successfully [{env}]'.encode('ascii', 'ignore').decode())
    return app.logger


# ================================================================
# دوال مساعدة
# ================================================================

def log_activity(user, action, details=None):
    """تسجيل النشاط في Console + ملفات + قاعدة البيانات"""
    msg = f'Activity: {action} | User: {user} | Details: {details}'

    # Console / File
    logging.getLogger('activity').info(msg)

    # myscanner.log أيضاً
    try:
        from flask import current_app
        current_app.logger.info(msg)
    except RuntimeError:
        logging.getLogger('tasks').info(msg)

    # قاعدة البيانات
    try:
        from flask import current_app, request
        from models import LogEntry
        from extensions import db
        from models import User

        # الحصول على IP
        ip = None
        try:
            ip = request.remote_addr
        except Exception:
            pass

        # الحصول على user_id
        user_id = None
        try:
            with current_app.app_context():
                user_obj = User.query.filter_by(username=user).first()
                if user_obj:
                    user_id = user_obj.id
        except Exception:
            pass

        with current_app.app_context():
            entry = LogEntry(
                level='INFO',
                action=action,
                username=user,
                user_id=user_id,
                message=details or '',
                ip_address=ip
            )
            db.session.add(entry)
            db.session.commit()

    except Exception as e:
        logging.getLogger('tasks').warning(f'Failed to save log to DB: {str(e)}')


def log_performance(endpoint, duration_ms, user):
    """تسجيل أداء التطبيق"""
    logging.getLogger('performance').info(
        f'Performance: {endpoint} took {duration_ms}ms | User: {user}'
    )


def log_error(error, user=None, details=None):
    """تسجيل الأخطاء"""
    msg = f'Error: {error} | User: {user} | Details: {details}'
    try:
        from flask import current_app
        current_app.logger.error(msg, exc_info=True)
    except RuntimeError:
        logging.getLogger('tasks').error(msg, exc_info=True)