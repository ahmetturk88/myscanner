"""Queue one URL for the persistent, owner-bound URL scan pipeline.

API callers get the same worker, quota, time budget and stored report as
the dashboard form instead of running the analysis inside a web request.
"""
from flask import current_app, jsonify
from flask_login import current_user

from extensions import db
from services.permissions import reserve_request_quota
from services.safe_http import UnsafeTargetError, accept_scan_url

MAX_URL_LENGTH = 500


def queue_url_scan(url):
    if not isinstance(url, str) or not url.strip() or len(url.strip()) > MAX_URL_LENGTH:
        return jsonify(error='Provide an HTTP or HTTPS URL of at most 500 characters'), 400
    from services.url_tricks import unmask
    url, tricks = unmask(url.strip())
    try:
        url = accept_scan_url(url)
    except UnsafeTargetError:
        return jsonify(error='Provide a public HTTP or HTTPS address without credentials'), 400
    from celery_app import celery, require_broker
    try:
        require_broker(celery)
    except RuntimeError:
        return jsonify(error='URL analysis is temporarily unavailable. Please try again later.'), 503
    failure = reserve_request_quota('url_analyzer')
    if failure is not None:
        return failure
    from services.url_scan_storage import enqueue_url_scan
    from tasks import scan_url_task
    try:
        scan_id = enqueue_url_scan(scan_url_task, url, current_user.id, tricks)
    except Exception:
        db.session.rollback()
        current_app.logger.error('URL scan could not be queued')
        return jsonify(error='URL analysis is temporarily unavailable. Please try again later.'), 503
    return jsonify(scan_id=scan_id, status='queued',
                   status_url=f'/api/scan_status/{scan_id}',
                   result_url=f'/result/{scan_id}'), 202


def start_quietly(url):
    """The id of a full scan of `url` for the current user, or None when it can't start (bad address, no
    broker, no link-scan allowance left). Used by the message check, which then keeps its quick lookup."""
    from services.url_tricks import unmask
    try:
        url, tricks = unmask((url or '').strip())
        if not url or len(url) > MAX_URL_LENGTH:
            return None
        url = accept_scan_url(url)
    except Exception:
        return None
    from celery_app import celery, require_broker
    try:
        require_broker(celery)
    except RuntimeError:
        return None
    if reserve_request_quota('url_analyzer') is not None:
        return None
    from services.url_scan_storage import enqueue_url_scan
    from tasks import scan_url_task
    try:
        return enqueue_url_scan(scan_url_task, url, current_user.id, tricks)
    except Exception:
        db.session.rollback()
        current_app.logger.error('URL scan could not be queued')
        return None
