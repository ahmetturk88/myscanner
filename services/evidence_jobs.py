"""Run slow evidence collection in a scan worker instead of a web request.

The web endpoint validates input, charges the quota and queues a job; the
worker runs the same analyzer and returns either the report or a fixed,
user-facing message. Exception text never reaches the response.
"""
from flask import current_app, jsonify
from flask_login import current_user

from services.safe_http import TargetResolutionError, UnsafeTargetError
from services.upload_validation import remove_temporary_upload

DNS_UNAVAILABLE = 'Target DNS is temporarily unavailable; please retry'
POLICY_BLOCKED = 'The target could not be assessed under the public-network policy'
UNAVAILABLE = {
    'site': 'Site assessment is temporarily unavailable',
    'subdomain_discovery': 'Discovery temporarily unavailable. Please retry.',
    'subdomain_inspection': 'URL inspection temporarily unavailable. Please retry.',
    'file_scan': 'File scan is temporarily unavailable. Please retry.',
    'file_deep': 'File analysis is temporarily unavailable. Please retry.',
}
INVALID = {
    'site': 'Provide a valid public HTTP or HTTPS URL',
    'file_scan': 'The file could not be analyzed.',
    'file_deep': 'The file could not be analyzed.',
}
FILE_JOBS = ('file_scan', 'file_deep')
# The daily allowance each job kind was charged against.
QUOTA_SERVICE = {'site': 'site_scan', 'subdomain_discovery': 'subdomain_finder',
                 'subdomain_inspection': 'subdomain_finder', 'file_scan': 'file_scan', 'file_deep': 'file_scan'}


def _user_message(text, fallback):
    # Analyzer validation messages are product text; cap them defensively.
    return text if isinstance(text, str) and 0 < len(text) <= 200 else fallback


def _site(params, user_id):
    from services.site_analyzer import SiteAnalyzer
    result = SiteAnalyzer().comprehensive_analysis(params['domain'], include_provider=params['include_provider'],
                                                   include_discovery=params['include_discovery'])
    if result.get('error'):
        raise ValueError(result['error'])
    from services.simple_report_view import plain_web_report
    result['plain'] = plain_web_report(result, source='site')
    return result


def _subdomain_discovery(params, user_id):
    from services.subdomain_finder import SubdomainFinder
    from services.simple_report_view import plain_subdomain_report
    result = SubdomainFinder().find_subdomains(params['domain'], include_ct=params['include_ct'])
    result['plain'] = plain_subdomain_report(result)
    return result


def _subdomain_inspection(params, user_id):
    from services.subdomain_finder import normalize_domain
    from services.web_assessment import WebAssessment
    domain = normalize_domain(params['domain'])
    from services.simple_report_view import plain_web_report
    result = WebAssessment().analyze('https://' + domain + '/', include_provider=params['include_provider'])
    result['plain'] = plain_web_report(result)
    return result


def _read_upload(params):
    from services.upload_validation import FILE_MAX_SIZE
    with open(params['path'], 'rb') as handle:
        content = handle.read(FILE_MAX_SIZE + 1)
    if len(content) > FILE_MAX_SIZE:
        raise ValueError('File too large')
    return content


def _file_scan(params, user_id):
    from services.file_threat_intel import get_file_threat_intel
    from services.file_pdf_receipts import issue_file_pdf_receipt
    result = get_file_threat_intel().comprehensive_file_scan(_read_upload(params), params['filename'])
    # Bind PDF export to this server-generated result and its owner.
    try:
        result['_pdf_receipt'] = issue_file_pdf_receipt(result, str(user_id), current_app.config['SECRET_KEY'])
    except (ValueError, TypeError):
        result['_pdf_receipt'] = None
    return result


def _file_deep(params, user_id):
    from services.file_deep_analyzer import FileDeepAnalyzer
    return FileDeepAnalyzer(use_exiftool=True).comprehensive_analysis(_read_upload(params), params['filename'])


RUNNERS = {'site': _site, 'subdomain_discovery': _subdomain_discovery,
           'subdomain_inspection': _subdomain_inspection, 'file_scan': _file_scan, 'file_deep': _file_deep}


def _refund(kind, user_id):
    # Only failures on our side are refunded; invalid or blocked targets are not.
    if kind in QUOTA_SERVICE:
        from services.daily_quota import refund_after_failure
        refund_after_failure(user_id, QUOTA_SERVICE[kind])


def run_evidence_job(kind, params, user_id):
    """Worker side. Returns {'status': 'completed', 'result': ...} or a failure."""
    try:
        if kind not in RUNNERS:
            return {'status': 'failed', 'user_error': 'Unsupported analysis request.'}
        return {'status': 'completed', 'result': RUNNERS[kind](params, user_id)}
    except TargetResolutionError:
        _refund(kind, user_id)
        return {'status': 'failed', 'user_error': DNS_UNAVAILABLE}
    except UnsafeTargetError:
        return {'status': 'failed', 'user_error': POLICY_BLOCKED}
    except ValueError as error:
        message = INVALID.get(kind) or _user_message(str(error), UNAVAILABLE[kind])
        return {'status': 'failed', 'user_error': message}
    except Exception as error:
        from services.error_reporting import report_exception
        report_exception(error)
        current_app.logger.exception('Evidence job failed: %s', kind)
        _refund(kind, user_id)
        return {'status': 'failed', 'user_error': UNAVAILABLE.get(kind, 'Analysis failed. Please retry.')}
    finally:
        if kind in FILE_JOBS and isinstance(params, dict) and params.get('path'):
            remove_temporary_upload(params['path'])


def queue_evidence_job(kind, params):
    """Web side, after validation and quota: publish an owner-bound job (202).

    A 503 here means nothing was queued; the caller that reserved the quota
    refunds it (check_permission does so for any 5xx response).
    """
    from celery_app import celery, require_broker
    from services.task_dispatch import enqueue_owned_task
    from tasks import evidence_job_task
    try:
        require_broker(celery)
        task_id = enqueue_owned_task(evidence_job_task, (kind, params, current_user.id), current_user.id)
    except Exception:
        current_app.logger.exception('Evidence job could not be queued: %s', kind)
        if kind in FILE_JOBS:
            remove_temporary_upload(params['path'])
        return jsonify(error=UNAVAILABLE[kind]), 503
    return jsonify(task_id=task_id, status='started', status_url=f'/api/task-status/{task_id}'), 202
