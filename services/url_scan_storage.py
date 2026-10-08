"""Owner-bound URL jobs, durable transitions and a bounded execution lifetime."""
from datetime import datetime, timedelta, timezone
import json
import uuid
from sqlalchemy import update
from extensions import db
from models import Scan, AsyncScanTask
from services.url_scan_coverage import url_scan_outcome

JOB_MARKER = 'URL analysis queued.'
JOB_LIFETIME = timedelta(minutes=45)
FAILURE = 'URL analysis could not finish. Please start a new scan.'


def enqueue_url_scan(task, url, user_id):
    task_id = str(uuid.uuid4())
    scan = Scan(url=url, user_id=user_id, status='queued', verdict='pending',
                result=JOB_MARKER, raw_report=json.dumps({'task_id': task_id}))
    db.session.add(scan)
    db.session.add(AsyncScanTask(task_id=task_id, user_id=user_id))
    db.session.commit()  # Both durable records exist before any worker can receive the message.
    scan_id = scan.id
    try:
        task.apply_async(args=(url, user_id, scan_id, task_id), task_id=task_id,
                         expires=int(JOB_LIFETIME.total_seconds()))
    except Exception:
        # Keep ownership even if an ambiguous broker error happened after delivery.
        fail_url_scan(scan_id, user_id, url)
        raise
    return scan_id


def claim_url_scan(scan_id, user_id, url, task_id):
    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - JOB_LIFETIME
    with db.engine.begin() as connection:
        result = connection.execute(update(Scan).where(
            Scan.id == scan_id, Scan.user_id == user_id, Scan.url == url,
            Scan.status == 'queued', Scan.result == JOB_MARKER,
            Scan.date_posted > cutoff,
            Scan.raw_report == json.dumps({'task_id': task_id}),
            AsyncScanTask.__table__.select().with_only_columns(AsyncScanTask.task_id).where(
                AsyncScanTask.task_id == task_id, AsyncScanTask.user_id == user_id).exists(),
        ).values(status='running'))
        return result.rowcount == 1


def save_url_scan(scan_id, user_id, url, local, deep):
    if any(not isinstance(value, dict) or value.get('error') for value in (local, deep)):
        raise ValueError('URL analysis did not return a usable report')
    from services.url_assessment import assess_url
    aggregate = assess_url(local, deep)
    if aggregate['assessed_categories'] == 0:
        raise ValueError('URL analysis did not contain usable evidence')
    status, verdict = aggregate['coverage'], aggregate['verdict']
    report = {'urlvet': local.get('urlvet') or {}, 'local_analysis': local,
              'deep_analysis': deep, 'aggregate_assessment': aggregate, 'scanned_at': datetime.now(timezone.utc).isoformat(),
              'sources': ['url.vet', 'local_analysis']}
    raw = json.dumps(report, ensure_ascii=False, allow_nan=False)
    with db.engine.begin() as connection:
        result = connection.execute(update(Scan).where(
            Scan.id == scan_id, Scan.user_id == user_id, Scan.url == url,
            Scan.status == 'running', Scan.result == JOB_MARKER,
            Scan.date_posted > datetime.now(timezone.utc).replace(tzinfo=None) - JOB_LIFETIME,
        ).values(status=status, verdict=verdict, result='URL analysis: ' + status + '. Verdict: ' + verdict + '.', raw_report=raw))
        if result.rowcount != 1:
            raise ValueError('URL scan is no longer eligible for completion')
    return {'status': status, 'verdict': verdict}


def fail_url_scan(scan_id, user_id, url):
    with db.engine.begin() as connection:
        result = connection.execute(update(Scan).where(
            Scan.id == scan_id, Scan.user_id == user_id, Scan.url == url,
            Scan.status.in_(('queued', 'running')), Scan.result == JOB_MARKER,
        ).values(status='error', verdict='unknown', result=FAILURE,
                 raw_report=json.dumps({'status': 'failed', 'error': FAILURE})))
        return result.rowcount == 1


def expire_url_scans(now=None):
    """Beat expires stalled jobs; it never silently repeats network analysis."""
    cutoff = (now or datetime.now(timezone.utc).replace(tzinfo=None)) - JOB_LIFETIME
    with db.engine.begin() as connection:
        result = connection.execute(update(Scan).where(
            Scan.status.in_(('queued', 'running')), Scan.result == JOB_MARKER,
            Scan.date_posted <= cutoff,
        ).values(status='error', verdict='unknown', result=FAILURE,
                 raw_report=json.dumps({'status': 'failed', 'error': FAILURE})))
        return result.rowcount

