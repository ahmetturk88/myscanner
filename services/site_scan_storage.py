"""Durable, owner-bound site worker transitions using existing Scan columns."""
from datetime import datetime, timezone
import json
import math
from sqlalchemy import update
from extensions import db
from models import Scan

ACTIVE_STATES = ('pending', 'queued', 'running')
VERDICTS = {'safe', 'suspicious', 'malicious', 'dangerous', 'unknown'}


def claim_site_scan(scan_id, user_id, domain):
    """Only one delivery may move its exact owner/target row into running."""
    with db.engine.begin() as connection:
        outcome = connection.execute(update(Scan).where(
            Scan.id == scan_id, Scan.user_id == user_id,
            Scan.url == 'https://' + domain, Scan.status.in_(('pending', 'queued')),
        ).values(status='running'))
        return outcome.rowcount == 1


def save_site_scan(scan_id, user_id, domain, result):
    if not isinstance(result, dict) or result.get('error'):
        raise ValueError('Site analysis did not return a usable report')
    status = result.get('status')
    if not isinstance(status, str) or status not in {'success', 'completed', 'partial', 'unavailable'}:
        raise ValueError('Site analysis status is not a confirmed result state')
    status = status if status in {'partial', 'unavailable'} else 'completed'
    verdict = result.get('verdict')
    verdict = verdict if isinstance(verdict, str) and verdict in VERDICTS else 'unknown'
    if status in {'partial', 'unavailable'} and verdict == 'safe':
        verdict = 'unknown'
    score = result.get('security_score')
    score = score if isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(score) and 0 <= score <= 100 else None
    stored = dict(result)
    stored.update(status=status, verdict=verdict, security_score=score,
                  completed_at=datetime.now(timezone.utc).isoformat())
    raw = json.dumps(stored, ensure_ascii=False, allow_nan=False)
    with db.engine.begin() as connection:
        outcome = connection.execute(update(Scan).where(
            Scan.id == scan_id, Scan.user_id == user_id,
            Scan.url == 'https://' + domain, Scan.status == 'running',
        ).values(status=status, verdict=verdict,
                 result='Site analysis: ' + status + '. Verdict: ' + verdict + '.', raw_report=raw))
        if outcome.rowcount != 1:
            raise ValueError('Site scan is no longer eligible for completion')
    return stored


def fail_site_scan(scan_id, user_id, domain):
    """Record a bounded generic failure without overwriting terminal/cancelled rows."""
    with db.engine.begin() as connection:
        outcome = connection.execute(update(Scan).where(
            Scan.id == scan_id, Scan.user_id == user_id,
            Scan.url == 'https://' + domain, Scan.status.in_(ACTIVE_STATES),
        ).values(status='error', verdict='unknown', result='Site analysis failed. Please retry.',
                 raw_report=json.dumps({'status': 'failed', 'error': 'Site analysis failed. Please retry.'})))
        return outcome.rowcount == 1
