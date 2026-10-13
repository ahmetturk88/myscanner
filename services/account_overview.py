"""Read-only account figures for the profile and workspace pages."""
from datetime import datetime, timezone

from sqlalchemy import func

from extensions import db
from models import Scan
from services.daily_quota import SERVICES
from services.quota_policy import DAILY_LIMITS

LABELS = {
    'url_analyzer': 'URL scans', 'site_scan': 'Site scans', 'file_scan': 'File scans',
    'email_check': 'Email checks', 'ip_check': 'IP lookups', 'domain_lookup': 'Domain lookups',
    'ssl_check': 'SSL checks', 'qr_scan': 'QR scans', 'subdomain_finder': 'Subdomain searches',
    'password_check': 'Password checks',
}
REVIEW_VERDICTS = ('suspicious', 'high_risk')


def scan_counts(user_id):
    """Totals over all of the user's saved URL scans, not just the recent page."""
    rows = dict(db.session.query(Scan.verdict, func.count(Scan.id)).filter(Scan.user_id == user_id).group_by(Scan.verdict).all())
    total = sum(rows.values())
    malicious = rows.get('malicious', 0)
    review = sum(rows.get(v, 0) for v in REVIEW_VERDICTS)
    clear = rows.get('harmless', 0)
    return {'total': total, 'malicious': malicious, 'review': review, 'harmless': clear,
            'unresolved': max(0, total - malicious - review - clear)}


def daily_allowance(user, now=None):
    """What each tool has left today, computed without writing the reset.

    Mirrors services.daily_quota: a day that has rolled over shows the full
    limit; administrators are unlimited.
    """
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(tzinfo=None)
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    unlimited = bool(user.is_admin) or user.role == 'admin'
    tier = 'premium' if user.role == 'premium' else 'user'
    expired = user.scans_reset_date is None or user.scans_reset_date < midnight
    rows = []
    for service in SERVICES:
        if service not in LABELS:
            continue
        limit = DAILY_LIMITS[tier][service]
        if unlimited or limit >= 999999:
            rows.append({'service': service, 'label': LABELS[service], 'limit': None, 'remaining': None, 'percent': 100})
            continue
        stored = getattr(user, service + '_remaining')
        remaining = limit if expired or stored is None else max(0, min(int(stored), limit))
        rows.append({'service': service, 'label': LABELS[service], 'limit': limit, 'remaining': remaining,
                     'percent': round(100 * remaining / limit) if limit else 0})
    return rows
