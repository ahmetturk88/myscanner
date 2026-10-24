"""Delete an account and everything stored for it.

Used by the website's account page and by the mobile app. Rows that other
people's records point at (threat-intel matches, vulnerabilities assigned to
the user) are kept but no longer name the user.
"""
from extensions import db
from models import AIContext, ApiToken, AsyncScanTask, IoCMatch, LogEntry, ProInterest, Scan, User, VerifiedTarget
from models.vulnerability import ScanConfig, Vulnerability, VulnerabilityScan


def matches(user, typed):
    """The confirmation a user types must be their own email address."""
    return isinstance(typed, str) and typed.strip().lower() == (user.email or '').strip().lower()


def delete_account(user_id):
    """Remove the user and their data in one transaction. Returns False when the user no longer exists."""
    user = db.session.get(User, user_id)
    if user is None:
        return False
    username = user.username
    scans = [row.id for row in VulnerabilityScan.query.filter_by(user_id=user_id).with_entities(VulnerabilityScan.id)]
    if scans:
        Vulnerability.query.filter(Vulnerability.scan_id.in_(scans)).delete(synchronize_session=False)
    Vulnerability.query.filter_by(assigned_to=user_id).update({'assigned_to': None}, synchronize_session=False)
    IoCMatch.query.filter_by(user_id=user_id).update({'user_id': None}, synchronize_session=False)
    for model in (VulnerabilityScan, ScanConfig, ApiToken, AIContext, AsyncScanTask, Scan, VerifiedTarget):
        model.query.filter_by(user_id=user_id).delete(synchronize_session=False)
    LogEntry.query.filter((LogEntry.user_id == user_id) | (LogEntry.username == username)).delete(synchronize_session=False)
    ProInterest.query.filter((ProInterest.user_id == user_id) | (ProInterest.email == (user.email or '').strip().lower())).delete(synchronize_session=False)
    db.session.delete(user)
    db.session.commit()
    return True
