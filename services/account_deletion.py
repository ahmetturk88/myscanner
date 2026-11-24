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
    _delete_business_data(user_id, (user.email or '').strip().lower())
    db.session.delete(user)
    db.session.commit()
    return True


def _delete_business_data(user_id, email):
    """Owned workspaces with everything under them, memberships, invitations, Telegram link and pilot sign-up.

    The database cascades these too; deleting them here keeps the result the same on every database.
    """
    from models import (BusinessChat, BusinessDomain, BusinessEvent, BusinessLead, BusinessLookalike, BusinessMember,
                        BusinessSnapshot, BusinessUptimeDay, BusinessWorkspace)
    workspaces = [row.id for row in BusinessWorkspace.query.filter_by(owner_id=user_id).with_entities(BusinessWorkspace.id)]
    if workspaces:
        domains = [row.id for row in BusinessDomain.query.filter(BusinessDomain.workspace_id.in_(workspaces))
                   .with_entities(BusinessDomain.id)]
        if domains:
            for model in (BusinessEvent, BusinessLookalike, BusinessUptimeDay, BusinessSnapshot):
                model.query.filter(model.domain_id.in_(domains)).delete(synchronize_session=False)
            BusinessDomain.query.filter(BusinessDomain.id.in_(domains)).delete(synchronize_session=False)
        BusinessMember.query.filter(BusinessMember.workspace_id.in_(workspaces)).delete(synchronize_session=False)
        BusinessWorkspace.query.filter(BusinessWorkspace.id.in_(workspaces)).delete(synchronize_session=False)
    member = BusinessMember.user_id == user_id
    if email:
        member = member | (BusinessMember.email == email)
    BusinessMember.query.filter(member).delete(synchronize_session=False)
    BusinessChat.query.filter_by(user_id=user_id).delete(synchronize_session=False)
    lead = BusinessLead.user_id == user_id
    if email:
        lead = lead | (BusinessLead.email == email)
    BusinessLead.query.filter(lead).delete(synchronize_session=False)
