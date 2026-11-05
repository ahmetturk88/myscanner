"""MyScanner Business (İşletme): a company workspace, its monitored domains, and pre-registrations.

A workspace belongs to one account. A domain is monitored only after its owner
proves control with a DNS TXT record (`_myscanner.<domain>`); the proof is
rechecked later by the monitoring jobs. A lead is a pre-registration from the
public page: the email, an optional website and a sector, with consent.
"""
from datetime import datetime, timezone

from extensions import db


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class BusinessWorkspace(db.Model):
    __tablename__ = 'business_workspace'

    id         = db.Column(db.Integer, primary_key=True)
    owner_id   = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, unique=True, index=True)
    name       = db.Column(db.String(80), nullable=False)
    status     = db.Column(db.String(12), nullable=False, default='pilot')  # pilot, active, paused
    created_at = db.Column(db.DateTime, nullable=False, default=_now)
    # Alerts go to the owner's verified email.
    alert_lang     = db.Column(db.String(2), nullable=False, default='tr')
    instant_alerts = db.Column(db.Boolean, nullable=False, default=True)   # an email right after a serious change
    daily_digest   = db.Column(db.Boolean, nullable=False, default=True)   # one summary a day when anything changed
    last_digest_at = db.Column(db.DateTime, nullable=True)


class BusinessDomain(db.Model):
    __tablename__ = 'business_domain'

    id              = db.Column(db.Integer, primary_key=True)
    workspace_id    = db.Column(db.Integer, db.ForeignKey('business_workspace.id', ondelete='CASCADE'), nullable=False, index=True)
    domain          = db.Column(db.String(253), nullable=False)
    token           = db.Column(db.String(64), nullable=False)
    created_at      = db.Column(db.DateTime, nullable=False, default=_now)
    verified_at     = db.Column(db.DateTime, nullable=True)
    last_checked_at = db.Column(db.DateTime, nullable=True)
    monitored_at    = db.Column(db.DateTime, nullable=True)   # last daily monitoring run
    weekly_at       = db.Column(db.DateTime, nullable=True)   # last weekly site inspection
    proof_misses    = db.Column(db.Integer, nullable=False, default=0)  # daily runs in a row without our TXT record
    lookalike_at     = db.Column(db.DateTime, nullable=True)            # last look-alike watch run
    lookalike_cursor = db.Column(db.Integer, nullable=False, default=0)  # where the next batch of candidate names starts
    __table_args__ = (db.UniqueConstraint('workspace_id', 'domain', name='uq_business_domain_workspace_domain'),)


class BusinessSnapshot(db.Model):
    """One monitoring run of one domain: each check's state and facts (JSON), and the resulting score."""
    __tablename__ = 'business_snapshot'

    id         = db.Column(db.Integer, primary_key=True)
    domain_id  = db.Column(db.Integer, db.ForeignKey('business_domain.id', ondelete='CASCADE'), nullable=False, index=True)
    kind       = db.Column(db.String(10), nullable=False, default='daily')  # daily, weekly
    created_at = db.Column(db.DateTime, nullable=False, default=_now, index=True)
    score      = db.Column(db.Integer, nullable=True)
    results    = db.Column(db.Text, nullable=False)


class BusinessEvent(db.Model):
    """Something that changed between two runs (a new problem, a fix, a renewed certificate…).

    The text is not stored: a code and its parameters are rendered in the reader's language.
    notified_at is set when an alert about it has been sent.
    """
    __tablename__ = 'business_event'

    id          = db.Column(db.Integer, primary_key=True)
    domain_id   = db.Column(db.Integer, db.ForeignKey('business_domain.id', ondelete='CASCADE'), nullable=False, index=True)
    snapshot_id = db.Column(db.Integer, db.ForeignKey('business_snapshot.id', ondelete='CASCADE'), nullable=True)
    created_at  = db.Column(db.DateTime, nullable=False, default=_now, index=True)
    code        = db.Column(db.String(40), nullable=False)
    severity    = db.Column(db.String(8), nullable=False, default='info')  # info, warn, bad, good
    params      = db.Column(db.Text, nullable=False, default='{}')
    notified_at = db.Column(db.DateTime, nullable=True)


class BusinessLookalike(db.Model):
    """A registered name that looks like a watched domain (typo, other ending, brand + word, or seen in certificates)."""
    __tablename__ = 'business_lookalike'

    id         = db.Column(db.Integer, primary_key=True)
    domain_id  = db.Column(db.Integer, db.ForeignKey('business_domain.id', ondelete='CASCADE'), nullable=False, index=True)
    name       = db.Column(db.String(253), nullable=False)
    source     = db.Column(db.String(8), nullable=False, default='typo')   # typo, ct
    first_seen = db.Column(db.DateTime, nullable=False, default=_now)
    last_seen  = db.Column(db.DateTime, nullable=False, default=_now)
    resolves   = db.Column(db.Boolean, nullable=False, default=True)
    live       = db.Column(db.Boolean, nullable=False, default=False)     # answers on the web
    risk       = db.Column(db.String(8), nullable=False, default='low')   # low, medium, high
    title      = db.Column(db.String(200), nullable=True)
    status     = db.Column(db.String(10), nullable=False, default='open') # open, dismissed
    __table_args__ = (db.UniqueConstraint('domain_id', 'name', name='uq_business_lookalike_domain_name'),)


class BusinessLead(db.Model):
    __tablename__ = 'business_lead'

    id         = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_now, index=True)
    email      = db.Column(db.String(254), nullable=False, unique=True)
    website    = db.Column(db.String(253), nullable=True)
    sector     = db.Column(db.String(20), nullable=False, default='other')
    lang       = db.Column(db.String(2), nullable=False, default='en')
    source     = db.Column(db.String(40), nullable=False, default='direct')
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
