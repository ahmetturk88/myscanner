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


class BusinessDomain(db.Model):
    __tablename__ = 'business_domain'

    id              = db.Column(db.Integer, primary_key=True)
    workspace_id    = db.Column(db.Integer, db.ForeignKey('business_workspace.id', ondelete='CASCADE'), nullable=False, index=True)
    domain          = db.Column(db.String(253), nullable=False)
    token           = db.Column(db.String(64), nullable=False)
    created_at      = db.Column(db.DateTime, nullable=False, default=_now)
    verified_at     = db.Column(db.DateTime, nullable=True)
    last_checked_at = db.Column(db.DateTime, nullable=True)
    __table_args__ = (db.UniqueConstraint('workspace_id', 'domain', name='uq_business_domain_workspace_domain'),)


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
