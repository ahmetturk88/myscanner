# models/ai_context.py
"""Report evidence a user asked the AI assistant about, with its cached answers."""
from datetime import datetime, timezone
from extensions import db


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _expiry():
    from datetime import timedelta
    return _now() + timedelta(days=30)


class AIContext(db.Model):
    __tablename__ = 'ai_context'

    id           = db.Column(db.String(36), primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    tool         = db.Column(db.String(32), nullable=False)
    # Contexts backed by saved reports are verified server-side. Legacy
    # client-supplied contexts are explicitly marked unverified.
    source_kind  = db.Column(db.String(24), nullable=False, default='client_unverified')
    source_report_id = db.Column(db.Integer, db.ForeignKey('scan.id', ondelete='CASCADE'), nullable=True, index=True)
    evidence_hash = db.Column(db.String(64), nullable=True)
    evidence     = db.Column(db.Text, nullable=False)          # sanitized JSON
    explanations = db.Column(db.Text, nullable=False, default='{}')  # {"ar": {...}, "en": {...}}
    chat         = db.Column(db.Text, nullable=False, default='[]')  # [{"role", "text"}]
    created_at   = db.Column(db.DateTime, nullable=False, default=_now, index=True)
    expires_at   = db.Column(db.DateTime, nullable=False, index=True, default=_expiry)
