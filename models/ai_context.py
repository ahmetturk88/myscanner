# models/ai_context.py
"""Report evidence a user asked the AI assistant about, with its cached answers."""
from datetime import datetime, timezone
from extensions import db


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AIContext(db.Model):
    __tablename__ = 'ai_context'

    id           = db.Column(db.String(36), primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    tool         = db.Column(db.String(32), nullable=False)
    evidence     = db.Column(db.Text, nullable=False)          # sanitized JSON
    explanations = db.Column(db.Text, nullable=False, default='{}')  # {"ar": {...}, "en": {...}}
    chat         = db.Column(db.Text, nullable=False, default='[]')  # [{"role", "text"}]
    created_at   = db.Column(db.DateTime, nullable=False, default=_now, index=True)
