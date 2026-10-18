# models/api_token.py
"""Sign-in tokens for the mobile app. Only a SHA-256 hash of each token is stored."""
from datetime import datetime, timezone
from extensions import db


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ApiToken(db.Model):
    __tablename__ = 'api_token'

    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    token_hash   = db.Column(db.String(64), nullable=False, unique=True)
    device       = db.Column(db.String(80), nullable=False, default='')
    created_at   = db.Column(db.DateTime, nullable=False, default=_now)
    last_used_at = db.Column(db.DateTime, nullable=False, default=_now)
    expires_at   = db.Column(db.DateTime, nullable=False, index=True)
