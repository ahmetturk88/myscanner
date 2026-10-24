# models/pro_interest.py
"""Interest in MyScanner Pro before it opens: page visits by source, and waitlist sign-ups.

A visit row holds only its source and language (no IP, no cookie id). A sign-up
row holds the email given for the one launch notice.
"""
from datetime import datetime, timezone
from extensions import db


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ProInterest(db.Model):
    __tablename__ = 'pro_interest'

    id         = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_now, index=True)
    kind       = db.Column(db.String(10), nullable=False)  # 'visit' or 'signup'
    source     = db.Column(db.String(40), nullable=False, default='direct')
    lang       = db.Column(db.String(2), nullable=False, default='en')
    email      = db.Column(db.String(254), nullable=True, index=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
