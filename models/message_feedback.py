# models/message_feedback.py
""""This result is wrong" on a message check: our verdict, the reader's answer and the signs we found.

No message text, no link, no account: only what is needed to see where the rules go wrong.
"""
from datetime import datetime, timezone
from extensions import db


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class MessageFeedback(db.Model):
    __tablename__ = 'message_feedback'

    id         = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_now, index=True)
    tone       = db.Column(db.String(10), nullable=False)   # our verdict: danger / caution / safe / unknown
    answer     = db.Column(db.String(10), nullable=False)   # the reader: 'real' or 'scam'
    signals    = db.Column(db.String(200), nullable=False, default='')  # comma-separated sign keys
