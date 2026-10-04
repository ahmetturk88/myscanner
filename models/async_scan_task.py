from datetime import datetime

from extensions import db


class AsyncScanTask(db.Model):
    """Durable ownership for Celery scan results."""

    __tablename__ = 'async_scan_task'

    task_id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
