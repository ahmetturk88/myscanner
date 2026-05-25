from extensions import db
from datetime import datetime, timezone
from models.user import User
from models.scan import Scan

def _now():
    return datetime.now(timezone.utc)

class LogEntry(db.Model):
    __tablename__ = 'log_entry'

    id         = db.Column(db.Integer, primary_key=True)
    timestamp  = db.Column(db.DateTime, default=_now, nullable=False, index=True)
    level      = db.Column(db.String(10),  default='INFO',  nullable=False)
    action     = db.Column(db.String(50),  nullable=False,  index=True)
    message    = db.Column(db.Text)
    ip_address = db.Column(db.String(50))
    user_id    = db.Column(db.Integer, nullable=True, index=True)
    username   = db.Column(db.String(100), nullable=True)

    def __repr__(self) -> str:
        return f'<LogEntry {self.id} [{self.level}] {self.action}>'