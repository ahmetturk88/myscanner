from extensions import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone


def _now():
    """Timezone-aware UTC timestamp — works on Python 3.12+"""
    return datetime.now(timezone.utc)


# ══════════════════════════════════════════════════════════════
#  USER
# ══════════════════════════════════════════════════════════════
class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False, index=True)
    email         = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin      = db.Column(db.Boolean, default=False,  nullable=False)
    is_verified   = db.Column(db.Boolean, default=False,  nullable=False)
    date_joined   = db.Column(db.DateTime, default=_now,  nullable=False)
    
    # الحقول الجديدة
    last_login = db.Column(db.DateTime, nullable=True)
    role = db.Column(db.String(20), default='user')
    remaining_scans = db.Column(db.Integer, default=20)
    scans_reset_date = db.Column(db.DateTime, default=_now)

    # ── Relationships ──
    scans = db.relationship('Scan', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    log_entries = db.relationship('LogEntry', backref='user_obj', lazy='dynamic', cascade='all, delete-orphan')

    # ── Password helpers ──
    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    # ── Role helpers ──
    @property
    def is_premium(self) -> bool:
        return self.role == 'premium'
    
    @property
    def is_admin_user(self) -> bool:
        return self.is_admin or self.role == 'admin'
    
    def can_scan(self) -> tuple:
        today = datetime.now(timezone.utc).date()
        reset_date = self.scans_reset_date.date()
        
        if reset_date != today:
            self.remaining_scans = 20 if self.role == 'user' else 999999
            self.scans_reset_date = _now()
            db.session.commit()
        
        if self.remaining_scans <= 0:
            return False, "Daily scan limit reached. Upgrade to premium!"
        
        return True, "OK"
    
    def increment_scan_count(self):
        if self.remaining_scans > 0:
            self.remaining_scans -= 1
            db.session.commit()
    
    def can_access_admin(self) -> bool:
        return self.is_admin or self.role == 'admin'

    # ── Convenience ──
    @property
    def scan_count(self) -> int:
        return self.scans.count()

    def __repr__(self) -> str:
        return f'<User {self.id} {self.username}>'


# ══════════════════════════════════════════════════════════════
#  SCAN
# ══════════════════════════════════════════════════════════════
class Scan(db.Model):
    __tablename__ = 'scan'

    id          = db.Column(db.Integer, primary_key=True)
    url         = db.Column(db.String(500), nullable=False)
    status      = db.Column(db.String(20),  default='pending',  nullable=False)
    verdict     = db.Column(db.String(20),  default='pending',  nullable=False, index=True)
    result      = db.Column(db.Text)
    raw_report  = db.Column(db.Text)
    date_posted = db.Column(db.DateTime, default=_now, nullable=False, index=True)
    security_score = db.Column(db.Integer, default=0)  # إضافة درجة الأمان

    # FK → User
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id', ondelete='CASCADE'),
        nullable=False,
        index=True
    )

    def __repr__(self) -> str:
        return f'<Scan {self.id} [{self.verdict}] {self.url[:60]}>'


# ══════════════════════════════════════════════════════════════
#  LOG ENTRY (للتسجيل في قاعدة البيانات - اختياري)
# ══════════════════════════════════════════════════════════════
class LogEntry(db.Model):
    __tablename__ = 'log_entry'

    id         = db.Column(db.Integer, primary_key=True)
    timestamp  = db.Column(db.DateTime, default=_now, nullable=False, index=True)
    level      = db.Column(db.String(10),  default='INFO',  nullable=False)
    action     = db.Column(db.String(50),  nullable=False,  index=True)
    message    = db.Column(db.Text)
    ip_address = db.Column(db.String(50))

    # FK → User (nullable — logs can exist for anonymous users)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id', ondelete='SET NULL'),
        nullable=True,
        index=True
    )

    # username snapshot — preserved even if the user is deleted later
    username = db.Column(db.String(100), nullable=True)

    # ── Convenience ──
    @property
    def user_display(self) -> str:
        """Returns live username if user still exists, else the snapshot."""
        if self.user_obj:
            return self.user_obj.username
        return self.username or 'deleted'

    def __repr__(self) -> str:
        return f'<LogEntry {self.id} [{self.level}] {self.action} by {self.user_display}>'