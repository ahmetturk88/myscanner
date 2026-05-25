# models/user.py
from flask_login import UserMixin
from datetime import datetime, timezone
from extensions import db
from extensions import db, bcrypt

from datetime import timezone

def _now():
    return datetime.now(timezone.utc)

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    
    id               = db.Column(db.Integer, primary_key=True)
    username         = db.Column(db.String(80), nullable=False)
    email            = db.Column(db.String(120), unique=True, nullable=False)
    password_hash    = db.Column(db.String(256), nullable=False)
    is_verified      = db.Column(db.Boolean, default=False)
    is_admin         = db.Column(db.Boolean, default=False)
    date_joined      = db.Column(db.DateTime, default=_now)
    last_login       = db.Column(db.DateTime, nullable=True)
    role             = db.Column(db.String(20), default='user')
    remaining_scans  = db.Column(db.Integer, default=20)
    scans_reset_date = db.Column(db.DateTime, default=_now)

    # ===== حدود الفحوصات اليومية =====
    site_scan_remaining        = db.Column(db.Integer, default=10)
    file_scan_remaining        = db.Column(db.Integer, default=5)
    url_analyzer_remaining     = db.Column(db.Integer, default=3)
    email_check_remaining      = db.Column(db.Integer, default=15)
    ip_check_remaining         = db.Column(db.Integer, default=15)
    domain_lookup_remaining    = db.Column(db.Integer, default=15)
    ssl_check_remaining        = db.Column(db.Integer, default=15)
    qr_scan_remaining          = db.Column(db.Integer, default=15)
    subdomain_finder_remaining = db.Column(db.Integer, default=5)
    password_check_remaining   = db.Column(db.Integer, default=3)

    scans = db.relationship('Scan', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')  # 

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password) 

    def can_scan(self):
        today = datetime.now(timezone.utc).date()
        if self.scans_reset_date.date() != today:
            self.remaining_scans = 20 if self.role == 'user' else 999999
            self.scans_reset_date = _now()
            db.session.commit()
        if self.remaining_scans <= 0:
            return False, "Daily scan limit reached!"
        return True, "OK"

    def increment_scan_count(self):
        if self.remaining_scans > 0:
            self.remaining_scans -= 1
            db.session.commit()

# ================================================================
# TIP Models (Threat Intelligence Platform)
# ================================================================

from datetime import datetime, timezone, timedelta
from extensions import db

def _now():
    return datetime.now(timezone.utc)


class IoCSource(db.Model):
    __tablename__ = 'ioc_source'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    url = db.Column(db.String(500), nullable=False)
    feed_type = db.Column(db.String(30), nullable=False)
    trust_score = db.Column(db.Integer, default=80, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    fetch_interval = db.Column(db.Integer, default=3600, nullable=False)
    last_fetched = db.Column(db.DateTime, nullable=True)
    last_count = db.Column(db.Integer, default=0)
    error_count = db.Column(db.Integer, default=0)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=_now, nullable=False)

    @property
    def is_due(self):
        if not self.last_fetched:
            return True
        last = self.last_fetched.replace(tzinfo=timezone.utc) if self.last_fetched.tzinfo is None else self.last_fetched
        return (_now() - last).total_seconds() >= self.fetch_interval

    def __repr__(self):
        return f'<IoCSource {self.id} {self.name}>'


class IoCEntry(db.Model):
    __tablename__ = 'ioc_entry'
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(512), nullable=False, index=True)
    ioc_type = db.Column(db.String(20), nullable=False, index=True)
    severity = db.Column(db.String(20), default='medium', nullable=False)
    confidence = db.Column(db.Integer, default=50, nullable=False)
    source_count = db.Column(db.Integer, default=1, nullable=False)
    threat_type = db.Column(db.String(50), nullable=True)
    tags = db.Column(db.String(500), nullable=True)
    description = db.Column(db.Text, nullable=True)
    first_seen = db.Column(db.DateTime, default=_now, nullable=False)
    last_seen = db.Column(db.DateTime, default=_now, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    source_id = db.Column(db.Integer, db.ForeignKey('ioc_source.id', ondelete='SET NULL'), nullable=True)
    misp_event_id = db.Column(db.String(100), nullable=True)
    misp_attribute = db.Column(db.String(100), nullable=True)
    raw_data = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=_now, nullable=False)
    updated_at = db.Column(db.DateTime, default=_now, onupdate=_now)

    __table_args__ = (
        db.UniqueConstraint('value', 'ioc_type', name='uq_ioc_value_type'),
        db.Index('idx_ioc_active_severity', 'is_active', 'severity'),
    )

    source = db.relationship('IoCSource', foreign_keys=[source_id])

    @property
    def is_expired(self):
        if not self.expires_at:
            return False
        expires = self.expires_at.replace(tzinfo=timezone.utc) if self.expires_at.tzinfo is None else self.expires_at
        return _now() > expires
    @property
    def tags_list(self):
        if not self.tags:
            return []
        return [t.strip() for t in self.tags.split(',') if t.strip()]
    
    def update_confidence(self):
        base = self.source.trust_score if self.source else 50
        multi_source_bonus = min((self.source_count - 1) * 10, 30)
        try:
            first = self.first_seen.replace(tzinfo=timezone.utc) if self.first_seen.tzinfo is None else self.first_seen
            age_days = (_now() - first).days
        except Exception:
            age_days = 0
        age_penalty = min(age_days // 30 * 5, 20)
        self.confidence = max(0, min(100, base + multi_source_bonus - age_penalty))
 
    def to_dict(self):
        return {
            'id': self.id,
            'value': self.value,
            'type': self.ioc_type,
            'severity': self.severity,
            'confidence': self.confidence,
            'threat_type': self.threat_type,
            'tags': self.tags_list,
            'description': self.description,
            'source_count': self.source_count,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_active': self.is_active,
            'is_expired': self.is_expired,
            'source_name': self.source.name if self.source else 'manual',
        }

    def __repr__(self):
        return f'<IoCEntry {self.id} [{self.ioc_type}] {self.value[:50]}>'


class IoCMatch(db.Model):
    __tablename__ = 'ioc_match'
    id = db.Column(db.Integer, primary_key=True)
    ioc_id = db.Column(db.Integer, db.ForeignKey('ioc_entry.id', ondelete='SET NULL'), nullable=True)
    ioc_value = db.Column(db.String(512), nullable=False)
    ioc_type = db.Column(db.String(20), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    context = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(512), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    matched_at = db.Column(db.DateTime, default=_now, nullable=False)

    ioc = db.relationship('IoCEntry', foreign_keys=[ioc_id])
    user = db.relationship('User', foreign_keys=[user_id])

    def __repr__(self):
        return f'<IoCMatch {self.id} [{self.ioc_type}] {self.ioc_value[:40]}>'


class TIPFeedLog(db.Model):
    __tablename__ = 'tip_feed_log'
    id = db.Column(db.Integer, primary_key=True)
    source_id = db.Column(db.Integer, db.ForeignKey('ioc_source.id', ondelete='CASCADE'), nullable=False)
    started_at = db.Column(db.DateTime, default=_now, nullable=False)
    ended_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='running', nullable=False)
    added_count = db.Column(db.Integer, default=0)
    updated_count = db.Column(db.Integer, default=0)
    skipped_count = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text, nullable=True)

    source = db.relationship('IoCSource', foreign_keys=[source_id])

    @property
    def duration_seconds(self):
        if self.ended_at:
            return (self.ended_at - self.started_at).total_seconds()
        return None

    def __repr__(self):
        return f'<TIPFeedLog {self.id} src={self.source_id} status={self.status}>'