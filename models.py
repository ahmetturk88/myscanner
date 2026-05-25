from extensions import db, bcrypt
from flask_login import UserMixin
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
    password_hash = db.Column(db.String(128), nullable=False)  # 128 كافية لـ bcrypt
    is_admin      = db.Column(db.Boolean, default=False,  nullable=False)
    is_verified   = db.Column(db.Boolean, default=False,  nullable=False)
    date_joined   = db.Column(db.DateTime, default=_now,  nullable=False)
    
    # الحقول الجديدة
    last_login = db.Column(db.DateTime, nullable=True)
    role = db.Column(db.String(20), default='user')
    remaining_scans = db.Column(db.Integer, default=20)
    scans_reset_date = db.Column(db.DateTime, default=_now)

    # ===== حدود الفحوصات اليومية لكل خدمة =====
    site_scan_remaining = db.Column(db.Integer, default=10)
    file_scan_remaining = db.Column(db.Integer, default=5)
    url_analyzer_remaining = db.Column(db.Integer, default=20)
    email_check_remaining = db.Column(db.Integer, default=15)
    ip_check_remaining = db.Column(db.Integer, default=15)
    domain_lookup_remaining = db.Column(db.Integer, default=15)
    ssl_check_remaining = db.Column(db.Integer, default=15)
    qr_scan_remaining = db.Column(db.Integer, default=15)
    subdomain_finder_remaining = db.Column(db.Integer, default=5)
    password_check_remaining = db.Column(db.Integer, default=3)
    

    # ── Relationships ──
    scans = db.relationship('Scan', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    log_entries = db.relationship('LogEntry', backref='user_obj', lazy='dynamic', cascade='all, delete-orphan')

    # ── Password helpers using bcrypt ──
    def set_password(self, password: str) -> None:
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, password)

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
    security_score = db.Column(db.Integer, default=0)

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
#  LOG ENTRY
# ══════════════════════════════════════════════════════════════
class LogEntry(db.Model):
    __tablename__ = 'log_entry'

    id         = db.Column(db.Integer, primary_key=True)
    timestamp  = db.Column(db.DateTime, default=_now, nullable=False, index=True)
    level      = db.Column(db.String(10),  default='INFO',  nullable=False)
    action     = db.Column(db.String(50),  nullable=False,  index=True)
    message    = db.Column(db.Text)
    ip_address = db.Column(db.String(50))

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id', ondelete='SET NULL'),
        nullable=True,
        index=True
    )

    username = db.Column(db.String(100), nullable=True)

    @property
    def user_display(self) -> str:
        if self.user_obj:
            return self.user_obj.username
        return self.username or 'deleted'

    def __repr__(self) -> str:
        return f'<LogEntry {self.id} [{self.level}] {self.action} by {self.user_display}>'

# ================================================================
# TIP (Threat Intelligence Platform) — إضافة لـ models.py
# أضف هذا الكود في نهاية ملف models.py الموجود
# ================================================================




# ══════════════════════════════════════════════════════════════
#  IOC SOURCE — مصادر معلومات التهديدات
# ══════════════════════════════════════════════════════════════
class IoCSource(db.Model):
    """
    مصادر قوائم IoC المدعومة.
    كل مصدر له URL للجلب، نوع البيانات، وأولوية للثقة.
    """
    __tablename__ = 'ioc_source'

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(100), unique=True, nullable=False)
    url         = db.Column(db.String(500), nullable=False)
    feed_type   = db.Column(db.String(30),  nullable=False)
    # feed_type values: 'ip_list' | 'domain_list' | 'url_list' | 'hash_list' | 'misp_feed' | 'csv' | 'json'

    # مستوى الثقة 0..100 — يؤثر على Confidence Score للـ IoC
    trust_score = db.Column(db.Integer, default=80, nullable=False)

    is_active      = db.Column(db.Boolean, default=True,  nullable=False)
    fetch_interval = db.Column(db.Integer, default=3600,  nullable=False)  # بالثواني
    last_fetched   = db.Column(db.DateTime, nullable=True)
    last_count     = db.Column(db.Integer, default=0)  # عدد IoCs في آخر جلب
    error_count    = db.Column(db.Integer, default=0)  # عدد أخطاء متتالية
    notes          = db.Column(db.Text, nullable=True)
    created_at     = db.Column(db.DateTime, default=_now, nullable=False)

    iocs = db.relationship('IoCEntry', backref='source', lazy='dynamic',
                           cascade='all, delete-orphan')

    @property
    def is_due(self) -> bool:
        """هل حان وقت جلب المصدر مجدداً؟"""
        if not self.last_fetched:
            return True
        return (_now() - self.last_fetched).total_seconds() >= self.fetch_interval

    def __repr__(self):
        return f'<IoCSource {self.id} {self.name}>'


# ══════════════════════════════════════════════════════════════
#  IOC ENTRY — مؤشرات الاختراق
# ══════════════════════════════════════════════════════════════
class IoCEntry(db.Model):
    """
    مؤشر اختراق واحد (IP أو domain أو URL أو hash).
    يُخزّن مع درجة خطورة وثقة وتاريخ انتهاء.
    """
    __tablename__ = 'ioc_entry'

    id         = db.Column(db.Integer, primary_key=True)
    value      = db.Column(db.String(512), nullable=False, index=True)
    ioc_type   = db.Column(db.String(20),  nullable=False, index=True)
    # ioc_type values: 'ip' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256' | 'email'

    # ── درجة الخطورة ──
    severity = db.Column(db.String(20), default='medium', nullable=False, index=True)
    # severity values: 'critical' | 'high' | 'medium' | 'low' | 'info'

    # ── درجة الثقة 0..100 ──
    # تُحسب من trust_score المصدر × عدد المصادر التي أبلغت عنه
    confidence   = db.Column(db.Integer, default=50, nullable=False)

    # ── عدد المصادر التي أبلغت عن هذا الـ IoC ──
    source_count = db.Column(db.Integer, default=1, nullable=False)

    # ── تصنيف التهديد ──
    threat_type = db.Column(db.String(50), nullable=True)
    # threat_type examples: 'malware' | 'phishing' | 'botnet' | 'ransomware' | 'spam' | 'scanner'

    tags        = db.Column(db.String(500), nullable=True)   # comma-separated tags
    description = db.Column(db.Text, nullable=True)

    # ── التواريخ ──
    first_seen = db.Column(db.DateTime, default=_now,  nullable=False)
    last_seen  = db.Column(db.DateTime, default=_now,  nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True, index=True)
    # expires_at=None → لا ينتهي / expires_at في الماضي → منتهي

    is_active  = db.Column(db.Boolean, default=True, nullable=False, index=True)

    # ── مصدر الإضافة ──
    source_id  = db.Column(
        db.Integer,
        db.ForeignKey('ioc_source.id', ondelete='SET NULL'),
        nullable=True,
        index=True
    )

    # ── بيانات MISP (اختياري) ──
    misp_event_id  = db.Column(db.String(100), nullable=True)
    misp_attribute = db.Column(db.String(100), nullable=True)

    # ── raw data من المصدر الأصلي (JSON) ──
    raw_data = db.Column(db.Text, nullable=True)

    created_at = db.Column(db.DateTime, default=_now, nullable=False)
    updated_at = db.Column(db.DateTime, default=_now, onupdate=_now, nullable=False)

    # ── Unique constraint: قيمة + نوع فريد ──
    __table_args__ = (
        db.UniqueConstraint('value', 'ioc_type', name='uq_ioc_value_type'),
        db.Index('idx_ioc_active_severity', 'is_active', 'severity'),
        db.Index('idx_ioc_type_value', 'ioc_type', 'value'),
    )

    @property
    def is_expired(self) -> bool:
        if not self.expires_at:
            return False
        return _now() > self.expires_at

    @property
    def severity_score(self) -> int:
        """تحويل severity لرقم للمقارنة"""
        return {'critical': 100, 'high': 75, 'medium': 50, 'low': 25, 'info': 10}.get(self.severity, 50)

    @property
    def tags_list(self) -> list:
        if not self.tags:
            return []
        return [t.strip() for t in self.tags.split(',') if t.strip()]

    def update_confidence(self):
        """
        إعادة حساب Confidence بناءً على:
        - trust_score المصدر
        - عدد المصادر التي أبلغت (source_count)
        - عمر الـ IoC
        """
        base = self.source.trust_score if self.source else 50
        # كل مصدر إضافي يرفع الثقة بنسبة 10%، حد أقصى 100
        multi_source_bonus = min((self.source_count - 1) * 10, 30)
        # كلما كان قديماً أكثر من 30 يوم، تنخفض الثقة
        age_days = (_now() - self.first_seen).days
        age_penalty = min(age_days // 30 * 5, 20)
        self.confidence = max(0, min(100, base + multi_source_bonus - age_penalty))

    def to_dict(self) -> dict:
        return {
            'id':           self.id,
            'value':        self.value,
            'type':         self.ioc_type,
            'severity':     self.severity,
            'confidence':   self.confidence,
            'threat_type':  self.threat_type,
            'tags':         self.tags_list,
            'description':  self.description,
            'source_count': self.source_count,
            'first_seen':   self.first_seen.isoformat(),
            'last_seen':    self.last_seen.isoformat(),
            'expires_at':   self.expires_at.isoformat() if self.expires_at else None,
            'is_active':    self.is_active,
            'is_expired':   self.is_expired,
            'source_name':  self.source.name if self.source else 'manual',
        }

    def __repr__(self):
        return f'<IoCEntry {self.id} [{self.ioc_type}] {self.value[:50]} sev={self.severity}>'


# ══════════════════════════════════════════════════════════════
#  IOC MATCH LOG — سجل مطابقات البحث
# ══════════════════════════════════════════════════════════════
class IoCMatch(db.Model):
    """
    كل مرة يُطابق فيها محلل (URL/IP/Domain) مؤشر IoC يُسجّل هنا.
    يُستخدم للإحصاءات والتقارير.
    """
    __tablename__ = 'ioc_match'

    id         = db.Column(db.Integer, primary_key=True)
    ioc_id     = db.Column(db.Integer, db.ForeignKey('ioc_entry.id', ondelete='SET NULL'), nullable=True, index=True)
    ioc_value  = db.Column(db.String(512), nullable=False)   # نسخة من القيمة لو حُذف الـ IoC
    ioc_type   = db.Column(db.String(20),  nullable=False)
    severity   = db.Column(db.String(20),  nullable=False)
    context    = db.Column(db.String(50),  nullable=False)   # 'url_analyzer' | 'ip_check' | 'domain_lookup' ...
    target     = db.Column(db.String(512), nullable=True)    # الهدف الذي تم فحصه (الـ URL أو IP)
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True, index=True)
    matched_at = db.Column(db.DateTime, default=_now, nullable=False, index=True)

    ioc   = db.relationship('IoCEntry', foreign_keys=[ioc_id])
    user  = db.relationship('User',     foreign_keys=[user_id])

    def __repr__(self):
        return f'<IoCMatch {self.id} [{self.ioc_type}] {self.ioc_value[:40]} in {self.context}>'


# ══════════════════════════════════════════════════════════════
#  TIP FEED LOG — سجل عمليات جلب المصادر
# ══════════════════════════════════════════════════════════════
class TIPFeedLog(db.Model):
    """
    سجل كل عملية جلب (fetch) لمصدر IoC.
    يُستخدم لمتابعة الأخطاء والإحصاءات.
    """
    __tablename__ = 'tip_feed_log'

    id         = db.Column(db.Integer, primary_key=True)
    source_id  = db.Column(db.Integer, db.ForeignKey('ioc_source.id', ondelete='CASCADE'), nullable=False, index=True)
    started_at = db.Column(db.DateTime, default=_now, nullable=False)
    ended_at   = db.Column(db.DateTime, nullable=True)
    status     = db.Column(db.String(20), default='running', nullable=False)
    # status: 'running' | 'success' | 'partial' | 'failed'

    added_count   = db.Column(db.Integer, default=0)   # IoCs جديدة أُضيفت
    updated_count = db.Column(db.Integer, default=0)   # IoCs موجودة تم تحديثها
    skipped_count = db.Column(db.Integer, default=0)   # IoCs تم تجاهلها (مكررة)
    error_message = db.Column(db.Text, nullable=True)

    source = db.relationship('IoCSource', foreign_keys=[source_id])

    @property
    def duration_seconds(self):
        if self.ended_at:
            return (self.ended_at - self.started_at).total_seconds()
        return None

    def __repr__(self):
        return f'<TIPFeedLog {self.id} src={self.source_id} status={self.status}>'