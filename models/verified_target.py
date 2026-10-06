"""User-specific, exact web-origin DNS proof; never a scanner enable flag."""
from extensions import db

class VerifiedTarget(db.Model):
    __tablename__ = 'verified_target'
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    origin = db.Column(db.String(300), nullable=False)
    hostname = db.Column(db.String(253), nullable=False)
    token = db.Column(db.String(64), nullable=False)
    challenge_expires_at = db.Column(db.Float, nullable=False)
    verified_until = db.Column(db.Float, nullable=True)
    revoked = db.Column(db.Boolean, nullable=False, default=False)
    __table_args__ = (db.UniqueConstraint('user_id', 'origin', name='uq_verified_target_owner_origin'),)
