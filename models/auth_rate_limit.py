from extensions import db


class AuthRateLimit(db.Model):
    __tablename__ = 'auth_rate_limit'
    key = db.Column(db.String(64), primary_key=True)
    hits = db.Column(db.Integer, nullable=False)
    expires_at = db.Column(db.Float, nullable=False, index=True)
