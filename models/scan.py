# models/scan.py
from datetime import datetime
from extensions import db

class Scan(db.Model):
    __tablename__ = 'scan'
    
    id          = db.Column(db.Integer, primary_key=True)
    url         = db.Column(db.String(500), nullable=False)
    result      = db.Column(db.String(1000))
    raw_report  = db.Column(db.Text)
    verdict     = db.Column(db.String(50))
    status      = db.Column(db.String(20), default='pending')
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)