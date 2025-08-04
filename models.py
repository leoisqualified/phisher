# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

db = SQLAlchemy()

class URLLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2083))
    prediction_score = db.Column(db.Float)
    verdict = db.Column(db.String(32))
    timestamp = db.Column(db.DateTime, default=timezone.utc)

    company_id = db.Column(db.Integer, db.ForeignKey('company.id'))

class Blacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    url = db.Column(db.String(2048))
    reason = db.Column(db.String(128))

class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    api_key = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # One-to-many: a company has many URL logs
    url_logs = db.relationship('URLLog', backref='company', lazy=True)


class AdminUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    email = db.Column(db.String(128), unique=True)
    password_hash = db.Column(db.String(128))
