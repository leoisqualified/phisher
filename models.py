# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

db = SQLAlchemy()

class URLLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    url = db.Column(db.String(2048))
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    prediction_score = db.Column(db.Float)
    verdict = db.Column(db.String(32))

class Blacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('company.id'), nullable=False)
    url = db.Column(db.String(2048))
    reason = db.Column(db.String(128))

class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    api_key = db.Column(db.String(64), unique=True, nullable=False)  # For authentication
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
