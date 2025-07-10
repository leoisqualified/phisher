# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone

db = SQLAlchemy()

class URLLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    prediction_score = db.Column(db.Float)
    verdict = db.Column(db.String)

class Blacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String, nullable=False, unique=True)
    reason = db.Column(db.String)
    date_added = db.Column(db.DateTime, default=datetime.now(timezone.utc))
