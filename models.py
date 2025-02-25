from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    # Additional fields to demonstrate in vulnerable profile
    bio = db.Column(db.String(500))
    phone = db.Column(db.String(20))
    address = db.Column(db.String(200))
