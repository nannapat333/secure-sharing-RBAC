# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy.types import Text
import json


db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(256))
    role = db.Column(db.String(50))  # admin, uploader, viewer, guest
    rsa_public_key = db.Column(db.Text)
    rsa_private_key = db.Column(db.Text)  # Should be encrypted in a real-world app

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    encrypted_keys = db.Column(db.Text)  # NEW: store {user_id: encrypted AES key hex}
    file_path = db.Column(db.String(255))
    shared_with = db.Column(db.Text)  # CSV of user IDs

    def get_encrypted_key_for_user(self, user_id):
        key_map = json.loads(self.encrypted_keys)
        return key_map.get(str(user_id))