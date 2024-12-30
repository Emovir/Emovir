from flask_login import UserMixin
from datetime import datetime
import jwt
from flask import current_app
from extensions import db
from time import time

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    dni = db.Column(db.String(20), nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_visually_impaired = db.Column(db.Boolean, default=False)
    disability_document_path = db.Column(db.String(255), nullable=True)
    disability_verified = db.Column(db.Boolean, default=False)
    disability_verification_date = db.Column(db.DateTime, nullable=True)
    verification_notes = db.Column(db.Text, nullable=True)
    is_subscribed = db.Column(db.Boolean, default=False)
    subscription_end = db.Column(db.DateTime, nullable=True)
    lifetime_access = db.Column(db.Boolean, default=False)  # Nuevo campo para acceso vitalicio
    contacts = db.relationship('Contact', backref='user', lazy=True)

    def get_verification_token(self, expires_in=3600):
        return jwt.encode(
            {'verify_email': self.id, 'exp': time() + expires_in},
            current_app.config['SECRET_KEY'],
            algorithm='HS256'
        )

    @staticmethod
    def verify_token(token):
        try:
            id = jwt.decode(
                token,
                current_app.config['SECRET_KEY'],
                algorithms=['HS256']
            )['verify_email']
        except:
            return None
        return User.query.get(id)

    def is_administrator(self):
        return self.is_admin

    def has_active_subscription(self):
        """Verificar si el usuario tiene una suscripción activa o acceso especial"""
        # Los usuarios con discapacidad visual verificada tienen acceso vitalicio automático
        if self.is_visually_impaired and self.disability_verified:
            return True

        # También permitir acceso si tiene acceso vitalicio explícito o una suscripción activa
        return self.lifetime_access or \
               (self.is_subscribed and self.subscription_end and self.subscription_end > datetime.utcnow())

class Contact(db.Model):
    __tablename__ = 'contacts'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=True)
    photo_path = db.Column(db.String(255), nullable=True)
    voice_path = db.Column(db.String(255), nullable=True)
    is_generated_voice = db.Column(db.Boolean, default=True)
    is_emergency_contact = db.Column(db.Boolean, default=False)
    emergency_priority = db.Column(db.Integer, default=0)