import logging
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, TextAreaField, BooleanField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, Optional, NumberRange, ValidationError
import re

logging.basicConfig(level=logging.INFO)

def custom_email_validator(form, field):
    """Validador personalizado que solo verifica formato básico de email"""
    email = field.data.lower()
    # Validación básica: contiene @ y al menos un punto después
    if not '@' in email or not '.' in email.split('@')[1]:
        logging.error(f"Email inválido: {email}")
        raise ValidationError('Por favor, ingrese un correo electrónico válido')

    logging.info(f"Email válido: {email}")

class LoginForm(FlaskForm):
    email = StringField('Correo Electrónico', validators=[
        DataRequired(message='El correo electrónico es requerido'),
        custom_email_validator
    ])
    password = PasswordField('Contraseña', validators=[
        DataRequired(message='La contraseña es requerida')
    ])

class RegistrationForm(FlaskForm):
    name = StringField('Nombre', validators=[
        DataRequired(message='El nombre es requerido'),
        Length(min=2, max=100, message='El nombre debe tener entre 2 y 100 caracteres')
    ])
    email = StringField('Correo Electrónico', validators=[
        DataRequired(message='El correo electrónico es requerido'),
        custom_email_validator
    ])
    phone = StringField('Teléfono de Contacto', validators=[
        DataRequired(message='El teléfono es requerido para contactar sobre la verificación')
    ])
    dni = StringField('Documento de Identidad', validators=[
        DataRequired(message='El documento de identidad es requerido')
    ])
    password = PasswordField('Contraseña', validators=[
        DataRequired(message='La contraseña es requerida'),
        Length(min=6, message='La contraseña debe tener al menos 6 caracteres')
    ])
    confirm_password = PasswordField(
        'Confirmar Contraseña',
        validators=[
            DataRequired(message='Por favor, confirme su contraseña'),
            EqualTo('password', message='Las contraseñas deben coincidir')
        ]
    )
    is_visually_impaired = BooleanField('Soy una persona con discapacidad visual')
    disability_document = FileField('Documento acreditativo de discapacidad visual', validators=[
        FileAllowed(['pdf', 'jpg', 'jpeg', 'png'], 'Solo se permiten archivos PDF o imágenes (jpg, jpeg, png)')
    ])

class ContactForm(FlaskForm):
    name = StringField('Nombre', validators=[
        DataRequired(message='El nombre es requerido'),
        Length(min=2, max=100, message='El nombre debe tener entre 2 y 100 caracteres')
    ])
    phone = StringField('Teléfono', validators=[
        DataRequired(message='El número de teléfono es requerido')
    ])
    photo = FileField('Foto del Contacto', validators=[
        FileAllowed(['jpg', 'png', 'jpeg'], 'Solo se permiten imágenes (jpg, png, jpeg)')
    ])
    message = TextAreaField('Texto del Mensaje de Voz')
    voice_file = FileField('Archivo de Voz (MP3)', validators=[
        FileAllowed(['mp3'], 'Solo se permiten archivos MP3')
    ])
    is_emergency_contact = BooleanField('Contacto de Emergencia')
    emergency_priority = IntegerField('Prioridad de Emergencia (1-5)', validators=[
        Optional(),
        NumberRange(min=1, max=5, message='La prioridad debe estar entre 1 y 5')
    ])