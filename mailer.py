from flask import current_app, render_template
from flask_mail import Message
import logging
import ssl

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def test_email_configuration():
    """
    Prueba la configuración del servidor de correo.
    Retorna (bool, str) indicando éxito y mensaje de estado.
    """
    try:
        from app import mail  # Import here to avoid circular import

        # Verificar que las credenciales estén configuradas
        if not current_app.config['MAIL_USERNAME'] or not current_app.config['MAIL_PASSWORD']:
            logger.error("Credenciales de correo no configuradas")
            return False, "Credenciales de correo no configuradas"

        logger.debug(f"Configuración de correo:")
        logger.debug(f"Servidor SMTP: {current_app.config['MAIL_SERVER']}")
        logger.debug(f"Puerto: {current_app.config['MAIL_PORT']}")
        logger.debug(f"Usuario: {current_app.config['MAIL_USERNAME']}")
        logger.debug(f"TLS habilitado: {current_app.config['MAIL_USE_TLS']}")

        # Intentar enviar un correo de prueba
        msg = Message(
            "Prueba de Configuración - Gestor de Contactos",
            sender=current_app.config['MAIL_USERNAME'],
            recipients=[current_app.config['MAIL_USERNAME']]  # Enviar al mismo correo como prueba
        )
        msg.html = render_template('email/test_email.html')
        mail.send(msg)
        logger.info("Configuración de correo probada exitosamente")
        return True, "Configuración de correo correcta"
    except ssl.SSLError as e:
        logger.error(f"Error SSL al conectar con Gmail: {str(e)}")
        return False, f"Error de conexión segura con Gmail: {str(e)}"
    except Exception as e:
        logger.error(f"Error al probar la configuración de correo: {str(e)}")
        return False, f"Error al probar la configuración: {str(e)}"

def send_verification_email(user):
    """Envía un correo electrónico de verificación al usuario."""
    from app import mail
    try:
        token = user.get_verification_token()
        msg = Message(
            'Verificación de Cuenta - Gestor de Contactos',
            sender=current_app.config['MAIL_USERNAME'],
            recipients=[user.email]
        )
        msg.html = render_template('email/verify_email.html', 
                                user=user,
                                token=token)

        logger.info(f"Enviando correo de verificación a {user.email}")
        mail.send(msg)
        logger.info(f"Correo de verificación enviado exitosamente a {user.email}")
        return True
    except Exception as e:
        logger.error(f"Error al enviar correo de verificación a {user.email}: {str(e)}")
        return False

def send_disability_verification_notification(user, is_approved):
    """Envía notificación sobre el estado de verificación de discapacidad visual."""
    try:
        from app import mail
        status = "aprobada" if is_approved else "rechazada"
        msg = Message(
            f'Verificación de Discapacidad Visual {status.capitalize()}',
            sender=current_app.config['MAIL_USERNAME'],
            recipients=[user.email]
        )

        msg.html = render_template(
            'email/disability_verification.html',
            user=user,
            is_approved=is_approved
        )

        logger.info(f"Enviando notificación de verificación de discapacidad a {user.email}")
        mail.send(msg)
        logger.info(f"Notificación de verificación enviada exitosamente a {user.email}")
        return True
    except Exception as e:
        logger.error(f"Error al enviar notificación de verificación a {user.email}: {str(e)}")
        return False

def send_subscription_status_email(user, is_active):
    """Envía notificación sobre el estado de la suscripción."""
    try:
        from app import mail
        status = "activada" if is_active else "cancelada"
        msg = Message(
            f'Estado de Suscripción - {status.capitalize()}',
            sender=current_app.config['MAIL_USERNAME'],
            recipients=[user.email]
        )

        msg.html = render_template(
            'email/subscription_status.html',
            user=user,
            is_active=is_active
        )

        logger.info(f"Enviando notificación de suscripción a {user.email}")
        mail.send(msg)
        logger.info(f"Notificación de suscripción enviada exitosamente a {user.email}")
        return True
    except Exception as e:
        logger.error(f"Error al enviar notificación de suscripción a {user.email}: {str(e)}")
        return False

from flask import render_template