from datetime import datetime, timedelta
import os
import paypalrestsdk
from flask import url_for
from extensions import db, logger
from models import User

# Configuración de PayPal con mejor manejo de errores
def configure_paypal():
    try:
        client_id = os.environ.get("PAYPAL_CLIENT_ID")
        client_secret = os.environ.get("PAYPAL_CLIENT_SECRET")

        if not client_id or not client_secret:
            logger.error("Credenciales de PayPal no encontradas en las variables de entorno")
            return False

        paypalrestsdk.configure({
            "mode": "sandbox",  # Cambiar a "live" en producción
            "client_id": client_id,
            "client_secret": client_secret
        })
        return True
    except Exception as e:
        logger.error(f"Error al configurar PayPal: {str(e)}")
        return False

def create_subscription(user):
    """Crear una suscripción mensual de 1€ para un usuario."""
    try:
        if not configure_paypal():
            logger.error("No se pudo configurar PayPal")
            return None

        payment = paypalrestsdk.Payment({
            "intent": "sale",
            "payer": {
                "payment_method": "paypal"
            },
            "redirect_urls": {
                "return_url": url_for('confirm_subscription', user_id=user.id, _external=True),
                "cancel_url": url_for('cancel_subscription', _external=True)
            },
            "transactions": [{
                "item_list": {
                    "items": [{
                        "name": "Suscripción Mensual - Gestor de Contactos",
                        "sku": "CONTACT-SUB-1",
                        "price": "1.00",
                        "currency": "EUR",
                        "quantity": 1
                    }]
                },
                "amount": {
                    "currency": "EUR",
                    "total": "1.00"
                },
                "description": "Suscripción mensual al Gestor de Contactos"
            }]
        })

        if payment.create():
            logger.info(f"Pago creado exitosamente para el usuario {user.email}")
            return payment
        else:
            logger.error(f"Error al crear el pago: {payment.error}")
            return None
    except Exception as e:
        logger.error(f"Error en PayPal: {str(e)}")
        return None

def execute_payment(payment_id, payer_id, user):
    """Ejecutar el pago y activar la suscripción del usuario."""
    try:
        if not configure_paypal():
            logger.error("No se pudo configurar PayPal para ejecutar el pago")
            return False

        payment = paypalrestsdk.Payment.find(payment_id)
        if payment.execute({"payer_id": payer_id}):
            # Actualizar estado de suscripción del usuario
            user.is_subscribed = True
            user.subscription_end = datetime.utcnow() + timedelta(days=30)
            db.session.commit()
            logger.info(f"Pago ejecutado exitosamente para el usuario {user.email}")
            return True
        logger.error(f"Error al ejecutar el pago: {payment.error}")
        return False
    except Exception as e:
        logger.error(f"Error al ejecutar el pago: {str(e)}")
        return False

def check_subscription_status(user):
    """Verificar si la suscripción del usuario está activa."""
    try:
        if user.is_visually_impaired and user.disability_verified:
            logger.info(f"Usuario {user.email} tiene acceso gratuito por discapacidad visual verificada")
            return True
        if user.is_admin:
            logger.info(f"Usuario {user.email} tiene acceso por ser administrador")
            return True

        is_active = user.is_subscribed and user.subscription_end > datetime.utcnow()
        logger.info(f"Estado de suscripción para {user.email}: {is_active}")
        return is_active
    except Exception as e:
        logger.error(f"Error al verificar suscripción para {user.email}: {str(e)}")
        # Si hay error, permitimos acceso si es admin o tiene discapacidad verificada
        return user.is_admin or (user.is_visually_impaired and user.disability_verified)

def cancel_user_subscription(user):
    """Cancelar la suscripción de un usuario."""
    try:
        if not user.is_visually_impaired:
            user.is_subscribed = False
            user.subscription_end = None
            db.session.commit()
            logger.info(f"Suscripción cancelada para el usuario {user.email}")
            return True
        logger.warning(f"Intento de cancelar suscripción de usuario con discapacidad visual: {user.email}")
        return False
    except Exception as e:
        logger.error(f"Error al cancelar suscripción para {user.email}: {str(e)}")
        return False