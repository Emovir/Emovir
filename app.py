import os
from flask import Flask, jsonify, render_template, redirect, url_for, request, flash
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.utils import secure_filename
import logging
from extensions import db, mail, migrate, login_manager, init_extensions, logger
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from functools import wraps
from datetime import datetime, timedelta
from payments import create_subscription, execute_payment, check_subscription_status

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_administrator():
            flash('Acceso denegado. Se requieren privilegios de administrador.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def create_app():
    app = Flask(__name__)

    # Database configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }

    # Email configuration for Gmail
    app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')

    # Secret key for session management
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default-secret-key")

    # Initialize extensions
    with app.app_context():
        if not init_extensions(app):
            raise Exception("Failed to initialize extensions")

        # Import models and create tables
        from models import User, Contact
        db.create_all()
        logger.info("Database tables created successfully")

    # User loader callback
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Log configuration
    logger.debug("Configuración del servidor de correo:")
    logger.debug(f"Mail Server: {app.config['MAIL_SERVER']}")
    logger.debug(f"Mail Port: {app.config['MAIL_PORT']}")
    logger.debug(f"Mail Username configurado: {'Sí' if app.config['MAIL_USERNAME'] else 'No'}")
    logger.debug(f"Mail Password configurado: {'Sí' if app.config['MAIL_PASSWORD'] else 'No'}")

    def verify_access():
        """Decorator para verificar si el usuario tiene acceso (pago o discapacidad verificada)"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                if not current_user.is_authenticated:
                    return redirect(url_for('login'))

                if current_user.is_admin:
                    return f(*args, **kwargs)

                if not (current_user.has_active_subscription() or
                       (current_user.is_visually_impaired and current_user.disability_verified)):
                    flash('Por favor, complete su registro o suscripción para acceder.', 'warning')
                    return redirect(url_for('subscription'))

                return f(*args, **kwargs)
            return decorated_function
        return decorator

    # Authentication routes
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('index'))

        from forms import LoginForm
        form = LoginForm()
        if form.validate_on_submit():
            logger.debug(f"Intento de login para email: {form.email.data}")
            user = User.query.filter_by(email=form.email.data.lower()).first()

            if user:
                logger.debug(f"Usuario encontrado con ID: {user.id}")
                logger.debug(f"Hash almacenado: {user.password_hash}")

                if check_password_hash(user.password_hash, form.password.data):
                    login_user(user)
                    logger.info(f"Login exitoso para usuario: {user.email}")
                    flash('Has iniciado sesión correctamente.', 'success')
                    return redirect(url_for('index'))
                else:
                    logger.warning(f"Contraseña incorrecta para usuario: {user.email}")
            else:
                logger.warning(f"Usuario no encontrado para email: {form.email.data}")

            flash('Email o contraseña incorrectos.', 'error')

        return render_template('auth/login.html', form=form)

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if current_user.is_authenticated:
            return redirect(url_for('index'))

        from forms import RegistrationForm
        form = RegistrationForm()
        if form.validate_on_submit():
            logger.debug(f"Intento de registro para email: {form.email.data}")

            # Verificar si el usuario ya existe
            if User.query.filter_by(email=form.email.data.lower()).first():
                flash('Este correo electrónico ya está registrado.', 'error')
                return render_template('auth/register.html', form=form)

            # Generar hash de contraseña usando el método predeterminado
            password_hash = generate_password_hash(form.password.data)
            logger.debug(f"Hash generado para nuevo usuario: {password_hash}")

            # Crear nuevo usuario
            user = User(
                name=form.name.data,
                email=form.email.data.lower(),
                phone=form.phone.data,
                dni=form.dni.data,
                password_hash=password_hash,
                is_visually_impaired=form.is_visually_impaired.data
            )

            if form.disability_document.data:
                filename = secure_filename(form.disability_document.data.filename)
                form.disability_document.data.save(os.path.join(app.root_path, 'static', 'uploads', filename))
                user.disability_document_path = f'uploads/{filename}'

            try:
                db.session.add(user)
                db.session.commit()
                logger.info(f"Usuario registrado exitosamente: {user.email}")
                flash('Registro exitoso. Por favor inicia sesión.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error al registrar usuario: {str(e)}")
                flash('Error al registrar el usuario. Por favor, intenta nuevamente.', 'error')

        return render_template('auth/register.html', form=form)

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        flash('Has cerrado sesión correctamente.', 'info')
        return redirect(url_for('index'))

    @app.route('/verification-pending')
    def verification_pending():
        return render_template('auth/verification_pending.html')

    # Main routes
    @app.route('/')
    def index():
        """Main page route."""
        logger.info("Accessing main page")
        try:
            if current_user.is_authenticated and not (
                current_user.has_active_subscription() or
                (current_user.is_visually_impaired and current_user.disability_verified) or
                current_user.is_admin
            ):
                flash('Por favor, complete su registro o suscripción para acceder.', 'warning')
                return redirect(url_for('subscription'))
            return render_template('home.html')
        except Exception as e:
            logger.error(f"Error rendering home template: {str(e)}")
            return render_template('errors/500.html'), 500

    # Test routes
    @app.route('/test')
    def test():
        """Basic test route to verify server functionality."""
        logger.info("Test route accessed")
        return jsonify({"status": "success", "message": "Server is running"})

    @app.route('/test-email')
    def test_email():
        """Test email functionality."""
        try:
            from mailer import test_email_configuration
            logger.info("Starting email test")
            success, message = test_email_configuration()

            if success:
                return jsonify({"status": "success", "message": message})
            else:
                return jsonify({"status": "error", "message": message}), 500
        except Exception as e:
            logger.error(f"Error in test_email route: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500

    @app.route('/update-admin', methods=['GET', 'POST', 'PUT'])
    def update_admin():
        """Actualizar o crear usuario administrador."""
        try:
            email = request.form.get('email', os.environ.get('MAIL_USERNAME'))
            password = request.form.get('password', 'admin2024$')

            user = User.query.filter_by(email=email).first()

            if user:
                # Actualizar usuario existente
                user.password_hash = generate_password_hash(password)
                user.is_admin = True
                user.email_verified = True
                db.session.commit()
                logger.info(f"Usuario administrador actualizado: {email}")
                return jsonify({
                    "status": "success",
                    "message": f"Usuario {email} actualizado como administrador."
                })
            else:
                # Crear nuevo usuario administrador
                new_admin = User(
                    email=email,
                    name="Administrador del Sistema",
                    password_hash=generate_password_hash(password),
                    is_admin=True,
                    email_verified=True,
                    phone="+34600000000"  # Número de teléfono de contacto del sistema
                )
                db.session.add(new_admin)
                db.session.commit()
                logger.info(f"Nuevo usuario administrador creado: {email}")
                return jsonify({
                    "status": "success",
                    "message": f"Administrador {email} creado exitosamente."
                })
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error al actualizar administrador: {str(e)}")
            return jsonify({
                "status": "error",
                "message": f"Error al actualizar administrador: {str(e)}"
            }), 500

    # Contacts routes
    @app.route('/contacts')
    @login_required
    @verify_access()
    def contacts():
        """Lista de contactos del usuario."""
        user_contacts = Contact.query.filter_by(user_id=current_user.id).all()
        return render_template('contacts/list.html', contacts=user_contacts)

    @app.route('/contacts/add', methods=['GET', 'POST'])
    @login_required
    @verify_access()
    def add_contact():
        """Añadir nuevo contacto."""
        from forms import ContactForm
        form = ContactForm()
        if form.validate_on_submit():
            contact = Contact(
                user_id=current_user.id,
                name=form.name.data,
                phone=form.phone.data,
                message=form.message.data,
                is_emergency_contact=form.is_emergency_contact.data,
                emergency_priority=form.emergency_priority.data if form.is_emergency_contact.data else 0
            )

            if form.photo.data:
                filename = secure_filename(form.photo.data.filename)
                form.photo.data.save(os.path.join(app.root_path, 'static', 'uploads', filename))
                contact.photo_path = f'uploads/{filename}'

            if form.voice_file.data:
                filename = secure_filename(form.voice_file.data.filename)
                form.voice_file.data.save(os.path.join(app.root_path, 'static', 'uploads', filename))
                contact.voice_path = f'uploads/{filename}'

            db.session.add(contact)
            db.session.commit()
            flash('Contacto añadido exitosamente.', 'success')
            return redirect(url_for('contacts'))

        return render_template('contacts/add.html', form=form)

    @app.route('/contacts/delete/<int:contact_id>', methods=['POST'])
    @login_required
    @verify_access()
    def delete_contact(contact_id):
        """Eliminar un contacto existente."""
        try:
            contact = Contact.query.filter_by(id=contact_id, user_id=current_user.id).first()

            if not contact:
                flash('Contacto no encontrado.', 'error')
                return redirect(url_for('contacts'))

            # Eliminar archivos asociados si existen
            if contact.photo_path:
                photo_path = os.path.join(app.root_path, 'static', contact.photo_path)
                if os.path.exists(photo_path):
                    os.remove(photo_path)

            if contact.voice_path:
                voice_path = os.path.join(app.root_path, 'static', contact.voice_path)
                if os.path.exists(voice_path):
                    os.remove(voice_path)

            db.session.delete(contact)
            db.session.commit()
            flash('Contacto eliminado exitosamente.', 'success')

        except Exception as e:
            db.session.rollback()
            logger.error(f"Error al eliminar contacto: {str(e)}")
            flash('Error al eliminar el contacto.', 'error')

        return redirect(url_for('contacts'))

    @app.route('/emergency_contacts')
    @login_required
    @verify_access()
    def emergency_contacts():
        """Obtener lista de contactos de emergencia ordenados por prioridad."""
        try:
            emergency_contacts = Contact.query.filter_by(
                user_id=current_user.id,
                is_emergency_contact=True
            ).order_by(Contact.emergency_priority.asc()).all()

            contacts_data = [{
                'name': contact.name,
                'phone': contact.phone,
                'priority': contact.emergency_priority
            } for contact in emergency_contacts]

            logger.info(f"Contactos de emergencia recuperados: {len(contacts_data)}")
            return jsonify(contacts_data)
        except Exception as e:
            logger.error(f"Error al obtener contactos de emergencia: {str(e)}")
            return jsonify({"error": "Error al obtener contactos de emergencia"}), 500


    @app.route('/admin')
    @login_required
    @admin_required
    def admin_dashboard():
        """Panel de administración principal."""
        users_with_visual_impairment = User.query.filter_by(is_visually_impaired=True).all()
        regular_users = User.query.filter_by(is_visually_impaired=False).all()
        return render_template('admin/dashboard.html',
                             users_with_visual_impairment=users_with_visual_impairment,
                             regular_users=regular_users)

    @app.route('/admin/verify/<int:user_id>', methods=['POST'])
    @login_required
    @admin_required
    def admin_verify_disability(user_id):
        """Verificar documento de discapacidad visual y otorgar acceso vitalicio."""
        user = User.query.get_or_404(user_id)
        user.disability_verified = True
        user.disability_verification_date = datetime.utcnow()
        user.lifetime_access = True  # Otorgar acceso vitalicio automáticamente
        user.is_subscribed = True    # Marcar como suscrito
        user.subscription_end = None  # Sin fecha de finalización para acceso vitalicio
        db.session.commit()

        # Enviar notificación por correo
        from mailer import send_disability_verification_notification
        send_disability_verification_notification(user, True)

        flash(f'Documento de discapacidad visual verificado para {user.name}. Acceso vitalicio otorgado.', 'success')
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/note/<int:user_id>', methods=['POST'])
    @login_required
    @admin_required
    def admin_add_verification_note(user_id):
        """Añadir nota de verificación."""
        user = User.query.get_or_404(user_id)
        note = request.form.get('note')
        if note:
            user.verification_notes = note
            db.session.commit()
            flash('Nota añadida correctamente', 'success')
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
    @login_required
    @admin_required
    def admin_delete_user(user_id):
        """Eliminar usuario."""
        if current_user.id == user_id:
            flash('No puedes eliminar tu propia cuenta de administrador', 'error')
            return redirect(url_for('admin_dashboard'))

        user = User.query.get_or_404(user_id)
        if user.is_admin:
            flash('No se pueden eliminar otros administradores', 'error')
            return redirect(url_for('admin_dashboard'))

        try:
            db.session.delete(user)
            db.session.commit()
            flash(f'Usuario {user.name} eliminado correctamente', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error al eliminar usuario: {str(e)}', 'error')

        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/user/<int:user_id>/subscription', methods=['POST'])
    @login_required
    @admin_required
    def admin_manage_subscription(user_id):
        """Gestionar suscripción de usuario."""
        user = User.query.get_or_404(user_id)
        action = request.form.get('action')

        if action == 'activate':
            user.is_subscribed = True
            user.subscription_end = datetime.utcnow() + timedelta(days=30)
            message = f'Suscripción activada para {user.name}'
        elif action == 'deactivate':
            user.is_subscribed = False
            user.subscription_end = None
            message = f'Suscripción desactivada para {user.name}'

        db.session.commit()

        # Enviar notificación por correo
        from mailer import send_subscription_status_email
        send_subscription_status_email(user, user.is_subscribed)

        flash(message, 'success')
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/user/<int:user_id>/edit', methods=['POST'])
    @login_required
    @admin_required
    def admin_edit_user(user_id):
        """Editar información de usuario."""
        user = User.query.get_or_404(user_id)

        # Actualizar campos básicos
        user.name = request.form.get('name', user.name)
        user.is_visually_impaired = 'is_visually_impaired' in request.form

        if user.is_visually_impaired:
            user.disability_verified = 'disability_verified' in request.form
        else:
            user.is_subscribed = 'is_subscribed' in request.form
            if user.is_subscribed and not user.subscription_end:
                user.subscription_end = datetime.utcnow() + timedelta(days=30)
            elif not user.is_subscribed:
                user.subscription_end = None

        try:
            db.session.commit()
            flash('Usuario actualizado correctamente', 'success')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error al actualizar usuario: {str(e)}")
            flash('Error al actualizar usuario', 'error')

        return redirect(url_for('admin_dashboard'))

    # New routes for payments and disability document processing

    @app.route('/subscription')
    @login_required
    def subscription():
        """Página de suscripción y estado."""
        return render_template('payments/subscription.html',
                             paypal_client_id=os.environ.get('PAYPAL_CLIENT_ID'))

    @app.route('/confirm-payment', methods=['POST'])
    @login_required
    def confirm_payment():
        """Confirmar pago de PayPal y activar suscripción."""
        try:
            data = request.get_json()
            payment_id = data.get('orderID')
            payer_id = data.get('details', {}).get('payer', {}).get('payer_id')

            if not payment_id or not payer_id:
                logger.error("Datos de pago incompletos")
                return jsonify({"success": False, "message": "Datos de pago incompletos"}), 400

            if execute_payment(payment_id, payer_id, current_user):
                flash('¡Suscripción activada exitosamente!', 'success')
                return jsonify({"success": True})
            else:
                logger.error("Error al ejecutar el pago")
                return jsonify({"success": False, "message": "Error al procesar el pago"}), 500

        except Exception as e:
            logger.error(f"Error en confirm_payment: {str(e)}")
            return jsonify({"success": False, "message": str(e)}), 500

    @app.route('/upload-disability-document', methods=['POST'])
    @login_required
    def upload_disability_document():
        """Subir documento de discapacidad visual."""
        if 'disability_document' not in request.files:
            flash('No se ha seleccionado ningún archivo', 'error')
            return redirect(url_for('subscription'))

        file = request.files['disability_document']
        if file.filename == '':
            flash('No se ha seleccionado ningún archivo', 'error')
            return redirect(url_for('subscription'))

        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.root_path, 'static', 'uploads', 'documents', filename))

            current_user.disability_document_path = f'uploads/documents/{filename}'
            current_user.is_visually_impaired = True
            current_user.disability_verified = False  # Requiere verificación del admin
            db.session.commit()

            # Enviar notificación por correo al administrador
            try:
                from mailer import send_disability_document_notification
                admin_users = User.query.filter_by(is_admin=True).all()
                for admin in admin_users:
                    send_disability_document_notification(admin, current_user)
            except Exception as e:
                logger.error(f"Error al enviar notificación: {str(e)}")

            flash('Documento subido exitosamente. Será revisado por nuestro equipo.', 'success')

        return redirect(url_for('subscription'))

    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        logger.warning(f"404 Error: {request.url}")
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        logger.error(f"500 Error: {error}")
        return render_template('errors/500.html'), 500

    return app

# Create the application instance
app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

@app.route('/admin/user/<int:user_id>/lifetime-access', methods=['POST'])
@login_required
@admin_required
def admin_toggle_lifetime_access(user_id):
    """Activar o desactivar acceso vitalicio para un usuario."""
    try:
        from models import User
        user = User.query.get_or_404(user_id)
        action = request.form.get('action')

        if action == 'activate':
            user.lifetime_access = True
            user.is_subscribed = True
            user.subscription_end = None  # No necesita fecha de fin para acceso vitalicio
            message = f'Acceso vitalicio activado para {user.name}'
        elif action == 'deactivate':
            user.lifetime_access = False
            user.is_subscribed = False
            user.subscription_end = None
            message = f'Acceso vitalicio desactivado para {user.name}'

        db.session.commit()
        flash(message, 'success')

        # Enviar notificación por correo
        from mailer import send_subscription_status_email
        send_subscription_status_email(user, user.lifetime_access)

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error al gestionar acceso vitalicio: {str(e)}")
        flash('Error al modificar el acceso vitalicio', 'error')

    return redirect(url_for('admin_dashboard'))