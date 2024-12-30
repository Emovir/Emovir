from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_migrate import Migrate
from flask_login import LoginManager
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize extensions
db = SQLAlchemy()
mail = Mail()
migrate = Migrate()
login_manager = LoginManager()

def init_extensions(app):
    """Initialize all Flask extensions"""
    try:
        logger.debug("Inicializando extensión Mail...")
        mail.init_app(app)
        logger.info("Extensión Mail inicializada correctamente")

        logger.debug("Inicializando extensión SQLAlchemy...")
        db.init_app(app)
        logger.info("Extensión SQLAlchemy inicializada correctamente")

        logger.debug("Inicializando extensión Flask-Migrate...")
        migrate.init_app(app, db)
        logger.info("Extensión Flask-Migrate inicializada correctamente")

        logger.debug("Inicializando extensión Login Manager...")
        login_manager.init_app(app)
        login_manager.login_view = 'login'
        logger.info("Extensión Login Manager inicializada correctamente")
        
        return True
    except Exception as e:
        logger.error(f"Error during extension initialization: {str(e)}")
        return False
