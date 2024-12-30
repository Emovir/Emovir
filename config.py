import os
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Config:
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "your-secret-key")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL")
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_recycle": 300,
        "pool_pre_ping": True,
    }

    # Mail configuration - Using Gmail SMTP
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_USERNAME')
    MAIL_MAX_EMAILS = 50  # Limit emails per connection
    MAIL_ASCII_ATTACHMENTS = False  # Support UTF-8 filenames

    @staticmethod
    def init_app(app):
        if not all([
            app.config['MAIL_USERNAME'],
            app.config['MAIL_PASSWORD'],
            app.config['MAIL_SERVER']
        ]):
            logger.warning("Email configuration incomplete. Some features may not work.")
        else:
            logger.info("Email configuration loaded successfully")