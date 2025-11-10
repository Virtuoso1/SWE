import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

class Config:
    """Base configuration class"""
    
    # Basic Flask configuration
    SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(32))
    
    # Session configuration
    SESSION_TYPE = 'filesystem'
    SESSION_FILE_DIR = Path(__file__).resolve().parent / 'sessions'
    SESSION_FILE_THRESHOLD = 500
    SESSION_FILE_MODE = 0o600
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    SESSION_KEY_PREFIX = 'library:'
    PERMANENT_SESSION_LIFETIME = 3600  # 1 hour in seconds
    
    # Security settings
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1 hour
    WTF_CSRF_SSL_STRICT = False  # Set to True in production with HTTPS
    
    # Cookie security
    SESSION_COOKIE_SECURE = os.getenv('FLASK_ENV') == 'production'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # CORS settings
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:3000').split(',')
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = os.getenv('RATELIMIT_STORAGE_URL', 'memory://')
    RATELIMIT_DEFAULT = "200 per day, 50 per hour"
    
    # Database configuration
    DB_HOST = os.getenv('DB_HOST', 'localhost')
    DB_PORT = os.getenv('DB_PORT', '3306')
    DB_USER = os.getenv('DB_USER', 'root')
    DB_PASSWORD = os.getenv('DB_PASSWORD', '')
    DB_NAME = os.getenv('DB_NAME', 'library_db')
    
    # Authentication settings
    LOGIN_ATTEMPT_LIMIT = int(os.getenv('LOGIN_ATTEMPT_LIMIT', '5'))
    LOGIN_ATTEMPT_WINDOW = int(os.getenv('LOGIN_ATTEMPT_WINDOW', '15'))  # minutes
    PASSWORD_MIN_LENGTH = int(os.getenv('PASSWORD_MIN_LENGTH', '8'))
    SESSION_MAX_AGE = int(os.getenv('SESSION_MAX_AGE', '3600'))  # seconds
    
    # Logging configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'app.log')
    
    # API settings
    API_VERSION = os.getenv('API_VERSION', 'v1')
    API_PREFIX = f'/api/{API_VERSION}'
    
    # Security headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'"
    }

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    
    # Less strict security for development
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_SSL_STRICT = False
    
    # Allow more requests in development
    RATELIMIT_DEFAULT = "1000 per day, 100 per hour"

class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    
    # Use in-memory database for testing
    DB_NAME = 'test_library_db'
    
    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False
    
    # Short session lifetime for testing
    PERMANENT_SESSION_LIFETIME = 60  # 1 minute

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    # Strict security for production
    SESSION_COOKIE_SECURE = True
    WTF_CSRF_SSL_STRICT = True
    
    # More restrictive rate limiting
    RATELIMIT_DEFAULT = "100 per day, 20 per hour"
    
    # Longer session lifetime for production
    PERMANENT_SESSION_LIFETIME = 7200  # 2 hours

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get the appropriate configuration based on environment"""
    env = os.getenv('FLASK_ENV', 'default')
    return config.get(env, config['default'])