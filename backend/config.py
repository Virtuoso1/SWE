import os
from dotenv import load_dotenv
from pathlib import Path
import logging

# Load environment variables
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

# Configure logging
logger = logging.getLogger(__name__)

class Config:
    """Application configuration class"""
    
    # Flask Configuration
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here-change-in-production")
    PORT = int(os.getenv("PORT", "5000"))
    
    # Database Configuration
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = int(os.getenv("DB_PORT", "3306"))
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "Noobacious99")
    DB_NAME = os.getenv("DB_NAME", "library_db")
    
    # Security Configuration
    LOGIN_ATTEMPT_LIMIT = int(os.getenv("LOGIN_ATTEMPT_LIMIT", "5"))
    LOGIN_ATTEMPT_WINDOW = int(os.getenv("LOGIN_ATTEMPT_WINDOW", "15"))
    PASSWORD_MIN_LENGTH = int(os.getenv("PASSWORD_MIN_LENGTH", "8"))
    SESSION_MAX_AGE = int(os.getenv("SESSION_MAX_AGE", "3600"))
    
    # CORS Configuration
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
    
    # Logging Configuration
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE = os.getenv("LOG_FILE", "app.log")
    
    # API Configuration
    API_VERSION = os.getenv("API_VERSION", "v1")
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = os.getenv("RATELIMIT_STORAGE_URL", "memory://")
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "200 per day, 50 per hour")
    
    # Session Configuration
    SESSION_FILE_DIR = os.getenv("SESSION_FILE_DIR", "./sessions")
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
    }
    
    @classmethod
    def validate_database_config(cls):
        """Validate database configuration"""
        required_vars = ["DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME"]
        missing_vars = [var for var in required_vars if not getattr(cls, var)]
        
        if missing_vars:
            error_msg = f"Missing required database configuration: {', '.join(missing_vars)}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        logger.info("Database configuration validated successfully")
        return True
    
    @classmethod
    def get_database_uri(cls):
        """Get database URI for connection"""
        return f"mysql://{cls.DB_USER}:{cls.DB_PASSWORD}@{cls.DB_HOST}:{cls.DB_PORT}/{cls.DB_NAME}"

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    
    @classmethod
    def validate_production_config(cls):
        """Validate production-specific configuration"""
        if cls.SECRET_KEY == "your-secret-key-here-change-in-production":
            error_msg = "SECURITY WARNING: Please change the default SECRET_KEY in production"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        if cls.DB_PASSWORD == "yourpassword":
            error_msg = "SECURITY WARNING: Please change the default DB_PASSWORD in production"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        return True

class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = True
    TESTING = True
    DB_NAME = "test_library_db"

# Configuration mapping
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get current configuration based on FLASK_ENV"""
    env = os.getenv("FLASK_ENV", "development")
    return config.get(env, config['default'])