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
    SESSION_COOKIE_DOMAIN = os.getenv('SESSION_COOKIE_DOMAIN', None)
    SESSION_COOKIE_PATH = os.getenv('SESSION_COOKIE_PATH', '/')
    SESSION_COOKIE_NAME = os.getenv('SESSION_COOKIE_NAME', 'library_session')
    
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
    
    # Database Connection Pool Configuration
    DB_POOL_SIZE = int(os.getenv('DB_POOL_SIZE', '10'))
    DB_POOL_MAX_OVERFLOW = int(os.getenv('DB_POOL_MAX_OVERFLOW', '20'))
    DB_POOL_RECYCLE = int(os.getenv('DB_POOL_RECYCLE', '3600'))  # 1 hour
    DB_POOL_TIMEOUT = int(os.getenv('DB_POOL_TIMEOUT', '30'))
    DB_CONNECTION_TIMEOUT = int(os.getenv('DB_CONNECTION_TIMEOUT', '60'))
    DB_COMMAND_TIMEOUT = int(os.getenv('DB_COMMAND_TIMEOUT', '30'))
    
    # Query Optimization Configuration
    QUERY_CACHE_SIZE = int(os.getenv('QUERY_CACHE_SIZE', '1000'))
    SLOW_QUERY_THRESHOLD = float(os.getenv('SLOW_QUERY_THRESHOLD', '1.0'))  # seconds
    QUERY_OPTIMIZATION_ENABLED = os.getenv('QUERY_OPTIMIZATION_ENABLED', 'true').lower() == 'true'
    
    # Authentication settings
    LOGIN_ATTEMPT_LIMIT = int(os.getenv('LOGIN_ATTEMPT_LIMIT', '5'))
    LOGIN_ATTEMPT_WINDOW = int(os.getenv('LOGIN_ATTEMPT_WINDOW', '15'))  # minutes
    PASSWORD_MIN_LENGTH = int(os.getenv('PASSWORD_MIN_LENGTH', '8'))
    SESSION_MAX_AGE = int(os.getenv('SESSION_MAX_AGE', '3600'))  # seconds
    
    # JWT Configuration
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', os.urandom(32).hex())
    JWT_REFRESH_SECRET_KEY = os.getenv('JWT_REFRESH_SECRET_KEY', os.urandom(32).hex())
    JWT_ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
    JWT_ACCESS_TOKEN_EXPIRES = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', '15'))  # minutes
    JWT_REFRESH_TOKEN_EXPIRES = int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES', '7'))  # days
    JWT_COOKIE_SECURE = os.getenv('FLASK_ENV') == 'production'
    JWT_COOKIE_HTTPONLY = True
    JWT_COOKIE_SAMESITE = 'Lax'
    JWT_COOKIE_DOMAIN = os.getenv('JWT_COOKIE_DOMAIN', None)
    JWT_COOKIE_PATH = os.getenv('JWT_COOKIE_PATH', '/')
    JWT_ACCESS_COOKIE_NAME = os.getenv('JWT_ACCESS_COOKIE_NAME', 'access_token_cookie')
    JWT_REFRESH_COOKIE_NAME = os.getenv('JWT_REFRESH_COOKIE_NAME', 'refresh_token_cookie')
    JWT_CSRF_COOKIE_NAME = os.getenv('JWT_CSRF_COOKIE_NAME', 'csrf_token_cookie')
    JWT_CSRF_IN_COOKIES = True
    JWT_ACCESS_COOKIE_PATH = os.getenv('JWT_ACCESS_COOKIE_PATH', '/')
    JWT_REFRESH_COOKIE_PATH = os.getenv('JWT_REFRESH_COOKIE_PATH', '/')
    JWT_SESSION_COOKIE = True
    
    # MFA Configuration
    MFA_ISSUER = os.getenv('MFA_ISSUER', 'Library Management System')
    MFA_DIGITS = int(os.getenv('MFA_DIGITS', '6'))
    
    # Rate Limiting Configuration
    RATE_LIMIT_LOGIN_ATTEMPTS = int(os.getenv('RATE_LIMIT_LOGIN_ATTEMPTS', '5'))
    RATE_LIMIT_LOGIN_WINDOW = int(os.getenv('RATE_LIMIT_LOGIN_WINDOW', '15'))  # minutes
    RATE_LIMIT_PASSWORD_RESET = int(os.getenv('RATE_LIMIT_PASSWORD_RESET', '3'))
    RATE_LIMIT_PASSWORD_RESET_WINDOW = int(os.getenv('RATE_LIMIT_PASSWORD_RESET_WINDOW', '60'))  # minutes
    RATE_LIMIT_API_REQUESTS = int(os.getenv('RATE_LIMIT_API_REQUESTS', '100'))
    RATE_LIMIT_API_WINDOW = int(os.getenv('RATE_LIMIT_API_WINDOW', '60'))  # minutes
    
    # Advanced Rate Limiting and DDoS Protection
    DDOS_DETECTION_ENABLED = os.getenv('DDOS_DETECTION_ENABLED', 'true').lower() == 'true'
    DDOS_THRESHOLD_MINUTE = int(os.getenv('DDOS_THRESHOLD_MINUTE', '100'))
    DDOS_THRESHOLD_5MIN = int(os.getenv('DDOS_THRESHOLD_5MIN', '500'))
    DDOS_THRESHOLD_HOUR = int(os.getenv('DDOS_THRESHOLD_HOUR', '2000'))
    IP_REPUTATION_ENABLED = os.getenv('IP_REPUTATION_ENABLED', 'true').lower() == 'true'
    IP_REPUTATION_UPDATE_INTERVAL = int(os.getenv('IP_REPUTATION_UPDATE_INTERVAL', '3600'))  # seconds
    ADAPTIVE_RATE_LIMITING = os.getenv('ADAPTIVE_RATE_LIMITING', 'true').lower() == 'true'
    RATE_LIMIT_STORAGE = os.getenv('RATE_LIMIT_STORAGE', 'redis')  # redis, database, memory
    RATE_LIMIT_PENALTY_SCORE = int(os.getenv('RATE_LIMIT_PENALTY_SCORE', '-50'))
    RATE_LIMIT_BONUS_SCORE = int(os.getenv('RATE_LIMIT_BONUS_SCORE', '50'))
    AUTO_IP_BLOCKING = os.getenv('AUTO_IP_BLOCKING', 'true').lower() == 'true'
    AUTO_IP_BLOCK_DURATION = int(os.getenv('AUTO_IP_BLOCK_DURATION', '60'))  # minutes
    GEOIP_BLOCKING_ENABLED = os.getenv('GEOIP_BLOCKING_ENABLED', 'false').lower() == 'true'
    GEOIP_ALLOWED_COUNTRIES = os.getenv('GEOIP_ALLOWED_COUNTRIES', 'US,CA,GB,DE,FR,AU,NZ').split(',')
    
    # Password Policy
    PASSWORD_MIN_LENGTH = int(os.getenv('PASSWORD_MIN_LENGTH', '8'))
    PASSWORD_MAX_LENGTH = int(os.getenv('PASSWORD_MAX_LENGTH', '128'))
    PASSWORD_REQUIRE_UPPERCASE = os.getenv('PASSWORD_REQUIRE_UPPERCASE', 'true').lower() == 'true'
    PASSWORD_REQUIRE_LOWERCASE = os.getenv('PASSWORD_REQUIRE_LOWERCASE', 'true').lower() == 'true'
    PASSWORD_REQUIRE_NUMBERS = os.getenv('PASSWORD_REQUIRE_NUMBERS', 'true').lower() == 'true'
    PASSWORD_REQUIRE_SPECIAL = os.getenv('PASSWORD_REQUIRE_SPECIAL', 'true').lower() == 'true'
    PASSWORD_HISTORY_COUNT = int(os.getenv('PASSWORD_HISTORY_COUNT', '5'))
    
    # Account Lockout Policy
    ACCOUNT_LOCKOUT_THRESHOLD = int(os.getenv('ACCOUNT_LOCKOUT_THRESHOLD', '5'))
    ACCOUNT_LOCKOUT_DURATION = int(os.getenv('ACCOUNT_LOCKOUT_DURATION', '30'))  # minutes
    ACCOUNT_LOCKOUT_PROGRESSIVE = os.getenv('ACCOUNT_LOCKOUT_PROGRESSIVE', 'true').lower() == 'true'
    ACCOUNT_LOCKOUT_MAX_DURATION = int(os.getenv('ACCOUNT_LOCKOUT_MAX_DURATION', '1440'))  # 24 hours
    
    # Device Fingerprinting
    DEVICE_FINGERPRINT_ENABLED = os.getenv('DEVICE_FINGERPRINT_ENABLED', 'true').lower() == 'true'
    DEVICE_TRUST_DURATION = int(os.getenv('DEVICE_TRUST_DURATION', '30'))  # days
    
    # Audit Logging
    AUDIT_LOG_RETENTION_DAYS = int(os.getenv('AUDIT_LOG_RETENTION_DAYS', '365'))
    AUDIT_LOG_ENCRYPTION = os.getenv('AUDIT_LOG_ENCRYPTION', 'true').lower() == 'true'
    AUDIT_ENCRYPTION_KEY = os.getenv('AUDIT_ENCRYPTION_KEY', None)
    AUDIT_ENCRYPTION_SALT = os.getenv('AUDIT_ENCRYPTION_SALT', 'audit_salt_key')
    AUDIT_SIGNING_KEY = os.getenv('AUDIT_SIGNING_KEY', None)
    AUDIT_LOG_LEVEL = os.getenv('AUDIT_LOG_LEVEL', 'INFO')
    AUDIT_MAX_EXPORT_RECORDS = int(os.getenv('AUDIT_MAX_EXPORT_RECORDS', '10000'))
    
    # Redis Configuration (for session storage)
    REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
    REDIS_PORT = int(os.getenv('REDIS_PORT', '6379'))
    REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', '')
    REDIS_DB = int(os.getenv('REDIS_DB', '0'))
    REDIS_SESSION_PREFIX = os.getenv('REDIS_SESSION_PREFIX', 'session:')
    
    # Redis Session Configuration
    SESSION_ENCRYPTION_KEY = os.getenv('SESSION_ENCRYPTION_KEY', None)
    SESSION_ENCRYPTION_SALT = os.getenv('SESSION_ENCRYPTION_SALT', 'session_salt_key')
    SESSION_COMPRESSION_ENABLED = os.getenv('SESSION_COMPRESSION_ENABLED', 'true').lower() == 'true'
    SESSION_COOKIE_NAME = os.getenv('SESSION_COOKIE_NAME', 'session_id')
    SESSION_COOKIE_SECURE = os.getenv('FLASK_ENV') == 'production'
    SESSION_COOKIE_HTTPONLY = os.getenv('SESSION_COOKIE_HTTPONLY', 'true').lower() == 'true'
    SESSION_COOKIE_SAMESITE = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
    SESSION_COOKIE_PATH = os.getenv('SESSION_COOKIE_PATH', '/')
    SESSION_COOKIE_DOMAIN = os.getenv('SESSION_COOKIE_DOMAIN', None)
    SESSION_MAX_AGE = int(os.getenv('SESSION_MAX_AGE', '3600'))  # 1 hour
    SESSION_REDIS_URL = os.getenv('SESSION_REDIS_URL', None)  # Full Redis URL
    SESSION_REDIS_CONNECTION_POOL = os.getenv('SESSION_REDIS_CONNECTION_POOL', 'true').lower() == 'true'
    SESSION_REDIS_MAX_CONNECTIONS = int(os.getenv('SESSION_REDIS_MAX_CONNECTIONS', '50'))
    
    # OAuth/SAML Configuration
    OAUTH_ENABLED = os.getenv('OAUTH_ENABLED', 'false').lower() == 'true'
    SAML_ENABLED = os.getenv('SAML_ENABLED', 'false').lower() == 'true'
    
    # Security Headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
        'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
        'Cross-Origin-Embedder-Policy': 'require-corp',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Resource-Policy': 'same-origin'
    }
    
    # Advanced Cookie Security
    COOKIE_SECURITY = {
        'secure': os.getenv('FLASK_ENV') == 'production',
        'httponly': True,
        'samesite': 'Lax',
        'domain': os.getenv('COOKIE_DOMAIN', None),
        'path': '/',
        'max_age': int(os.getenv('COOKIE_MAX_AGE', '3600')),  # 1 hour
        'expires': None,  # Use max_age instead
        'partitioned': os.getenv('COOKIE_PARTITIONED', 'true').lower() == 'true',  # CHIPS for privacy
        'priority': 'High'  # Cookie priority for browsers that support it
    }
    
    # CSRF Protection
    CSRF_COOKIE_NAME = os.getenv('CSRF_COOKIE_NAME', 'csrf_token')
    CSRF_COOKIE_SECURE = os.getenv('FLASK_ENV') == 'production'
    CSRF_COOKIE_HTTPONLY = False  # JavaScript needs to read this for AJAX requests
    CSRF_COOKIE_SAMESITE = 'Strict'
    CSRF_COOKIE_PATH = '/'
    CSRF_TIME_LIMIT = int(os.getenv('CSRF_TIME_LIMIT', '3600'))  # 1 hour
    CSRF_FIELD_NAME = 'csrf_token'
    CSRF_HEADER_NAME = 'X-CSRFToken'
    
    # Logging configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'app.log')
    
    # API settings
    API_VERSION = os.getenv('API_VERSION', 'v1')
    API_PREFIX = f'/api/{API_VERSION}'
    
    # Additional Security Settings
    COOKIE_SERIALIZER = 'json'  # Use JSON serialization for cookies
    COOKIE_ENCRYPTION = os.getenv('COOKIE_ENCRYPTION', 'true').lower() == 'true'
    COOKIE_SALT = os.getenv('COOKIE_SALT', 'cookie_salt_key')
    COOKIE_SIGNATURE_KEY = os.getenv('COOKIE_SIGNATURE_KEY', os.urandom(32).hex())
    
    # Session Security
    SESSION_MODIFY = True  # Force session to be saved on each request
    SESSION_REFRESH_EACH_REQUEST = True
    SESSION_COOKIE_REFRESH_EACH_REQUEST = True

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    TESTING = False
    
    # Less strict security for development
    SESSION_COOKIE_SECURE = False
    WTF_CSRF_SSL_STRICT = False
    JWT_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False
    COOKIE_SECURITY = {
        'secure': False,
        'httponly': True,
        'samesite': 'Lax',
        'domain': None,
        'path': '/',
        'max_age': 3600,
        'expires': None,
        'partitioned': False,
        'priority': 'High'
    }
    
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
    JWT_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    COOKIE_SECURITY = {
        'secure': True,
        'httponly': True,
        'samesite': 'Strict',
        'domain': os.getenv('COOKIE_DOMAIN', None),
        'path': '/',
        'max_age': 7200,  # 2 hours
        'expires': None,
        'partitioned': True,
        'priority': 'High'
    }
    
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