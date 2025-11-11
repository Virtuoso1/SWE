# server.py
from flask import Flask, jsonify, session, request # type: ignore
from flask_cors import CORS # type: ignore
from flask_session import Session # type: ignore
from flask_wtf.csrf import CSRFProtect
import logging
import os
from pathlib import Path

# Import configuration
from config import get_config

# Import blueprints
from routes.auth import auth_bp
from routes.enterprise_auth import enterprise_auth_bp
from routes.oauth_saml_auth import oauth_saml_bp
from routes.privacy import privacy_bp
from routes.audit import audit_bp
from routes.rate_limit import rate_limit_bp
from routes.database_management import database_bp
from routes.auth_monitoring import monitoring_bp
from routes.user_behavior import behavior_bp
from books.books import books_bp
from routes.users import users_bp
from routes.borrows import borrows_bp
from routes.fines import fines_bp
from routes.dashboard import dashboard_bp

# Import services
from services.jwt_service import JWTService
from services.audit_service import audit_service
from services.rate_limit_service import rate_limit_service
from services.redis_session_service import redis_session_service
from services.database_pool_service import db_pool_service
from services.query_optimization_service import query_optimization_service
from services.auth_monitoring_service import auth_monitoring_service
from services.user_behavior_service import user_behavior_service
from db.enterprise_init import create_enterprise_tables, create_token_blacklist_table

# Import utilities
from utils.cookie_utils import cookie_manager

# Initialize Flask app
app = Flask(__name__)

# Load configuration
config = get_config()
app.config.from_object(config)

# Configure Redis session interface
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis_session_service._redis_client
app.config['SESSION_INTERFACE'] = redis_session_service

# Initialize JWT service
jwt_service = JWTService(app)

# Initialize cookie manager
cookie_manager.init_app(app)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize audit service
audit_service.init_app(app)

# Initialize rate limit service
rate_limit_service.init_app(app)

# Initialize Redis session service
redis_session_service.init_app(app)

# Initialize database pool service
db_pool_service.init_app(app)

# Initialize authentication monitoring service
auth_monitoring_service.init_app(app)

# Initialize user behavior service
user_behavior_service.init_app(app)

# Initialize session (fallback)
sess = Session()
sess.init_app(app)

# Configure CORS
CORS(app,
     origins=config.CORS_ORIGINS,
     supports_credentials=True,
     methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
     allow_headers=['Content-Type', 'Authorization', 'X-CSRF-Token'])

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s',
    handlers=[
        logging.FileHandler(config.LOG_FILE),
        logging.StreamHandler()
    ]
)

# Create session directory if it doesn't exist
session_dir = Path(config.SESSION_FILE_DIR)
session_dir.mkdir(exist_ok=True)

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(enterprise_auth_bp)
app.register_blueprint(oauth_saml_bp)
app.register_blueprint(privacy_bp)
app.register_blueprint(audit_bp)
app.register_blueprint(rate_limit_bp)
app.register_blueprint(database_bp)
app.register_blueprint(monitoring_bp)
app.register_blueprint(behavior_bp)
app.register_blueprint(books_bp)
app.register_blueprint(users_bp)
app.register_blueprint(borrows_bp)
app.register_blueprint(fines_bp)
app.register_blueprint(dashboard_bp)

@app.before_request
def before_request():
    """Execute before each request"""
    # Log request info
    app.logger.info(f"Request: {request.method} {request.path} from {request.remote_addr}")

@app.after_request
def after_request(response):
    """Execute after each request"""
    # Add security headers
    for header, value in config.SECURITY_HEADERS.items():
        response.headers[header] = value
    
    # Log response info
    app.logger.info(f"Response: {response.status_code} for {request.method} {request.path}")
    
    return response

@app.route('/')
def home():
    return jsonify({
        "message": "Library API is running",
        "version": config.API_VERSION,
        "endpoints": {
            "auth": "/auth/login",
            "books": "/books",
            "health": "/health"
        }
    })

@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        # Check database connection
        from db.database import get_connection
        conn = get_connection(silent=True)
        db_status = "connected" if conn else "disconnected"
        if conn:
            conn.close()
            
        return jsonify({
            "status": "healthy",
            "database": db_status,
            "version": config.API_VERSION
        }), 200
    except Exception as e:
        app.logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            "status": "unhealthy",
            "error": str(e),
            "version": config.API_VERSION
        }), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "message": "Endpoint not found",
        "error_code": "NOT_FOUND"
    }), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal server error: {str(error)}")
    return jsonify({
        "success": False,
        "message": "Internal server error",
        "error_code": "INTERNAL_ERROR"
    }), 500

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        "success": False,
        "message": "Method not allowed",
        "error_code": "METHOD_NOT_ALLOWED"
    }), 405

if __name__ == '__main__':
    # Initialize database
    try:
        from db.database import init_db
        init_db()
        app.logger.info("Database initialized successfully")
        
        # Initialize enterprise schema
        from db.enterprise_schema import create_enterprise_tables
        create_enterprise_tables()
        app.logger.info("Enterprise database schema initialized successfully")
        
        # Create JWT token blacklist table
        create_token_blacklist_table()
        app.logger.info("JWT token blacklist table created successfully")
        
    except Exception as e:
        app.logger.error(f"Database initialization failed: {str(e)}")
    
    # Run the application
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=config.DEBUG
    )
