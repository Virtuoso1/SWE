# server.py
from flask import Flask, jsonify, session, request # type: ignore
from flask_cors import CORS # type: ignore
from flask_session import Session # type: ignore
import logging
import os
from pathlib import Path

# Import configuration
from config import get_config

# Import blueprints
from routes.auth import auth_bp
from books.books import books_bp
#from routes.users import users_bp
#from routes.borrows import borrows_bp
#from routes.fines import fines_bp
#from routes.dashboard import dashboard_bp

# Initialize Flask app
app = Flask(__name__)

# Load configuration
config = get_config()
app.config.from_object(config)

# Initialize session
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
app.register_blueprint(books_bp)
#app.register_blueprint(users_bp)
#app.register_blueprint(borrows_bp)
#app.register_blueprint(fines_bp)
#app.register_blueprint(dashboard_bp)

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
    except Exception as e:
        app.logger.error(f"Database initialization failed: {str(e)}")
    
    # Run the application
    app.run(
        host='0.0.0.0',
        port=int(os.getenv('PORT', 5000)),
        debug=config.DEBUG
    )
