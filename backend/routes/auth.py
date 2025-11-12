"""
Authentication routes for the Library Management System
Handles HTTP requests and responses for authentication
"""

from flask import Blueprint, request, jsonify, session
from flask_cors import cross_origin
import time
from datetime import datetime
import logging

from services.auth_service import AuthService
from utils.validators import validate_email, validate_password
from utils.security import generate_csrf_token

logger = logging.getLogger(__name__)

# Create blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['POST'])
@cross_origin(supports_credentials=True)
def login():
    """
    Authenticate user and create session
    
    Expected JSON payload:
    {
        "email": "user@example.com",
        "password": "userpassword"
    }
    
    Returns:
        Success: {
            "success": true,
            "message": "Login successful",
            "user": {
                "user_id": 1,
                "full_name": "John Doe",
                "email": "user@example.com",
                "role": "student"
            },
            "csrf_token": "random_csrf_token"
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    start_time = time.time()
    
    try:
        # Get JSON data from request
        data = request.get_json()
        
        # Validate request data
        if not data:
            return jsonify({
                "success": False,
                "message": "Invalid request format. JSON data required.",
                "error_code": "INVALID_REQUEST"
            }), 400
        
        # Extract and validate email
        email = data.get('email', '').strip().lower()
        if not email:
            return jsonify({
                "success": False,
                "message": "Email is required",
                "error_code": "MISSING_EMAIL"
            }), 400
            
        if not validate_email(email):
            return jsonify({
                "success": False,
                "message": "Invalid email format",
                "error_code": "INVALID_EMAIL"
            }), 400
        
        # Extract and validate password
        password = data.get('password', '')
        if not password:
            return jsonify({
                "success": False,
                "message": "Password is required",
                "error_code": "MISSING_PASSWORD"
            }), 400
            
        if not validate_password(password):
            return jsonify({
                "success": False,
                "message": "Password must be at least 8 characters long",
                "error_code": "INVALID_PASSWORD"
            }), 400
        
        # Get client IP for logging
        client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
        user_agent = request.headers.get('User-Agent', 'unknown')
        
        # Check rate limiting
        if not AuthService.check_rate_limit(email):
            logger.warning(f"Rate limit exceeded for email: {email} from IP: {client_ip}")
            return jsonify({
                "success": False,
                "message": "Too many login attempts. Please try again later.",
                "error_code": "RATE_LIMIT_EXCEEDED"
            }), 429
        
        # Authenticate user
        user_data = AuthService.authenticate_user(email, password)
        
        if user_data:
            # Create session
            session.clear()  # Clear any existing session
            session['user_id'] = user_data['user_id']
            session['email'] = user_data['email']
            session['full_name'] = user_data['full_name']
            session['role'] = user_data['role']
            session['authenticated'] = True
            session['login_time'] = datetime.utcnow().isoformat()
            
            # Generate CSRF token for subsequent requests
            csrf_token = generate_csrf_token()
            session['csrf_token'] = csrf_token
            
            # Log successful login
            AuthService.log_login_attempt(
                user_data['user_id'], 
                email, 
                True, 
                client_ip,
                user_agent
            )
            
            # Calculate response time for monitoring
            response_time = time.time() - start_time
            logger.info(f"Login successful for {email} in {response_time:.3f}s")
            
            # Return success response
            return jsonify({
                "success": True,
                "message": "Login successful",
                "user": {
                    "user_id": user_data['user_id'],
                    "full_name": user_data['full_name'],
                    "email": user_data['email'],
                    "role": user_data['role']
                },
                "csrf_token": csrf_token
            }), 200
        else:
            # Log failed login attempt
            AuthService.log_login_attempt(
                None,  # user_id is None for failed attempts
                email, 
                False, 
                client_ip,
                user_agent
            )
            
            # Calculate response time for monitoring
            response_time = time.time() - start_time
            logger.warning(f"Login failed for {email} in {response_time:.3f}s")
            
            # Return error response
            return jsonify({
                "success": False,
                "message": "Invalid email or password",
                "error_code": "INVALID_CREDENTIALS"
            }), 401
            
    except Exception as e:
        logger.error(f"Login endpoint error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An internal server error occurred. Please try again later.",
            "error_code": "INTERNAL_ERROR"
        }), 500

@auth_bp.route('/logout', methods=['POST'])
@cross_origin(supports_credentials=True)
def logout():
    """
    Logout user and clear session
    
    Returns:
        {
            "success": true,
            "message": "Logout successful"
        }
    """
    try:
        # Get user info for logging before clearing session
        user_id = session.get('user_id')
        email = session.get('email', 'unknown')
        
        # Clear session
        session.clear()
        
        logger.info(f"User {email} (ID: {user_id}) logged out")
        
        return jsonify({
            "success": True,
            "message": "Logout successful"
        }), 200
        
    except Exception as e:
        logger.error(f"Logout endpoint error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred during logout",
            "error_code": "LOGOUT_ERROR"
        }), 500

@auth_bp.route('/check', methods=['GET'])
@cross_origin(supports_credentials=True)
def check_auth():
    """
    Check if user is authenticated
    
    Returns:
        Success: {
            "success": true,
            "authenticated": true,
            "user": {
                "user_id": 1,
                "full_name": "John Doe",
                "email": "user@example.com",
                "role": "student"
            }
        }
        
        Not authenticated: {
            "success": true,
            "authenticated": false
        }
    """
    try:
        if session.get('authenticated') and session.get('user_id'):
            return jsonify({
                "success": True,
                "authenticated": True,
                "user": {
                    "user_id": session.get('user_id'),
                    "full_name": session.get('full_name'),
                    "email": session.get('email'),
                    "role": session.get('role')
                }
            }), 200
        else:
            return jsonify({
                "success": True,
                "authenticated": False
            }), 200
            
    except Exception as e:
        logger.error(f"Auth check endpoint error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred while checking authentication",
            "error_code": "AUTH_CHECK_ERROR"
        }), 500

@auth_bp.route('/register', methods=['POST'])
@cross_origin(supports_credentials=True)
def register():
    """
    Register a new user
    
    Expected JSON payload:
    {
        "email": "user@example.com",
        "password": "userpassword",
        "full_name": "John Doe"
    }
    
    Returns:
        Success: {
            "success": true,
            "message": "Registration successful",
            "user": {
                "user_id": 1,
                "full_name": "John Doe",
                "email": "user@example.com",
                "role": "student"
            }
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        # Get JSON data from request
        data = request.get_json()
        
        # Validate request data
        if not data:
            return jsonify({
                "success": False,
                "message": "Invalid request format. JSON data required.",
                "error_code": "INVALID_REQUEST"
            }), 400
        
        # Extract and validate email
        email = data.get('email', '').strip().lower()
        if not email:
            return jsonify({
                "success": False,
                "message": "Email is required",
                "error_code": "MISSING_EMAIL"
            }), 400
            
        if not validate_email(email):
            return jsonify({
                "success": False,
                "message": "Invalid email format",
                "error_code": "INVALID_EMAIL"
            }), 400
        
        # Extract and validate password
        password = data.get('password', '')
        if not password:
            return jsonify({
                "success": False,
                "message": "Password is required",
                "error_code": "MISSING_PASSWORD"
            }), 400
            
        if not validate_password(password):
            return jsonify({
                "success": False,
                "message": "Password must be at least 8 characters long",
                "error_code": "INVALID_PASSWORD"
            }), 400
        
        # Extract full name (optional but recommended)
        full_name = data.get('full_name', '').strip()
        if not full_name:
            full_name = email.split('@')[0]  # Use email prefix as default name
        
        # Register user using AuthService
        user_data = AuthService.register_user(email, password, full_name)
        
        if user_data:
            logger.info(f"New user registered: {email}")
            
            # Return success response
            return jsonify({
                "success": True,
                "message": "Registration successful",
                "user": {
                    "user_id": user_data['user_id'],
                    "full_name": user_data['full_name'],
                    "email": user_data['email'],
                    "role": user_data['role']
                }
            }), 201
        else:
            return jsonify({
                "success": False,
                "message": "Registration failed. User may already exist.",
                "error_code": "REGISTRATION_FAILED"
            }), 400
            
    except Exception as e:
        logger.error(f"Register endpoint error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An internal server error occurred. Please try again later.",
            "error_code": "INTERNAL_ERROR"
        }), 500