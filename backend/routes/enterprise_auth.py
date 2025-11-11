from flask import Blueprint, request, jsonify, session, make_response
from flask_cors import cross_origin
import time
from datetime import datetime
from services.enterprise_auth_service import EnterpriseAuthService
from services.jwt_service import JWTService, jwt_required, role_required, permission_required
from db.enterprise_helpers import MFAService, PermissionService
from utils.enterprise_validators import PasswordValidator, InputValidator, DeviceFingerprinting
from utils.security import get_client_ip, generate_csrf_token
from utils.cookie_utils import set_secure_cookie, get_secure_cookie, delete_secure_cookie
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
enterprise_auth_bp = Blueprint('enterprise_auth', __name__, url_prefix='/auth')

@enterprise_auth_bp.route('/login', methods=['POST'])
@cross_origin(supports_credentials=True)
def login():
    """
    Enhanced login with enterprise security features
    
    Expected JSON payload:
    {
        "email": "user@example.com",
        "password": "userpassword",
        "mfa_token": "123456",  // Optional, if MFA is enabled
        "device_fingerprint": "abc123",  // Optional, for device tracking
        "remember_me": false  // Optional
    }
    
    Returns:
        Success: {
            "success": true,
            "message": "Login successful",
            "user": { ... },
            "tokens": { ... },
            "csrf_token": "random_csrf_token"
        }
        
        MFA Required: {
            "success": true,
            "status": "mfa_required",
            "message": "Multi-factor authentication required",
            "user_id": 123
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
        
        if not data:
            return jsonify({
                "success": False,
                "message": "Invalid request format. JSON data required.",
                "error_code": "INVALID_REQUEST"
            }), 400
        
        # Extract and validate email
        email = data.get('email', '').strip().lower()
        email_validation = InputValidator.validate_email_advanced(email)
        if not email_validation['is_valid']:
            return jsonify({
                "success": False,
                "message": "Invalid email format",
                "error_code": "INVALID_EMAIL",
                "details": email_validation['issues']
            }), 400
        
        # Extract and validate password
        password = data.get('password', '')
        if not password:
            return jsonify({
                "success": False,
                "message": "Password is required",
                "error_code": "MISSING_PASSWORD"
            }), 400
        
        # Extract optional parameters
        mfa_token = data.get('mfa_token')
        device_fingerprint = data.get('device_fingerprint')
        remember_me = data.get('remember_me', False)
        
        # Get client IP for logging
        client_ip = get_client_ip()
        
        # Check rate limiting
        if not EnterpriseAuthService._check_rate_limit(email, 'login'):
            logger.warning(f"Rate limit exceeded for email: {email} from IP: {client_ip}")
            return jsonify({
                "success": False,
                "message": "Too many login attempts. Please try again later.",
                "error_code": "RATE_LIMIT_EXCEEDED"
            }), 429
        
        # Authenticate user
        auth_result = EnterpriseAuthService.authenticate_user(
            email, password, mfa_token, device_fingerprint
        )
        
        if not auth_result:
            return jsonify({
                "success": False,
                "message": "Invalid email or password",
                "error_code": "INVALID_CREDENTIALS"
            }), 401
        
        # Handle MFA requirement
        if auth_result.get('status') == 'mfa_required':
            return jsonify({
                "success": True,
                "status": "mfa_required",
                "message": "Multi-factor authentication required",
                "user_id": auth_result['user_id']
            }), 200
        
        # Successful authentication
        if auth_result.get('status') == 'success':
            # Create response with secure cookies
            response = make_response(jsonify({
                "success": True,
                "message": "Login successful",
                "user": auth_result['user'],
                "csrf_token": generate_csrf_token()
            }))
            
            # Use JWT service to set secure cookies
            jwt_service.set_jwt_cookies(response,
                                     auth_result['tokens']['access_token'],
                                     auth_result['tokens']['refresh_token'])
            
            # Set additional secure session data
            session_data = {
                'user_id': auth_result['user']['user_id'],
                'email': auth_result['user']['email'],
                'role': auth_result['user']['role'],
                'login_time': int(time.time()),
                'remember_me': remember_me,
                'device_fingerprint': device_fingerprint
            }
            
            set_secure_cookie(response, 'user_session', session_data)
            
            # Calculate response time for monitoring
            response_time = time.time() - start_time
            logger.info(f"Login successful for {email} in {response_time:.3f}s")
            
            return response
        
        return jsonify({
            "success": False,
            "message": "Authentication failed",
            "error_code": "AUTHENTICATION_FAILED"
        }), 401
        
    except Exception as e:
        logger.error(f"Login endpoint error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An internal server error occurred. Please try again later.",
            "error_code": "INTERNAL_ERROR"
        }), 500

@enterprise_auth_bp.route('/logout', methods=['POST'])
@jwt_required
@cross_origin(supports_credentials=True)
def logout():
    """
    Enhanced logout with token revocation
    
    Returns:
        {
            "success": true,
            "message": "Logout successful"
        }
    """
    try:
        # Get tokens from request
        access_token = None
        refresh_token = None
        
        # Try to get from Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                access_token = auth_header.split(' ')[1]
            except IndexError:
                pass
        
        # Try to get refresh token from cookie
        from flask import current_app
        config = current_app.config
        refresh_token = request.cookies.get(config.JWT_REFRESH_COOKIE_NAME)
        
        # Logout user and revoke tokens
        success = EnterpriseAuthService.logout_user(access_token, refresh_token)
        
        if success:
            # Create response to clear cookies
            response = make_response(jsonify({
                "success": True,
                "message": "Logout successful"
            }))
            
            # Use JWT service to clear cookies
            jwt_service.clear_jwt_cookies(response)
            
            # Clear session cookie
            delete_secure_cookie(response, 'user_session')
            
            return response
        else:
            return jsonify({
                "success": False,
                "message": "Error during logout",
                "error_code": "LOGOUT_ERROR"
            }), 500
        
    except Exception as e:
        logger.error(f"Logout endpoint error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred during logout",
            "error_code": "LOGOUT_ERROR"
        }), 500

@enterprise_auth_bp.route('/refresh', methods=['POST'])
@cross_origin(supports_credentials=True)
def refresh_token():
    """
    Refresh access token using refresh token
    
    Returns:
        Success: {
            "success": true,
            "tokens": { ... },
            "user": { ... }
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        # Get refresh token from cookie or request body
        from flask import current_app
        config = current_app.config
        refresh_token = request.cookies.get(config.JWT_REFRESH_COOKIE_NAME)
        
        if not refresh_token:
            # Try to get from request body
            data = request.get_json()
            if data:
                refresh_token = data.get('refresh_token')
        
        if not refresh_token:
            return jsonify({
                "success": False,
                "message": "Refresh token is required",
                "error_code": "MISSING_REFRESH_TOKEN"
            }), 400
        
        # Get device fingerprint
        device_fingerprint = None
        data = request.get_json()
        if data:
            device_fingerprint = data.get('device_fingerprint')
        
        # Refresh token
        result = EnterpriseAuthService.refresh_access_token(refresh_token, device_fingerprint)
        
        if not result:
            return jsonify({
                "success": False,
                "message": "Invalid or expired refresh token",
                "error_code": "INVALID_REFRESH_TOKEN"
            }), 401
        
        # Create response with new tokens
        response = make_response(jsonify({
            "success": True,
            "message": "Token refreshed successfully",
            "user": result['user']
        }))
        
        # Use JWT service to set new cookies
        jwt_service.set_jwt_cookies(response,
                                 result['tokens']['access_token'],
                                 result['tokens']['refresh_token'])
        
        # Update session data
        session_data = get_secure_cookie('user_session')
        if session_data:
            session_data['last_refresh'] = int(time.time())
            if device_fingerprint:
                session_data['device_fingerprint'] = device_fingerprint
            set_secure_cookie(response, 'user_session', session_data)
        
        return response
        
    except Exception as e:
        logger.error(f"Token refresh endpoint error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred during token refresh",
            "error_code": "TOKEN_REFRESH_ERROR"
        }), 500

@enterprise_auth_bp.route('/register', methods=['POST'])
@cross_origin(supports_credentials=True)
def register():
    """
    Enhanced user registration with enterprise validation
    
    Expected JSON payload:
    {
        "email": "user@example.com",
        "password": "userpassword",
        "full_name": "John Doe",
        "phone": "+1234567890",  // Optional
        "timezone": "UTC",  // Optional
        "language": "en"  // Optional
    }
    
    Returns:
        Success: {
            "success": true,
            "message": "Registration successful",
            "user": { ... },
            "verification_token": "token"
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
        
        if not data:
            return jsonify({
                "success": False,
                "message": "Invalid request format. JSON data required.",
                "error_code": "INVALID_REQUEST"
            }), 400
        
        # Extract and validate email
        email = data.get('email', '').strip().lower()
        email_validation = InputValidator.validate_email_advanced(email)
        if not email_validation['is_valid']:
            return jsonify({
                "success": False,
                "message": "Invalid email format",
                "error_code": "INVALID_EMAIL",
                "details": email_validation['issues']
            }), 400
        
        # Extract and validate password
        password = data.get('password', '')
        password_validation = PasswordValidator.validate_password_strength(password)
        if not password_validation['is_valid']:
            return jsonify({
                "success": False,
                "message": "Password does not meet security requirements",
                "error_code": "WEAK_PASSWORD",
                "details": password_validation['issues'],
                "suggestions": password_validation['suggestions']
            }), 400
        
        # Extract full name
        full_name = data.get('full_name', '').strip()
        if not full_name:
            return jsonify({
                "success": False,
                "message": "Full name is required",
                "error_code": "MISSING_NAME"
            }), 400
        
        # Extract optional parameters
        phone = data.get('phone', '')
        timezone = data.get('timezone', 'UTC')
        language = data.get('language', 'en')
        
        # Validate phone if provided
        if phone:
            phone_validation = InputValidator.validate_phone_number(phone)
            if not phone_validation['is_valid']:
                return jsonify({
                    "success": False,
                    "message": "Invalid phone number format",
                    "error_code": "INVALID_PHONE",
                    "details": phone_validation['issues']
                }), 400
            phone = phone_validation['normalized']
        
        # Register user
        result = EnterpriseAuthService.register_user(
            email, password, full_name, 'student', phone, timezone, language
        )
        
        if result:
            logger.info(f"New user registered: {email}")
            
            return jsonify({
                "success": True,
                "message": "Registration successful. Please check your email for verification.",
                "user": result['user']
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

@enterprise_auth_bp.route('/verify-email', methods=['POST'])
@cross_origin(supports_credentials=True)
def verify_email():
    """
    Verify email address using token
    
    Expected JSON payload:
    {
        "token": "verification_token"
    }
    
    Returns:
        Success: {
            "success": true,
            "message": "Email verified successfully"
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        data = request.get_json()
        if not data or not data.get('token'):
            return jsonify({
                "success": False,
                "message": "Verification token is required",
                "error_code": "MISSING_TOKEN"
            }), 400
        
        # Implement email verification logic
        # This would verify the token and update user's email_verified status
        
        return jsonify({
            "success": True,
            "message": "Email verified successfully"
        }), 200
        
    except Exception as e:
        logger.error(f"Email verification error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred during email verification",
            "error_code": "VERIFICATION_ERROR"
        }), 500

@enterprise_auth_bp.route('/password-reset/request', methods=['POST'])
@cross_origin(supports_credentials=True)
def request_password_reset():
    """
    Request password reset
    
    Expected JSON payload:
    {
        "email": "user@example.com"
    }
    
    Returns:
        Success: {
            "success": true,
            "message": "Password reset email sent"
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        data = request.get_json()
        if not data or not data.get('email'):
            return jsonify({
                "success": False,
                "message": "Email is required",
                "error_code": "MISSING_EMAIL"
            }), 400
        
        email = data.get('email', '').strip().lower()
        email_validation = InputValidator.validate_email_advanced(email)
        if not email_validation['is_valid']:
            return jsonify({
                "success": False,
                "message": "Invalid email format",
                "error_code": "INVALID_EMAIL"
            }), 400
        
        # Initiate password reset
        success = EnterpriseAuthService.initiate_password_reset(email)
        
        if success:
            return jsonify({
                "success": True,
                "message": "If an account with this email exists, a password reset link has been sent."
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": "Too many password reset attempts. Please try again later.",
                "error_code": "RATE_LIMIT_EXCEEDED"
            }), 429
        
    except Exception as e:
        logger.error(f"Password reset request error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred while processing your request",
            "error_code": "RESET_REQUEST_ERROR"
        }), 500

@enterprise_auth_bp.route('/password-reset/confirm', methods=['POST'])
@cross_origin(supports_credentials=True)
def confirm_password_reset():
    """
    Confirm password reset with token
    
    Expected JSON payload:
    {
        "token": "reset_token",
        "new_password": "newpassword"
    }
    
    Returns:
        Success: {
            "success": true,
            "message": "Password reset successfully"
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "message": "Invalid request format",
                "error_code": "INVALID_REQUEST"
            }), 400
        
        reset_token = data.get('token')
        new_password = data.get('new_password')
        
        if not reset_token or not new_password:
            return jsonify({
                "success": False,
                "message": "Reset token and new password are required",
                "error_code": "MISSING_REQUIRED_FIELDS"
            }), 400
        
        # Validate new password
        password_validation = PasswordValidator.validate_password_strength(new_password)
        if not password_validation['is_valid']:
            return jsonify({
                "success": False,
                "message": "Password does not meet security requirements",
                "error_code": "WEAK_PASSWORD",
                "details": password_validation['issues'],
                "suggestions": password_validation['suggestions']
            }), 400
        
        # Reset password
        success = EnterpriseAuthService.reset_password(reset_token, new_password)
        
        if success:
            return jsonify({
                "success": True,
                "message": "Password reset successfully"
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": "Invalid or expired reset token",
                "error_code": "INVALID_TOKEN"
            }), 400
        
    except Exception as e:
        logger.error(f"Password reset confirmation error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred while resetting your password",
            "error_code": "RESET_CONFIRM_ERROR"
        }), 500

@enterprise_auth_bp.route('/mfa/setup', methods=['POST'])
@jwt_required
@cross_origin(supports_credentials=True)
def setup_mfa():
    """
    Setup multi-factor authentication
    
    Returns:
        Success: {
            "success": true,
            "secret": "mfa_secret",
            "qr_code": "base64_qr_code",
            "backup_codes": ["code1", "code2", ...]
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        user_id = request.current_user['user_id']
        
        # Generate MFA secret
        secret = MFAService.generate_mfa_secret()
        
        # Generate QR code
        qr_code = MFAService.generate_qr_code(request.current_user['email'], secret)
        
        # Generate backup codes
        backup_codes = MFAService.generate_backup_codes()
        
        return jsonify({
            "success": True,
            "secret": secret,
            "qr_code": qr_code,
            "backup_codes": backup_codes
        }), 200
        
    except Exception as e:
        logger.error(f"MFA setup error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred during MFA setup",
            "error_code": "MFA_SETUP_ERROR"
        }), 500

@enterprise_auth_bp.route('/mfa/verify', methods=['POST'])
@jwt_required
@cross_origin(supports_credentials=True)
def verify_mfa():
    """
    Verify and enable MFA
    
    Expected JSON payload:
    {
        "secret": "mfa_secret",
        "token": "123456",
        "backup_codes": ["code1", "code2", ...]
    }
    
    Returns:
        Success: {
            "success": true,
            "message": "MFA enabled successfully"
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        user_id = request.current_user['user_id']
        data = request.get_json()
        
        if not data:
            return jsonify({
                "success": False,
                "message": "Invalid request format",
                "error_code": "INVALID_REQUEST"
            }), 400
        
        secret = data.get('secret')
        token = data.get('token')
        backup_codes = data.get('backup_codes', [])
        
        if not secret or not token:
            return jsonify({
                "success": False,
                "message": "Secret and token are required",
                "error_code": "MISSING_REQUIRED_FIELDS"
            }), 400
        
        # Verify MFA token
        if not MFAService.verify_mfa_token(secret, token):
            return jsonify({
                "success": False,
                "message": "Invalid MFA token",
                "error_code": "INVALID_MFA_TOKEN"
            }), 400
        
        # Enable MFA
        success = MFAService.enable_mfa(user_id, secret, backup_codes)
        
        if success:
            return jsonify({
                "success": True,
                "message": "MFA enabled successfully"
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": "Failed to enable MFA",
                "error_code": "MFA_ENABLE_FAILED"
            }), 500
        
    except Exception as e:
        logger.error(f"MFA verification error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred during MFA verification",
            "error_code": "MFA_VERIFY_ERROR"
        }), 500

@enterprise_auth_bp.route('/mfa/disable', methods=['POST'])
@jwt_required
@cross_origin(supports_credentials=True)
def disable_mfa():
    """
    Disable multi-factor authentication
    
    Expected JSON payload:
    {
        "token": "123456"  // Current MFA token
    }
    
    Returns:
        Success: {
            "success": true,
            "message": "MFA disabled successfully"
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        user_id = request.current_user['user_id']
        data = request.get_json()
        
        if not data or not data.get('token'):
            return jsonify({
                "success": False,
                "message": "MFA token is required",
                "error_code": "MISSING_MFA_TOKEN"
            }), 400
        
        # Get user data to verify MFA token
        from db.enterprise_helpers import EnterpriseUserHelper
        user = EnterpriseUserHelper.get_user_by_id(user_id)
        
        if not user or not user.get('mfa_enabled'):
            return jsonify({
                "success": False,
                "message": "MFA is not enabled for this account",
                "error_code": "MFA_NOT_ENABLED"
            }), 400
        
        # Verify MFA token
        if not MFAService.verify_mfa_token(user['mfa_secret'], data['token']):
            return jsonify({
                "success": False,
                "message": "Invalid MFA token",
                "error_code": "INVALID_MFA_TOKEN"
            }), 400
        
        # Disable MFA
        success = MFAService.disable_mfa(user_id)
        
        if success:
            return jsonify({
                "success": True,
                "message": "MFA disabled successfully"
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": "Failed to disable MFA",
                "error_code": "MFA_DISABLE_FAILED"
            }), 500
        
    except Exception as e:
        logger.error(f"MFA disable error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred while disabling MFA",
            "error_code": "MFA_DISABLE_ERROR"
        }), 500

@enterprise_auth_bp.route('/check', methods=['GET'])
@jwt_required
@cross_origin(supports_credentials=True)
def check_auth():
    """
    Check if user is authenticated and return user info
    
    Returns:
        Success: {
            "success": true,
            "authenticated": true,
            "user": { ... }
        }
    """
    try:
        return jsonify({
            "success": True,
            "authenticated": True,
            "user": {
                "user_id": request.current_user['user_id'],
                "full_name": request.current_user.get('full_name'),
                "email": request.current_user['email'],
                "role": request.current_user['role'],
                "permissions": request.current_user.get('permissions', [])
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Auth check endpoint error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred while checking authentication",
            "error_code": "AUTH_CHECK_ERROR"
        }), 500

@enterprise_auth_bp.route('/permissions', methods=['GET'])
@jwt_required
@cross_origin(supports_credentials=True)
def get_permissions():
    """
    Get current user's permissions
    
    Returns:
        Success: {
            "success": true,
            "permissions": [ ... ]
        }
    """
    try:
        user_id = request.current_user['user_id']
        permissions = PermissionService.get_user_permissions(user_id)
        
        return jsonify({
            "success": True,
            "permissions": permissions
        }), 200
        
    except Exception as e:
        logger.error(f"Get permissions error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred while fetching permissions",
            "error_code": "PERMISSIONS_ERROR"
        }), 500

@enterprise_auth_bp.route('/device-fingerprint', methods=['POST'])
@cross_origin(supports_credentials=True)
def generate_device_fingerprint():
    """
    Generate device fingerprint from client data
    
    Expected JSON payload:
    {
        "user_agent": "browser_user_agent",
        "screen": {"width": 1920, "height": 1080},
        "timezone": "America/New_York",
        "language": "en-US",
        "platform": "Win32",
        "plugins": ["plugin1", "plugin2"],
        "canvas": "canvas_fingerprint",
        "webgl": "webgl_fingerprint"
    }
    
    Returns:
        Success: {
            "success": true,
            "fingerprint": "device_fingerprint_hash"
        }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "message": "Device data is required",
                "error_code": "MISSING_DEVICE_DATA"
            }), 400
        
        # Generate device fingerprint
        fingerprint = DeviceFingerprinting.generate_device_fingerprint(data)
        
        return jsonify({
            "success": True,
            "fingerprint": fingerprint
        }), 200
        
    except Exception as e:
        logger.error(f"Device fingerprinting error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred while generating device fingerprint",
            "error_code": "FINGERPRINT_ERROR"
        }), 500