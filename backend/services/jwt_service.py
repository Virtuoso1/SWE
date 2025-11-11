import jwt
import secrets
import time
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from functools import wraps
from flask import request, jsonify, current_app, make_response
from db.database import get_connection
import logging

logger = logging.getLogger(__name__)

class JWTService:
    """Service for handling JWT tokens with refresh token rotation"""
    
    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize JWT service with Flask app"""
        self.app = app
        app.jwt_service = self
    
    @staticmethod
    def generate_tokens(user_id: int, email: str, role: str, 
                       device_fingerprint: str = None) -> Tuple[str, str, datetime]:
        """
        Generate access and refresh tokens
        
        Args:
            user_id: User ID
            email: User email
            role: User role
            device_fingerprint: Device fingerprint for tracking
            
        Returns:
            Tuple of (access_token, refresh_token, expires_at)
        """
        app = current_app or JWTService._get_app()
        
        # Access token payload (short-lived)
        access_payload = {
            'user_id': user_id,
            'email': email,
            'role': role,
            'type': 'access',
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(minutes=app.config['JWT_ACCESS_TOKEN_EXPIRES']),
            'jti': secrets.token_urlsafe(16)  # JWT ID for token tracking
        }
        
        # Refresh token payload (longer-lived)
        refresh_payload = {
            'user_id': user_id,
            'type': 'refresh',
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(days=app.config['JWT_REFRESH_TOKEN_EXPIRES']),
            'jti': secrets.token_urlsafe(16)
        }
        
        # Generate tokens
        access_token = jwt.encode(
            access_payload,
            app.config['JWT_SECRET_KEY'],
            algorithm=app.config['JWT_ALGORITHM']
        )
        
        refresh_token = jwt.encode(
            refresh_payload,
            app.config['JWT_REFRESH_SECRET_KEY'],
            algorithm=app.config['JWT_ALGORITHM']
        )
        
        # Store refresh token in database
        JWTService._store_refresh_token(
            user_id, refresh_token, device_fingerprint, 
            access_payload['exp'], refresh_payload['exp']
        )
        
        return access_token, refresh_token, access_payload['exp']
    
    def set_jwt_cookies(self, response, access_token: str, refresh_token: str) -> None:
        """
        Set JWT tokens in secure HttpOnly cookies
        
        Args:
            response: Flask response object
            access_token: JWT access token
            refresh_token: JWT refresh token
        """
        app = current_app or self._get_app()
        
        # Set access token cookie
        response.set_cookie(
            app.config['JWT_ACCESS_COOKIE_NAME'],
            access_token,
            max_age=app.config['JWT_ACCESS_TOKEN_EXPIRES'] * 60,  # Convert minutes to seconds
            secure=app.config['JWT_COOKIE_SECURE'],
            httponly=app.config['JWT_COOKIE_HTTPONLY'],
            samesite=app.config['JWT_COOKIE_SAMESITE'],
            path=app.config.get('JWT_ACCESS_COOKIE_PATH', '/'),
            domain=app.config.get('JWT_COOKIE_DOMAIN')
        )
        
        # Set refresh token cookie
        response.set_cookie(
            app.config['JWT_REFRESH_COOKIE_NAME'],
            refresh_token,
            max_age=app.config['JWT_REFRESH_TOKEN_EXPIRES'] * 86400,  # Convert days to seconds
            secure=app.config['JWT_COOKIE_SECURE'],
            httponly=app.config['JWT_COOKIE_HTTPONLY'],
            samesite=app.config['JWT_COOKIE_SAMESITE'],
            path=app.config.get('JWT_REFRESH_COOKIE_PATH', '/'),
            domain=app.config.get('JWT_COOKIE_DOMAIN')
        )
        
        # Set CSRF token cookie if enabled
        if app.config.get('JWT_CSRF_IN_COOKIES', True):
            import secrets
            csrf_token = secrets.token_urlsafe(32)
            response.set_cookie(
                app.config.get('JWT_CSRF_COOKIE_NAME', 'csrf_token_cookie'),
                csrf_token,
                max_age=app.config['JWT_ACCESS_TOKEN_EXPIRES'] * 60,
                secure=app.config['JWT_COOKIE_SECURE'],
                httponly=False,  # JavaScript needs to read this for AJAX requests
                samesite='Strict',
                path=app.config.get('JWT_ACCESS_COOKIE_PATH', '/'),
                domain=app.config.get('JWT_COOKIE_DOMAIN')
            )
    
    def get_jwt_from_cookies(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Get JWT tokens from cookies
        
        Returns:
            Tuple of (access_token, refresh_token)
        """
        app = current_app or self._get_app()
        
        access_token = request.cookies.get(app.config['JWT_ACCESS_COOKIE_NAME'])
        refresh_token = request.cookies.get(app.config['JWT_REFRESH_COOKIE_NAME'])
        
        return access_token, refresh_token
    
    def clear_jwt_cookies(self, response) -> None:
        """
        Clear JWT cookies
        
        Args:
            response: Flask response object
        """
        app = current_app or self._get_app()
        
        # Clear access token cookie
        response.set_cookie(
            app.config['JWT_ACCESS_COOKIE_NAME'],
            '',
            expires=0,
            path=app.config.get('JWT_ACCESS_COOKIE_PATH', '/'),
            domain=app.config.get('JWT_COOKIE_DOMAIN')
        )
        
        # Clear refresh token cookie
        response.set_cookie(
            app.config['JWT_REFRESH_COOKIE_NAME'],
            '',
            expires=0,
            path=app.config.get('JWT_REFRESH_COOKIE_PATH', '/'),
            domain=app.config.get('JWT_COOKIE_DOMAIN')
        )
        
        # Clear CSRF token cookie
        if app.config.get('JWT_CSRF_IN_COOKIES', True):
            response.set_cookie(
                app.config.get('JWT_CSRF_COOKIE_NAME', 'csrf_token_cookie'),
                '',
                expires=0,
                path=app.config.get('JWT_ACCESS_COOKIE_PATH', '/'),
                domain=app.config.get('JWT_COOKIE_DOMAIN')
            )
    
    def rotate_jwt_cookies(self, response, device_fingerprint: str = None) -> bool:
        """
        Rotate JWT tokens in cookies
        
        Args:
            response: Flask response object
            device_fingerprint: Device fingerprint for tracking
            
        Returns:
            True if successful, False otherwise
        """
        access_token, refresh_token = self.get_jwt_from_cookies()
        
        if not refresh_token:
            return False
        
        # Generate new tokens
        new_tokens = self.refresh_access_token(refresh_token, device_fingerprint)
        if not new_tokens:
            return False
        
        new_access_token, new_refresh_token, _ = new_tokens
        
        # Set new cookies
        self.set_jwt_cookies(response, new_access_token, new_refresh_token)
        
        return True
    
    @staticmethod
    def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode access token
        
        Args:
            token: JWT access token
            
        Returns:
            Dict containing token payload if valid, None otherwise
        """
        app = current_app or JWTService._get_app()
        
        try:
            payload = jwt.decode(
                token,
                app.config['JWT_SECRET_KEY'],
                algorithms=[app.config['JWT_ALGORITHM']]
            )
            
            # Verify token type
            if payload.get('type') != 'access':
                logger.warning("Invalid token type provided")
                return None
                
            # Check if token is blacklisted
            if JWTService._is_token_blacklisted(payload.get('jti')):
                logger.warning("Blacklisted token used")
                return None
                
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Access token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid access token: {str(e)}")
            return None
    
    @staticmethod
    def verify_refresh_token(token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode refresh token
        
        Args:
            token: JWT refresh token
            
        Returns:
            Dict containing token payload if valid, None otherwise
        """
        app = current_app or JWTService._get_app()
        
        try:
            payload = jwt.decode(
                token,
                app.config['JWT_REFRESH_SECRET_KEY'],
                algorithms=[app.config['JWT_ALGORITHM']]
            )
            
            # Verify token type
            if payload.get('type') != 'refresh':
                logger.warning("Invalid token type provided")
                return None
                
            # Check if token exists in database and is active
            if not JWTService._is_refresh_token_valid(payload.get('jti'), payload.get('user_id')):
                logger.warning("Invalid or revoked refresh token")
                return None
                
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Refresh token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid refresh token: {str(e)}")
            return None
    
    @staticmethod
    def refresh_access_token(refresh_token: str, device_fingerprint: str = None) -> Optional[Tuple[str, str, datetime]]:
        """
        Generate new access token using refresh token (with rotation)
        
        Args:
            refresh_token: Valid refresh token
            device_fingerprint: Device fingerprint for tracking
            
        Returns:
            Tuple of (new_access_token, new_refresh_token, expires_at) or None
        """
        # Verify refresh token
        payload = JWTService.verify_refresh_token(refresh_token)
        if not payload:
            return None
        
        user_id = payload['user_id']
        
        # Get user information
        user_data = JWTService._get_user_data(user_id)
        if not user_data:
            logger.error(f"User {user_id} not found during token refresh")
            return None
        
        # Revoke old refresh token
        JWTService._revoke_refresh_token(payload.get('jti'))
        
        # Generate new tokens
        return JWTService.generate_tokens(
            user_id, user_data['email'], user_data['role'], device_fingerprint
        )
    
    @staticmethod
    def revoke_token(jti: str, token_type: str = 'access') -> bool:
        """
        Revoke a token by adding it to blacklist
        
        Args:
            jti: JWT ID
            token_type: Type of token ('access' or 'refresh')
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            if token_type == 'refresh':
                # Mark refresh token as revoked
                cursor.execute("""
                    UPDATE user_sessions 
                    SET is_active = FALSE 
                    WHERE refresh_token_hash = %s
                """, (hashlib.sha256(jti.encode()).hexdigest(),))
            else:
                # Add access token to blacklist
                cursor.execute("""
                    INSERT INTO token_blacklist (jti, expires_at, created_at)
                    VALUES (%s, DATE_ADD(NOW(), INTERVAL 1 HOUR), NOW())
                    ON DUPLICATE KEY UPDATE expires_at = DATE_ADD(NOW(), INTERVAL 1 HOUR)
                """, (jti,))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error revoking token: {str(e)}")
            return False
    
    @staticmethod
    def revoke_all_user_tokens(user_id: int) -> bool:
        """
        Revoke all tokens for a user
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Deactivate all user sessions
            cursor.execute("""
                UPDATE user_sessions 
                SET is_active = FALSE 
                WHERE user_id = %s
            """, (user_id,))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"All tokens revoked for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error revoking all user tokens: {str(e)}")
            return False
    
    @staticmethod
    def _store_refresh_token(user_id: int, refresh_token: str, 
                            device_fingerprint: str, access_expires: datetime, 
                            refresh_expires: datetime) -> bool:
        """Store refresh token in database"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Parse refresh token to get JTI
            payload = jwt.decode(
                refresh_token,
                current_app.config['JWT_REFRESH_SECRET_KEY'],
                algorithms=[current_app.config['JWT_ALGORITHM']]
            )
            
            session_id = secrets.token_urlsafe(64)
            token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
            
            # Store session information
            cursor.execute("""
                INSERT INTO user_sessions (
                    session_id, user_id, ip_address, user_agent, 
                    device_fingerprint, is_active, created_at, 
                    last_activity, expires_at, refresh_token_hash
                ) VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW(), %s, %s)
            """, (
                session_id, user_id, 
                request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR')),
                request.headers.get('User-Agent', ''),
                device_fingerprint, True, refresh_expires, token_hash
            ))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error storing refresh token: {str(e)}")
            return False
    
    @staticmethod
    def _is_refresh_token_valid(jti: str, user_id: int) -> bool:
        """Check if refresh token is valid and active"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Check if token exists and is active
            cursor.execute("""
                SELECT COUNT(*) FROM user_sessions 
                WHERE user_id = %s AND is_active = TRUE AND expires_at > NOW()
            """, (user_id,))
            
            count = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            
            return count > 0
            
        except Exception as e:
            logger.error(f"Error checking refresh token validity: {str(e)}")
            return False
    
    @staticmethod
    def _revoke_refresh_token(jti: str) -> bool:
        """Revoke a specific refresh token"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Deactivate the session
            cursor.execute("""
                UPDATE user_sessions 
                SET is_active = FALSE 
                WHERE refresh_token_hash = %s
            """, (hashlib.sha256(jti.encode()).hexdigest(),))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error revoking refresh token: {str(e)}")
            return False
    
    @staticmethod
    def _is_token_blacklisted(jti: str) -> bool:
        """Check if token is blacklisted"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Check if token is in blacklist
            cursor.execute("""
                SELECT COUNT(*) FROM token_blacklist 
                WHERE jti = %s AND expires_at > NOW()
            """, (jti,))
            
            count = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            
            return count > 0
            
        except Exception as e:
            logger.error(f"Error checking token blacklist: {str(e)}")
            return False
    
    @staticmethod
    def _get_user_data(user_id: int) -> Optional[Dict[str, Any]]:
        """Get user data from database"""
        try:
            from db.helpers import get_user_by_id
            
            user = get_user_by_id(user_id)
            if user:
                return {
                    'user_id': user['user_id'],
                    'email': user['email'],
                    'role': user['role'],
                    'status': user['status']
                }
            return None
            
        except Exception as e:
            logger.error(f"Error getting user data: {str(e)}")
            return None
    
    @staticmethod
    def _get_app():
        """Get Flask app instance"""
        from flask import current_app
        return current_app

# Decorator for protecting routes with JWT
def jwt_required(f):
    """Decorator to require JWT authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Try to get token from Authorization header first
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({
                    'success': False,
                    'message': 'Invalid authorization header format',
                    'error_code': 'INVALID_AUTH_HEADER'
                }), 401
        
        # If no token in header, try to get from cookies
        if not token:
            app = current_app or JWTService._get_app()
            token = request.cookies.get(app.config['JWT_ACCESS_COOKIE_NAME'])
        
        if not token:
            return jsonify({
                'success': False,
                'message': 'Access token is required',
                'error_code': 'MISSING_TOKEN'
            }), 401
        
        # Verify token
        payload = JWTService.verify_access_token(token)
        if not payload:
            return jsonify({
                'success': False,
                'message': 'Invalid or expired access token',
                'error_code': 'INVALID_TOKEN'
            }), 401
        
        # Add user info to request context
        request.current_user = payload
        return f(*args, **kwargs)
    
    return decorated_function


# Decorator for protecting routes with JWT and CSRF protection
def jwt_required_with_csrf(f):
    """Decorator to require JWT authentication with CSRF protection"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Try to get token from Authorization header first
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({
                    'success': False,
                    'message': 'Invalid authorization header format',
                    'error_code': 'INVALID_AUTH_HEADER'
                }), 401
        
        # If no token in header, try to get from cookies
        if not token:
            app = current_app or JWTService._get_app()
            token = request.cookies.get(app.config['JWT_ACCESS_COOKIE_NAME'])
            
            # For cookie-based auth, verify CSRF token
            if token and app.config.get('JWT_CSRF_IN_COOKIES', True):
                csrf_token_cookie = request.cookies.get(app.config.get('JWT_CSRF_COOKIE_NAME', 'csrf_token_cookie'))
                csrf_token_header = request.headers.get(app.config.get('CSRF_HEADER_NAME', 'X-CSRFToken'))
                
                if not csrf_token_cookie or not csrf_token_header:
                    return jsonify({
                        'success': False,
                        'message': 'CSRF token required',
                        'error_code': 'MISSING_CSRF_TOKEN'
                    }), 401
                
                if csrf_token_cookie != csrf_token_header:
                    return jsonify({
                        'success': False,
                        'message': 'Invalid CSRF token',
                        'error_code': 'INVALID_CSRF_TOKEN'
                    }), 401
        
        if not token:
            return jsonify({
                'success': False,
                'message': 'Access token is required',
                'error_code': 'MISSING_TOKEN'
            }), 401
        
        # Verify token
        payload = JWTService.verify_access_token(token)
        if not payload:
            return jsonify({
                'success': False,
                'message': 'Invalid or expired access token',
                'error_code': 'INVALID_TOKEN'
            }), 401
        
        # Add user info to request context
        request.current_user = payload
        return f(*args, **kwargs)
    
    return decorated_function

# Decorator for role-based access control
def role_required(*required_roles):
    """Decorator to require specific roles"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if user is authenticated
            if not hasattr(request, 'current_user'):
                return jsonify({
                    'success': False,
                    'message': 'Authentication required',
                    'error_code': 'AUTHENTICATION_REQUIRED'
                }), 401
            
            user_role = request.current_user.get('role')
            
            # Check if user has required role
            if user_role not in required_roles:
                return jsonify({
                    'success': False,
                    'message': 'Insufficient permissions',
                    'error_code': 'INSUFFICIENT_PERMISSIONS'
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# Decorator for permission-based access control
def permission_required(resource: str, action: str):
    """Decorator to require specific permission"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if user is authenticated
            if not hasattr(request, 'current_user'):
                return jsonify({
                    'success': False,
                    'message': 'Authentication required',
                    'error_code': 'AUTHENTICATION_REQUIRED'
                }), 401
            
            user_id = request.current_user.get('user_id')
            
            # Check if user has required permission
            if not JWTService._check_user_permission(user_id, resource, action):
                return jsonify({
                    'success': False,
                    'message': 'Insufficient permissions',
                    'error_code': 'INSUFFICIENT_PERMISSIONS'
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# Add token blacklist table to schema
def create_token_blacklist_table():
    """Create token blacklist table if it doesn't exist"""
    try:
        from db.enterprise_init import create_token_blacklist_table as create_table
        return create_table()
    except Exception as e:
        logger.error(f"Error creating token blacklist table: {str(e)}")
        return False

@staticmethod
def _check_user_permission(user_id: int, resource: str, action: str) -> bool:
    """Check if user has specific permission"""
    try:
        from db.enterprise_helpers import PermissionService
        return PermissionService.check_user_permission(user_id, resource, action)
        
    except Exception as e:
        logger.error(f"Error checking user permission: {str(e)}")
        return False