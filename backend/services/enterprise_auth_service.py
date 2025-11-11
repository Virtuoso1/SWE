import secrets
import hashlib
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from flask import request, current_app
from db.database import get_connection
from db.enterprise_helpers import EnterpriseUserHelper, MFAService, PermissionService
from services.jwt_service import JWTService
from utils.security import get_client_ip, generate_password_reset_token, hash_token
from utils.validators import validate_email, validate_password_strength
import logging

logger = logging.getLogger(__name__)

# Import audit service
from services.audit_service import log_authentication_event, log_authorization_event, log_security_event

# Import monitoring service
from services.auth_monitoring_service import auth_monitoring_service, AuthEventType

class EnterpriseAuthService:
    """Enterprise-grade authentication service with advanced security features"""
    
    @staticmethod
    def authenticate_user(email: str, password: str, mfa_token: str = None, 
                        device_fingerprint: str = None) -> Optional[Dict[str, Any]]:
        """
        Authenticate user with enterprise security features
        
        Args:
            email: User's email address
            password: User's password
            mfa_token: MFA token (if MFA is enabled)
            device_fingerprint: Device fingerprint for tracking
            
        Returns:
            Dict containing authentication result or None
        """
        if not email or not password:
            logger.warning("Authentication failed: Missing email or password")
            return None
        
        try:
            # Get user from database
            user = EnterpriseUserHelper.get_user_by_email(email)
            
            if not user:
                # Use constant-time response to prevent timing attacks
                EnterpriseAuthService._simulate_password_check()
                logger.warning(f"Authentication failed: User not found for email {email}")
                EnterpriseAuthService._log_login_attempt(
                    None, email, False, "user_not_found", 
                    get_client_ip(), device_fingerprint
                )
                return None
            
            # Check if account is locked
            is_locked, lock_until = EnterpriseUserHelper.check_account_lock(user['user_id'])
            if is_locked:
                logger.warning(f"Authentication failed: Account locked for email {email}")
                EnterpriseAuthService._log_login_attempt(
                    user['user_id'], email, False, "account_locked", 
                    get_client_ip(), device_fingerprint
                )
                return None
            
            # Check if user is active
            if user.get('status') != 'active':
                logger.warning(f"Authentication failed: User {email} is {user.get('status')}")
                EnterpriseAuthService._log_login_attempt(
                    user['user_id'], email, False, f"account_{user.get('status')}", 
                    get_client_ip(), device_fingerprint
                )
                return None
            
            # Verify password
            if not EnterpriseUserHelper.verify_password(password, user['password']):
                # Increment failed login attempts
                EnterpriseUserHelper.increment_failed_login(user['user_id'])
                
                logger.warning(f"Authentication failed: Invalid password for user {email}")
                EnterpriseAuthService._log_login_attempt(
                    user['user_id'], email, False, "invalid_password", 
                    get_client_ip(), device_fingerprint
                )
                return None
            
            # Check MFA if enabled
            if user.get('mfa_enabled'):
                if not mfa_token:
                    logger.warning(f"Authentication failed: MFA token required for user {email}")
                    EnterpriseAuthService._log_login_attempt(
                        user['user_id'], email, False, "mfa_required", 
                        get_client_ip(), device_fingerprint
                    )
                    return {
                        'status': 'mfa_required',
                        'user_id': user['user_id'],
                        'message': 'Multi-factor authentication required'
                    }
                
                # Verify MFA token
                if not MFAService.verify_mfa_token(user['mfa_secret'], mfa_token):
                    # Try backup codes
                    if not MFAService.verify_backup_code(user['user_id'], mfa_token):
                        logger.warning(f"Authentication failed: Invalid MFA token for user {email}")
                        EnterpriseAuthService._log_login_attempt(
                            user['user_id'], email, False, "invalid_mfa", 
                            get_client_ip(), device_fingerprint
                        )
                        return None
            
            # Reset failed login attempts on successful authentication
            EnterpriseUserHelper.reset_failed_login(user['user_id'])
            
            # Track device if fingerprinting is enabled
            if device_fingerprint:
                EnterpriseAuthService._track_device(user['user_id'], device_fingerprint)
            
            # Log successful authentication
            EnterpriseAuthService._log_login_attempt(
                user['user_id'], email, True, "success", 
                get_client_ip(), device_fingerprint
            )
            
            # Update last login time
            EnterpriseAuthService._update_last_login(user['user_id'])
            
            # Generate JWT tokens
            access_token, refresh_token, expires_at = JWTService.generate_tokens(
                user['user_id'], user['email'], user['role'], device_fingerprint
            )
            
            # Return authentication result
            return {
                'status': 'success',
                'user': {
                    'user_id': user['user_id'],
                    'full_name': user['full_name'],
                    'email': user['email'],
                    'role': user['role'],
                    'permissions': user.get('permissions', []),
                    'mfa_enabled': user.get('mfa_enabled', False),
                    'last_login': user.get('last_login')
                },
                'tokens': {
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'expires_at': expires_at.isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return None
    
    @staticmethod
    def register_user(email: str, password: str, full_name: str, role: str = "student",
                     phone: str = None, timezone: str = "UTC", language: str = "en") -> Optional[Dict[str, Any]]:
        """
        Register a new user with enterprise validation
        
        Args:
            email: User's email address
            password: User's password
            full_name: User's full name
            role: User's role
            phone: User's phone number
            timezone: User's timezone
            language: User's preferred language
            
        Returns:
            Dict containing registration result or None
        """
        try:
            # Validate input
            if not validate_email(email):
                logger.warning(f"Registration failed: Invalid email format {email}")
                return None
            
            if not validate_password_strength(password):
                logger.warning(f"Registration failed: Weak password for email {email}")
                return None
            
            # Check if user already exists
            existing_user = EnterpriseUserHelper.get_user_by_email(email)
            if existing_user:
                logger.warning(f"Registration failed: User with email {email} already exists")
                return None
            
            # Create user
            user_data = EnterpriseUserHelper.create_user(
                full_name, email, password, role, phone, timezone, language
            )
            
            if not user_data:
                logger.error(f"Registration failed: Error creating user {email}")
                return None
            
            # Generate email verification token
            verification_token = EnterpriseAuthService._generate_email_verification_token(user_data['user_id'])
            
            # Log registration
            EnterpriseAuthService._log_security_event(
                "user_registration", "medium", user_data['user_id'],
                f"New user registered: {email}", {
                    'email': email,
                    'role': role,
                    'ip_address': get_client_ip()
                }
            )
            
            # Send verification email (would integrate with email service)
            # EmailService.send_verification_email(email, verification_token)
            
            return {
                'status': 'success',
                'user': {
                    'user_id': user_data['user_id'],
                    'full_name': user_data['full_name'],
                    'email': user_data['email'],
                    'role': user_data['role'],
                    'email_verified': user_data.get('email_verified', False)
                },
                'verification_token': verification_token
            }
            
        except Exception as e:
            logger.error(f"User registration error: {str(e)}")
            return None
    
    @staticmethod
    def refresh_access_token(refresh_token: str, device_fingerprint: str = None) -> Optional[Dict[str, Any]]:
        """
        Refresh access token using refresh token
        
        Args:
            refresh_token: Valid refresh token
            device_fingerprint: Device fingerprint for tracking
            
        Returns:
            Dict containing new tokens or None
        """
        try:
            # Verify refresh token and generate new tokens
            result = JWTService.refresh_access_token(refresh_token, device_fingerprint)
            
            if not result:
                logger.warning("Token refresh failed: Invalid refresh token")
                return None
            
            access_token, new_refresh_token, expires_at = result
            
            # Get user information
            payload = JWTService.verify_access_token(access_token)
            if not payload:
                return None
            
            user_data = EnterpriseUserHelper.get_user_by_id(payload['user_id'])
            if not user_data:
                return None
            
            # Log token refresh
            EnterpriseAuthService._log_security_event(
                "token_refresh", "low", payload['user_id'],
                "Access token refreshed", {
                    'ip_address': get_client_ip(),
                    'device_fingerprint': device_fingerprint
                }
            )
            
            return {
                'status': 'success',
                'tokens': {
                    'access_token': access_token,
                    'refresh_token': new_refresh_token,
                    'expires_at': expires_at.isoformat()
                },
                'user': {
                    'user_id': user_data['user_id'],
                    'full_name': user_data['full_name'],
                    'email': user_data['email'],
                    'role': user_data['role'],
                    'permissions': user_data.get('permissions', [])
                }
            }
            
        except Exception as e:
            logger.error(f"Token refresh error: {str(e)}")
            return None
    
    @staticmethod
    def logout_user(access_token: str, refresh_token: str = None) -> bool:
        """
        Logout user and revoke tokens
        
        Args:
            access_token: Access token to revoke
            refresh_token: Refresh token to revoke (optional)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get user info from access token
            payload = JWTService.verify_access_token(access_token)
            if not payload:
                return False
            
            user_id = payload['user_id']
            
            # Revoke access token
            JWTService.revoke_token(payload['jti'], 'access')
            
            # Revoke refresh token if provided
            if refresh_token:
                refresh_payload = JWTService.verify_refresh_token(refresh_token)
                if refresh_payload:
                    JWTService.revoke_token(refresh_payload['jti'], 'refresh')
            
            # Log logout
            EnterpriseAuthService._log_security_event(
                "user_logout", "low", user_id,
                "User logged out", {
                    'ip_address': get_client_ip()
                }
            )
            
            # Track logout event in monitoring service
            auth_monitoring_service.track_auth_event(
                event_type=AuthEventType.LOGOUT,
                user_id=str(user_id),
                username=None,
                ip_address=get_client_ip(),
                user_agent=request.headers.get('User-Agent', '') if request else '',
                success=True,
                details={'logout_type': 'manual'}
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return False
    
    @staticmethod
    def initiate_password_reset(email: str) -> bool:
        """
        Initiate password reset process
        
        Args:
            email: User's email address
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check rate limiting
            if not EnterpriseAuthService._check_rate_limit(email, 'password_reset'):
                logger.warning(f"Password reset rate limit exceeded for email: {email}")
                return False
            
            # Get user
            user = EnterpriseUserHelper.get_user_by_email(email)
            if not user:
                # Use constant-time response to prevent enumeration
                return True
            
            # Generate reset token
            reset_token = generate_password_reset_token()
            token_hash = hash_token(reset_token)
            expires_at = datetime.utcnow() + timedelta(hours=1)  # 1 hour expiry
            
            # Store reset token
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO password_reset_tokens 
                (user_id, token_hash, expires_at, ip_address, created_at)
                VALUES (%s, %s, %s, %s, NOW())
                ON DUPLICATE KEY UPDATE
                token_hash = VALUES(token_hash),
                expires_at = VALUES(expires_at),
                ip_address = VALUES(ip_address),
                created_at = NOW()
            """, (user['user_id'], token_hash, expires_at, get_client_ip()))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            # Send reset email (would integrate with email service)
            # EmailService.send_password_reset_email(email, reset_token)
            
            # Log password reset request
            EnterpriseAuthService._log_security_event(
                "password_reset_request", "medium", user['user_id'],
                f"Password reset requested for email: {email}", {
                    'ip_address': get_client_ip()
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Password reset initiation error: {str(e)}")
            return False
    
    @staticmethod
    def reset_password(reset_token: str, new_password: str) -> bool:
        """
        Reset password using reset token
        
        Args:
            reset_token: Password reset token
            new_password: New password
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate password strength
            if not validate_password_strength(new_password):
                return False
            
            # Hash token and check database
            token_hash = hash_token(reset_token)
            
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT prt.user_id, prt.expires_at, u.email
                FROM password_reset_tokens prt
                JOIN users u ON prt.user_id = u.user_id
                WHERE prt.token_hash = %s AND prt.used_at IS NULL
            """, (token_hash,))
            
            result = cursor.fetchone()
            if not result:
                cursor.close()
                conn.close()
                return False
            
            # Check if token is expired
            if result['expires_at'] < datetime.utcnow():
                cursor.close()
                conn.close()
                return False
            
            user_id = result['user_id']
            email = result['email']
            
            # Update password
            if not EnterpriseUserHelper.update_password(user_id, new_password):
                cursor.close()
                conn.close()
                return False
            
            # Mark token as used
            cursor.execute("""
                UPDATE password_reset_tokens 
                SET used_at = NOW()
                WHERE token_hash = %s
            """, (token_hash,))
            
            # Revoke all user tokens
            JWTService.revoke_all_user_tokens(user_id)
            
            conn.commit()
            cursor.close()
            conn.close()
            
            # Log password reset
            EnterpriseAuthService._log_security_event(
                "password_reset", "high", user_id,
                f"Password reset completed for email: {email}", {
                    'ip_address': get_client_ip()
                }
            )
            
            # Track password reset event in monitoring service
            auth_monitoring_service.track_auth_event(
                event_type=AuthEventType.PASSWORD_CHANGE,
                user_id=str(user_id),
                username=email,
                ip_address=get_client_ip(),
                user_agent=request.headers.get('User-Agent', '') if request else '',
                success=True,
                details={'reset_type': 'password_reset'}
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Password reset error: {str(e)}")
            return False
    
    @staticmethod
    def _simulate_password_check() -> None:
        """Simulate a password check to prevent timing attacks"""
        dummy_hash = EnterpriseUserHelper.hash_password("dummy")
        EnterpriseUserHelper.verify_password("wrong", dummy_hash)
    
    @staticmethod
    def _log_login_attempt(user_id: Optional[int], email: str, success: bool,
                          failure_reason: str = None, ip_address: str = None,
                          device_fingerprint: str = None) -> None:
        """Log login attempt for security monitoring"""
        try:
            conn = get_connection()
            if not conn:
                return
                
            cursor = conn.cursor()
            
            # Get user agent and location data
            user_agent = request.headers.get('User-Agent', '') if request else ''
            
            cursor.execute("""
                INSERT INTO login_attempts
                (user_id, email, success, failure_reason, ip_address,
                 user_agent, device_fingerprint, attempt_time)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())
            """, (user_id, email, success, failure_reason, ip_address,
                   user_agent, device_fingerprint))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            # Track event in monitoring service
            event_type = AuthEventType.LOGIN_SUCCESS if success else AuthEventType.LOGIN_FAILURE
            
            auth_monitoring_service.track_auth_event(
                event_type=event_type,
                user_id=str(user_id) if user_id else None,
                username=email,
                ip_address=ip_address or get_client_ip(),
                user_agent=user_agent,
                success=success,
                details={'failure_reason': failure_reason} if not success else {},
                device_fingerprint=device_fingerprint
            )
            
        except Exception as e:
            logger.error(f"Failed to log login attempt: {str(e)}")
    
    @staticmethod
    def _log_security_event(event_type: str, severity: str, user_id: Optional[int],
                           description: str, metadata: Dict[str, Any] = None) -> None:
        """Log security event for audit trail"""
        try:
            conn = get_connection()
            if not conn:
                return
                
            cursor = conn.cursor()
            
            # Generate hash signature for tamper protection
            event_data = f"{event_type}{severity}{user_id}{description}{metadata}"
            hash_signature = hashlib.sha256(event_data.encode()).hexdigest()
            
            cursor.execute("""
                INSERT INTO audit_logs 
                (user_id, action, resource_type, description, ip_address, 
                 user_agent, timestamp, severity, category, hash_signature, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s, %s)
            """, (user_id, event_type, 'authentication', description, get_client_ip(),
                   request.headers.get('User-Agent', '') if request else '', severity,
                   'authentication', hash_signature, str(metadata) if metadata else None))
            
            conn.commit()
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to log security event: {str(e)}")
    
    @staticmethod
    def _track_device(user_id: int, device_fingerprint: str) -> None:
        """Track device for fingerprinting"""
        try:
            if not device_fingerprint:
                return
                
            conn = get_connection()
            if not conn:
                return
                
            cursor = conn.cursor()
            
            # Get device info
            user_agent = request.headers.get('User-Agent', '') if request else ''
            ip_address = get_client_ip()
            
            # Check if device exists
            cursor.execute("""
                SELECT device_id, is_trusted FROM user_devices 
                WHERE user_id = %s AND device_fingerprint = %s
            """, (user_id, device_fingerprint))
            
            result = cursor.fetchone()
            
            if result:
                # Update last seen
                device_id, is_trusted = result
                cursor.execute("""
                    UPDATE user_devices 
                    SET last_seen = NOW(), ip_address = %s
                    WHERE device_id = %s
                """, (ip_address, device_id))
            else:
                # Add new device
                cursor.execute("""
                    INSERT INTO user_devices 
                    (user_id, device_fingerprint, device_name, device_type, 
                     platform, browser, ip_address, last_seen, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                """, (user_id, device_fingerprint, 'Unknown Device', 'unknown',
                       'Unknown', 'Unknown', ip_address))
            
            conn.commit()
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to track device: {str(e)}")
    
    @staticmethod
    def _update_last_login(user_id: int) -> None:
        """Update user's last login time"""
        try:
            conn = get_connection()
            if not conn:
                return
                
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE users 
                SET last_login = NOW(), updated_at = NOW()
                WHERE user_id = %s
            """, (user_id,))
            
            conn.commit()
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to update last login: {str(e)}")
    
    @staticmethod
    def _generate_email_verification_token(user_id: int) -> str:
        """Generate email verification token"""
        try:
            token = secrets.token_urlsafe(32)
            token_hash = hash_token(token)
            expires_at = datetime.utcnow() + timedelta(hours=24)  # 24 hour expiry
            
            conn = get_connection()
            if not conn:
                return ""
                
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO email_verification_tokens 
                (user_id, token_hash, expires_at, ip_address, created_at)
                VALUES (%s, %s, %s, %s, NOW())
                ON DUPLICATE KEY UPDATE
                token_hash = VALUES(token_hash),
                expires_at = VALUES(expires_at),
                ip_address = VALUES(ip_address),
                created_at = NOW()
            """, (user_id, token_hash, expires_at, get_client_ip()))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return token
            
        except Exception as e:
            logger.error(f"Failed to generate email verification token: {str(e)}")
            return ""
    
    @staticmethod
    def _check_rate_limit(identifier: str, action: str, max_attempts: int = None, 
                         window_minutes: int = None) -> bool:
        """Check rate limiting for various actions"""
        try:
            config = current_app.config if current_app else get_config()
            
            if action == 'password_reset':
                max_attempts = max_attempts or config.RATE_LIMIT_PASSWORD_RESET
                window_minutes = window_minutes or config.RATE_LIMIT_PASSWORD_RESET_WINDOW
            else:
                max_attempts = max_attempts or config.RATE_LIMIT_LOGIN_ATTEMPTS
                window_minutes = window_minutes or config.RATE_LIMIT_LOGIN_ATTEMPTS_WINDOW
            
            conn = get_connection()
            if not conn:
                return True  # Allow if DB connection fails
                
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT COUNT(*) FROM rate_limits 
                WHERE identifier = %s AND window_type = 'minute'
                AND window_start > DATE_SUB(NOW(), INTERVAL %s MINUTE)
            """, (identifier, window_minutes))
            
            count = cursor.fetchone()[0]
            
            if count >= max_attempts:
                # Block for progressive duration
                block_duration = min(30 * (2 ** (count - max_attempts)), 1440)  # Max 24 hours
                block_until = datetime.utcnow() + timedelta(minutes=block_duration)
                
                cursor.execute("""
                    INSERT INTO rate_limits 
                    (identifier, window_type, window_start, request_count, 
                     max_requests, block_until)
                    VALUES (%s, 'minute', NOW(), %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                    request_count = VALUES(request_count),
                    block_until = VALUES(block_until)
                """, (identifier, count, max_attempts, block_until))
                
                conn.commit()
                cursor.close()
                conn.close()
                
                return False
            
            # Update rate limit counter
            cursor.execute("""
                INSERT INTO rate_limits 
                (identifier, window_type, window_start, request_count, max_requests)
                VALUES (%s, 'minute', NOW(), 1, %s)
                ON DUPLICATE KEY UPDATE
                request_count = request_count + 1
            """, (identifier, max_attempts))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Rate limit check error: {str(e)}")
            return True  # Allow if check fails