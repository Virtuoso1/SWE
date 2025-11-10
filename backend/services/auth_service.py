import bcrypt
import time
from typing import Optional, Dict, Any
from db.helpers import get_user_by_email
from db.database import get_connection
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AuthService:
    """Service class for handling authentication operations"""
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash using constant-time comparison
        
        Args:
            plain_password: The password to verify
            hashed_password: The hashed password to compare against
            
        Returns:
            bool: True if password matches, False otherwise
        """
        try:
            # Use bcrypt's built-in constant-time comparison
            return bcrypt.checkpw(
                plain_password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )
        except Exception as e:
            logger.error(f"Password verification error: {str(e)}")
            return False
    
    @staticmethod
    def authenticate_user(email: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate a user by email and password
        
        Args:
            email: User's email address
            password: User's plain text password
            
        Returns:
            Dict containing user data if authentication successful, None otherwise
        """
        if not email or not password:
            logger.warning("Authentication failed: Missing email or password")
            return None
            
        try:
            # Get user from database
            user = get_user_by_email(email)
            
            if not user:
                # Use constant-time response to prevent timing attacks
                AuthService._simulate_password_check()
                logger.warning(f"Authentication failed: User not found for email {email}")
                return None
                
            # Check if user is active
            if user.get('status') != 'active':
                logger.warning(f"Authentication failed: User {email} is inactive")
                return None
                
            # Verify password
            if AuthService.verify_password(password, user['password']):
                # Remove sensitive data before returning
                user_data = {
                    'user_id': user['user_id'],
                    'full_name': user['full_name'],
                    'email': user['email'],
                    'role': user['role'],
                    'status': user['status'],
                    'date_joined': user['date_joined']
                }
                logger.info(f"Authentication successful for user: {email}")
                return user_data
            else:
                logger.warning(f"Authentication failed: Invalid password for user {email}")
                return None
                
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return None
    
    @staticmethod
    def _simulate_password_check() -> None:
        """
        Simulate a password check to prevent timing attacks when user doesn't exist
        This ensures consistent response time regardless of whether user exists
        """
        dummy_hash = bcrypt.hashpw("dummy".encode('utf-8'), bcrypt.gensalt())
        bcrypt.checkpw("wrong".encode('utf-8'), dummy_hash)
    
    @staticmethod
    def log_login_attempt(user_id: int, email: str, success: bool, ip_address: str = None) -> None:
        """
        Log login attempts for security monitoring
        
        Args:
            user_id: ID of the user attempting to login
            email: Email of the user
            success: Whether the login was successful
            ip_address: IP address of the request
        """
        try:
            conn = get_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO login_attempts (user_id, email, success, ip_address, attempt_time)
                    VALUES (%s, %s, %s, %s, NOW())
                """, (user_id, email, success, ip_address))
                conn.commit()
                cursor.close()
                conn.close()
        except Exception as e:
            logger.error(f"Failed to log login attempt: {str(e)}")
    
    @staticmethod
    def check_rate_limit(email: str, max_attempts: int = 5, window_minutes: int = 15) -> bool:
        """
        Check if user has exceeded rate limit for login attempts
        
        Args:
            email: User's email address
            max_attempts: Maximum allowed attempts in time window
            window_minutes: Time window in minutes
            
        Returns:
            bool: True if rate limit is not exceeded, False otherwise
        """
        try:
            conn = get_connection()
            if not conn:
                return True  # Allow if DB connection fails
                
            cursor = conn.cursor()
            cursor.execute("""
                SELECT COUNT(*) FROM login_attempts 
                WHERE email = %s AND success = 0 
                AND attempt_time > DATE_SUB(NOW(), INTERVAL %s MINUTE)
            """, (email, window_minutes))
            
            failed_attempts = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            
            return failed_attempts < max_attempts
            
        except Exception as e:
            logger.error(f"Rate limit check error: {str(e)}")
            return True  # Allow if check fails