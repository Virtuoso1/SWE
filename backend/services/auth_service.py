"""
Authentication service for the Library Management System
Handles all authentication-related business logic
"""

import time
import logging
from typing import Optional, Dict, Any
from datetime import datetime

from db.repositories import get_repositories
from utils.validators import validate_email, validate_password

logger = logging.getLogger(__name__)

class AuthService:
    """Service class for handling authentication operations"""
    
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
            repos = get_repositories()
            user = repos['user'].get_by_email(email)
            
            if not user:
                # Use constant-time response to prevent timing attacks
                AuthService._simulate_password_check()
                logger.warning(f"Authentication failed: User not found for email {email}")
                return None
                
            # Check if user is active
            if user.status != 'active':
                logger.warning(f"Authentication failed: User {email} is inactive")
                return None
                
            # Verify password
            if user.verify_password(password):
                # Return user data without sensitive information
                user_data = user.to_dict()
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
        import bcrypt
        dummy_hash = bcrypt.hashpw("dummy".encode('utf-8'), bcrypt.gensalt())
        bcrypt.checkpw("wrong".encode('utf-8'), dummy_hash)
    
    @staticmethod
    def log_login_attempt(user_id: int, email: str, success: bool, ip_address: str = None, user_agent: str = None) -> None:
        """
        Log login attempts for security monitoring
        
        Args:
            user_id: ID of the user attempting to login
            email: Email of the user
            success: Whether the login was successful
            ip_address: IP address of the request
            user_agent: User agent string
        """
        try:
            from db.models import LoginAttempt
            repos = get_repositories()
            attempt = LoginAttempt(
                user_id=user_id,
                email=email,
                success=success,
                ip_address=ip_address,
                user_agent=user_agent,
                attempt_time=datetime.now()
            )
            repos['login_attempt'].create(attempt)
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
            repos = get_repositories()
            failed_attempts = repos['login_attempt'].get_failed_attempts(email, window_minutes)
            return failed_attempts < max_attempts
        except Exception as e:
            logger.error(f"Rate limit check error: {str(e)}")
            return True  # Allow if check fails
    
    @staticmethod
    def register_user(email: str, password: str, full_name: str, role: str = "student") -> Optional[Dict[str, Any]]:
        """
        Register a new user in the database
        
        Args:
            email: User's email address
            password: User's plain text password
            full_name: User's full name
            role: User's role (default: 'student')
            
        Returns:
            Dict containing user data if registration successful, None otherwise
        """
        try:
            # Validate input
            if not validate_email(email):
                logger.warning(f"Registration failed: Invalid email format {email}")
                return None
                
            if not validate_password(password):
                logger.warning(f"Registration failed: Invalid password for {email}")
                return None
            
            # Check if user already exists
            repos = get_repositories()
            existing_user = repos['user'].get_by_email(email)
            if existing_user:
                logger.warning(f"Registration failed: User with email {email} already exists")
                return None
            
            # Create new user
            from db.models import User
            new_user = User(
                full_name=full_name,
                email=email,
                password=password,  # Will be hashed in the repository
                role=role,
                status='active',
                date_joined=datetime.now()
            )
            
            user_id = repos['user'].create(new_user)

            if user_id:
                # Get the newly created user
                created_user = repos['user'].get_by_id(user_id)
                if created_user:
                    user_data = created_user.to_dict()
                    logger.info(f"User registered successfully: {email}")
                    return user_data
                else:
                    logger.error(f"Failed to retrieve newly created user: {email}")
                    return None
            else:
                logger.error(f"Failed to create user: {email}")
                return None
                
        except Exception as e:
            logger.error(f"User registration error: {str(e)}")
            return None
    
    @staticmethod
    def create_user(full_name: str, email: str, password: str, role: str = "student") -> bool:
        """
        Create a new user (for admin/librarian use)
        
        Args:
            full_name: User's full name
            email: User's email address
            password: User's plain text password
            role: User's role (default: 'student')
            
        Returns:
            bool: True if user creation successful, False otherwise
        """
        try:
            # Use the existing register_user method
            result = AuthService.register_user(email, password, full_name, role)
            return result is not None
        except Exception as e:
            logger.error(f"User creation error: {str(e)}")
            return False
    
    @staticmethod
    def reset_password(user_id: int, new_password: str) -> bool:
        """
        Reset user password
        
        Args:
            user_id: ID of the user
            new_password: New plain text password
            
        Returns:
            bool: True if password reset successful, False otherwise
        """
        try:
            if not validate_password(new_password):
                logger.warning(f"Password reset failed: Invalid password for user {user_id}")
                return False
            
            repos = get_repositories()
            return repos['user'].update_password(user_id, new_password)
        except Exception as e:
            logger.error(f"Password reset error: {str(e)}")
            return False
    
    @staticmethod
    def change_user_status(user_id: int, status: str) -> bool:
        """
        Change user status (activate/suspend)
        
        Args:
            user_id: ID of the user
            status: New status ('active' or 'inactive')
            
        Returns:
            bool: True if status change successful, False otherwise
        """
        try:
            repos = get_repositories()
            user = repos['user'].get_by_id(user_id)
            if not user:
                logger.warning(f"Status change failed: User {user_id} not found")
                return False
            
            if status == 'active':
                return repos['user'].activate(user_id)
            elif status == 'inactive':
                return repos['user'].suspend(user_id)
            else:
                logger.warning(f"Status change failed: Invalid status {status}")
                return False
        except Exception as e:
            logger.error(f"Status change error: {str(e)}")
            return False
    
    @staticmethod
    def get_user_profile(user_id: int) -> Optional[Dict[str, Any]]:
        """
        Get user profile information
        
        Args:
            user_id: ID of the user
            
        Returns:
            Dict containing user data if found, None otherwise
        """
        try:
            repos = get_repositories()
            user = repos['user'].get_by_id(user_id)
            if user:
                return user.to_dict()
            return None
        except Exception as e:
            logger.error(f"Get user profile error: {str(e)}")
            return None
    
    @staticmethod
    def update_user_profile(user_id: int, full_name: str = None, email: str = None, role: str = None) -> bool:
        """
        Update user profile information
        
        Args:
            user_id: ID of the user
            full_name: New full name (optional)
            email: New email (optional)
            role: New role (optional)
            
        Returns:
            bool: True if update successful, False otherwise
        """
        try:
            repos = get_repositories()
            user = repos['user'].get_by_id(user_id)
            if not user:
                logger.warning(f"Profile update failed: User {user_id} not found")
                return False
            
            # Update fields if provided
            if full_name is not None:
                user.full_name = full_name
            if email is not None:
                if not validate_email(email):
                    logger.warning(f"Profile update failed: Invalid email format {email}")
                    return False
                user.email = email
            if role is not None:
                user.role = role
            
            return repos['user'].update(user)
        except Exception as e:
            logger.error(f"Profile update error: {str(e)}")
            return False