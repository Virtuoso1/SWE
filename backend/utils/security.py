import secrets
import hashlib
import hmac
from typing import Optional, Dict, Any
from flask import session, request
import time
import logging

logger = logging.getLogger(__name__)

def generate_csrf_token() -> str:
    """
    Generate a secure CSRF token
    
    Returns:
        str: Random CSRF token
    """
    return secrets.token_urlsafe(32)

def validate_csrf_token(token: str) -> bool:
    """
    Validate CSRF token against session token
    
    Args:
        token: Token to validate
        
    Returns:
        bool: True if token is valid, False otherwise
    """
    if not token or not isinstance(token, str):
        return False
        
    session_token = session.get('csrf_token')
    if not session_token:
        return False
        
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(token, session_token)

def generate_session_token() -> str:
    """
    Generate a secure session token
    
    Returns:
        str: Random session token
    """
    return secrets.token_urlsafe(64)

def hash_token(token: str) -> str:
    """
    Hash a token for storage
    
    Args:
        token: Token to hash
        
    Returns:
        str: Hashed token
    """
    return hashlib.sha256(token.encode()).hexdigest()

def is_secure_request() -> bool:
    """
    Check if the request is secure (HTTPS)
    
    Returns:
        bool: True if request is secure, False otherwise
    """
    # Check various headers that might indicate HTTPS
    if request.is_secure:
        return True
        
    # Check for common headers set by reverse proxies
    secure_headers = [
        'X-Forwarded-Proto',
        'X-Forwarded-Scheme',
        'X-Forwarded-SSL'
    ]
    
    for header in secure_headers:
        if request.headers.get(header, '').lower() == 'https':
            return True
            
    return False

def get_client_ip() -> str:
    """
    Get the client's IP address, considering proxies
    
    Returns:
        str: Client IP address
    """
    # Check for common headers set by proxies
    ip_headers = [
        'X-Forwarded-For',
        'X-Real-IP',
        'X-Client-IP',
        'CF-Connecting-IP',  # Cloudflare
        'True-Client-IP'
    ]
    
    for header in ip_headers:
        ip = request.headers.get(header)
        if ip:
            # X-Forwarded-For can contain multiple IPs, get the first one
            if ',' in ip:
                ip = ip.split(',')[0].strip()
            return ip
            
    # Fallback to remote address
    return request.environ.get('REMOTE_ADDR', 'unknown')

def rate_limit_key(identifier: str, action: str) -> str:
    """
    Generate a rate limiting key
    
    Args:
        identifier: Unique identifier (email, IP, etc.)
        action: Action being rate limited
        
    Returns:
        str: Rate limit key
    """
    timestamp = int(time.time() // 60)  # Minute-level granularity
    return f"rate_limit:{action}:{identifier}:{timestamp}"

def sanitize_headers(headers: dict) -> dict:
    """
    Sanitize headers for logging (remove sensitive information)
    
    Args:
        headers: Original headers dictionary
        
    Returns:
        dict: Sanitized headers
    """
    sensitive_headers = [
        'authorization',
        'cookie',
        'set-cookie',
        'x-api-key',
        'x-auth-token'
    ]
    
    sanitized = {}
    for key, value in headers.items():
        if key.lower() in sensitive_headers:
            sanitized[key] = '[REDACTED]'
        else:
            sanitized[key] = value
            
    return sanitized

def validate_session_age(max_age_seconds: int = 3600) -> bool:
    """
    Validate that the session is not too old
    
    Args:
        max_age_seconds: Maximum allowed session age in seconds
        
    Returns:
        bool: True if session is valid, False otherwise
    """
    login_time = session.get('login_time')
    if not login_time:
        return False
        
    try:
        from datetime import datetime
        login_dt = datetime.fromisoformat(login_time)
        current_dt = datetime.utcnow()
        age_seconds = (current_dt - login_dt).total_seconds()
        
        return age_seconds <= max_age_seconds
    except (ValueError, TypeError):
        return False

def generate_password_reset_token() -> str:
    """
    Generate a secure password reset token
    
    Returns:
        str: Password reset token
    """
    return secrets.token_urlsafe(32)

def verify_password_reset_token(token: str, expected_hash: str) -> bool:
    """
    Verify a password reset token
    
    Args:
        token: Token to verify
        expected_hash: Expected hash of the token
        
    Returns:
        bool: True if token is valid, False otherwise
    """
    if not token or not expected_hash:
        return False
        
    token_hash = hash_token(token)
    return hmac.compare_digest(token_hash, expected_hash)

def is_authenticated() -> bool:
    """
    Check if current session is authenticated
    
    Returns:
        bool: True if authenticated, False otherwise
    """
    return bool(session.get('authenticated') and session.get('user_id'))

def get_current_user_id() -> Optional[int]:
    """
    Get current user ID from session
    
    Returns:
        int: User ID if authenticated, None otherwise
    """
    return session.get('user_id')

def get_current_user_role() -> Optional[str]:
    """
    Get current user role from session
    
    Returns:
        str: User role if authenticated, None otherwise
    """
    return session.get('role')

def has_permission(required_role: str) -> bool:
    """
    Check if current user has required role or higher
    
    Args:
        required_role: Required role ('student', 'librarian', 'admin')
        
    Returns:
        bool: True if user has permission, False otherwise
    """
    current_role = get_current_user_role()
    
    if not current_role:
        return False
    
    # Role hierarchy
    role_hierarchy = {
        'student': 1,
        'librarian': 2,
        'admin': 3
    }
    
    current_level = role_hierarchy.get(current_role, 0)
    required_level = role_hierarchy.get(required_role, 0)
    
    return current_level >= required_level

def is_admin() -> bool:
    """
    Check if current user is admin
    
    Returns:
        bool: True if admin, False otherwise
    """
    return get_current_user_role() == 'admin'

def is_librarian_or_admin() -> bool:
    """
    Check if current user is librarian or admin
    
    Returns:
        bool: True if librarian or admin, False otherwise
    """
    role = get_current_user_role()
    return role in ['librarian', 'admin']

def log_security_event(event_type: str, details: Dict[str, Any] = None) -> None:
    """
    Log security-related events
    
    Args:
        event_type: Type of security event
        details: Additional event details
    """
    try:
        client_ip = get_client_ip()
        user_agent = request.headers.get('User-Agent', 'unknown')
        user_id = get_current_user_id()
        
        log_data = {
            'event_type': event_type,
            'timestamp': time.time(),
            'ip_address': client_ip,
            'user_agent': user_agent,
            'user_id': user_id
        }
        
        if details:
            log_data.update(details)
        
        logger.warning(f"Security event: {event_type} - {log_data}")
    except Exception as e:
        logger.error(f"Failed to log security event: {str(e)}")

def validate_api_key(api_key: str) -> bool:
    """
    Validate API key (if API key authentication is used)
    
    Args:
        api_key: API key to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    # This would typically check against a database or configuration
    # For now, return False as API key auth is not implemented
    return False

def encrypt_sensitive_data(data: str, key: str) -> str:
    """
    Encrypt sensitive data
    
    Args:
        data: Data to encrypt
        key: Encryption key
        
    Returns:
        str: Encrypted data
    """
    try:
        from cryptography.fernet import Fernet
        f = Fernet(key.encode())
        encrypted_data = f.encrypt(data.encode())
        return encrypted_data.decode()
    except ImportError:
        logger.warning("Cryptography library not available, using simple encoding")
        # Fallback to simple encoding (not secure for production)
        import base64
        return base64.b64encode(data.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        return data

def decrypt_sensitive_data(encrypted_data: str, key: str) -> str:
    """
    Decrypt sensitive data
    
    Args:
        encrypted_data: Encrypted data
        key: Decryption key
        
    Returns:
        str: Decrypted data
    """
    try:
        from cryptography.fernet import Fernet
        f = Fernet(key.encode())
        decrypted_data = f.decrypt(encrypted_data.encode())
        return decrypted_data.decode()
    except ImportError:
        logger.warning("Cryptography library not available, using simple decoding")
        # Fallback to simple decoding (not secure for production)
        import base64
        return base64.b64decode(encrypted_data.encode()).decode()
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        return encrypted_data