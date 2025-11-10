import secrets
import hashlib
import hmac
from typing import Optional
from flask import session, request
import time

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