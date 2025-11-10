import re
from typing import Optional

def validate_email(email: str) -> bool:
    """
    Validate email format using regex
    
    Args:
        email: Email address to validate
        
    Returns:
        bool: True if email is valid, False otherwise
    """
    if not email or not isinstance(email, str):
        return False
        
    # Basic email regex pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_password(password: str) -> bool:
    """
    Validate password strength
    
    Args:
        password: Password to validate
        
    Returns:
        bool: True if password meets requirements, False otherwise
    """
    if not password or not isinstance(password, str):
        return False
        
    # Basic password validation - at least 8 characters
    if len(password) < 8:
        return False
        
    # You can add more complex validation here if needed
    # For example: require uppercase, lowercase, numbers, special characters
    
    return True

def validate_name(name: str) -> bool:
    """
    Validate full name format
    
    Args:
        name: Full name to validate
        
    Returns:
        bool: True if name is valid, False otherwise
    """
    if not name or not isinstance(name, str):
        return False
        
    # Remove leading/trailing whitespace
    name = name.strip()
    
    # Check if name is between 2 and 100 characters
    if len(name) < 2 or len(name) > 100:
        return False
        
    # Allow letters, spaces, hyphens, and apostrophes
    pattern = r'^[a-zA-Z\s\-\'\.]+$'
    return bool(re.match(pattern, name))

def sanitize_input(input_string: str) -> str:
    """
    Sanitize user input to prevent injection attacks
    
    Args:
        input_string: Input string to sanitize
        
    Returns:
        str: Sanitized string
    """
    if not input_string or not isinstance(input_string, str):
        return ""
        
    # Remove potential dangerous characters
    dangerous_chars = ['<', '>', '"', "'", '&', '\x00', '\n', '\r', '\t', '\\']
    sanitized = input_string
    
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
        
    return sanitized.strip()

def validate_role(role: str) -> bool:
    """
    Validate user role
    
    Args:
        role: Role to validate
        
    Returns:
        bool: True if role is valid, False otherwise
    """
    valid_roles = ['student', 'librarian', 'admin']
    return role in valid_roles

def validate_user_id(user_id: any) -> bool:
    """
    Validate user ID format
    
    Args:
        user_id: User ID to validate
        
    Returns:
        bool: True if user ID is valid, False otherwise
    """
    try:
        user_id_int = int(user_id)
        return user_id_int > 0
    except (ValueError, TypeError):
        return False