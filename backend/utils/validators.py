import re
from typing import Optional, Any
import logging

logger = logging.getLogger(__name__)

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

def validate_user_id(user_id: Any) -> bool:
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

def validate_book_id(book_id: Any) -> bool:
    """
    Validate book ID format
    
    Args:
        book_id: Book ID to validate
        
    Returns:
        bool: True if book ID is valid, False otherwise
    """
    try:
        book_id_int = int(book_id)
        return book_id_int > 0
    except (ValueError, TypeError):
        return False

def validate_borrow_id(borrow_id: Any) -> bool:
    """
    Validate borrow ID format
    
    Args:
        borrow_id: Borrow ID to validate
        
    Returns:
        bool: True if borrow ID is valid, False otherwise
    """
    try:
        borrow_id_int = int(borrow_id)
        return borrow_id_int > 0
    except (ValueError, TypeError):
        return False

def validate_fine_id(fine_id: Any) -> bool:
    """
    Validate fine ID format
    
    Args:
        fine_id: Fine ID to validate
        
    Returns:
        bool: True if fine ID is valid, False otherwise
    """
    try:
        fine_id_int = int(fine_id)
        return fine_id_int > 0
    except (ValueError, TypeError):
        return False

def validate_amount(amount: Any) -> bool:
    """
    Validate amount format
    
    Args:
        amount: Amount to validate
        
    Returns:
        bool: True if amount is valid, False otherwise
    """
    try:
        amount_float = float(amount)
        return amount_float > 0
    except (ValueError, TypeError):
        return False

def validate_year(year: Any) -> bool:
    """
    Validate year format
    
    Args:
        year: Year to validate
        
    Returns:
        bool: True if year is valid, False otherwise
    """
    try:
        year_int = int(year)
        current_year = 2024  # Could be dynamic
        return 1900 <= year_int <= current_year
    except (ValueError, TypeError):
        return False

def validate_quantity(quantity: Any) -> bool:
    """
    Validate quantity format
    
    Args:
        quantity: Quantity to validate
        
    Returns:
        bool: True if quantity is valid, False otherwise
    """
    try:
        quantity_int = int(quantity)
        return quantity_int > 0
    except (ValueError, TypeError):
        return False

def validate_date_string(date_string: str) -> bool:
    """
    Validate date string format (YYYY-MM-DD)
    
    Args:
        date_string: Date string to validate
        
    Returns:
        bool: True if date string is valid, False otherwise
    """
    if not date_string or not isinstance(date_string, str):
        return False
    
    try:
        from datetime import datetime
        datetime.strptime(date_string, '%Y-%m-%d')
        return True
    except ValueError:
        return False

def validate_pagination_params(page: Any = None, per_page: Any = None) -> tuple:
    """
    Validate pagination parameters
    
    Args:
        page: Page number
        per_page: Items per page
        
    Returns:
        tuple: (validated_page, validated_per_page)
    """
    # Default values
    validated_page = 1
    validated_per_page = 10
    
    # Validate page
    if page is not None:
        try:
            page_int = int(page)
            if page_int > 0:
                validated_page = page_int
        except (ValueError, TypeError):
            logger.warning(f"Invalid page parameter: {page}")
    
    # Validate per_page
    if per_page is not None:
        try:
            per_page_int = int(per_page)
            if 1 <= per_page_int <= 100:  # Limit to 100 items per page
                validated_per_page = per_page_int
        except (ValueError, TypeError):
            logger.warning(f"Invalid per_page parameter: {per_page}")
    
    return validated_page, validated_per_page

# Alias for backward compatibility
validate_password_strength = validate_password