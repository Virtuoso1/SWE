import re
import secrets
import string
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from config import get_config
import logging

def validate_password_strength(password: str, user_data: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Validate password strength against enterprise requirements
    
    Args:
        password: Password to validate
        user_data: User data for additional checks (email, name, etc.)
        
    Returns:
        Dict containing validation result and details
    """
    return PasswordValidator.validate_password_strength(password, user_data)

logger = logging.getLogger(__name__)

class PasswordValidator:
    """Enterprise-grade password validation with historical checks"""
    
    @staticmethod
    def validate_password_strength(password: str, user_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Validate password strength against enterprise requirements
        
        Args:
            password: Password to validate
            user_data: User data for additional checks (email, name, etc.)
            
        Returns:
            Dict containing validation result and details
        """
        config = get_config()
        result = {
            'is_valid': True,
            'score': 0,
            'issues': [],
            'suggestions': []
        }
        
        # Basic length check
        if len(password) < config.PASSWORD_MIN_LENGTH:
            result['is_valid'] = False
            result['issues'].append(f"Password must be at least {config.PASSWORD_MIN_LENGTH} characters long")
        elif len(password) > config.PASSWORD_MAX_LENGTH:
            result['is_valid'] = False
            result['issues'].append(f"Password must not exceed {config.PASSWORD_MAX_LENGTH} characters")
        else:
            result['score'] += 10
        
        # Character complexity checks
        if config.PASSWORD_REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            result['is_valid'] = False
            result['issues'].append("Password must contain at least one uppercase letter")
        elif re.search(r'[A-Z]', password):
            result['score'] += 15
        
        if config.PASSWORD_REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            result['is_valid'] = False
            result['issues'].append("Password must contain at least one lowercase letter")
        elif re.search(r'[a-z]', password):
            result['score'] += 15
        
        if config.PASSWORD_REQUIRE_NUMBERS and not re.search(r'\d', password):
            result['is_valid'] = False
            result['issues'].append("Password must contain at least one number")
        elif re.search(r'\d', password):
            result['score'] += 15
        
        if config.PASSWORD_REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password):
            result['is_valid'] = False
            result['issues'].append("Password must contain at least one special character")
        elif re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password):
            result['score'] += 15
        
        # Check for common patterns
        common_patterns = [
            r'123456', r'password', r'qwerty', r'abc123', r'admin',
            r'letmein', r'welcome', r'monkey', r'login'
        ]
        
        for pattern in common_patterns:
            if re.search(pattern, password, re.IGNORECASE):
                result['is_valid'] = False
                result['issues'].append("Password contains common patterns that are easily guessable")
                break
        
        # Check for sequential characters
        if PasswordValidator._has_sequential_chars(password):
            result['score'] -= 10
            result['suggestions'].append("Avoid sequential characters (e.g., '123', 'abc')")
        
        # Check for repeated characters
        if PasswordValidator._has_repeated_chars(password):
            result['score'] -= 10
            result['suggestions'].append("Avoid repeated characters (e.g., 'aaa', '111')")
        
        # Check against user information
        if user_data:
            if PasswordValidator._contains_user_info(password, user_data):
                result['is_valid'] = False
                result['issues'].append("Password should not contain your personal information")
        
        # Calculate entropy
        entropy = PasswordValidator._calculate_entropy(password)
        if entropy < 50:
            result['score'] -= 15
            result['suggestions'].append("Consider using a more complex password with higher entropy")
        elif entropy > 70:
            result['score'] += 20
        
        # Add suggestions based on score
        if result['score'] < 60:
            result['suggestions'].extend([
                "Consider using a passphrase with multiple words",
                "Mix different types of characters (letters, numbers, symbols)",
                "Avoid dictionary words and common substitutions"
            ])
        
        # Determine strength level
        if result['score'] >= 80:
            result['strength'] = 'very_strong'
        elif result['score'] >= 60:
            result['strength'] = 'strong'
        elif result['score'] >= 40:
            result['strength'] = 'moderate'
        elif result['score'] >= 20:
            result['strength'] = 'weak'
        else:
            result['strength'] = 'very_weak'
        
        return result
    
    @staticmethod
    def _has_sequential_chars(password: str) -> bool:
        """Check for sequential characters in password"""
        password_lower = password.lower()
        
        # Check for sequential letters
        for i in range(len(password_lower) - 2):
            if (ord(password_lower[i+1]) == ord(password_lower[i]) + 1 and
                ord(password_lower[i+2]) == ord(password_lower[i]) + 2):
                return True
        
        # Check for sequential numbers
        for i in range(len(password) - 2):
            if (password[i].isdigit() and password[i+1].isdigit() and password[i+2].isdigit()):
                if (int(password[i+1]) == int(password[i]) + 1 and
                    int(password[i+2]) == int(password[i]) + 2):
                    return True
        
        return False
    
    @staticmethod
    def _has_repeated_chars(password: str) -> bool:
        """Check for repeated characters in password"""
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                return True
        return False
    
    @staticmethod
    def _contains_user_info(password: str, user_data: Dict[str, Any]) -> bool:
        """Check if password contains user information"""
        password_lower = password.lower()
        
        # Check against email
        email = user_data.get('email', '').lower()
        if email:
            email_parts = email.split('@')
            if email_parts[0] and email_parts[0] in password_lower:
                return True
        
        # Check against name
        full_name = user_data.get('full_name', '').lower()
        if full_name:
            name_parts = full_name.split()
            for part in name_parts:
                if len(part) > 2 and part in password_lower:
                    return True
        
        # Check against phone
        phone = user_data.get('phone', '')
        if phone:
            # Remove non-digit characters
            phone_digits = re.sub(r'\D', '', phone)
            if len(phone_digits) >= 4 and phone_digits in password:
                return True
        
        return False
    
    @staticmethod
    def _calculate_entropy(password: str) -> float:
        """Calculate password entropy"""
        if not password:
            return 0
        
        # Count different character types
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>\/?]', password))
        
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32
        
        # Calculate entropy: log2(charset_size^length)
        import math
        entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
        
        return entropy
    
    @staticmethod
    def generate_secure_password(length: int = 16, include_special: bool = True) -> str:
        """Generate a secure random password"""
        config = get_config()
        
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        # Build character pool
        char_pool = lowercase + uppercase + digits
        if include_special and config.PASSWORD_REQUIRE_SPECIAL:
            char_pool += special
        
        # Ensure password meets requirements
        password = []
        
        # Add at least one of each required type
        if config.PASSWORD_REQUIRE_LOWERCASE:
            password.append(secrets.choice(lowercase))
        if config.PASSWORD_REQUIRE_UPPERCASE:
            password.append(secrets.choice(uppercase))
        if config.PASSWORD_REQUIRE_NUMBERS:
            password.append(secrets.choice(digits))
        if config.PASSWORD_REQUIRE_SPECIAL and include_special:
            password.append(secrets.choice(special))
        
        # Fill remaining length
        remaining_length = max(length - len(password), 0)
        for _ in range(remaining_length):
            password.append(secrets.choice(char_pool))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)

class DeviceFingerprinting:
    """Device fingerprinting for anomaly detection"""
    
    @staticmethod
    def generate_device_fingerprint(request_data: Dict[str, Any]) -> str:
        """
        Generate device fingerprint from request data
        
        Args:
            request_data: Dictionary containing request information
            
        Returns:
            Device fingerprint string
        """
        import hashlib
        
        # Collect fingerprint components
        components = []
        
        # User agent
        user_agent = request_data.get('user_agent', '')
        if user_agent:
            components.append(user_agent)
        
        # Screen resolution (if available)
        screen = request_data.get('screen', {})
        if screen:
            components.append(f"{screen.get('width', 0)}x{screen.get('height', 0)}")
        
        # Timezone
        timezone = request_data.get('timezone', '')
        if timezone:
            components.append(timezone)
        
        # Language
        language = request_data.get('language', '')
        if language:
            components.append(language)
        
        # Platform info
        platform = request_data.get('platform', '')
        if platform:
            components.append(platform)
        
        # Browser plugins (if available)
        plugins = request_data.get('plugins', [])
        if plugins:
            components.append('|'.join(sorted(plugins)))
        
        # Canvas fingerprint (if available)
        canvas = request_data.get('canvas', '')
        if canvas:
            components.append(canvas)
        
        # WebGL fingerprint (if available)
        webgl = request_data.get('webgl', '')
        if webgl:
            components.append(webgl)
        
        # Generate hash
        fingerprint_data = '|'.join(components)
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
        
        return fingerprint
    
    @staticmethod
    def analyze_device_risk(user_id: int, device_fingerprint: str, 
                          ip_address: str) -> Dict[str, Any]:
        """
        Analyze device risk based on historical data
        
        Args:
            user_id: User ID
            device_fingerprint: Device fingerprint
            ip_address: IP address
            
        Returns:
            Dict containing risk analysis
        """
        from db.database import get_connection
        
        risk_score = 0
        risk_factors = []
        
        try:
            conn = get_connection()
            if not conn:
                return {'risk_score': 50, 'risk_factors': ['database_error']}
                
            cursor = conn.cursor(dictionary=True)
            
            # Check if device is known
            cursor.execute("""
                SELECT device_id, is_trusted, last_seen, created_at
                FROM user_devices
                WHERE user_id = %s AND device_fingerprint = %s
            """, (user_id, device_fingerprint))
            
            device = cursor.fetchone()
            
            if not device:
                # New device
                risk_score += 30
                risk_factors.append('new_device')
            else:
                # Check if device is trusted
                if not device['is_trusted']:
                    risk_score += 15
                    risk_factors.append('untrusted_device')
                
                # Check last seen time
                last_seen = device['last_seen']
                if last_seen:
                    days_since_last = (datetime.utcnow() - last_seen).days
                    if days_since_last > 30:
                        risk_score += 10
                        risk_factors.append('device_not_seen_recently')
            
            # Check IP address history
            cursor.execute("""
                SELECT COUNT(*) as ip_count, MAX(attempt_time) as last_seen
                FROM login_attempts
                WHERE user_id = %s AND ip_address = %s AND success = 1
            """, (user_id, ip_address))
            
            ip_data = cursor.fetchone()
            
            if ip_data['ip_count'] == 0:
                # New IP address
                risk_score += 20
                risk_factors.append('new_ip_address')
            else:
                # Check last seen time for IP
                if ip_data['last_seen']:
                    days_since_last = (datetime.utcnow() - ip_data['last_seen']).days
                    if days_since_last > 7:
                        risk_score += 5
                        risk_factors.append('ip_not_seen_recently')
            
            # Check for recent failed attempts from this IP
            cursor.execute("""
                SELECT COUNT(*) as failed_count
                FROM login_attempts
                WHERE ip_address = %s AND success = 0 
                AND attempt_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            """, (ip_address,))
            
            failed_count = cursor.fetchone()['failed_count']
            if failed_count > 5:
                risk_score += 25
                risk_factors.append('high_failed_attempts_from_ip')
            
            # Check for concurrent sessions
            cursor.execute("""
                SELECT COUNT(*) as active_sessions
                FROM user_sessions
                WHERE user_id = %s AND is_active = 1 AND expires_at > NOW()
            """, (user_id,))
            
            active_sessions = cursor.fetchone()['active_sessions']
            if active_sessions > 3:
                risk_score += 10
                risk_factors.append('multiple_active_sessions')
            
            cursor.close()
            conn.close()
            
            # Determine risk level
            if risk_score >= 70:
                risk_level = 'high'
            elif risk_score >= 40:
                risk_level = 'medium'
            else:
                risk_level = 'low'
            
            return {
                'risk_score': risk_score,
                'risk_level': risk_level,
                'risk_factors': risk_factors,
                'device_known': device is not None,
                'device_trusted': device['is_trusted'] if device else False
            }
            
        except Exception as e:
            logger.error(f"Error analyzing device risk: {str(e)}")
            return {'risk_score': 50, 'risk_factors': ['analysis_error']}

class InputValidator:
    """Enhanced input validation for security"""
    
    @staticmethod
    def sanitize_input(input_string: str, allow_html: bool = False) -> str:
        """
        Sanitize user input to prevent injection attacks
        
        Args:
            input_string: Input string to sanitize
            allow_html: Whether to allow certain HTML tags
            
        Returns:
            Sanitized string
        """
        if not input_string or not isinstance(input_string, str):
            return ""
        
        # Basic sanitization
        sanitized = input_string.strip()
        
        if not allow_html:
            # Remove all HTML tags
            sanitized = re.sub(r'<[^>]+>', '', sanitized)
        
        # Remove potentially dangerous characters
        dangerous_patterns = [
            r'javascript:', r'vbscript:', r'onload=', r'onerror=',
            r'onmouseover=', r'onclick=', r'data:', r'file:',
            r'ftp:', r'http://', r'https://'
        ]
        
        for pattern in dangerous_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        # Limit length
        max_length = 1000
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized
    
    @staticmethod
    def validate_email_advanced(email: str) -> Dict[str, Any]:
        """
        Advanced email validation
        
        Args:
            email: Email address to validate
            
        Returns:
            Dict containing validation result
        """
        result = {
            'is_valid': True,
            'issues': [],
            'normalized': None
        }
        
        if not email or not isinstance(email, str):
            result['is_valid'] = False
            result['issues'].append("Email is required")
            return result
        
        email = email.strip().lower()
        result['normalized'] = email
        
        # Basic format check
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            result['is_valid'] = False
            result['issues'].append("Invalid email format")
            return result
        
        # Length checks
        if len(email) > 254:
            result['is_valid'] = False
            result['issues'].append("Email address is too long")
        
        # Local part checks
        local_part = email.split('@')[0]
        if len(local_part) > 64:
            result['is_valid'] = False
            result['issues'].append("Email local part is too long")
        
        # Domain checks
        domain = email.split('@')[1]
        if len(domain) > 253:
            result['is_valid'] = False
            result['issues'].append("Email domain is too long")
        
        # Check for consecutive dots
        if '..' in email:
            result['is_valid'] = False
            result['issues'].append("Email cannot contain consecutive dots")
        
        # Check for leading/trailing dots
        if local_part.startswith('.') or local_part.endswith('.'):
            result['is_valid'] = False
            result['issues'].append("Email local part cannot start or end with a dot")
        
        # Check for common disposable email domains
        disposable_domains = [
            '10minutemail.com', 'guerrillamail.com', 'mailinator.com',
            'tempmail.org', 'yopmail.com', 'throwaway.email'
        ]
        
        domain_parts = domain.split('.')
        for disposable_domain in disposable_domains:
            if disposable_domain in domain:
                result['issues'].append("Disposable email addresses are not allowed")
                # Note: Not marking as invalid, just adding warning
        
        return result
    
    @staticmethod
    def validate_phone_number(phone: str, country_code: str = 'US') -> Dict[str, Any]:
        """
        Validate phone number format
        
        Args:
            phone: Phone number to validate
            country_code: Country code for validation rules
            
        Returns:
            Dict containing validation result
        """
        result = {
            'is_valid': True,
            'issues': [],
            'normalized': None
        }
        
        if not phone:
            return result  # Phone is optional
        
        # Remove all non-digit characters
        digits_only = re.sub(r'\D', '', phone)
        
        # Basic length check
        if len(digits_only) < 10:
            result['is_valid'] = False
            result['issues'].append("Phone number is too short")
            return result
        
        if len(digits_only) > 15:
            result['is_valid'] = False
            result['issues'].append("Phone number is too long")
            return result
        
        # Country-specific validation
        if country_code == 'US':
            # US phone number validation
            if len(digits_only) == 10:
                # Standard 10-digit US number
                normalized = f"+1{digits_only}"
            elif len(digits_only) == 11 and digits_only.startswith('1'):
                # US number with country code
                normalized = f"+{digits_only}"
            else:
                result['is_valid'] = False
                result['issues'].append("Invalid US phone number format")
                return result
        else:
            # International format
            normalized = f"+{digits_only}"
        
        result['normalized'] = normalized
        return result

class RateLimitValidator:
    """Advanced rate limiting validation"""
    
    @staticmethod
    def check_rate_limit_advanced(identifier: str, action: str, 
                               custom_limits: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Advanced rate limiting with multiple windows
        
        Args:
            identifier: Unique identifier (email, IP, user_id, etc.)
            action: Action being rate limited
            custom_limits: Custom limit configuration
            
        Returns:
            Dict containing rate limit status
        """
        from db.database import get_connection
        
        result = {
            'allowed': True,
            'remaining': 0,
            'reset_time': None,
            'retry_after': None
        }
        
        try:
            conn = get_connection()
            if not conn:
                return result
                
            cursor = conn.cursor(dictionary=True)
            
            # Define rate limit windows
            windows = [
                {'name': 'minute', 'duration': 60, 'max_requests': 5},
                {'name': 'hour', 'duration': 3600, 'max_requests': 20},
                {'name': 'day', 'duration': 86400, 'max_requests': 100}
            ]
            
            # Apply custom limits if provided
            if custom_limits:
                for window in windows:
                    if window['name'] in custom_limits:
                        window['max_requests'] = custom_limits[window['name']]
            
            # Check each window
            for window in windows:
                cursor.execute("""
                    SELECT COUNT(*) as request_count,
                           MAX(window_start) as last_window_start
                    FROM rate_limits
                    WHERE identifier = %s AND window_type = %s
                    AND window_start > DATE_SUB(NOW(), INTERVAL %s SECOND)
                """, (identifier, window['name'], window['duration']))
                
                data = cursor.fetchone()
                request_count = data['request_count'] if data else 0
                
                if request_count >= window['max_requests']:
                    result['allowed'] = False
                    result['retry_after'] = window['duration']
                    
                    # Calculate reset time
                    if data['last_window_start']:
                        reset_time = data['last_window_start'] + timedelta(seconds=window['duration'])
                        result['reset_time'] = reset_time.isoformat()
                    
                    break
                else:
                    result['remaining'] = min(result['remaining'], 
                                           window['max_requests'] - request_count)
            
            cursor.close()
            conn.close()
            
            return result
            
        except Exception as e:
            logger.error(f"Rate limit check error: {str(e)}")
            return result
    
    @staticmethod
    def validate_ip_address(ip_address: str) -> bool:
        """
        Validate IP address (IPv4 or IPv6)
        
        Args:
            ip_address: IP address string to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            import ipaddress
            ipaddress.ip_address(ip_address)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_ip_range(ip_range: str) -> bool:
        """
        Validate IP range in CIDR notation
        
        Args:
            ip_range: IP range in CIDR notation (e.g., "192.168.1.0/24")
            
        Returns:
            True if valid, False otherwise
        """
        try:
            import ipaddress
            ipaddress.ip_network(ip_range, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_private_ip(ip_address: str) -> bool:
        """
        Check if IP address is private/internal
        
        Args:
            ip_address: IP address string to check
            
        Returns:
            True if private IP, False otherwise
        """
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private
        except ValueError:
            return False
    
    @staticmethod
    def is_reserved_ip(ip_address: str) -> bool:
        """
        Check if IP address is reserved
        
        Args:
            ip_address: IP address string to check
            
        Returns:
            True if reserved IP, False otherwise
        """
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)
            return ip.is_reserved
        except ValueError:
            return False
    
    @staticmethod
    def get_ip_country(ip_address: str) -> Optional[str]:
        """
        Get country code for IP address (placeholder for GeoIP integration)
        
        Args:
            ip_address: IP address string
            
        Returns:
            Country code or None if not available
        """
        # This would integrate with a GeoIP database like MaxMind
        # For now, return None as placeholder
        return None
    
    @staticmethod
    def validate_rate_limit_params(limit: int, window: int) -> Dict[str, Any]:
        """
        Validate rate limiting parameters
        
        Args:
            limit: Maximum requests allowed
            window: Time window in seconds
            
        Returns:
            Validation result
        """
        issues = []
        
        if not isinstance(limit, int) or limit < 1:
            issues.append('Limit must be a positive integer')
        
        if not isinstance(window, int) or window < 1:
            issues.append('Window must be a positive integer')
        
        if limit > 100000:
            issues.append('Limit cannot exceed 100,000')
        
        if window > 86400:  # 24 hours
            issues.append('Window cannot exceed 24 hours')
        
        return {
            'is_valid': len(issues) == 0,
            'issues': issues
        }

def validate_pagination(page: int, per_page: int, max_per_page: int = 100) -> Dict[str, Any]:
    """
    Validate pagination parameters
    
    Args:
        page: Page number
        per_page: Items per page
        max_per_page: Maximum allowed items per page
        
    Returns:
        Dict containing validation result
    """
    issues = []
    
    if not isinstance(page, int) or page < 1:
        issues.append('Page must be a positive integer')
    
    if not isinstance(per_page, int) or per_page < 1:
        issues.append('Per page must be a positive integer')
    elif per_page > max_per_page:
        issues.append(f'Per page cannot exceed {max_per_page}')
    
    return {
        'is_valid': len(issues) == 0,
        'issues': issues,
        'page': max(1, page) if isinstance(page, int) else 1,
        'per_page': min(max(1, per_page), max_per_page) if isinstance(per_page, int) else 10
    }

def validate_sort_order(sort_by: str, valid_fields: List[str],
                      sort_order: str = 'asc') -> Dict[str, Any]:
    """
    Validate sort order parameters
    
    Args:
        sort_by: Field to sort by
        valid_fields: List of valid sort fields
        sort_order: Sort order ('asc' or 'desc')
        
    Returns:
        Dict containing validation result
    """
    issues = []
    
    if sort_by and sort_by not in valid_fields:
        issues.append(f'Invalid sort field. Must be one of: {", ".join(valid_fields)}')
    
    if sort_order not in ['asc', 'desc']:
        issues.append('Sort order must be "asc" or "desc"')
    
    return {
        'is_valid': len(issues) == 0,
        'issues': issues,
        'sort_by': sort_by if sort_by in valid_fields else valid_fields[0],
        'sort_order': sort_order if sort_order in ['asc', 'desc'] else 'asc'
    }