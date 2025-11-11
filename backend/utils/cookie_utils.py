"""
Secure Cookie Utilities for Enterprise Authentication System

This module provides secure cookie handling with encryption, signing,
and validation for enterprise-grade security requirements.
"""

import json
import hmac
import hashlib
import time
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import current_app, request, make_response
from typing import Dict, Any, Optional, Union


class SecureCookieManager:
    """
    Enterprise-grade secure cookie manager with encryption and signing
    """
    
    def __init__(self, app=None):
        self.app = app
        self._cipher = None
        self._signing_key = None
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the cookie manager with Flask app"""
        self.app = app
        
        # Initialize encryption cipher
        self._init_cipher()
        
        # Initialize signing key
        self._init_signing_key()
    
    def _init_cipher(self):
        """Initialize the encryption cipher using PBKDF2"""
        # Get encryption key from config or generate one
        key = current_app.config.get('COOKIE_SIGNATURE_KEY')
        if not key:
            raise ValueError("COOKIE_SIGNATURE_KEY must be configured")
        
        # Convert hex string to bytes
        key_bytes = bytes.fromhex(key) if isinstance(key, str) else key
        
        # Use PBKDF2 to derive encryption key
        salt = current_app.config.get('COOKIE_SALT', 'cookie_salt_key').encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(key_bytes))
        
        self._cipher = Fernet(derived_key)
    
    def _init_signing_key(self):
        """Initialize the HMAC signing key"""
        key = current_app.config.get('COOKIE_SIGNATURE_KEY')
        if not key:
            raise ValueError("COOKIE_SIGNATURE_KEY must be configured")
        
        self._signing_key = key.encode() if isinstance(key, str) else key
    
    def _sign_data(self, data: str) -> str:
        """Sign data using HMAC-SHA256"""
        signature = hmac.new(
            self._signing_key,
            data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return signature
    
    def _verify_signature(self, data: str, signature: str) -> bool:
        """Verify HMAC signature"""
        expected_signature = self._sign_data(data)
        return hmac.compare_digest(expected_signature, signature)
    
    def _encrypt_data(self, data: str) -> str:
        """Encrypt data using Fernet symmetric encryption"""
        if not self._cipher:
            raise RuntimeError("Cipher not initialized")
        
        encrypted_data = self._cipher.encrypt(data.encode('utf-8'))
        return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
    
    def _decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt data using Fernet symmetric encryption"""
        if not self._cipher:
            raise RuntimeError("Cipher not initialized")
        
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            decrypted_data = self._cipher.decrypt(encrypted_bytes)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            current_app.logger.error(f"Cookie decryption failed: {str(e)}")
            raise ValueError("Invalid or corrupted cookie data")
    
    def _serialize_data(self, data: Dict[str, Any]) -> str:
        """Serialize data to JSON string"""
        try:
            return json.dumps(data, separators=(',', ':'), sort_keys=True)
        except Exception as e:
            current_app.logger.error(f"Cookie serialization failed: {str(e)}")
            raise ValueError("Failed to serialize cookie data")
    
    def _deserialize_data(self, data: str) -> Dict[str, Any]:
        """Deserialize JSON string to dictionary"""
        try:
            return json.loads(data)
        except Exception as e:
            current_app.logger.error(f"Cookie deserialization failed: {str(e)}")
            raise ValueError("Invalid or corrupted cookie data")
    
    def set_secure_cookie(
        self,
        response,
        name: str,
        value: Dict[str, Any],
        max_age: Optional[int] = None,
        expires: Optional[int] = None,
        path: Optional[str] = None,
        domain: Optional[str] = None,
        secure: Optional[bool] = None,
        httponly: Optional[bool] = None,
        samesite: Optional[str] = None,
        partitioned: Optional[bool] = None
    ) -> None:
        """
        Set a secure cookie with encryption and signing
        
        Args:
            response: Flask response object
            name: Cookie name
            value: Dictionary value to store
            max_age: Cookie max age in seconds
            expires: Expiration timestamp
            path: Cookie path
            domain: Cookie domain
            secure: HTTPS only flag
            httponly: HttpOnly flag
            samesite: SameSite policy
            partitioned: Partitioned cookie flag (CHIPS)
        """
        # Get default values from config
        cookie_config = current_app.config.get('COOKIE_SECURITY', {})
        
        max_age = max_age or cookie_config.get('max_age', 3600)
        secure = secure if secure is not None else cookie_config.get('secure', True)
        httponly = httponly if httponly is not None else cookie_config.get('httponly', True)
        samesite = samesite or cookie_config.get('samesite', 'Lax')
        path = path or cookie_config.get('path', '/')
        domain = domain or cookie_config.get('domain')
        partitioned = partitioned if partitioned is not None else cookie_config.get('partitioned', False)
        
        # Add timestamp for freshness validation
        value['_timestamp'] = int(time.time())
        value['_version'] = '1.0'
        
        # Serialize the data
        serialized_data = self._serialize_data(value)
        
        # Encrypt the data if encryption is enabled
        if current_app.config.get('COOKIE_ENCRYPTION', True):
            encrypted_data = self._encrypt_data(serialized_data)
            # Sign the encrypted data
            signature = self._sign_data(encrypted_data)
            # Combine encrypted data and signature
            cookie_value = f"{encrypted_data}.{signature}"
        else:
            # Sign the serialized data directly
            signature = self._sign_data(serialized_data)
            # Combine data and signature
            cookie_value = f"{serialized_data}.{signature}"
        
        # Set the cookie with security attributes
        response.set_cookie(
            name,
            cookie_value,
            max_age=max_age,
            expires=expires,
            path=path,
            domain=domain,
            secure=secure,
            httponly=httponly,
            samesite=samesite
        )
        
        # Add additional security headers for partitioned cookies
        if partitioned:
            response.headers['Set-Cookie'] = response.headers.get('Set-Cookie', '') + '; Partitioned'
        
        current_app.logger.debug(f"Secure cookie '{name}' set successfully")
    
    def get_secure_cookie(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get and validate a secure cookie
        
        Args:
            name: Cookie name
            
        Returns:
            Dictionary value or None if invalid
        """
        cookie_value = request.cookies.get(name)
        if not cookie_value:
            return None
        
        try:
            # Split cookie value into data and signature
            parts = cookie_value.split('.')
            if len(parts) != 2:
                current_app.logger.warning(f"Invalid cookie format for '{name}'")
                return None
            
            data_part, signature_part = parts
            
            # Verify signature
            if not self._verify_signature(data_part, signature_part):
                current_app.logger.warning(f"Invalid cookie signature for '{name}'")
                return None
            
            # Decrypt data if encryption is enabled
            if current_app.config.get('COOKIE_ENCRYPTION', True):
                decrypted_data = self._decrypt_data(data_part)
            else:
                decrypted_data = data_part
            
            # Deserialize the data
            value = self._deserialize_data(decrypted_data)
            
            # Validate timestamp for freshness
            if '_timestamp' in value:
                timestamp = value['_timestamp']
                max_age = current_app.config.get('COOKIE_SECURITY', {}).get('max_age', 3600)
                if int(time.time()) - timestamp > max_age:
                    current_app.logger.warning(f"Expired cookie '{name}'")
                    return None
            
            # Validate version
            if '_version' in value and value['_version'] != '1.0':
                current_app.logger.warning(f"Unsupported cookie version for '{name}'")
                return None
            
            # Remove metadata before returning
            value.pop('_timestamp', None)
            value.pop('_version', None)
            
            current_app.logger.debug(f"Secure cookie '{name}' retrieved successfully")
            return value
            
        except Exception as e:
            current_app.logger.error(f"Error processing cookie '{name}': {str(e)}")
            return None
    
    def delete_secure_cookie(
        self,
        response,
        name: str,
        path: Optional[str] = None,
        domain: Optional[str] = None
    ) -> None:
        """
        Delete a secure cookie
        
        Args:
            response: Flask response object
            name: Cookie name
            path: Cookie path
            domain: Cookie domain
        """
        cookie_config = current_app.config.get('COOKIE_SECURITY', {})
        path = path or cookie_config.get('path', '/')
        domain = domain or cookie_config.get('domain')
        
        response.delete_cookie(
            name,
            path=path,
            domain=domain
        )
        
        current_app.logger.debug(f"Secure cookie '{name}' deleted")
    
    def rotate_cookie(
        self,
        response,
        name: str,
        new_value: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Rotate a cookie (delete old and set new)
        
        Args:
            response: Flask response object
            name: Cookie name
            new_value: New value to set (if None, uses current value)
            
        Returns:
            Previous cookie value or None
        """
        # Get current value
        current_value = self.get_secure_cookie(name)
        
        # Delete old cookie
        self.delete_secure_cookie(response, name)
        
        # Set new cookie if value provided
        if new_value is not None:
            self.set_secure_cookie(response, name, new_value)
        elif current_value is not None:
            # Re-set with current value to rotate signature
            self.set_secure_cookie(response, name, current_value)
        
        return current_value
    
    def validate_cookie_integrity(self, name: str) -> bool:
        """
        Validate cookie integrity without decrypting
        
        Args:
            name: Cookie name
            
        Returns:
            True if cookie is valid, False otherwise
        """
        cookie_value = request.cookies.get(name)
        if not cookie_value:
            return False
        
        try:
            parts = cookie_value.split('.')
            if len(parts) != 2:
                return False
            
            data_part, signature_part = parts
            return self._verify_signature(data_part, signature_part)
        except Exception:
            return False


# Global cookie manager instance
cookie_manager = SecureCookieManager()


def set_secure_cookie(
    response,
    name: str,
    value: Dict[str, Any],
    **kwargs
) -> None:
    """Convenience function to set a secure cookie"""
    cookie_manager.set_secure_cookie(response, name, value, **kwargs)


def get_secure_cookie(name: str) -> Optional[Dict[str, Any]]:
    """Convenience function to get a secure cookie"""
    return cookie_manager.get_secure_cookie(name)


def delete_secure_cookie(
    response,
    name: str,
    **kwargs
) -> None:
    """Convenience function to delete a secure cookie"""
    cookie_manager.delete_secure_cookie(response, name, **kwargs)


def rotate_cookie(
    response,
    name: str,
    new_value: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    """Convenience function to rotate a secure cookie"""
    return cookie_manager.rotate_cookie(response, name, new_value)


def validate_cookie_integrity(name: str) -> bool:
    """Convenience function to validate cookie integrity"""
    return cookie_manager.validate_cookie_integrity(name)