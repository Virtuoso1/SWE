"""
Redis-based Session Storage with Encrypted Data

This module provides enterprise-grade session storage using Redis
with encryption, compression, and advanced session management features.
"""

import json
import pickle
import gzip
import time
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import logging
from flask import current_app, session, g
import redis

logger = logging.getLogger(__name__)

class RedisSessionService:
    """
    Enterprise-grade Redis session storage with encryption
    """
    
    def __init__(self, app=None):
        self.app = app
        self._redis_client = None
        self._cipher = None
        self._session_prefix = None
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize Redis session service with Flask app"""
        self.app = app
        app.redis_session_service = self
        
        # Initialize Redis connection
        self._init_redis()
        
        # Initialize encryption
        self._init_encryption()
        
        # Set session prefix
        self._session_prefix = app.config.get('REDIS_SESSION_PREFIX', 'session:')
        
        # Configure Flask session interface
        app.session_interface = self
    
    def _init_redis(self):
        """Initialize Redis connection"""
        try:
            redis_host = current_app.config.get('REDIS_HOST', 'localhost')
            redis_port = current_app.config.get('REDIS_PORT', 6379)
            redis_password = current_app.config.get('REDIS_PASSWORD')
            redis_db = current_app.config.get('REDIS_DB', 0)
            
            # Create Redis connection pool
            self._redis_client = redis.Redis(
                host=redis_host,
                port=redis_port,
                password=redis_password,
                db=redis_db,
                decode_responses=False,  # We'll handle decoding ourselves
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
                max_connections=50,
                health_check_interval=30
            )
            
            # Test connection
            self._redis_client.ping()
            logger.info("Redis connection established for session storage")
            
        except Exception as e:
            logger.error(f"Failed to initialize Redis for sessions: {str(e)}")
            raise RuntimeError(f"Redis initialization failed: {str(e)}")
    
    def _init_encryption(self):
        """Initialize encryption for session data"""
        try:
            # Get encryption key from config
            key = current_app.config.get('SESSION_ENCRYPTION_KEY')
            if not key:
                # Generate key if not provided
                key = Fernet.generate_key().decode()
                logger.warning("No session encryption key provided, generated temporary key")
            
            # Convert to bytes if needed
            key_bytes = key.encode() if isinstance(key, str) else key
            
            # Derive encryption key
            salt = current_app.config.get('SESSION_ENCRYPTION_SALT', 'session_salt').encode()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            derived_key = base64.urlsafe_b64encode(kdf.derive(key_bytes))
            
            self._cipher = Fernet(derived_key)
            
        except Exception as e:
            logger.error(f"Failed to initialize session encryption: {str(e)}")
            raise RuntimeError(f"Session encryption initialization failed: {str(e)}")
    
    def _serialize_session_data(self, data: Dict[str, Any]) -> bytes:
        """
        Serialize and compress session data
        
        Args:
            data: Session data dictionary
            
        Returns:
            Serialized and compressed bytes
        """
        try:
            # Add metadata
            session_data = {
                'data': data,
                'created_at': datetime.utcnow().isoformat(),
                'version': '1.0',
                'checksum': None  # Will be set after serialization
            }
            
            # Serialize with pickle
            serialized = pickle.dumps(session_data)
            
            # Compress if enabled
            if current_app.config.get('SESSION_COMPRESSION_ENABLED', True):
                compressed = gzip.compress(serialized)
                logger.debug(f"Session data compressed: {len(serialized)} -> {len(compressed)} bytes")
                serialized = compressed
            
            # Calculate checksum
            session_data['checksum'] = hashlib.sha256(serialized).hexdigest()
            
            # Re-serialize with checksum
            final_serialized = pickle.dumps(session_data)
            
            # Compress final data if compression was applied
            if current_app.config.get('SESSION_COMPRESSION_ENABLED', True):
                final_serialized = gzip.compress(final_serialized)
            
            return final_serialized
            
        except Exception as e:
            logger.error(f"Failed to serialize session data: {str(e)}")
            raise RuntimeError(f"Session serialization failed: {str(e)}")
    
    def _deserialize_session_data(self, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Deserialize and decompress session data
        
        Args:
            data: Serialized session data bytes
            
        Returns:
            Deserialized session data or None
        """
        try:
            # Decompress if needed
            if current_app.config.get('SESSION_COMPRESSION_ENABLED', True):
                try:
                    data = gzip.decompress(data)
                except:
                    # Data might not be compressed
                    pass
            
            # Deserialize
            session_data = pickle.loads(data)
            
            # Verify checksum
            if 'checksum' in session_data:
                # Re-serialize without checksum to verify
                temp_data = session_data.copy()
                temp_data.pop('checksum')
                temp_serialized = pickle.dumps(temp_data)
                
                if current_app.config.get('SESSION_COMPRESSION_ENABLED', True):
                    temp_serialized = gzip.compress(temp_serialized)
                
                expected_checksum = hashlib.sha256(temp_serialized).hexdigest()
                if session_data['checksum'] != expected_checksum:
                    logger.warning("Session data checksum mismatch - possible tampering")
                    return None
            
            # Verify version
            if session_data.get('version') != '1.0':
                logger.warning(f"Unsupported session version: {session_data.get('version')}")
                return None
            
            return session_data.get('data', {})
            
        except Exception as e:
            logger.error(f"Failed to deserialize session data: {str(e)}")
            return None
    
    def _encrypt_session_data(self, data: bytes) -> bytes:
        """
        Encrypt session data
        
        Args:
            data: Serialized session data bytes
            
        Returns:
            Encrypted bytes
        """
        if not self._cipher:
            return data
        
        try:
            encrypted_data = self._cipher.encrypt(data)
            return encrypted_data
        except Exception as e:
            logger.error(f"Failed to encrypt session data: {str(e)}")
            raise RuntimeError(f"Session encryption failed: {str(e)}")
    
    def _decrypt_session_data(self, encrypted_data: bytes) -> Optional[bytes]:
        """
        Decrypt session data
        
        Args:
            encrypted_data: Encrypted session data bytes
            
        Returns:
            Decrypted bytes or None
        """
        if not self._cipher:
            return encrypted_data
        
        try:
            decrypted_data = self._cipher.decrypt(encrypted_data)
            return decrypted_data
        except Exception as e:
            logger.error(f"Failed to decrypt session data: {str(e)}")
            return None
    
    def generate_session_id(self) -> str:
        """
        Generate a secure session ID
        
        Returns:
            Session ID string
        """
        return str(uuid.uuid4()).replace('-', '')
    
    def create_session(self, session_data: Dict[str, Any], 
                    session_id: Optional[str] = None,
                    expires_in: Optional[int] = None) -> str:
        """
        Create a new session with encrypted storage
        
        Args:
            session_data: Data to store in session
            session_id: Optional session ID (generated if not provided)
            expires_in: Expiration time in seconds (uses config default)
            
        Returns:
            Session ID
        """
        try:
            # Generate session ID if not provided
            if not session_id:
                session_id = self.generate_session_id()
            
            # Set expiration
            if expires_in is None:
                expires_in = current_app.config.get('SESSION_MAX_AGE', 3600)
            
            expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
            
            # Add session metadata
            session_data.update({
                'session_id': session_id,
                'created_at': datetime.utcnow().isoformat(),
                'expires_at': expires_at.isoformat(),
                'last_accessed': datetime.utcnow().isoformat(),
                'ip_address': getattr(g, 'client_ip', None),
                'user_agent': getattr(g, 'user_agent', None)
            })
            
            # Serialize and encrypt session data
            serialized_data = self._serialize_session_data(session_data)
            encrypted_data = self._encrypt_session_data(serialized_data)
            
            # Store in Redis
            session_key = f"{self._session_prefix}{session_id}"
            
            # Use Redis pipeline for atomic operations
            pipe = self._redis_client.pipeline()
            
            # Store session data
            pipe.setex(
                session_key,
                expires_in,
                encrypted_data
            )
            
            # Store session metadata
            metadata_key = f"{self._session_prefix}meta:{session_id}"
            metadata = {
                'created_at': session_data['created_at'],
                'expires_at': session_data['expires_at'],
                'ip_address': session_data['ip_address'],
                'user_agent': session_data['user_agent']
            }
            
            pipe.setex(
                metadata_key,
                expires_in,
                json.dumps(metadata)
            )
            
            # Add to active sessions index
            if 'user_id' in session_data:
                user_sessions_key = f"{self._session_prefix}user:{session_data['user_id']}"
                pipe.sadd(user_sessions_key, session_id)
                pipe.expire(user_sessions_key, expires_in)
            
            # Execute pipeline
            pipe.execute()
            
            logger.info(f"Session created: {session_id}")
            return session_id
            
        except Exception as e:
            logger.error(f"Failed to create session: {str(e)}")
            raise RuntimeError(f"Session creation failed: {str(e)}")
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve and decrypt session data
        
        Args:
            session_id: Session ID to retrieve
            
        Returns:
            Session data dictionary or None
        """
        try:
            session_key = f"{self._session_prefix}{session_id}"
            
            # Get encrypted session data
            encrypted_data = self._redis_client.get(session_key)
            if not encrypted_data:
                logger.debug(f"Session not found: {session_id}")
                return None
            
            # Decrypt and deserialize
            decrypted_data = self._decrypt_session_data(encrypted_data)
            if not decrypted_data:
                logger.warning(f"Failed to decrypt session: {session_id}")
                return None
            
            session_data = self._deserialize_session_data(decrypted_data)
            if not session_data:
                logger.warning(f"Failed to deserialize session: {session_id}")
                return None
            
            # Check expiration
            if 'expires_at' in session_data:
                expires_at = datetime.fromisoformat(session_data['expires_at'])
                if datetime.utcnow() > expires_at:
                    logger.debug(f"Session expired: {session_id}")
                    self.delete_session(session_id)
                    return None
            
            # Update last accessed time
            self.update_last_accessed(session_id)
            
            logger.debug(f"Session retrieved: {session_id}")
            return session_data
            
        except Exception as e:
            logger.error(f"Failed to get session: {str(e)}")
            return None
    
    def update_session(self, session_id: str, 
                   update_data: Dict[str, Any]) -> bool:
        """
        Update existing session with new data
        
        Args:
            session_id: Session ID to update
            update_data: New data to merge with existing
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get current session data
            current_data = self.get_session(session_id)
            if not current_data:
                return False
            
            # Merge with new data
            current_data.update(update_data)
            current_data['last_accessed'] = datetime.utcnow().isoformat()
            
            # Store updated session
            self.create_session(current_data, session_id)
            
            logger.debug(f"Session updated: {session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update session: {str(e)}")
            return False
    
    def update_last_accessed(self, session_id: str) -> bool:
        """
        Update last accessed time for session
        
        Args:
            session_id: Session ID to update
            
        Returns:
            True if successful, False otherwise
        """
        try:
            metadata_key = f"{self._session_prefix}meta:{session_id}"
            
            # Get current metadata
            metadata_json = self._redis_client.get(metadata_key)
            if not metadata_json:
                return False
            
            metadata = json.loads(metadata_json)
            metadata['last_accessed'] = datetime.utcnow().isoformat()
            
            # Update metadata
            self._redis_client.setex(
                metadata_key,
                3600,  # 1 hour
                json.dumps(metadata)
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to update last accessed: {str(e)}")
            return False
    
    def delete_session(self, session_id: str) -> bool:
        """
        Delete a session from Redis
        
        Args:
            session_id: Session ID to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            session_key = f"{self._session_prefix}{session_id}"
            metadata_key = f"{self._session_prefix}meta:{session_id}"
            
            # Get session data for cleanup
            session_data = self.get_session(session_id)
            
            # Use Redis pipeline for atomic deletion
            pipe = self._redis_client.pipeline()
            
            # Delete session data and metadata
            pipe.delete(session_key)
            pipe.delete(metadata_key)
            
            # Remove from user sessions index
            if session_data and 'user_id' in session_data:
                user_sessions_key = f"{self._session_prefix}user:{session_data['user_id']}"
                pipe.srem(user_sessions_key, session_id)
            
            # Execute pipeline
            pipe.execute()
            
            logger.info(f"Session deleted: {session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete session: {str(e)}")
            return False
    
    def get_user_sessions(self, user_id: int) -> List[str]:
        """
        Get all active sessions for a user
        
        Args:
            user_id: User ID to get sessions for
            
        Returns:
            List of session IDs
        """
        try:
            user_sessions_key = f"{self._session_prefix}user:{user_id}"
            
            # Get session IDs from Redis set
            session_ids = self._redis_client.smembers(user_sessions_key)
            
            # Filter valid sessions
            valid_sessions = []
            for session_id in session_ids:
                if self.get_session(session_id):
                    valid_sessions.append(session_id)
            
            return valid_sessions
            
        except Exception as e:
            logger.error(f"Failed to get user sessions: {str(e)}")
            return []
    
    def revoke_user_sessions(self, user_id: int, 
                         except_session_id: Optional[str] = None) -> bool:
        """
        Revoke all sessions for a user except optionally one
        
        Args:
            user_id: User ID to revoke sessions for
            except_session_id: Session ID to keep (optional)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            user_sessions = self.get_user_sessions(user_id)
            revoked_count = 0
            
            for session_id in user_sessions:
                if session_id != except_session_id:
                    if self.delete_session(session_id):
                        revoked_count += 1
            
            logger.info(f"Revoked {revoked_count} sessions for user {user_id}")
            return revoked_count > 0
            
        except Exception as e:
            logger.error(f"Failed to revoke user sessions: {str(e)}")
            return False
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions from Redis
        
        Returns:
            Number of sessions cleaned up
        """
        try:
            # Redis automatically handles expiration with setex
            # This method can be used for manual cleanup or reporting
            
            # Get all session keys
            session_keys = self._redis_client.keys(f"{self._session_prefix}*")
            
            cleaned_count = 0
            for key in session_keys:
                # Skip metadata keys
                if b':meta:' in key:
                    continue
                
                # Check if session exists and is expired
                session_id = key.decode().replace(self._session_prefix.encode(), b'').decode()
                if not self.get_session(session_id):
                    cleaned_count += 1
            
            logger.info(f"Cleaned up {cleaned_count} expired sessions")
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions: {str(e)}")
            return 0
    
    def get_session_stats(self) -> Dict[str, Any]:
        """
        Get session storage statistics
        
        Returns:
            Dictionary with session statistics
        """
        try:
            # Get Redis info
            redis_info = self._redis_client.info()
            
            # Count active sessions
            session_keys = self._redis_client.keys(f"{self._session_prefix}*")
            active_sessions = 0
            for key in session_keys:
                if b':meta:' not in key and b':user:' not in key:
                    active_sessions += 1
            
            # Get memory usage
            memory_used = redis_info.get('used_memory', 0)
            memory_peak = redis_info.get('used_memory_peak', 0)
            
            return {
                'active_sessions': active_sessions,
                'redis_memory_used': memory_used,
                'redis_memory_peak': memory_peak,
                'redis_connected_clients': redis_info.get('connected_clients', 0),
                'redis_total_commands': redis_info.get('total_commands_processed', 0),
                'session_prefix': self._session_prefix,
                'encryption_enabled': self._cipher is not None,
                'compression_enabled': current_app.config.get('SESSION_COMPRESSION_ENABLED', True)
            }
            
        except Exception as e:
            logger.error(f"Failed to get session stats: {str(e)}")
            return {}
    
    # Flask session interface methods
    def open_session(self, app, request):
        """Open session (Flask session interface)"""
        # Get session ID from cookie
        session_id = request.cookies.get(app.config.get('SESSION_COOKIE_NAME', 'session_id'))
        
        if not session_id:
            return {}
        
        # Get session data
        session_data = self.get_session(session_id)
        if not session_data:
            return {}
        
        return session_data
    
    def save_session(self, app, session, response):
        """Save session (Flask session interface)"""
        if not session:
            return
        
        # Get session ID from session or generate new one
        session_id = session.get('session_id')
        if not session_id:
            session_id = self.generate_session_id()
            session['session_id'] = session_id
        
        # Store session
        self.create_session(dict(session), session_id)
        
        # Set session cookie
        cookie_options = {
            'httponly': app.config.get('SESSION_COOKIE_HTTPONLY', True),
            'secure': app.config.get('SESSION_COOKIE_SECURE', False),
            'samesite': app.config.get('SESSION_COOKIE_SAMESITE', 'Lax'),
            'path': app.config.get('SESSION_COOKIE_PATH', '/'),
            'domain': app.config.get('SESSION_COOKIE_DOMAIN'),
            'max_age': app.config.get('SESSION_MAX_AGE', 3600)
        }
        
        response.set_cookie(
            app.config.get('SESSION_COOKIE_NAME', 'session_id'),
            session_id,
            **cookie_options
        )


# Global Redis session service instance
redis_session_service = RedisSessionService()