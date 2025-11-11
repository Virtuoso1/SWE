"""
Comprehensive Audit Logging Service with Tamper-Proof Storage

This module provides enterprise-grade audit logging with cryptographic integrity,
tamper detection, and secure storage for compliance and security monitoring.
"""

import json
import hashlib
import hmac
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import logging
from flask import current_app, request, g
from db.database import get_connection

logger = logging.getLogger(__name__)

class AuditService:
    """
    Enterprise-grade audit logging service with tamper-proof storage
    """
    
    def __init__(self, app=None):
        self.app = app
        self._cipher = None
        self._signing_key = None
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize audit service with Flask app"""
        self.app = app
        app.audit_service = self
        
        # Initialize encryption
        self._init_encryption()
        
        # Initialize signing
        self._init_signing()
        
        # Create audit log table if needed
        self._create_audit_table()
    
    def _init_encryption(self):
        """Initialize encryption for sensitive audit data"""
        try:
            # Get encryption key from config
            key = current_app.config.get('AUDIT_ENCRYPTION_KEY')
            if not key:
                # Generate key if not provided
                key = Fernet.generate_key().decode()
                logger.warning("No audit encryption key provided, generated temporary key")
            
            # Convert to bytes if needed
            if isinstance(key, str):
                key_bytes = key.encode()
            else:
                key_bytes = key
            
            # Derive encryption key
            salt = current_app.config.get('AUDIT_ENCRYPTION_SALT', b'audit_salt').encode()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            derived_key = base64.urlsafe_b64encode(kdf.derive(key_bytes))
            
            self._cipher = Fernet(derived_key)
            
        except Exception as e:
            logger.error(f"Failed to initialize audit encryption: {str(e)}")
            raise
    
    def _init_signing(self):
        """Initialize HMAC signing for tamper protection"""
        try:
            key = current_app.config.get('AUDIT_SIGNING_KEY')
            if not key:
                # Generate key if not provided
                key = base64.urlsafe_b64encode(uuid.uuid4().bytes).decode()
                logger.warning("No audit signing key provided, generated temporary key")
            
            self._signing_key = key.encode() if isinstance(key, str) else key
            
        except Exception as e:
            logger.error(f"Failed to initialize audit signing: {str(e)}")
            raise
    
    def _create_audit_table(self):
        """Create audit log table if it doesn't exist"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Create audit_logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    event_id VARCHAR(64) UNIQUE NOT NULL,
                    timestamp DATETIME(3) NOT NULL,
                    event_type VARCHAR(50) NOT NULL,
                    category VARCHAR(50) NOT NULL,
                    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
                    user_id BIGINT,
                    session_id VARCHAR(64),
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    resource_type VARCHAR(50),
                    resource_id VARCHAR(100),
                    action VARCHAR(100),
                    outcome ENUM('SUCCESS', 'FAILURE', 'ERROR') NOT NULL,
                    details_encrypted TEXT,
                    details_hash VARCHAR(64),
                    previous_hash VARCHAR(64),
                    current_hash VARCHAR(64) NOT NULL,
                    signature VARCHAR(128) NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_timestamp (timestamp),
                    INDEX idx_event_type (event_type),
                    INDEX idx_user_id (user_id),
                    INDEX idx_category (category),
                    INDEX idx_severity (severity),
                    INDEX idx_outcome (outcome)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Create audit_chain table for tamper detection
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_chain (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    event_id VARCHAR(64) NOT NULL,
                    previous_hash VARCHAR(64) NOT NULL,
                    current_hash VARCHAR(64) NOT NULL,
                    signature VARCHAR(128) NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_event_id (event_id),
                    INDEX idx_current_hash (current_hash)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info("Audit log tables created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create audit tables: {str(e)}")
            return False
    
    def _encrypt_data(self, data: str) -> str:
        """Encrypt sensitive audit data"""
        if not self._cipher or not current_app.config.get('AUDIT_LOG_ENCRYPTION', True):
            return data
        
        try:
            encrypted_data = self._cipher.encrypt(data.encode('utf-8'))
            return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to encrypt audit data: {str(e)}")
            return data
    
    def _decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive audit data"""
        if not self._cipher or not current_app.config.get('AUDIT_LOG_ENCRYPTION', True):
            return encrypted_data
        
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode('utf-8'))
            decrypted_data = self._cipher.decrypt(encrypted_bytes)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to decrypt audit data: {str(e)}")
            return encrypted_data
    
    def _sign_data(self, data: str) -> str:
        """Sign audit data with HMAC"""
        if not self._signing_key:
            return ''
        
        try:
            signature = hmac.new(
                self._signing_key,
                data.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            return signature
        except Exception as e:
            logger.error(f"Failed to sign audit data: {str(e)}")
            return ''
    
    def _calculate_hash(self, data: Dict[str, Any]) -> str:
        """Calculate hash for audit data"""
        try:
            # Sort keys for consistent hashing
            sorted_data = json.dumps(data, sort_keys=True, separators=(',', ':'))
            return hashlib.sha256(sorted_data.encode('utf-8')).hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate audit hash: {str(e)}")
            return ''
    
    def _get_previous_hash(self) -> str:
        """Get hash of the most recent audit entry"""
        try:
            conn = get_connection()
            if not conn:
                return ''
                
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT current_hash FROM audit_logs 
                ORDER BY timestamp DESC, id DESC 
                LIMIT 1
            """)
            
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            
            return result[0] if result else ''
            
        except Exception as e:
            logger.error(f"Failed to get previous hash: {str(e)}")
            return ''
    
    def log_event(
        self,
        event_type: str,
        category: str,
        severity: str = 'MEDIUM',
        user_id: Optional[int] = None,
        session_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        action: Optional[str] = None,
        outcome: str = 'SUCCESS',
        details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Log an audit event with tamper protection
        
        Args:
            event_type: Type of event (e.g., 'LOGIN', 'LOGOUT', 'DATA_ACCESS')
            category: Category of event (e.g., 'AUTHENTICATION', 'AUTHORIZATION', 'DATA')
            severity: Severity level ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
            user_id: User ID if applicable
            session_id: Session ID if applicable
            ip_address: IP address of the client
            user_agent: User agent string
            resource_type: Type of resource accessed
            resource_id: ID of resource accessed
            action: Action performed
            outcome: Outcome of the action ('SUCCESS', 'FAILURE', 'ERROR')
            details: Additional details about the event
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Generate unique event ID
            event_id = str(uuid.uuid4())
            
            # Get current timestamp
            timestamp = datetime.utcnow()
            
            # Get request context if available
            if request:
                ip_address = ip_address or request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR'))
                user_agent = user_agent or request.headers.get('User-Agent', '')
                session_id = session_id or getattr(g, 'session_id', None)
            
            # Prepare audit data
            audit_data = {
                'event_id': event_id,
                'timestamp': timestamp.isoformat(),
                'event_type': event_type,
                'category': category,
                'severity': severity,
                'user_id': user_id,
                'session_id': session_id,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'resource_type': resource_type,
                'resource_id': resource_id,
                'action': action,
                'outcome': outcome,
                'details': details or {}
            }
            
            # Get previous hash for chain integrity
            previous_hash = self._get_previous_hash()
            
            # Calculate current hash
            current_hash = self._calculate_hash(audit_data)
            
            # Prepare data for signing
            sign_data = f"{event_id}:{timestamp.isoformat()}:{event_type}:{category}:{severity}:{current_hash}:{previous_hash}"
            
            # Sign the data
            signature = self._sign_data(sign_data)
            
            # Encrypt sensitive details
            details_json = json.dumps(details or {})
            details_encrypted = self._encrypt_data(details_json)
            details_hash = hashlib.sha256(details_json.encode('utf-8')).hexdigest()
            
            # Store in database
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Insert audit log
            cursor.execute("""
                INSERT INTO audit_logs (
                    event_id, timestamp, event_type, category, severity,
                    user_id, session_id, ip_address, user_agent,
                    resource_type, resource_id, action, outcome,
                    details_encrypted, details_hash, previous_hash, current_hash, signature
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                event_id, timestamp, event_type, category, severity,
                user_id, session_id, ip_address, user_agent,
                resource_type, resource_id, action, outcome,
                details_encrypted, details_hash, previous_hash, current_hash, signature
            ))
            
            # Insert into chain for tamper detection
            cursor.execute("""
                INSERT INTO audit_chain (event_id, previous_hash, current_hash, signature)
                VALUES (%s, %s, %s, %s)
            """, (event_id, previous_hash, current_hash, signature))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"Audit event logged: {event_type} - {event_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {str(e)}")
            return False
    
    def verify_integrity(self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Verify audit log integrity for tamper detection
        
        Args:
            start_date: Start date for verification
            end_date: End date for verification
            
        Returns:
            Dictionary with integrity check results
        """
        try:
            conn = get_connection()
            if not conn:
                return {'valid': False, 'error': 'Database connection failed'}
                
            cursor = conn.cursor()
            
            # Build query with date filters
            query = """
                SELECT event_id, timestamp, event_type, category, severity,
                       user_id, session_id, ip_address, user_agent,
                       resource_type, resource_id, action, outcome,
                       details_hash, previous_hash, current_hash, signature
                FROM audit_logs
            """
            params = []
            
            if start_date:
                query += " WHERE timestamp >= %s"
                params.append(start_date)
            
            if end_date:
                query += " AND timestamp <= %s" if start_date else " WHERE timestamp <= %s"
                params.append(end_date)
            
            query += " ORDER BY timestamp, id"
            
            cursor.execute(query, params)
            records = cursor.fetchall()
            cursor.close()
            conn.close()
            
            if not records:
                return {'valid': True, 'message': 'No audit records found'}
            
            # Verify each record
            issues = []
            previous_hash = None
            
            for record in records:
                (event_id, timestamp, event_type, category, severity,
                 user_id, session_id, ip_address, user_agent,
                 resource_type, resource_id, action, outcome,
                 details_hash, record_previous_hash, current_hash, signature) = record
                
                # Verify hash chain
                if previous_hash and record_previous_hash != previous_hash:
                    issues.append({
                        'event_id': event_id,
                        'type': 'HASH_CHAIN_BREAK',
                        'message': f'Hash chain broken at {event_id}'
                    })
                
                # Verify signature
                audit_data = {
                    'event_id': event_id,
                    'timestamp': timestamp.isoformat() if hasattr(timestamp, 'isoformat') else timestamp,
                    'event_type': event_type,
                    'category': category,
                    'severity': severity,
                    'user_id': user_id,
                    'session_id': session_id,
                    'ip_address': ip_address,
                    'user_agent': user_agent,
                    'resource_type': resource_type,
                    'resource_id': resource_id,
                    'action': action,
                    'outcome': outcome
                }
                
                calculated_hash = self._calculate_hash(audit_data)
                if calculated_hash != current_hash:
                    issues.append({
                        'event_id': event_id,
                        'type': 'HASH_MISMATCH',
                        'message': f'Hash mismatch for {event_id}'
                    })
                
                # Verify signature
                sign_data = f"{event_id}:{timestamp}:{event_type}:{category}:{severity}:{current_hash}:{record_previous_hash}"
                expected_signature = self._sign_data(sign_data)
                if signature != expected_signature:
                    issues.append({
                        'event_id': event_id,
                        'type': 'SIGNATURE_MISMATCH',
                        'message': f'Signature mismatch for {event_id}'
                    })
                
                previous_hash = current_hash
            
            return {
                'valid': len(issues) == 0,
                'total_records': len(records),
                'issues': issues,
                'verified_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to verify audit integrity: {str(e)}")
            return {'valid': False, 'error': str(e)}
    
    def get_audit_logs(
        self,
        event_type: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        user_id: Optional[int] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """
        Retrieve audit logs with filtering options
        
        Args:
            event_type: Filter by event type
            category: Filter by category
            severity: Filter by severity
            user_id: Filter by user ID
            start_date: Filter by start date
            end_date: Filter by end date
            limit: Maximum number of records to return
            offset: Number of records to skip
            
        Returns:
            List of audit log entries
        """
        try:
            conn = get_connection()
            if not conn:
                return []
                
            cursor = conn.cursor()
            
            # Build query with filters
            query = """
                SELECT event_id, timestamp, event_type, category, severity,
                       user_id, session_id, ip_address, user_agent,
                       resource_type, resource_id, action, outcome,
                       details_encrypted, details_hash
                FROM audit_logs
                WHERE 1=1
            """
            params = []
            
            if event_type:
                query += " AND event_type = %s"
                params.append(event_type)
            
            if category:
                query += " AND category = %s"
                params.append(category)
            
            if severity:
                query += " AND severity = %s"
                params.append(severity)
            
            if user_id:
                query += " AND user_id = %s"
                params.append(user_id)
            
            if start_date:
                query += " AND timestamp >= %s"
                params.append(start_date)
            
            if end_date:
                query += " AND timestamp <= %s"
                params.append(end_date)
            
            query += " ORDER BY timestamp DESC, id DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])
            
            cursor.execute(query, params)
            records = cursor.fetchall()
            cursor.close()
            conn.close()
            
            # Process records
            logs = []
            for record in records:
                (event_id, timestamp, event_type, category, severity,
                 user_id, session_id, ip_address, user_agent,
                 resource_type, resource_id, action, outcome,
                 details_encrypted, details_hash) = record
                
                # Decrypt details if needed
                details = {}
                if details_encrypted:
                    try:
                        details_json = self._decrypt_data(details_encrypted)
                        details = json.loads(details_json)
                    except Exception as e:
                        logger.error(f"Failed to decrypt audit details for {event_id}: {str(e)}")
                
                logs.append({
                    'event_id': event_id,
                    'timestamp': timestamp.isoformat() if hasattr(timestamp, 'isoformat') else timestamp,
                    'event_type': event_type,
                    'category': category,
                    'severity': severity,
                    'user_id': user_id,
                    'session_id': session_id,
                    'ip_address': ip_address,
                    'user_agent': user_agent,
                    'resource_type': resource_type,
                    'resource_id': resource_id,
                    'action': action,
                    'outcome': outcome,
                    'details': details
                })
            
            return logs
            
        except Exception as e:
            logger.error(f"Failed to retrieve audit logs: {str(e)}")
            return []
    
    def cleanup_old_logs(self, retention_days: Optional[int] = None) -> Dict[str, Any]:
        """
        Clean up old audit logs based on retention policy
        
        Args:
            retention_days: Number of days to retain logs (from config if not provided)
            
        Returns:
            Dictionary with cleanup results
        """
        try:
            retention_days = retention_days or current_app.config.get('AUDIT_LOG_RETENTION_DAYS', 365)
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            
            conn = get_connection()
            if not conn:
                return {'success': False, 'error': 'Database connection failed'}
                
            cursor = conn.cursor()
            
            # Get count before deletion
            cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE timestamp < %s", (cutoff_date,))
            count_to_delete = cursor.fetchone()[0]
            
            if count_to_delete == 0:
                cursor.close()
                conn.close()
                return {'success': True, 'deleted_count': 0, 'message': 'No old logs to delete'}
            
            # Delete old logs
            cursor.execute("DELETE FROM audit_logs WHERE timestamp < %s", (cutoff_date,))
            cursor.execute("DELETE FROM audit_chain WHERE created_at < %s", (cutoff_date,))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"Cleaned up {count_to_delete} old audit logs")
            
            return {
                'success': True,
                'deleted_count': count_to_delete,
                'cutoff_date': cutoff_date.isoformat(),
                'retention_days': retention_days
            }
            
        except Exception as e:
            logger.error(f"Failed to cleanup old audit logs: {str(e)}")
            return {'success': False, 'error': str(e)}


# Global audit service instance
audit_service = AuditService()

# Convenience functions for common audit events
def log_authentication_event(
    event_type: str,
    user_id: Optional[int] = None,
    email: Optional[str] = None,
    ip_address: Optional[str] = None,
    outcome: str = 'SUCCESS',
    details: Optional[Dict[str, Any]] = None
) -> bool:
    """Log authentication-related events"""
    return audit_service.log_event(
        event_type=event_type,
        category='AUTHENTICATION',
        severity='HIGH' if outcome == 'FAILURE' else 'MEDIUM',
        user_id=user_id,
        ip_address=ip_address,
        action=event_type.lower(),
        outcome=outcome,
        details=details or {'email': email}
    )

def log_authorization_event(
    event_type: str,
    user_id: Optional[int] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    action: Optional[str] = None,
    outcome: str = 'SUCCESS',
    details: Optional[Dict[str, Any]] = None
) -> bool:
    """Log authorization-related events"""
    return audit_service.log_event(
        event_type=event_type,
        category='AUTHORIZATION',
        severity='HIGH' if outcome == 'FAILURE' else 'MEDIUM',
        user_id=user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        outcome=outcome,
        details=details
    )

def log_data_access_event(
    event_type: str,
    user_id: Optional[int] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    action: Optional[str] = None,
    outcome: str = 'SUCCESS',
    details: Optional[Dict[str, Any]] = None
) -> bool:
    """Log data access events"""
    return audit_service.log_event(
        event_type=event_type,
        category='DATA_ACCESS',
        severity='MEDIUM',
        user_id=user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        outcome=outcome,
        details=details
    )

def log_security_event(
    event_type: str,
    severity: str = 'HIGH',
    user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> bool:
    """Log security-related events"""
    return audit_service.log_event(
        event_type=event_type,
        category='SECURITY',
        severity=severity,
        user_id=user_id,
        ip_address=ip_address,
        action=event_type.lower(),
        outcome='FAILURE',
        details=details
    )