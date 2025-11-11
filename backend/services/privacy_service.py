
import json
import secrets
import hashlib
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from flask import current_app, request
from db.database import get_connection
from utils.security import get_client_ip
import logging

logger = logging.getLogger(__name__)

class PrivacyService:
    """GDPR and CCPA compliance service"""
    
    @staticmethod
    def record_conent(user_id: int, consent_type: str, granted: bool, 
                      consent_data: Dict[str, Any] = None) -> bool:
        """
        Record user consent for GDPR/CCPA compliance
        
        Args:
            user_id: User ID
            consent_type: Type of consent (data_processing, marketing, analytics, etc.)
            granted: Whether consent is granted
            consent_data: Additional consent data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Get current consent version
            version = PrivacyService._get_consent_version(consent_type)
            
            # Record consent
            cursor.execute("""
                INSERT INTO user_consent 
                (user_id, consent_type, granted, granted_at, ip_address, 
                 user_agent, version, consent_data)
                VALUES (%s, %s, %s, NOW(), %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                granted = VALUES(granted),
                granted_at = IF(granted = VALUES(granted), NOW(), granted_at),
                revoked_at = IF(granted = VALUES(granted), NULL, NOW()),
                ip_address = VALUES(ip_address),
                user_agent = VALUES(user_agent),
                version = VALUES(version),
                consent_data = VALUES(consent_data)
            """, (user_id, consent_type, granted, get_client_ip(),
                   request.headers.get('User-Agent', ''), version, 
                   json.dumps(consent_data) if consent_data else None))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            # Log consent change
            PrivacyService._log_privacy_event(
                'consent_recorded', user_id, {
                    'consent_type': consent_type,
                    'granted': granted,
                    'version': version,
                    'ip_address': get_client_ip()
                }
            )
            
            logger.info(f"Consent recorded for user {user_id}: {consent_type} = {granted}")
            return True
            
        except Exception as e:
            logger.error(f"Error recording consent: {str(e)}")
            return False
    
    @staticmethod
    def get_user_consents(user_id: int) -> List[Dict[str, Any]]:
        """
        Get all user consents
        
        Args:
            user_id: User ID
            
        Returns:
            List of consent records
        """
        try:
            conn = get_connection()
            if not conn:
                return []
                
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT consent_type, granted, granted_at, revoked_at, 
                       ip_address, user_agent, version, consent_data
                FROM user_consent
                WHERE user_id = %s
                ORDER BY granted_at DESC
            """, (user_id,))
            
            consents = cursor.fetchall()
            cursor.close()
            conn.close()
            
            return consents
            
        except Exception as e:
            logger.error(f"Error getting user consents: {str(e)}")
            return []
    
    @staticmethod
    def check_consent(user_id: int, consent_type: str) -> Optional[Dict[str, Any]]:
        """
        Check if user has granted specific consent
        
        Args:
            user_id: User ID
            consent_type: Type of consent to check
            
        Returns:
            Consent record or None
        """
        try:
            conn = get_connection()
            if not conn:
                return None
                
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT granted, granted_at, revoked_at, version
                FROM user_consent
                WHERE user_id = %s AND consent_type = %s
                ORDER BY granted_at DESC
                LIMIT 1
            """, (user_id, consent_type))
            
            consent = cursor.fetchone()
            cursor.close()
            conn.close()
            
            return consent
            
        except Exception as e:
            logger.error(f"Error checking consent: {str(e)}")
            return None
    
    @staticmethod
    def create_data_request(user_id: int, request_type: str, 
                          request_data: Dict[str, Any] = None) -> Optional[str]:
        """
        Create data access/deletion request
        
        Args:
            user_id: User ID
            request_type: Type of request (export, delete, restrict, correct)
            request_data: Additional request data
            
        Returns:
            Request ID if successful, None otherwise
        """
        try:
            conn = get_connection()
            if not conn:
                return None
                
            cursor = conn.cursor()
            
            # Generate request ID
            request_id = secrets.token_urlsafe(16)
            
            # Insert data request
            cursor.execute("""
                INSERT INTO data_requests 
                (user_id, request_type, request_data, ip_address, created_at)
                VALUES (%s, %s, %s, %s, NOW())
            """, (user_id, request_type, json.dumps(request_data) if request_data else None,
                   get_client_ip()))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            # Log data request
            PrivacyService._log_privacy_event(
                'data_request_created', user_id, {
                    'request_type': request_type,
                    'request_id': request_id,
                    'ip_address': get_client_ip()
                }
            )
            
            logger.info(f"Data request created for user {user_id}: {request_type} ({request_id})")
            return request_id
            
        except Exception as e:
            logger.error(f"Error creating data request: {str(e)}")
            return None
    
    @staticmethod
    def get_data_requests(user_id: int = None, status: str = None) -> List[Dict[str, Any]]:
        """
        Get data requests
        
        Args:
            user_id: User ID (None for admin to get all requests)
            status: Filter by status
            
        Returns:
            List of data requests
        """
        try:
            conn = get_connection()
            if not conn:
                return []
                
            cursor = conn.cursor(dictionary=True)
            
            query = """
                SELECT dr.*, u.email, u.full_name
                FROM data_requests dr
                JOIN users u ON dr.user_id = u.user_id
            """
            params = []
            
            if user_id:
                query += " WHERE dr.user_id = %s"
                params.append(user_id)
            
            if status:
                query += " AND dr.status = %s" if user_id else " WHERE dr.status = %s"
                params.append(status)
            
            query += " ORDER BY dr.created_at DESC"
            
            cursor.execute(query, tuple(params))
            
            requests = cursor.fetchall()
            cursor.close()
            conn.close()
            
            return requests
            
        except Exception as e:
            logger.error(f"Error getting data requests: {str(e)}")
            return []
    
    @staticmethod
    def update_data_request(request_id: str, status: str, response_data: Dict[str, Any] = None,
                         processed_by: int = None) -> bool:
        """
        Update data request status
        
        Args:
            request_id: Request ID
            status: New status
            response_data: Response data
            processed_by: User ID of processor
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Update request
            cursor.execute("""
                UPDATE data_requests 
                SET status = %s, response_data = %s, processed_by = %s, processed_at = NOW()
                WHERE request_id = %s
            """, (status, json.dumps(response_data) if response_data else None,
                   processed_by, request_id))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            # Log request update
            PrivacyService._log_privacy_event(
                'data_request_updated', None, {
                    'request_id': request_id,
                    'status': status,
                    'processed_by': processed_by
                }
            )
            
            logger.info(f"Data request updated: {request_id} -> {status}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating data request: {str(e)}")
            return False
    
    @staticmethod
    def export_user_data(user_id: int) -> Optional[Dict[str, Any]]:
        """
        Export all user data for GDPR compliance
        
        Args:
            user_id: User ID
            
        Returns:
            User data dictionary or None
        """
        try:
            conn = get_connection()
            if not conn:
                return None
                
            cursor = conn.cursor(dictionary=True)
            
            # Get user basic info
            cursor.execute("""
                SELECT user_id, full_name, email, phone, role, status, 
                       date_joined, last_login, created_at, updated_at
                FROM users
                WHERE user_id = %s
            """, (user_id,))
            
            user_data = cursor.fetchone()
            if not user_data:
                cursor.close()
                conn.close()
                return None
            
            # Get user roles
            cursor.execute("""
                SELECT r.role_name, ur.assigned_at, ur.expires_at
                FROM user_roles ur
                JOIN roles r ON ur.role_id = r.role_id
                WHERE ur.user_id = %s
            """, (user_id,))
            
            user_data['roles'] = cursor.fetchall()
            
            # Get user consents
            user_data['consents'] = PrivacyService.get_user_consents(user_id)
            
            # Get user OAuth accounts
            cursor.execute("""
                SELECT op.provider_name, op.display_name, uoa.created_at, uoa.is_active
                FROM user_oauth_accounts uoa
                JOIN oauth_providers op ON uoa.provider_id = op.provider_id
                WHERE uoa.user_id = %s
            """, (user_id,))
            
            user_data['oauth_accounts'] = cursor.fetchall()
            
            # Get user SAML accounts
            cursor.execute("""
                SELECT sp.provider_name, sp.display_name, usa.created_at, usa.is_active
                FROM user_saml_accounts usa
                JOIN saml_providers sp ON usa.provider_id = sp.provider_id
                WHERE usa.user_id = %s
            """, (user_id,))
            
            user_data['saml_accounts'] = cursor.fetchall()
            
            # Get user devices
            cursor.execute("""
                SELECT device_name, device_type, platform, browser, 
                       ip_address, is_trusted, last_seen, created_at
                FROM user_devices
                WHERE user_id = %s
                ORDER BY last_seen DESC
            """, (user_id,))
            
            user_data['devices'] = cursor.fetchall()
            
            # Get user activity (last 100 records)
            cursor.execute("""
                SELECT action, resource_type, resource_id, ip_address, 
                       user_agent, timestamp
                FROM audit_logs
                WHERE user_id = %s
                ORDER BY timestamp DESC
                LIMIT 100
            """, (user_id,))
            
            user_data['activity'] = cursor.fetchall()
            
            # Get user data requests
            user_data['data_requests'] = PrivacyService.get_data_requests(user_id)
            
            cursor.close()
            conn.close()
            
            # Remove sensitive data
            if 'password' in user_data:
                del user_data['password']
            
            # Add export metadata
            user_data['export_metadata'] = {
                'exported_at': datetime.utcnow().isoformat(),
                'exported_by': 'system',
                'format': 'json',
                'version': '1.0'
            }
            
            # Log data export
            PrivacyService._log_privacy_event(
                'data_exported', user_id, {
                    'export_type': 'full_user_data',
                    'ip_address': get_client_ip()
                }
            )
            
            logger.info(f"User data exported for user {user_id}")
            return user_data
            
        except Exception as e:
            logger.error(f"Error exporting user data: {str(e)}")
            return None
    
    @staticmethod
    def delete_user_data(user_id: int, deletion_reason: str = None) -> bool:
        """
        Delete user data for GDPR/CCPA compliance
        
        Args:
            user_id: User ID
            deletion_reason: Reason for deletion
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Get user email for logging
            cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
            user_email = cursor.fetchone()
            user_email = user_email[0] if user_email else 'unknown'
            
            # Delete user data in order of dependencies
            # Delete audit logs
            cursor.execute("DELETE FROM audit_logs WHERE user_id = %s", (user_id,))
            
            # Delete user behavior
            cursor.execute("DELETE FROM user_behavior WHERE user_id = %s", (user_id,))
            
            # Delete user devices
            cursor.execute("DELETE FROM user_devices WHERE user_id = %s", (user_id,))
            
            # Delete user sessions
            cursor.execute("DELETE FROM user_sessions WHERE user_id = %s", (user_id,))
            
            # Delete OAuth accounts
            cursor.execute("DELETE FROM user_oauth_accounts WHERE user_id = %s", (user_id,))
            
            # Delete SAML accounts
            cursor.execute("DELETE FROM user_saml_accounts WHERE user_id = %s", (user_id,))
            
            # Delete user consents
            cursor.execute("DELETE FROM user_consent WHERE user_id = %s", (user_id,))
            
            # Delete data requests
            cursor.execute("DELETE FROM data_requests WHERE user_id = %s", (user_id,))
            
            # Delete API keys
            cursor.execute("DELETE FROM api_keys WHERE user_id = %s", (user_id,))
            
            # Delete password history
            cursor.execute("DELETE FROM password_history WHERE user_id = %s", (user_id,))
            
            # Delete user record
            cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            # Log data deletion
            PrivacyService._log_privacy_event(
                'data_deleted', user_id, {
                    'deletion_reason': deletion_reason,
                    'ip_address': get_client_ip()
                }
            )
            
            logger.info(f"User data deleted for user {user_id} ({user_email})")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting user data: {str(e)}")
            return False
    
    @staticmethod
    def anonymize_user_data(user_id: int) -> bool:
        """
        Anonymize user data (pseudonymization) for GDPR compliance
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Generate anonymized data
            anonymized_email = f"deleted-{secrets.token_urlsafe(8)}@deleted.com"
            anonymized_name = "Deleted User"
            
            # Update user record with anonymized data
            cursor.execute("""
                UPDATE users 
                SET email = %s, full_name = %s, phone = NULL, 
                    status = 'deleted', updated_at = NOW()
                WHERE user_id = %s
            """, (anonymized_email, anonymized_name, user_id))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            # Log data anonymization
            PrivacyService._log_privacy_event(
                'data_anonymized', user_id, {
                    'ip_address': get_client_ip()
                }
            )
            
            logger.info(f"User data anonymized for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error anonymizing user data: {str(e)}")
            return False
    
    @staticmethod
    def _get_consent_version(consent_type: str) -> str:
        """Get current consent version"""
        # This could be stored in a separate table or config
        # For now, use a simple versioning scheme
        consent_versions = {
            'data_processing': '1.0',
            'marketing': '1.0',
            'analytics': '1.0',
            'cookies': '1.0',
            'third_party_sharing': '1.0'
        }
        
        return consent_versions.get(consent_type, '1.0')
    
    @staticmethod
    def _log_privacy_event(event_type: str, user_id: int = None, 
                          metadata: Dict[str, Any] = None) -> None:
        """Log privacy-related events"""
        try:
            conn = get_connection()
            if not conn:
                return
                
            cursor = conn.cursor()
            
            # Generate hash signature for tamper protection
            event_data = f"{event_type}{user_id}{metadata}"
            hash_signature = hashlib.sha256(event_data.encode()).hexdigest()
            
            cursor.execute("""
                INSERT INTO audit_logs 
                (user_id, action, resource_type, description, ip_address, 
                 user_agent, timestamp, severity, category, hash_signature, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s, %s)
            """, (user_id, event_type, 'privacy', 
                   f"Privacy event: {event_type}", get_client_ip(),
                   request.headers.get('User-Agent', ''), 'medium', 'privacy',
                   hash_signature, json.dumps(metadata) if metadata else None))
            
            conn.commit()
            cursor.close()
            conn.close()
            
        except Exception as e:
            logger.error(f"Error logging privacy event: {str(e)}")
    
    @staticmethod
    def get_privacy_policy(version: str = 'latest') -> Optional[Dict[str, Any]]:
        """
        Get privacy policy content
        
        Args:
            version: Policy version
            
        Returns:
            Privacy policy content or None
        """
        try:
            # This could be stored in database or files
            # For now, return a basic privacy policy
            policies = {
                '1.0': {
                    'title': 'Privacy Policy v1.0',
                    'effective_date': '2023-01-01'
                },
                'latest': {
                    'title': 'Privacy Policy',
                    'effective_date': '2023-01-01',
                    'sections': [
                        {
                            'title': 'Data Collection',
                            'content': 'We collect personal information you provide to us...'
                        },
                        {
                            'title': 'Data Usage',
                            'content': 'We use your data to provide and improve our services...'
                        },
                        {
                            'title': 'Data Sharing',
                            'content': 'We do not sell or rent your personal information...'
                        },
                        {
                            'title': 'Data Security',
                            'content': 'We implement appropriate security measures...'
                        },
                        {
                            'title': 'Your Rights',
                            'content': 'You have the right to access, correct, or delete your data...'
                        }
                    ]
                }
            }
            
            return policies.get(version, policies['latest'])
            
        except Exception as e:
            logger.error(f"Error getting privacy policy: {str(e)}")
            return None