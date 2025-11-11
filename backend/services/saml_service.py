import json
import secrets
import hashlib
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from flask import request, current_app, url_for
from python3_saml import Auth as OneLogin_Saml2_Auth
from python3_saml.utils import OneLogin_Saml2_Utils
from python3_saml.response import OneLogin_Saml2_Response
from python3_saml.settings import OneLogin_Saml2_Settings
from db.database import get_connection
from db.enterprise_helpers import EnterpriseUserHelper
from services.jwt_service import JWTService
from utils.security import get_client_ip
import logging

logger = logging.getLogger(__name__)

class SAMLService:
    """SAML integration service for enterprise SSO"""
    
    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize SAML service with Flask app"""
        self.app = app
        self._init_providers()
    
    def _init_providers(self):
        """Initialize SAML providers from database"""
        try:
            conn = get_connection()
            if not conn:
                return
                
            cursor = conn.cursor(dictionary=True)
            
            # Get active SAML providers
            cursor.execute("""
                SELECT provider_id, provider_name, display_name, entity_id, sso_url,
                       slo_url, x509_cert, attribute_mapping
                FROM saml_providers
                WHERE is_active = TRUE
            """)
            
            providers = cursor.fetchall()
            cursor.close()
            conn.close()
            
            # Store provider configurations
            self.providers = {}
            for provider in providers:
                self.providers[provider['provider_name']] = {
                    'id': provider['provider_id'],
                    'display_name': provider['display_name'],
                    'entity_id': provider['entity_id'],
                    'sso_url': provider['sso_url'],
                    'slo_url': provider['slo_url'],
                    'x509_cert': provider['x509_cert'],
                    'attribute_mapping': json.loads(provider['attribute_mapping']) if provider['attribute_mapping'] else {}
                }
            
            logger.info(f"SAML providers initialized: {list(self.providers.keys())}")
            
        except Exception as e:
            logger.error(f"Error initializing SAML providers: {str(e)}")
            self.providers = {}
    
    def get_provider_config(self, provider_name: str) -> Optional[Dict[str, Any]]:
        """Get SAML provider configuration"""
        return self.providers.get(provider_name)
    
    def create_auth_request(self, provider_name: str, relay_state: str = None) -> Optional[str]:
        """Create SAML authentication request"""
        try:
            provider_config = self.get_provider_config(provider_name)
            if not provider_config:
                logger.error(f"SAML provider not found: {provider_name}")
                return None
            
            # Create SAML settings
            saml_settings = {
                'sp': {
                    'entityId': current_app.config.get('SAML_SP_ENTITY_ID', url_for('auth.saml_metadata', _external=True)),
                    'assertionConsumerService': {
                        'url': url_for('auth.saml_acs', _external=True)
                    },
                    'singleLogoutService': {
                        'url': url_for('auth.saml_sls', _external=True)
                    },
                    'NameIDFormat': 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
                    'x509cert': current_app.config.get('SAML_SP_CERT', ''),
                    'privateKey': current_app.config.get('SAML_SP_KEY', '')
                },
                'idp': {
                    'entityId': provider_config['entity_id'],
                    'singleSignOnService': {
                        'url': provider_config['sso_url']
                    },
                    'singleLogoutService': {
                        'url': provider_config['slo_url']
                    },
                    'x509cert': provider_config['x509_cert']
                },
                'security': {
                    'nameIdEncrypted': False,
                    'authnRequestsSigned': True,
                    'logoutRequestSigned': True,
                    'logoutResponseSigned': True,
                    'signMetadata': True,
                    'wantMessagesSigned': True,
                    'wantAssertionsSigned': True,
                    'wantAssertionsEncrypted': False,
                    'wantNameIdEncrypted': False
                }
            }
            
            # Create SAML auth request
            auth = OneLogin_Saml2_Auth(saml_settings)
            
            # Set relay state if provided
            if relay_state:
                auth.set_relay_state(relay_state)
            
            # Return login URL
            return auth.login()
            
        except Exception as e:
            logger.error(f"Error creating SAML auth request for {provider_name}: {str(e)}")
            return None
    
    def process_response(self, provider_name: str, saml_response: str) -> Optional[Dict[str, Any]]:
        """Process SAML response and authenticate user"""
        try:
            provider_config = self.get_provider_config(provider_name)
            if not provider_config:
                logger.error(f"SAML provider not found: {provider_name}")
                return None
            
            # Create SAML settings
            saml_settings = {
                'sp': {
                    'entityId': current_app.config.get('SAML_SP_ENTITY_ID', url_for('auth.saml_metadata', _external=True)),
                    'assertionConsumerService': {
                        'url': url_for('auth.saml_acs', _external=True)
                    },
                    'singleLogoutService': {
                        'url': url_for('auth.saml_sls', _external=True)
                    },
                    'NameIDFormat': 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
                    'x509cert': current_app.config.get('SAML_SP_CERT', ''),
                    'privateKey': current_app.config.get('SAML_SP_KEY', '')
                },
                'idp': {
                    'entityId': provider_config['entity_id'],
                    'singleSignOnService': {
                        'url': provider_config['sso_url']
                    },
                    'singleLogoutService': {
                        'url': provider_config['slo_url']
                    },
                    'x509cert': provider_config['x509_cert']
                },
                'security': {
                    'nameIdEncrypted': False,
                    'authnRequestsSigned': True,
                    'logoutRequestSigned': True,
                    'logoutResponseSigned': True,
                    'signMetadata': True,
                    'wantMessagesSigned': True,
                    'wantAssertionsSigned': True,
                    'wantAssertionsEncrypted': False,
                    'wantNameIdEncrypted': False
                }
            }
            
            # Process SAML response
            auth = OneLogin_Saml2_Auth(saml_settings)
            auth.process_response(saml_response)
            
            # Check if authentication was successful
            if not auth.is_authenticated():
                logger.error(f"SAML authentication failed for {provider_name}")
                return None
            
            # Get attributes
            attributes = auth.get_attributes()
            
            # Map attributes using provider configuration
            user_info = self._map_saml_attributes(attributes, provider_config['attribute_mapping'])
            
            if not user_info.get('email'):
                logger.error(f"No email attribute found in SAML response from {provider_name}")
                return None
            
            # Process SAML user
            return self._process_saml_user(provider_name, user_info)
            
        except Exception as e:
            logger.error(f"Error processing SAML response for {provider_name}: {str(e)}")
            return None
    
    def _map_saml_attributes(self, attributes: Dict[str, Any], 
                             attribute_mapping: Dict[str, str]) -> Dict[str, Any]:
        """Map SAML attributes to standard user fields"""
        mapped_info = {}
        
        # Map standard attributes
        for field, saml_attr in attribute_mapping.items():
            if saml_attr in attributes:
                value = attributes[saml_attr]
                # Handle multi-valued attributes
                if isinstance(value, list) and value:
                    mapped_info[field] = value[0]
                else:
                    mapped_info[field] = value
        
        # Extract common attributes if not mapped
        if 'email' not in mapped_info:
            # Try common email attribute names
            for email_attr in ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
                             'email', 'Email', 'mail']:
                if email_attr in attributes:
                    mapped_info['email'] = attributes[email_attr][0] if isinstance(attributes[email_attr], list) else attributes[email_attr]
                    break
        
        if 'name' not in mapped_info:
            # Try common name attribute names
            for name_attr in ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
                            'name', 'Name', 'cn', 'displayName']:
                if name_attr in attributes:
                    mapped_info['name'] = attributes[name_attr][0] if isinstance(attributes[name_attr], list) else attributes[name_attr]
                    break
        
        if 'first_name' not in mapped_info:
            # Try common first name attribute names
            for fname_attr in ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
                              'givenname', 'firstName', 'FirstName']:
                if fname_attr in attributes:
                    mapped_info['first_name'] = attributes[fname_attr][0] if isinstance(attributes[fname_attr], list) else attributes[fname_attr]
                    break
        
        if 'last_name' not in mapped_info:
            # Try common last name attribute names
            for lname_attr in ['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
                              'surname', 'lastName', 'LastName']:
                if lname_attr in attributes:
                    mapped_info['last_name'] = attributes[lname_attr][0] if isinstance(attributes[lname_attr], list) else attributes[lname_attr]
                    break
        
        return mapped_info
    
    def _process_saml_user(self, provider_name: str, user_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process SAML user and create/update account"""
        try:
            email = user_info['email'].lower()
            
            # Check if user already exists with this email
            existing_user = EnterpriseUserHelper.get_user_by_email(email)
            
            if existing_user:
                # Check if SAML account is already linked
                if self._is_saml_linked(existing_user['user_id'], provider_name, user_info.get('provider_id')):
                    # Existing user with SAML linked - generate tokens
                    return self._generate_tokens_for_user(existing_user)
                else:
                    # Link SAML account to existing user
                    if self._link_saml_account(existing_user['user_id'], provider_name, user_info):
                        return self._generate_tokens_for_user(existing_user)
                    else:
                        return None
            else:
                # Create new user
                return self._create_saml_user(provider_name, user_info)
                
        except Exception as e:
            logger.error(f"Error processing SAML user: {str(e)}")
            return None
    
    def _is_saml_linked(self, user_id: int, provider_name: str, provider_id: str) -> bool:
        """Check if SAML account is already linked to user"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT COUNT(*) FROM user_saml_accounts usa
                JOIN saml_providers sp ON usa.provider_id = sp.provider_id
                WHERE usa.user_id = %s AND sp.provider_name = %s AND usa.provider_user_id = %s
                AND usa.is_active = TRUE
            """, (user_id, provider_name, provider_id))
            
            count = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            
            return count > 0
            
        except Exception as e:
            logger.error(f"Error checking SAML link: {str(e)}")
            return False
    
    def _link_saml_account(self, user_id: int, provider_name: str, user_info: Dict[str, Any]) -> bool:
        """Link SAML account to existing user"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Get provider ID
            cursor.execute("SELECT provider_id FROM saml_providers WHERE provider_name = %s", (provider_name,))
            result = cursor.fetchone()
            if not result:
                cursor.close()
                conn.close()
                return False
            
            provider_id = result[0]
            
            # Insert SAML account
            cursor.execute("""
                INSERT INTO user_saml_accounts 
                (user_id, provider_id, provider_user_id, name_id, 
                 attributes, is_active, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
                ON DUPLICATE KEY UPDATE
                attributes = VALUES(attributes),
                is_active = VALUES(is_active),
                updated_at = NOW()
            """, (user_id, provider_id, user_info.get('provider_id'), user_info.get('name_id'),
                   json.dumps(user_info), True))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"SAML account linked for user {user_id} with {provider_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error linking SAML account: {str(e)}")
            return False
    
    def _create_saml_user(self, provider_name: str, user_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create new user from SAML data"""
        try:
            # Generate a secure random password (user won't use it for SAML login)
            temp_password = secrets.token_urlsafe(32)
            
            # Create user with SAML data
            user_data = EnterpriseUserHelper.create_user(
                full_name=user_info.get('name', ''),
                email=user_info['email'],
                password=temp_password,
                role='student'  # Default role for SAML users
            )
            
            if not user_data:
                logger.error(f"Failed to create user for SAML {provider_name}")
                return None
            
            # Link SAML account
            if self._link_saml_account(user_data['user_id'], provider_name, user_info):
                # Mark email as verified since it's verified by SAML provider
                self._mark_email_verified(user_data['user_id'])
                
                return self._generate_tokens_for_user(user_data)
            else:
                return None
                
        except Exception as e:
            logger.error(f"Error creating SAML user: {str(e)}")
            return None
    
    def _mark_email_verified(self, user_id: int) -> bool:
        """Mark user email as verified"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE users SET email_verified = TRUE, updated_at = NOW()
                WHERE user_id = %s
            """, (user_id,))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error marking email verified: {str(e)}")
            return False
    
    def _generate_tokens_for_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate JWT tokens for user"""
        try:
            access_token, refresh_token, expires_at = JWTService.generate_tokens(
                user_data['user_id'], user_data['email'], user_data['role']
            )
            
            return {
                'status': 'success',
                'user': {
                    'user_id': user_data['user_id'],
                    'full_name': user_data['full_name'],
                    'email': user_data['email'],
                    'role': user_data['role'],
                    'permissions': user_data.get('permissions', []),
                    'email_verified': user_data.get('email_verified', False)
                },
                'tokens': {
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'expires_at': expires_at.isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Error generating tokens for SAML user: {str(e)}")
            return None
    
    def create_logout_request(self, provider_name: str, name_id: str, session_index: str = None) -> Optional[str]:
        """Create SAML logout request"""
        try:
            provider_config = self.get_provider_config(provider_name)
            if not provider_config:
                logger.error(f"SAML provider not found: {provider_name}")
                return None
            
            # Create SAML settings
            saml_settings = {
                'sp': {
                    'entityId': current_app.config.get('SAML_SP_ENTITY_ID', url_for('auth.saml_metadata', _external=True)),
                    'assertionConsumerService': {
                        'url': url_for('auth.saml_acs', _external=True)
                    },
                    'singleLogoutService': {
                        'url': url_for('auth.saml_sls', _external=True)
                    },
                    'NameIDFormat': 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
                    'x509cert': current_app.config.get('SAML_SP_CERT', ''),
                    'privateKey': current_app.config.get('SAML_SP_KEY', '')
                },
                'idp': {
                    'entityId': provider_config['entity_id'],
                    'singleSignOnService': {
                        'url': provider_config['sso_url']
                    },
                    'singleLogoutService': {
                        'url': provider_config['slo_url']
                    },
                    'x509cert': provider_config['x509_cert']
                },
                'security': {
                    'nameIdEncrypted': False,
                    'authnRequestsSigned': True,
                    'logoutRequestSigned': True,
                    'logoutResponseSigned': True,
                    'signMetadata': True,
                    'wantMessagesSigned': True,
                    'wantAssertionsSigned': True,
                    'wantAssertionsEncrypted': False,
                    'wantNameIdEncrypted': False
                }
            }
            
            # Create SAML logout request
            auth = OneLogin_Saml2_Auth(saml_settings)
            
            # Set name ID and session index if provided
            if name_id:
                auth.set_name_id(name_id)
            if session_index:
                auth.set_session_index(session_index)
            
            # Return logout URL
            return auth.logout()
            
        except Exception as e:
            logger.error(f"Error creating SAML logout request for {provider_name}: {str(e)}")
            return None
    
    def process_logout_response(self, provider_name: str, saml_response: str) -> bool:
        """Process SAML logout response"""
        try:
            provider_config = self.get_provider_config(provider_name)
            if not provider_config:
                logger.error(f"SAML provider not found: {provider_name}")
                return False
            
            # Create SAML settings
            saml_settings = {
                'sp': {
                    'entityId': current_app.config.get('SAML_SP_ENTITY_ID', url_for('auth.saml_metadata', _external=True)),
                    'assertionConsumerService': {
                        'url': url_for('auth.saml_acs', _external=True)
                    },
                    'singleLogoutService': {
                        'url': url_for('auth.saml_sls', _external=True)
                    },
                    'NameIDFormat': 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
                    'x509cert': current_app.config.get('SAML_SP_CERT', ''),
                    'privateKey': current_app.config.get('SAML_SP_KEY', '')
                },
                'idp': {
                    'entityId': provider_config['entity_id'],
                    'singleSignOnService': {
                        'url': provider_config['sso_url']
                    },
                    'singleLogoutService': {
                        'url': provider_config['slo_url']
                    },
                    'x509cert': provider_config['x509_cert']
                },
                'security': {
                    'nameIdEncrypted': False,
                    'authnRequestsSigned': True,
                    'logoutRequestSigned': True,
                    'logoutResponseSigned': True,
                    'signMetadata': True,
                    'wantMessagesSigned': True,
                    'wantAssertionsSigned': True,
                    'wantAssertionsEncrypted': False,
                    'wantNameIdEncrypted': False
                }
            }
            
            # Process SAML logout response
            auth = OneLogin_Saml2_Auth(saml_settings)
            auth.process_response(saml_response)
            
            # Check if logout was successful
            return True
            
        except Exception as e:
            logger.error(f"Error processing SAML logout response for {provider_name}: {str(e)}")
            return False
    
    def generate_metadata(self) -> str:
        """Generate SAML service provider metadata"""
        try:
            # Create SAML settings
            saml_settings = {
                'sp': {
                    'entityId': current_app.config.get('SAML_SP_ENTITY_ID', url_for('auth.saml_metadata', _external=True)),
                    'assertionConsumerService': {
                        'url': url_for('auth.saml_acs', _external=True)
                    },
                    'singleLogoutService': {
                        'url': url_for('auth.saml_sls', _external=True)
                    },
                    'NameIDFormat': 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
                    'x509cert': current_app.config.get('SAML_SP_CERT', ''),
                    'privateKey': current_app.config.get('SAML_SP_KEY', '')
                },
                'security': {
                    'nameIdEncrypted': False,
                    'authnRequestsSigned': True,
                    'logoutRequestSigned': True,
                    'logoutResponseSigned': True,
                    'signMetadata': True,
                    'wantMessagesSigned': True,
                    'wantAssertionsSigned': True,
                    'wantAssertionsEncrypted': False,
                    'wantNameIdEncrypted': False
                }
            }
            
            # Create SAML auth object and generate metadata
            auth = OneLogin_Saml2_Auth(saml_settings)
            metadata = auth.get_settings().get_sp_metadata()
            
            return metadata
            
        except Exception as e:
            logger.error(f"Error generating SAML metadata: {str(e)}")
            return ""
    
    def unlink_saml_account(self, user_id: int, provider_name: str) -> bool:
        """Unlink SAML account from user"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE user_saml_accounts usa
                JOIN saml_providers sp ON usa.provider_id = sp.provider_id
                SET usa.is_active = FALSE, usa.updated_at = NOW()
                WHERE usa.user_id = %s AND sp.provider_name = %s
            """, (user_id, provider_name))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"SAML account unlinked for user {user_id} from {provider_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error unlinking SAML account: {str(e)}")
            return False
    
    def get_linked_saml_accounts(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all linked SAML accounts for a user"""
        try:
            conn = get_connection()
            if not conn:
                return []
                
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT sp.provider_name, sp.display_name, usa.provider_user_id, 
                       usa.created_at, usa.is_active
                FROM user_saml_accounts usa
                JOIN saml_providers sp ON usa.provider_id = sp.provider_id
                WHERE usa.user_id = %s
                ORDER BY usa.created_at DESC
            """, (user_id,))
            
            accounts = cursor.fetchall()
            cursor.close()
            conn.close()
            
            return accounts
            
        except Exception as e:
            logger.error(f"Error getting linked SAML accounts: {str(e)}")
            return []

# Initialize SAML service
saml_service = SAMLService()