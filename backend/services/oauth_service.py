import json
import secrets
import hashlib
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from flask import request, current_app, url_for
from authlib.integrations.base_client import OAuthError
from authlib.integrations.flask_client import OAuth
from db.database import get_connection
from db.enterprise_helpers import EnterpriseUserHelper
from services.jwt_service import JWTService
from utils.security import get_client_ip
import logging

logger = logging.getLogger(__name__)

class OAuthService:
    """OAuth 2.0 integration service for third-party authentication"""
    
    def __init__(self, app=None):
        self.app = app
        self.oauth = None
        self._initialized = False
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize OAuth service with Flask app"""
        self.app = app
        self.oauth = OAuth(app)
        self._init_providers()
    
    def _init_providers(self):
        """Initialize OAuth providers"""
        if not self.app or not hasattr(self.app, 'config'):
            # Defer initialization if no app context
            return
            
        try:
            # Google OAuth
            self.oauth.register(
                name='google',
                client_id=self.app.config.get('GOOGLE_CLIENT_ID'),
                client_secret=self.app.config.get('GOOGLE_CLIENT_SECRET'),
                server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
                client_kwargs={'scope': 'openid email profile'},
                redirect_uri=self.app.config.get('GOOGLE_REDIRECT_URI', url_for('auth.google_callback', _external=True))
            )
            
            # Microsoft OAuth
            self.oauth.register(
                name='microsoft',
                client_id=self.app.config.get('MICROSOFT_CLIENT_ID'),
                client_secret=self.app.config.get('MICROSOFT_CLIENT_SECRET'),
                authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
                token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
                client_kwargs={'scope': 'openid email profile'},
                redirect_uri=self.app.config.get('MICROSOFT_REDIRECT_URI', url_for('auth.microsoft_callback', _external=True))
            )
            
            # GitHub OAuth
            self.oauth.register(
                name='github',
                client_id=self.app.config.get('GITHUB_CLIENT_ID'),
                client_secret=self.app.config.get('GITHUB_CLIENT_SECRET'),
                authorize_url='https://github.com/login/oauth/authorize',
                token_url='https://github.com/login/oauth/access_token',
                client_kwargs={'scope': 'user:email'},
                redirect_uri=self.app.config.get('GITHUB_REDIRECT_URI', url_for('auth.github_callback', _external=True))
            )
            
            self._initialized = True
            logger.info("OAuth providers initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing OAuth providers: {str(e)}")
    
    def get_provider(self, provider_name: str):
        """Get OAuth provider by name"""
        return self.oauth.create_client(provider_name)
    
    def authorize(self, provider_name: str):
        """Start OAuth authorization flow"""
        try:
            redirect_uri = self.oauth.create_client(provider_name).authorize_redirect()
            return redirect_uri
        except Exception as e:
            logger.error(f"OAuth authorization error for {provider_name}: {str(e)}")
            return None
    
    def handle_callback(self, provider_name: str):
        """Handle OAuth callback and authenticate user"""
        try:
            client = self.oauth.create_client(provider_name)
            token = client.authorize_access_token()
            
            # Get user info from provider
            user_info = self._get_user_info(provider_name, token)
            
            if not user_info:
                logger.error(f"Failed to get user info from {provider_name}")
                return None
            
            # Process OAuth user
            return self._process_oauth_user(provider_name, user_info, token)
            
        except OAuthError as e:
            logger.error(f"OAuth callback error for {provider_name}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Unexpected OAuth error for {provider_name}: {str(e)}")
            return None
    
    def _get_user_info(self, provider_name: str, token: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get user information from OAuth provider"""
        try:
            client = self.oauth.create_client(provider_name)
            
            if provider_name == 'google':
                # Get user info from Google
                resp = client.get('https://www.googleapis.com/oauth2/v2/userinfo', token=token)
                if resp.status_code == 200:
                    user_data = resp.json()
                    return {
                        'provider_id': user_data.get('id'),
                        'email': user_data.get('email'),
                        'name': user_data.get('name'),
                        'first_name': user_data.get('given_name'),
                        'last_name': user_data.get('family_name'),
                        'picture': user_data.get('picture'),
                        'verified': user_data.get('verified_email', False)
                    }
            
            elif provider_name == 'microsoft':
                # Get user info from Microsoft
                resp = client.get('https://graph.microsoft.com/v1.0/me', token=token)
                if resp.status_code == 200:
                    user_data = resp.json()
                    return {
                        'provider_id': user_data.get('id'),
                        'email': user_data.get('mail') or user_data.get('userPrincipalName'),
                        'name': user_data.get('displayName'),
                        'first_name': user_data.get('givenName'),
                        'last_name': user_data.get('surname'),
                        'verified': True
                    }
            
            elif provider_name == 'github':
                # Get user info from GitHub
                resp = client.get('https://api.github.com/user', token=token)
                if resp.status_code == 200:
                    user_data = resp.json()
                    # Get email separately as it might not be included in main user object
                    email_resp = client.get('https://api.github.com/user/emails', token=token)
                    emails = email_resp.json() if email_resp.status_code == 200 else []
                    primary_email = next((e['email'] for e in emails if e['primary']), user_data.get('email'))
                    
                    return {
                        'provider_id': str(user_data.get('id')),
                        'email': primary_email,
                        'name': user_data.get('name'),
                        'first_name': user_data.get('name', '').split()[0] if user_data.get('name') else '',
                        'last_name': ' '.join(user_data.get('name', '').split()[1:]) if user_data.get('name') else '',
                        'picture': user_data.get('avatar_url'),
                        'verified': any(e['verified'] for e in emails if e['email'] == primary_email)
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting user info from {provider_name}: {str(e)}")
            return None
    
    def _process_oauth_user(self, provider_name: str, user_info: Dict[str, Any], 
                          token: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process OAuth user and create/update account"""
        try:
            if not user_info.get('email'):
                logger.error(f"No email provided by {provider_name}")
                return None
            
            email = user_info['email'].lower()
            
            # Check if user already exists with this email
            existing_user = EnterpriseUserHelper.get_user_by_email(email)
            
            if existing_user:
                # Check if OAuth account is already linked
                if self._is_oauth_linked(existing_user['user_id'], provider_name, user_info['provider_id']):
                    # Existing user with OAuth linked - generate tokens
                    return self._generate_tokens_for_user(existing_user)
                else:
                    # Link OAuth account to existing user
                    if self._link_oauth_account(existing_user['user_id'], provider_name, user_info, token):
                        return self._generate_tokens_for_user(existing_user)
                    else:
                        return None
            else:
                # Create new user
                return self._create_oauth_user(provider_name, user_info, token)
                
        except Exception as e:
            logger.error(f"Error processing OAuth user: {str(e)}")
            return None
    
    def _is_oauth_linked(self, user_id: int, provider_name: str, provider_id: str) -> bool:
        """Check if OAuth account is already linked to user"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT COUNT(*) FROM user_oauth_accounts uoa
                JOIN oauth_providers op ON uoa.provider_id = op.provider_id
                WHERE uoa.user_id = %s AND op.provider_name = %s AND uoa.provider_user_id = %s
                AND uoa.is_active = TRUE
            """, (user_id, provider_name, provider_id))
            
            count = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            
            return count > 0
            
        except Exception as e:
            logger.error(f"Error checking OAuth link: {str(e)}")
            return False
    
    def _link_oauth_account(self, user_id: int, provider_name: str, user_info: Dict[str, Any], 
                          token: Dict[str, Any]) -> bool:
        """Link OAuth account to existing user"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Get provider ID
            cursor.execute("SELECT provider_id FROM oauth_providers WHERE provider_name = %s", (provider_name,))
            result = cursor.fetchone()
            if not result:
                cursor.close()
                conn.close()
                return False
            
            provider_id = result[0]
            
            # Encrypt and store tokens
            access_token_encrypted = self._encrypt_token(token.get('access_token'))
            refresh_token_encrypted = self._encrypt_token(token.get('refresh_token')) if token.get('refresh_token') else None
            
            # Calculate token expiry
            expires_at = None
            if token.get('expires_in'):
                expires_at = datetime.utcnow() + timedelta(seconds=token['expires_in'])
            
            # Insert OAuth account
            cursor.execute("""
                INSERT INTO user_oauth_accounts 
                (user_id, provider_id, provider_user_id, access_token_encrypted, 
                 refresh_token_encrypted, token_expires_at, profile_data, is_active, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NOW())
                ON DUPLICATE KEY UPDATE
                access_token_encrypted = VALUES(access_token_encrypted),
                refresh_token_encrypted = VALUES(refresh_token_encrypted),
                token_expires_at = VALUES(token_expires_at),
                profile_data = VALUES(profile_data),
                is_active = VALUES(is_active),
                updated_at = NOW()
            """, (user_id, provider_id, user_info['provider_id'], access_token_encrypted,
                   refresh_token_encrypted, expires_at, json.dumps(user_info), True))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"OAuth account linked for user {user_id} with {provider_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error linking OAuth account: {str(e)}")
            return False
    
    def _create_oauth_user(self, provider_name: str, user_info: Dict[str, Any], 
                         token: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create new user from OAuth data"""
        try:
            # Generate a secure random password (user won't use it for OAuth login)
            temp_password = secrets.token_urlsafe(32)
            
            # Create user with OAuth data
            user_data = EnterpriseUserHelper.create_user(
                full_name=user_info.get('name', ''),
                email=user_info['email'],
                password=temp_password,
                role='student'  # Default role for OAuth users
            )
            
            if not user_data:
                logger.error(f"Failed to create user for OAuth {provider_name}")
                return None
            
            # Link OAuth account
            if self._link_oauth_account(user_data['user_id'], provider_name, user_info, token):
                # Mark email as verified since it's verified by OAuth provider
                self._mark_email_verified(user_data['user_id'])
                
                return self._generate_tokens_for_user(user_data)
            else:
                return None
                
        except Exception as e:
            logger.error(f"Error creating OAuth user: {str(e)}")
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
            logger.error(f"Error generating tokens for OAuth user: {str(e)}")
            return None
    
    def _encrypt_token(self, token: str) -> str:
        """Encrypt OAuth token for storage"""
        try:
            from cryptography.fernet import Fernet
            key = current_app.config.get('OAUTH_TOKEN_ENCRYPTION_KEY')
            if not key:
                return token
            
            f = Fernet(key.encode())
            return f.encrypt(token.encode()).decode()
            
        except Exception as e:
            logger.error(f"Error encrypting token: {str(e)}")
            return token
    
    def _decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt OAuth token from storage"""
        try:
            from cryptography.fernet import Fernet
            key = current_app.config.get('OAUTH_TOKEN_ENCRYPTION_KEY')
            if not key:
                return encrypted_token
            
            f = Fernet(key.encode())
            return f.decrypt(encrypted_token.encode()).decode()
            
        except Exception as e:
            logger.error(f"Error decrypting token: {str(e)}")
            return encrypted_token
    
    def unlink_oauth_account(self, user_id: int, provider_name: str) -> bool:
        """Unlink OAuth account from user"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE user_oauth_accounts uoa
                JOIN oauth_providers op ON uoa.provider_id = op.provider_id
                SET uoa.is_active = FALSE, uoa.updated_at = NOW()
                WHERE uoa.user_id = %s AND op.provider_name = %s
            """, (user_id, provider_name))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info(f"OAuth account unlinked for user {user_id} from {provider_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error unlinking OAuth account: {str(e)}")
            return False
    
    def get_linked_oauth_accounts(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all linked OAuth accounts for a user"""
        try:
            conn = get_connection()
            if not conn:
                return []
                
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT op.provider_name, op.display_name, uoa.provider_user_id, 
                       uoa.created_at, uoa.is_active
                FROM user_oauth_accounts uoa
                JOIN oauth_providers op ON uoa.provider_id = op.provider_id
                WHERE uoa.user_id = %s
                ORDER BY uoa.created_at DESC
            """, (user_id,))
            
            accounts = cursor.fetchall()
            cursor.close()
            conn.close()
            
            return accounts
            
        except Exception as e:
            logger.error(f"Error getting linked OAuth accounts: {str(e)}")
            return []
    
    def refresh_oauth_token(self, user_id: int, provider_name: str) -> bool:
        """Refresh OAuth token for a provider"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor(dictionary=True)
            
            # Get OAuth account info
            cursor.execute("""
                SELECT uoa.access_token_encrypted, uoa.refresh_token_encrypted,
                       op.provider_name, op.client_id, op.client_secret,
                       op.token_url
                FROM user_oauth_accounts uoa
                JOIN oauth_providers op ON uoa.provider_id = op.provider_id
                WHERE uoa.user_id = %s AND op.provider_name = %s AND uoa.is_active = TRUE
            """, (user_id, provider_name))
            
            account = cursor.fetchone()
            if not account:
                cursor.close()
                conn.close()
                return False
            
            # Decrypt tokens
            refresh_token = self._decrypt_token(account['refresh_token_encrypted'])
            if not refresh_token:
                cursor.close()
                conn.close()
                return False
            
            # Refresh token using provider-specific logic
            new_token = self._refresh_provider_token(provider_name, refresh_token, account)
            
            if new_token:
                # Update stored token
                access_token_encrypted = self._encrypt_token(new_token.get('access_token'))
                refresh_token_encrypted = self._encrypt_token(new_token.get('refresh_token'))
                
                expires_at = None
                if new_token.get('expires_in'):
                    expires_at = datetime.utcnow() + timedelta(seconds=new_token['expires_in'])
                
                cursor.execute("""
                    UPDATE user_oauth_accounts 
                    SET access_token_encrypted = %s, refresh_token_encrypted = %s,
                        token_expires_at = %s, updated_at = NOW()
                    WHERE user_id = %s AND provider_id = (
                        SELECT provider_id FROM oauth_providers WHERE provider_name = %s
                    )
                """, (access_token_encrypted, refresh_token_encrypted, expires_at, user_id, provider_name))
                
                conn.commit()
                cursor.close()
                conn.close()
                
                logger.info(f"OAuth token refreshed for user {user_id} with {provider_name}")
                return True
            
            cursor.close()
            conn.close()
            return False
            
        except Exception as e:
            logger.error(f"Error refreshing OAuth token: {str(e)}")
            return False
    
    def _refresh_provider_token(self, provider_name: str, refresh_token: str, 
                             account_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Refresh token using provider-specific logic"""
        try:
            import requests
            
            if provider_name == 'google':
                # Google token refresh
                data = {
                    'client_id': account_info['client_id'],
                    'client_secret': account_info['client_secret'],
                    'refresh_token': refresh_token,
                    'grant_type': 'refresh_token'
                }
                
                response = requests.post('https://oauth2.googleapis.com/token', data=data)
                if response.status_code == 200:
                    return response.json()
            
            elif provider_name == 'microsoft':
                # Microsoft token refresh
                data = {
                    'client_id': account_info['client_id'],
                    'client_secret': account_info['client_secret'],
                    'refresh_token': refresh_token,
                    'grant_type': 'refresh_token'
                }
                
                response = requests.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', data=data)
                if response.status_code == 200:
                    return response.json()
            
            elif provider_name == 'github':
                # GitHub token refresh
                data = {
                    'client_id': account_info['client_id'],
                    'client_secret': account_info['client_secret'],
                    'refresh_token': refresh_token,
                    'grant_type': 'refresh_token'
                }
                
                response = requests.post('https://github.com/login/oauth/access_token', data=data)
                if response.status_code == 200:
                    return response.json()
            
            return None
            
        except Exception as e:
            logger.error(f"Error refreshing {provider_name} token: {str(e)}")
            return None

# Initialize OAuth service
oauth_service = OAuthService()