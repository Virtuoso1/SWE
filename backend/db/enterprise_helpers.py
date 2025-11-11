import bcrypt
import secrets
import hashlib
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
from db.database import get_connection
from config import get_config
import logging

logger = logging.getLogger(__name__)

class EnterpriseUserHelper:
    """Enhanced user management with enterprise features"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed.decode("utf-8")
    
    @staticmethod
    def verify_password(password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))
        except Exception as e:
            logger.error(f"Password verification error: {str(e)}")
            return False
    
    @staticmethod
    def create_user(full_name: str, email: str, password: str, role: str = "student", 
                   phone: str = None, timezone: str = "UTC", language: str = "en") -> Optional[Dict[str, Any]]:
        """Create a new user with enterprise features"""
        try:
            conn = get_connection()
            if not conn:
                return None
                
            cursor = conn.cursor()
            
            # Check if user already exists
            cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                cursor.close()
                conn.close()
                return None
            
            # Hash password
            hashed_password = EnterpriseUserHelper.hash_password(password)
            
            # Insert user
            cursor.execute("""
                INSERT INTO users (
                    full_name, email, password, role, phone, timezone, 
                    language, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
            """, (full_name, email, hashed_password, role, phone, timezone, language))
            
            user_id = cursor.lastrowid
            
            # Add to password history
            cursor.execute("""
                INSERT INTO password_history (user_id, password_hash, created_at)
                VALUES (%s, %s, NOW())
            """, (user_id, hashed_password))
            
            # Assign default role
            cursor.execute("""
                INSERT INTO user_roles (user_id, role_id, assigned_at)
                SELECT %s, role_id, NOW()
                FROM roles WHERE role_name = %s
            """, (user_id, role))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            # Get created user data
            return EnterpriseUserHelper.get_user_by_id(user_id)
            
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            return None
    
    @staticmethod
    def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID with roles and permissions"""
        try:
            conn = get_connection()
            if not conn:
                return None
                
            cursor = conn.cursor(dictionary=True)
            
            # Get basic user info
            cursor.execute("""
                SELECT u.*, 
                       GROUP_CONCAT(r.role_name) as roles
                FROM users u
                LEFT JOIN user_roles ur ON u.user_id = ur.user_id
                LEFT JOIN roles r ON ur.role_id = r.role_id
                WHERE u.user_id = %s
                GROUP BY u.user_id
            """, (user_id,))
            
            user = cursor.fetchone()
            if not user:
                cursor.close()
                conn.close()
                return None
            
            # Get user permissions
            cursor.execute("""
                SELECT DISTINCT p.permission_name, p.resource, p.action
                FROM permissions p
                JOIN role_permissions rp ON p.permission_id = rp.permission_id
                JOIN user_roles ur ON rp.role_id = ur.role_id
                WHERE ur.user_id = %s
            """, (user_id,))
            
            permissions = cursor.fetchall()
            user['permissions'] = permissions
            
            cursor.close()
            conn.close()
            
            return user
            
        except Exception as e:
            logger.error(f"Error getting user by ID: {str(e)}")
            return None
    
    @staticmethod
    def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
        """Get user by email with roles and permissions"""
        try:
            conn = get_connection()
            if not conn:
                return None
                
            cursor = conn.cursor(dictionary=True)
            
            # Get basic user info
            cursor.execute("""
                SELECT u.*, 
                       GROUP_CONCAT(r.role_name) as roles
                FROM users u
                LEFT JOIN user_roles ur ON u.user_id = ur.user_id
                LEFT JOIN roles r ON ur.role_id = r.role_id
                WHERE u.email = %s
                GROUP BY u.user_id
            """, (email,))
            
            user = cursor.fetchone()
            if not user:
                cursor.close()
                conn.close()
                return None
            
            # Get user permissions
            cursor.execute("""
                SELECT DISTINCT p.permission_name, p.resource, p.action
                FROM permissions p
                JOIN role_permissions rp ON p.permission_id = rp.permission_id
                JOIN user_roles ur ON rp.role_id = ur.role_id
                WHERE ur.user_id = %s
            """, (user['user_id'],))
            
            permissions = cursor.fetchall()
            user['permissions'] = permissions
            
            cursor.close()
            conn.close()
            
            return user
            
        except Exception as e:
            logger.error(f"Error getting user by email: {str(e)}")
            return None
    
    @staticmethod
    def update_password(user_id: int, new_password: str, current_password: str = None) -> bool:
        """Update user password with history tracking"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Get current password hash
            cursor.execute("SELECT password FROM users WHERE user_id = %s", (user_id,))
            result = cursor.fetchone()
            if not result:
                cursor.close()
                conn.close()
                return False
            
            current_hash = result[0]
            
            # Verify current password if provided
            if current_password and not EnterpriseUserHelper.verify_password(current_password, current_hash):
                cursor.close()
                conn.close()
                return False
            
            # Check password history
            config = get_config()
            cursor.execute("""
                SELECT password_hash FROM password_history 
                WHERE user_id = %s 
                ORDER BY created_at DESC 
                LIMIT %s
            """, (user_id, config.PASSWORD_HISTORY_COUNT))
            
            history = cursor.fetchall()
            new_hash = EnterpriseUserHelper.hash_password(new_password)
            
            # Check against password history
            for old_password_hash, in history:
                if EnterpriseUserHelper.verify_password(new_password, old_password_hash):
                    cursor.close()
                    conn.close()
                    return False
            
            # Update password
            cursor.execute("""
                UPDATE users 
                SET password = %s, password_changed_at = NOW(), updated_at = NOW()
                WHERE user_id = %s
            """, (new_hash, user_id))
            
            # Add to password history
            cursor.execute("""
                INSERT INTO password_history (user_id, password_hash, created_at)
                VALUES (%s, %s, NOW())
            """, (user_id, new_hash))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating password: {str(e)}")
            return False
    
    @staticmethod
    def lock_user_account(user_id: int, duration_minutes: int = None) -> bool:
        """Lock user account"""
        try:
            config = get_config()
            if duration_minutes is None:
                duration_minutes = config.ACCOUNT_LOCKOUT_DURATION
            
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            lock_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
            
            cursor.execute("""
                UPDATE users 
                SET status = 'locked', account_locked_until = %s, updated_at = NOW()
                WHERE user_id = %s
            """, (lock_until, user_id))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error locking user account: {str(e)}")
            return False
    
    @staticmethod
    def unlock_user_account(user_id: int) -> bool:
        """Unlock user account"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE users 
                SET status = 'active', account_locked_until = NULL, 
                    failed_login_attempts = 0, updated_at = NOW()
                WHERE user_id = %s
            """, (user_id,))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error unlocking user account: {str(e)}")
            return False
    
    @staticmethod
    def check_account_lock(user_id: int) -> Tuple[bool, Optional[datetime]]:
        """Check if account is locked"""
        try:
            conn = get_connection()
            if not conn:
                return False, None
                
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT status, account_locked_until 
                FROM users 
                WHERE user_id = %s
            """, (user_id,))
            
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if not result:
                return False, None
            
            status, locked_until = result
            
            if status == 'locked' and locked_until:
                if locked_until > datetime.utcnow():
                    return True, locked_until
                else:
                    # Auto-unlock if lock period has passed
                    EnterpriseUserHelper.unlock_user_account(user_id)
                    return False, None
            
            return status == 'locked', locked_until
            
        except Exception as e:
            logger.error(f"Error checking account lock: {str(e)}")
            return False, None
    
    @staticmethod
    def increment_failed_login(user_id: int) -> bool:
        """Increment failed login attempts and lock if threshold reached"""
        try:
            config = get_config()
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Get current failed attempts
            cursor.execute("""
                SELECT failed_login_attempts FROM users WHERE user_id = %s
            """, (user_id,))
            
            result = cursor.fetchone()
            if not result:
                cursor.close()
                conn.close()
                return False
            
            failed_attempts = result[0] + 1
            
            # Update failed attempts
            cursor.execute("""
                UPDATE users 
                SET failed_login_attempts = %s, updated_at = NOW()
                WHERE user_id = %s
            """, (failed_attempts, user_id))
            
            # Check if threshold reached
            if failed_attempts >= config.ACCOUNT_LOCKOUT_THRESHOLD:
                # Calculate lock duration (progressive if enabled)
                if config.ACCOUNT_LOCKOUT_PROGRESSIVE:
                    # Exponential backoff: 30min, 1hr, 2hr, 4hr, 8hr, 24hr
                    lock_duration = min(
                        30 * (2 ** (failed_attempts - config.ACCOUNT_LOCKOUT_THRESHOLD)),
                        config.ACCOUNT_LOCKOUT_MAX_DURATION
                    )
                else:
                    lock_duration = config.ACCOUNT_LOCKOUT_DURATION
                
                # Lock account
                lock_until = datetime.utcnow() + timedelta(minutes=lock_duration)
                cursor.execute("""
                    UPDATE users 
                    SET status = 'locked', account_locked_until = %s
                    WHERE user_id = %s
                """, (lock_until, user_id))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error incrementing failed login: {str(e)}")
            return False
    
    @staticmethod
    def reset_failed_login(user_id: int) -> bool:
        """Reset failed login attempts"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE users 
                SET failed_login_attempts = 0, updated_at = NOW()
                WHERE user_id = %s
            """, (user_id,))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error resetting failed login: {str(e)}")
            return False

class MFAService:
    """Multi-Factor Authentication Service"""
    
    @staticmethod
    def generate_mfa_secret() -> str:
        """Generate MFA secret"""
        return pyotp.random_base32()
    
    @staticmethod
    def generate_qr_code(email: str, secret: str) -> str:
        """Generate QR code for MFA setup"""
        try:
            config = get_config()
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=email,
                issuer_name=config.MFA_ISSUER
            )
            
            # Generate QR code
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(totp_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            img_str = base64.b64encode(buffer.getvalue()).decode()
            
            return f"data:image/png;base64,{img_str}"
            
        except Exception as e:
            logger.error(f"Error generating QR code: {str(e)}")
            return ""
    
    @staticmethod
    def verify_mfa_token(secret: str, token: str) -> bool:
        """Verify MFA token"""
        try:
            config = get_config()
            totp = pyotp.TOTP(secret, digits=config.MFA_DIGITS)
            return totp.verify(token, valid_window=1)  # Allow 1 step tolerance
        except Exception as e:
            logger.error(f"Error verifying MFA token: {str(e)}")
            return False
    
    @staticmethod
    def generate_backup_codes(count: int = 10) -> List[str]:
        """Generate backup codes"""
        codes = []
        for _ in range(count):
            code = ''.join([str(secrets.randbelow(10)) for _ in range(8)])
            codes.append(f"{code[:4]}-{code[4:]}")
        return codes
    
    @staticmethod
    def enable_mfa(user_id: int, secret: str, backup_codes: List[str]) -> bool:
        """Enable MFA for user"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE users 
                SET mfa_enabled = TRUE, mfa_secret = %s, 
                    totp_backup_codes = %s, updated_at = NOW()
                WHERE user_id = %s
            """, (secret, ','.join(backup_codes), user_id))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error enabling MFA: {str(e)}")
            return False
    
    @staticmethod
    def disable_mfa(user_id: int) -> bool:
        """Disable MFA for user"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE users 
                SET mfa_enabled = FALSE, mfa_secret = NULL, 
                    totp_backup_codes = NULL, updated_at = NOW()
                WHERE user_id = %s
            """, (user_id,))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error disabling MFA: {str(e)}")
            return False
    
    @staticmethod
    def verify_backup_code(user_id: int, code: str) -> bool:
        """Verify and consume backup code"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Get backup codes
            cursor.execute("""
                SELECT totp_backup_codes FROM users 
                WHERE user_id = %s AND mfa_enabled = TRUE
            """, (user_id,))
            
            result = cursor.fetchone()
            if not result or not result[0]:
                cursor.close()
                conn.close()
                return False
            
            backup_codes = result[0].split(',')
            
            # Check if code exists
            if code in backup_codes:
                # Remove used code
                backup_codes.remove(code)
                
                # Update user
                cursor.execute("""
                    UPDATE users 
                    SET totp_backup_codes = %s, updated_at = NOW()
                    WHERE user_id = %s
                """, (','.join(backup_codes), user_id))
                
                conn.commit()
                cursor.close()
                conn.close()
                
                return True
            
            cursor.close()
            conn.close()
            return False
            
        except Exception as e:
            logger.error(f"Error verifying backup code: {str(e)}")
            return False

class PermissionService:
    """Role-based access control service"""
    
    @staticmethod
    def check_user_permission(user_id: int, resource: str, action: str) -> bool:
        """Check if user has specific permission"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT COUNT(*) FROM permissions p
                JOIN role_permissions rp ON p.permission_id = rp.permission_id
                JOIN user_roles ur ON rp.role_id = ur.role_id
                WHERE ur.user_id = %s AND p.resource = %s AND p.action = %s
            """, (user_id, resource, action))
            
            count = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            
            return count > 0
            
        except Exception as e:
            logger.error(f"Error checking user permission: {str(e)}")
            return False
    
    @staticmethod
    def get_user_permissions(user_id: int) -> List[Dict[str, Any]]:
        """Get all permissions for a user"""
        try:
            conn = get_connection()
            if not conn:
                return []
                
            cursor = conn.cursor(dictionary=True)
            
            cursor.execute("""
                SELECT DISTINCT p.permission_name, p.resource, p.action
                FROM permissions p
                JOIN role_permissions rp ON p.permission_id = rp.permission_id
                JOIN user_roles ur ON rp.role_id = ur.role_id
                WHERE ur.user_id = %s
                ORDER BY p.resource, p.action
            """, (user_id,))
            
            permissions = cursor.fetchall()
            cursor.close()
            conn.close()
            
            return permissions
            
        except Exception as e:
            logger.error(f"Error getting user permissions: {str(e)}")
            return []
    
    @staticmethod
    def assign_role(user_id: int, role_name: str, assigned_by: int = None, expires_at: datetime = None) -> bool:
        """Assign role to user"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Get role ID
            cursor.execute("SELECT role_id FROM roles WHERE role_name = %s", (role_name,))
            result = cursor.fetchone()
            if not result:
                cursor.close()
                conn.close()
                return False
            
            role_id = result[0]
            
            # Assign role
            cursor.execute("""
                INSERT INTO user_roles (user_id, role_id, assigned_by, assigned_at, expires_at)
                VALUES (%s, %s, %s, NOW(), %s)
                ON DUPLICATE KEY UPDATE 
                    assigned_by = VALUES(assigned_by),
                    assigned_at = VALUES(assigned_at),
                    expires_at = VALUES(expires_at)
            """, (user_id, role_id, assigned_by, expires_at))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error assigning role: {str(e)}")
            return False
    
    @staticmethod
    def remove_role(user_id: int, role_name: str) -> bool:
        """Remove role from user"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            cursor.execute("""
                DELETE ur FROM user_roles ur
                JOIN roles r ON ur.role_id = r.role_id
                WHERE ur.user_id = %s AND r.role_name = %s
            """, (user_id, role_name))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Error removing role: {str(e)}")
            return False