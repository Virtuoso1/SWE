"""
Enterprise Authentication Service Tests

This module contains comprehensive tests for the enterprise authentication service
including unit tests and integration tests.
"""

import pytest
import json
import time
from unittest.mock import Mock, patch, MagicMock
from flask import Flask
from services.enterprise_auth_service import EnterpriseAuthService
from services.jwt_service import JWTService
from services.auth_monitoring_service import AuthEventType
from tests import (
    test_app, test_client, test_db, mock_redis,
    sample_user_data, sample_admin_data, auth_headers,
    create_test_token, assert_valid_json_response,
    assert_error_response, assert_valid_password_hash,
    assert_valid_email, assert_valid_phone
)

class TestEnterpriseAuthService:
    """Test cases for EnterpriseAuthService"""
    
    def test_authenticate_user_success(self, test_client, sample_user_data):
        """Test successful user authentication"""
        # Mock database operations
        with patch('services.enterprise_auth_service.EnterpriseUserHelper.get_user_by_email') as mock_get_user, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.verify_password') as mock_verify, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.check_account_lock') as mock_check_lock, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.reset_failed_login') as mock_reset, \
             patch('services.enterprise_auth_service.JWTService.generate_tokens') as mock_generate:
            
            # Setup mocks
            mock_get_user.return_value = sample_user_data
            mock_verify.return_value = True
            mock_check_lock.return_value = (False, None)
            mock_generate.return_value = ('access_token', 'refresh_token', time.time() + 3600)
            
            # Test authentication
            response = test_client.post('/api/auth/login', 
                json={
                    'email': sample_user_data['email'],
                    'password': sample_user_data['password']
                },
                headers={'Content-Type': 'application/json'}
            )
            
            # Assertions
            assert_valid_json_response(response)
            data = response.get_json()
            assert data['status'] == 'success'
            assert 'user' in data
            assert 'tokens' in data
            assert data['user']['email'] == sample_user_data['email']
            assert data['user']['role'] == sample_user_data['role']
            
            # Verify mocks were called
            mock_get_user.assert_called_once_with(sample_user_data['email'])
            mock_verify.assert_called_once()
            mock_check_lock.assert_called_once()
            mock_reset.assert_called_once()
            mock_generate.assert_called_once()
    
    def test_authenticate_user_invalid_password(self, test_client, sample_user_data):
        """Test authentication with invalid password"""
        with patch('services.enterprise_auth_service.EnterpriseUserHelper.get_user_by_email') as mock_get_user, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.verify_password') as mock_verify, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.increment_failed_login') as mock_increment:
            
            # Setup mocks
            mock_get_user.return_value = sample_user_data
            mock_verify.return_value = False
            
            # Test authentication
            response = test_client.post('/api/auth/login',
                json={
                    'email': sample_user_data['email'],
                    'password': 'wrongpassword'
                },
                headers={'Content-Type': 'application/json'}
            )
            
            # Assertions
            assert response.status_code == 401
            data = response.get_json()
            assert data['success'] is False
            
            # Verify mocks were called
            mock_get_user.assert_called_once()
            mock_verify.assert_called_once()
            mock_increment.assert_called_once()
    
    def test_authenticate_user_account_locked(self, test_client, sample_user_data):
        """Test authentication with locked account"""
        with patch('services.enterprise_auth_service.EnterpriseUserHelper.get_user_by_email') as mock_get_user, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.check_account_lock') as mock_check_lock:
            
            # Setup mocks
            mock_get_user.return_value = sample_user_data
            mock_check_lock.return_value = (True, time.time() + 3600)
            
            # Test authentication
            response = test_client.post('/api/auth/login',
                json={
                    'email': sample_user_data['email'],
                    'password': sample_user_data['password']
                },
                headers={'Content-Type': 'application/json'}
            )
            
            # Assertions
            assert response.status_code == 401
            data = response.get_json()
            assert data['success'] is False
            
            # Verify mocks were called
            mock_get_user.assert_called_once()
            mock_check_lock.assert_called_once()
    
    def test_authenticate_user_mfa_required(self, test_client, sample_user_data):
        """Test authentication with MFA required"""
        # Create user with MFA enabled
        mfa_user_data = sample_user_data.copy()
        mfa_user_data['mfa_enabled'] = True
        
        with patch('services.enterprise_auth_service.EnterpriseUserHelper.get_user_by_email') as mock_get_user, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.verify_password') as mock_verify, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.check_account_lock') as mock_check_lock, \
             patch('services.enterprise_auth_service.MFAService.verify_mfa_token') as mock_mfa:
            
            # Setup mocks
            mock_get_user.return_value = mfa_user_data
            mock_verify.return_value = True
            mock_check_lock.return_value = (False, None)
            mock_mfa.return_value = False
            
            # Test authentication without MFA token
            response = test_client.post('/api/auth/login',
                json={
                    'email': sample_user_data['email'],
                    'password': sample_user_data['password']
                },
                headers={'Content-Type': 'application/json'}
            )
            
            # Assertions
            assert_valid_json_response(response)
            data = response.get_json()
            assert data['status'] == 'mfa_required'
            assert 'user_id' in data
            assert data['message'] == 'Multi-factor authentication required'
            
            # Verify mocks were called
            mock_get_user.assert_called_once()
            mock_verify.assert_called_once()
            mock_check_lock.assert_called_once()
    
    def test_authenticate_user_missing_fields(self, test_client):
        """Test authentication with missing required fields"""
        # Test missing email
        response = test_client.post('/api/auth/login',
            json={'password': 'testpassword'},
            headers={'Content-Type': 'application/json'}
        )
        assert_error_response(response, 400, 'Missing required field: email')
        
        # Test missing password
        response = test_client.post('/api/auth/login',
            json={'email': 'test@example.com'},
            headers={'Content-Type': 'application/json'}
        )
        assert_error_response(response, 400, 'Missing required field: password')
    
    def test_register_user_success(self, test_client, sample_user_data):
        """Test successful user registration"""
        with patch('services.enterprise_auth_service.validate_email') as mock_validate_email, \
             patch('services.enterprise_auth_service.validate_password_strength') as mock_validate_password, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.get_user_by_email') as mock_get_user, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.create_user') as mock_create_user, \
             patch('services.enterprise_auth_service.EnterpriseAuthService._generate_email_verification_token') as mock_generate_token:
            
            # Setup mocks
            mock_validate_email.return_value = True
            mock_validate_password.return_value = True
            mock_get_user.return_value = None  # User doesn't exist
            mock_create_user.return_value = sample_user_data
            mock_generate_token.return_value = 'verification_token_123'
            
            # Test registration
            response = test_client.post('/api/auth/register',
                json={
                    'email': sample_user_data['email'],
                    'password': sample_user_data['password'],
                    'full_name': sample_user_data['full_name'],
                    'role': sample_user_data['role']
                },
                headers={'Content-Type': 'application/json'}
            )
            
            # Assertions
            assert_valid_json_response(response)
            data = response.get_json()
            assert data['status'] == 'success'
            assert 'user' in data
            assert 'verification_token' in data
            assert data['user']['email'] == sample_user_data['email']
            
            # Verify mocks were called
            mock_validate_email.assert_called_once_with(sample_user_data['email'])
            mock_validate_password.assert_called_once_with(sample_user_data['password'])
            mock_get_user.assert_called_once_with(sample_user_data['email'])
            mock_create_user.assert_called_once()
            mock_generate_token.assert_called_once()
    
    def test_register_user_invalid_email(self, test_client, sample_user_data):
        """Test registration with invalid email"""
        with patch('services.enterprise_auth_service.validate_email') as mock_validate_email:
            mock_validate_email.return_value = False
            
            # Test registration
            response = test_client.post('/api/auth/register',
                json={
                    'email': 'invalid-email',
                    'password': sample_user_data['password'],
                    'full_name': sample_user_data['full_name'],
                    'role': sample_user_data['role']
                },
                headers={'Content-Type': 'application/json'}
            )
            
            # Assertions
            assert response.status_code == 400
            data = response.get_json()
            assert data['success'] is False
            
            # Verify mock was called
            mock_validate_email.assert_called_once_with('invalid-email')
    
    def test_register_user_weak_password(self, test_client, sample_user_data):
        """Test registration with weak password"""
        with patch('services.enterprise_auth_service.validate_email') as mock_validate_email, \
             patch('services.enterprise_auth_service.validate_password_strength') as mock_validate_password:
            
            mock_validate_email.return_value = True
            mock_validate_password.return_value = False
            
            # Test registration
            response = test_client.post('/api/auth/register',
                json={
                    'email': sample_user_data['email'],
                    'password': 'weak',
                    'full_name': sample_user_data['full_name'],
                    'role': sample_user_data['role']
                },
                headers={'Content-Type': 'application/json'}
            )
            
            # Assertions
            assert response.status_code == 400
            data = response.get_json()
            assert data['success'] is False
            
            # Verify mocks were called
            mock_validate_email.assert_called_once()
            mock_validate_password.assert_called_once_with('weak')
    
    def test_register_user_existing_email(self, test_client, sample_user_data):
        """Test registration with existing email"""
        with patch('services.enterprise_auth_service.validate_email') as mock_validate_email, \
             patch('services.enterprise_auth_service.validate_password_strength') as mock_validate_password, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.get_user_by_email') as mock_get_user:
            
            mock_validate_email.return_value = True
            mock_validate_password.return_value = True
            mock_get_user.return_value = sample_user_data  # User exists
            
            # Test registration
            response = test_client.post('/api/auth/register',
                json={
                    'email': sample_user_data['email'],
                    'password': sample_user_data['password'],
                    'full_name': sample_user_data['full_name'],
                    'role': sample_user_data['role']
                },
                headers={'Content-Type': 'application/json'}
            )
            
            # Assertions
            assert response.status_code == 400
            data = response.get_json()
            assert data['success'] is False
            
            # Verify mocks were called
            mock_validate_email.assert_called_once()
            mock_validate_password.assert_called_once()
            mock_get_user.assert_called_once()
    
    def test_refresh_token_success(self, test_client, sample_user_data):
        """Test successful token refresh"""
        with patch('services.enterprise_auth_service.JWTService.refresh_access_token') as mock_refresh:
            mock_refresh.return_value = ('new_access_token', 'new_refresh_token', time.time() + 3600)
            
            # Test token refresh
            response = test_client.post('/api/auth/refresh',
                json={'refresh_token': 'valid_refresh_token'},
                headers={'Content-Type': 'application/json'}
            )
            
            # Assertions
            assert_valid_json_response(response)
            data = response.get_json()
            assert data['status'] == 'success'
            assert 'tokens' in data
            assert data['tokens']['access_token'] == 'new_access_token'
            assert data['tokens']['refresh_token'] == 'new_refresh_token'
            
            # Verify mock was called
            mock_refresh.assert_called_once_with('valid_refresh_token')
    
    def test_refresh_token_invalid(self, test_client):
        """Test token refresh with invalid token"""
        with patch('services.enterprise_auth_service.JWTService.refresh_access_token') as mock_refresh:
            mock_refresh.return_value = None
            
            # Test token refresh
            response = test_client.post('/api/auth/refresh',
                json={'refresh_token': 'invalid_refresh_token'},
                headers={'Content-Type': 'application/json'}
            )
            
            # Assertions
            assert response.status_code == 401
            data = response.get_json()
            assert data['success'] is False
            
            # Verify mock was called
            mock_refresh.assert_called_once_with('invalid_refresh_token')
    
    def test_logout_success(self, test_client, sample_user_data):
        """Test successful logout"""
        with patch('services.enterprise_auth_service.JWTService.verify_access_token') as mock_verify, \
             patch('services.enterprise_auth_service.JWTService.revoke_token') as mock_revoke:
            
            mock_verify.return_value = {
                'user_id': sample_user_data['user_id'],
                'jti': 'test-jti'
            }
            
            # Test logout
            response = test_client.post('/api/auth/logout',
                json={'access_token': 'valid_access_token'},
                headers={'Content-Type': 'application/json'}
            )
            
            # Assertions
            assert_valid_json_response(response)
            data = response.get_json()
            assert data['success'] is True
            
            # Verify mocks were called
            mock_verify.assert_called_once_with('valid_access_token')
            mock_revoke.assert_called_once()
    
    def test_logout_invalid_token(self, test_client):
        """Test logout with invalid token"""
        with patch('services.enterprise_auth_service.JWTService.verify_access_token') as mock_verify:
            mock_verify.return_value = None
            
            # Test logout
            response = test_client.post('/api/auth/logout',
                json={'access_token': 'invalid_access_token'},
                headers={'Content-Type': 'application/json'}
            )
            
            # Assertions
            assert response.status_code == 401
            data = response.get_json()
            assert data['success'] is False
            
            # Verify mock was called
            mock_verify.assert_called_once_with('invalid_access_token')
    
    def test_password_reset_request_success(self, test_client, sample_user_data):
        """Test successful password reset request"""
        with patch('services.enterprise_auth_service.EnterpriseUserHelper.get_user_by_email') as mock_get_user, \
             patch('services.enterprise_auth_service.generate_password_reset_token') as mock_generate_token, \
             patch('services.enterprise_auth_service.hash_token') as mock_hash_token:
            
            mock_get_user.return_value = sample_user_data
            mock_generate_token.return_value = 'reset_token_123'
            mock_hash_token.return_value = 'hashed_token_123'
            
            # Test password reset request
            response = test_client.post('/api/auth/password-reset/request',
                json={'email': sample_user_data['email']},
                headers={'Content-Type': 'application/json'}
            )
            
            # Assertions
            assert_valid_json_response(response)
            data = response.get_json()
            assert data['success'] is True
            
            # Verify mocks were called
            mock_get_user.assert_called_once_with(sample_user_data['email'])
            mock_generate_token.assert_called_once()
            mock_hash_token.assert_called_once()
    
    def test_password_reset_request_nonexistent_user(self, test_client):
        """Test password reset request for non-existent user"""
        with patch('services.enterprise_auth_service.EnterpriseUserHelper.get_user_by_email') as mock_get_user:
            mock_get_user.return_value = None
            
            # Test password reset request
            response = test_client.post('/api/auth/password-reset/request',
                json={'email': 'nonexistent@example.com'},
                headers={'Content-Type': 'application/json'}
            )
            
            # Assertions
            assert_valid_json_response(response)
            data = response.get_json()
            assert data['success'] is True  # Should return success for security
            
            # Verify mock was called
            mock_get_user.assert_called_once_with('nonexistent@example.com')
    
    def test_password_reset_success(self, test_client, sample_user_data):
        """Test successful password reset"""
        with patch('services.enterprise_auth_service.validate_password_strength') as mock_validate_password, \
             patch('services.enterprise_auth_service.hash_token') as mock_hash_token, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.get_user_by_email') as mock_get_user, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.update_password') as mock_update_password:
            
            mock_validate_password.return_value = True
            mock_hash_token.return_value = 'hashed_token_123'
            mock_get_user.return_value = {
                'user_id': sample_user_data['user_id'],
                'email': sample_user_data['email']
            }
            mock_update_password.return_value = True
            
            # Test password reset
            response = test_client.post('/api/auth/password-reset/confirm',
                json={
                    'reset_token': 'reset_token_123',
                    'new_password': 'NewPassword123!'
                },
                headers={'Content-Type': 'application/json'}
            )
            
            # Assertions
            assert_valid_json_response(response)
            data = response.get_json()
            assert data['success'] is True
            
            # Verify mocks were called
            mock_validate_password.assert_called_once_with('NewPassword123!')
            mock_hash_token.assert_called_once_with('reset_token_123')
            mock_get_user.assert_called_once()
            mock_update_password.assert_called_once()
    
    def test_password_reset_invalid_token(self, test_client):
        """Test password reset with invalid token"""
        with patch('services.enterprise_auth_service.hash_token') as mock_hash_token, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.get_user_by_email') as mock_get_user:
            
            mock_hash_token.return_value = 'hashed_invalid_token'
            mock_get_user.return_value = None
            
            # Test password reset
            response = test_client.post('/api/auth/password-reset/confirm',
                json={
                    'reset_token': 'invalid_token',
                    'new_password': 'NewPassword123!'
                },
                headers={'Content-Type': 'application/json'}
            )
            
            # Assertions
            assert response.status_code == 400
            data = response.get_json()
            assert data['success'] is False
            
            # Verify mocks were called
            mock_hash_token.assert_called_once_with('invalid_token')
            mock_get_user.assert_called_once()
    
    def test_password_reset_weak_password(self, test_client):
        """Test password reset with weak password"""
        with patch('services.enterprise_auth_service.validate_password_strength') as mock_validate_password:
            mock_validate_password.return_value = False
            
            # Test password reset
            response = test_client.post('/api/auth/password-reset/confirm',
                json={
                    'reset_token': 'valid_token',
                    'new_password': 'weak'
                },
                headers={'Content-Type': 'application/json'}
            )
            
            # Assertions
            assert response.status_code == 400
            data = response.get_json()
            assert data['success'] is False
            
            # Verify mock was called
            mock_validate_password.assert_called_once_with('weak')
    
    @patch('services.enterprise_auth_service.auth_monitoring_service')
    def test_login_attempt_tracking(self, mock_monitoring, test_client, sample_user_data):
        """Test that login attempts are tracked in monitoring service"""
        mock_monitoring.track_auth_event = Mock()
        
        with patch('services.enterprise_auth_service.EnterpriseUserHelper.get_user_by_email') as mock_get_user, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.verify_password') as mock_verify, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.check_account_lock') as mock_check_lock:
            
            mock_get_user.return_value = sample_user_data
            mock_verify.return_value = True
            mock_check_lock.return_value = (False, None)
            
            # Test authentication
            test_client.post('/api/auth/login',
                json={
                    'email': sample_user_data['email'],
                    'password': sample_user_data['password']
                },
                headers={'Content-Type': 'application/json'}
            )
            
            # Verify monitoring service was called
            mock_monitoring.track_auth_event.assert_called_once()
            
            # Check the event type and success status
            call_args = mock_monitoring.track_auth_event.call_args[0]
            assert call_args['event_type'] == AuthEventType.LOGIN_SUCCESS
            assert call_args['success'] is True
            assert call_args['user_id'] == str(sample_user_data['user_id'])
    
    @patch('services.enterprise_auth_service.auth_monitoring_service')
    def test_logout_tracking(self, mock_monitoring, test_client, sample_user_data):
        """Test that logout events are tracked in monitoring service"""
        mock_monitoring.track_auth_event = Mock()
        
        with patch('services.enterprise_auth_service.JWTService.verify_access_token') as mock_verify, \
             patch('services.enterprise_auth_service.JWTService.revoke_token') as mock_revoke:
            
            mock_verify.return_value = {
                'user_id': sample_user_data['user_id'],
                'jti': 'test-jti'
            }
            
            # Test logout
            test_client.post('/api/auth/logout',
                json={'access_token': 'valid_access_token'},
                headers={'Content-Type': 'application/json'}
            )
            
            # Verify monitoring service was called
            mock_monitoring.track_auth_event.assert_called_once()
            
            # Check the event type
            call_args = mock_monitoring.track_auth_event.call_args[0]
            assert call_args['event_type'] == AuthEventType.LOGOUT
            assert call_args['success'] is True
            assert call_args['user_id'] == str(sample_user_data['user_id'])
    
    @patch('services.enterprise_auth_service.auth_monitoring_service')
    def test_password_reset_tracking(self, mock_monitoring, test_client, sample_user_data):
        """Test that password reset events are tracked in monitoring service"""
        mock_monitoring.track_auth_event = Mock()
        
        with patch('services.enterprise_auth_service.validate_password_strength') as mock_validate_password, \
             patch('services.enterprise_auth_service.hash_token') as mock_hash_token, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.get_user_by_email') as mock_get_user, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.update_password') as mock_update_password:
            
            mock_validate_password.return_value = True
            mock_hash_token.return_value = 'hashed_token_123'
            mock_get_user.return_value = {
                'user_id': sample_user_data['user_id'],
                'email': sample_user_data['email']
            }
            mock_update_password.return_value = True
            
            # Test password reset
            test_client.post('/api/auth/password-reset/confirm',
                json={
                    'reset_token': 'reset_token_123',
                    'new_password': 'NewPassword123!'
                },
                headers={'Content-Type': 'application/json'}
            )
            
            # Verify monitoring service was called
            mock_monitoring.track_auth_event.assert_called_once()
            
            # Check the event type
            call_args = mock_monitoring.track_auth_event.call_args[0]
            assert call_args['event_type'] == AuthEventType.PASSWORD_CHANGE
            assert call_args['success'] is True
            assert call_args['user_id'] == str(sample_user_data['user_id'])


class TestEnterpriseAuthServiceIntegration:
    """Integration tests for EnterpriseAuthService"""
    
    def test_full_authentication_flow(self, test_client, sample_user_data):
        """Test complete authentication flow"""
        # Step 1: Register user
        with patch('services.enterprise_auth_service.validate_email') as mock_validate_email, \
             patch('services.enterprise_auth_service.validate_password_strength') as mock_validate_password, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.get_user_by_email') as mock_get_user, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.create_user') as mock_create_user:
            
            mock_validate_email.return_value = True
            mock_validate_password.return_value = True
            mock_get_user.return_value = None
            mock_create_user.return_value = sample_user_data
            
            register_response = test_client.post('/api/auth/register',
                json={
                    'email': sample_user_data['email'],
                    'password': sample_user_data['password'],
                    'full_name': sample_user_data['full_name'],
                    'role': sample_user_data['role']
                },
                headers={'Content-Type': 'application/json'}
            )
            
            assert_valid_json_response(register_response)
            
            # Step 2: Login user
            with patch('services.enterprise_auth_service.EnterpriseUserHelper.get_user_by_email') as mock_get_user_login, \
                 patch('services.enterprise_auth_service.EnterpriseUserHelper.verify_password') as mock_verify, \
                 patch('services.enterprise_auth_service.EnterpriseUserHelper.check_account_lock') as mock_check_lock, \
                 patch('services.enterprise_auth_service.JWTService.generate_tokens') as mock_generate:
                
                mock_get_user_login.return_value = sample_user_data
                mock_verify.return_value = True
                mock_check_lock.return_value = (False, None)
                mock_generate.return_value = ('access_token', 'refresh_token', time.time() + 3600)
                
                login_response = test_client.post('/api/auth/login',
                    json={
                        'email': sample_user_data['email'],
                        'password': sample_user_data['password']
                    },
                    headers={'Content-Type': 'application/json'}
                )
                
                assert_valid_json_response(login_response)
                login_data = login_response.get_json()
                assert login_data['status'] == 'success'
                
                # Step 3: Access protected endpoint
                access_token = login_data['tokens']['access_token']
                protected_response = test_client.get('/api/auth/profile',
                    headers={'Authorization': f'Bearer {access_token}'}
                )
                
                assert_valid_json_response(protected_response)
                
                # Step 4: Logout
                with patch('services.enterprise_auth_service.JWTService.verify_access_token') as mock_verify, \
                     patch('services.enterprise_auth_service.JWTService.revoke_token') as mock_revoke:
                    
                    mock_verify.return_value = {
                        'user_id': sample_user_data['user_id'],
                        'jti': 'test-jti'
                    }
                    
                    logout_response = test_client.post('/api/auth/logout',
                        json={'access_token': access_token},
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    assert_valid_json_response(logout_response)
    
    def test_mfa_authentication_flow(self, test_client, sample_user_data):
        """Test MFA authentication flow"""
        # Create user with MFA enabled
        mfa_user_data = sample_user_data.copy()
        mfa_user_data['mfa_enabled'] = True
        mfa_user_data['mfa_secret'] = 'JBSWY3DPEHPK3PXP'
        
        with patch('services.enterprise_auth_service.EnterpriseUserHelper.get_user_by_email') as mock_get_user, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.verify_password') as mock_verify, \
             patch('services.enterprise_auth_service.EnterpriseUserHelper.check_account_lock') as mock_check_lock, \
             patch('services.enterprise_auth_service.MFAService.verify_mfa_token') as mock_mfa_verify, \
             patch('services.enterprise_auth_service.JWTService.generate_tokens') as mock_generate:
            
            mock_get_user.return_value = mfa_user_data
            mock_verify.return_value = True
            mock_check_lock.return_value = (False, None)
            mock_mfa_verify.return_value = True
            mock_generate.return_value = ('access_token', 'refresh_token', time.time() + 3600)
            
            # Step 1: Login without MFA token
            response1 = test_client.post('/api/auth/login',
                json={
                    'email': sample_user_data['email'],
                    'password': sample_user_data['password']
                },
                headers={'Content-Type': 'application/json'}
            )
            
            assert_valid_json_response(response1)
            data1 = response1.get_json()
            assert data1['status'] == 'mfa_required'
            
            # Step 2: Login with MFA token
            response2 = test_client.post('/api/auth/login',
                json={
                    'email': sample_user_data['email'],
                    'password': sample_user_data['password'],
                    'mfa_token': '123456'
                },
                headers={'Content-Type': 'application/json'}
            )
            
            assert_valid_json_response(response2)
            data2 = response2.get_json()
            assert data2['status'] == 'success'
            
            # Verify mocks were called correctly
            assert mock_get_user.call_count == 2
            assert mock_verify.call_count == 2
            assert mock_check_lock.call_count == 2
            assert mock_mfa_verify.assert_called_once_with('JBSWY3DPEHPK3PXP', '123456')
            assert mock_generate.assert_called_once()
    
    def test_rate_limiting(self, test_client, sample_user_data):
        """Test rate limiting functionality"""
        with patch('services.enterprise_auth_service.EnterpriseAuthService._check_rate_limit') as mock_rate_limit:
            
            # First attempt should succeed
            mock_rate_limit.return_value = True
            response1 = test_client.post('/api/auth/login',
                json={
                    'email': sample_user_data['email'],
                    'password': 'wrongpassword'
                },
                headers={'Content-Type': 'application/json'}
            )
            
            assert response1.status_code == 401  # Invalid password, but not rate limited
            
            # Second attempt should succeed
            response2 = test_client.post('/api/auth/login',
                json={
                    'email': sample_user_data['email'],
                    'password': 'wrongpassword'
                },
                headers={'Content-Type': 'application/json'}
            )
            
            assert response2.status_code == 401  # Invalid password, but not rate limited
            
            # Third attempt should trigger rate limiting
            mock_rate_limit.return_value = False
            response3 = test_client.post('/api/auth/login',
                json={
                    'email': sample_user_data['email'],
                    'password': 'wrongpassword'
                },
                headers={'Content-Type': 'application/json'}
            )
            
            assert response3.status_code == 429  # Rate limited
            
            # Verify rate limit was checked
            assert mock_rate_limit.call_count == 3


if __name__ == '__main__':
    pytest.main([__file__])