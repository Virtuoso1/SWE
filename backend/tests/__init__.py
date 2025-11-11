"""
Test Package Initialization

This module initializes the test package with common fixtures and utilities.
"""

import os
import sys
import pytest
from flask import Flask
from unittest.mock import Mock, patch

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

@pytest.fixture(scope='session')
def test_app():
    """Create test Flask application"""
    app = Flask(__name__)
    
    # Test configuration
    app.config.update({
        'TESTING': True,
        'SECRET_KEY': 'test-secret-key',
        'JWT_SECRET_KEY': 'test-jwt-secret-key',
        'JWT_REFRESH_SECRET_KEY': 'test-jwt-refresh-secret-key',
        'DB_HOST': 'localhost',
        'DB_PORT': 3306,
        'DB_USER': 'test_user',
        'DB_PASSWORD': 'test_password',
        'DB_NAME': 'test_library_db',
        'REDIS_HOST': 'localhost',
        'REDIS_PORT': 6379,
        'REDIS_DB': 1,
        'WTF_CSRF_ENABLED': False,
        'RATELIMIT_STORAGE_URL': 'memory://',
        'AUDIT_LOG_ENCRYPTION': False,
        'SESSION_ENCRYPTION': False,
        'COOKIE_SECURITY': False,
        'DDOS_DETECTION_ENABLED': False,
        'ADAPTIVE_RATE_LIMITING': False,
        'AUTO_IP_BLOCKING': False,
        'GEOIP_BLOCKING_ENABLED': False,
        'OAUTH_ENABLED': False,
        'SAML_ENABLED': False,
        'DEVICE_FINGERPRINT_ENABLED': False,
        'QUERY_OPTIMIZATION_ENABLED': False,
        'CURRENT_TIME': '2023-01-01T00:00:00Z'
    })
    
    return app

@pytest.fixture
def test_client(test_app):
    """Create test client"""
    return test_app.test_client()

@pytest.fixture
def test_db():
    """Create test database connection"""
    # This would typically create a test database
    # For now, return a mock connection
    return Mock()

@pytest.fixture
def mock_redis():
    """Create mock Redis client"""
    return Mock()

@pytest.fixture
def sample_user_data():
    """Sample user data for testing"""
    return {
        'user_id': 1,
        'email': 'test@example.com',
        'password': 'TestPassword123!',
        'full_name': 'Test User',
        'role': 'student',
        'phone': '+1234567890',
        'timezone': 'UTC',
        'language': 'en',
        'status': 'active',
        'email_verified': True,
        'mfa_enabled': False,
        'permissions': ['read_books', 'borrow_books']
    }

@pytest.fixture
def sample_admin_data():
    """Sample admin data for testing"""
    return {
        'user_id': 2,
        'email': 'admin@example.com',
        'password': 'AdminPassword123!',
        'full_name': 'Admin User',
        'role': 'admin',
        'phone': '+1234567891',
        'timezone': 'UTC',
        'language': 'en',
        'status': 'active',
        'email_verified': True,
        'mfa_enabled': True,
        'permissions': ['read_books', 'borrow_books', 'manage_users', 'manage_system']
    }

@pytest.fixture
def auth_headers():
    """Sample authentication headers"""
    return {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer test-token',
        'X-CSRF-Token': 'test-csrf-token'
    }

@pytest.fixture
def sample_device_fingerprint():
    """Sample device fingerprint"""
    return 'fp_1234567890abcdef'

@pytest.fixture
def sample_location_data():
    """Sample location data"""
    return {
        'country': 'US',
        'region': 'California',
        'city': 'San Francisco',
        'latitude': 37.7749,
        'longitude': -122.4194
    }

@pytest.fixture
def sample_audit_data():
    """Sample audit data"""
    return {
        'user_id': 1,
        'action': 'login',
        'resource_type': 'authentication',
        'description': 'User login attempt',
        'ip_address': '192.168.1.1',
        'user_agent': 'Mozilla/5.0 (Test Browser)',
        'success': True,
        'details': {'login_method': 'password'}
    }

@pytest.fixture
def sample_rate_limit_data():
    """Sample rate limit data"""
    return {
        'identifier': '192.168.1.1',
        'window_type': 'minute',
        'request_count': 5,
        'max_requests': 10,
        'block_until': '2023-01-01T01:00:00Z'
    }

@pytest.fixture
def sample_behavior_event():
    """Sample behavior event data"""
    return {
        'user_id': '1',
        'event_type': 'login',
        'action': 'successful_login',
        'resource': 'authentication',
        'metadata': {
            'device_fingerprint': 'fp_1234567890abcdef',
            'location': {
                'country': 'US',
                'region': 'California'
            }
        },
        'duration': 1.5,
        'session_id': 'sess_1234567890'
    }

# Test utilities
def create_test_token(user_id=1, email='test@example.com', role='student'):
    """Create a test JWT token"""
    import jwt
    import time
    
    payload = {
        'user_id': user_id,
        'email': email,
        'role': role,
        'exp': int(time.time()) + 3600,
        'iat': int(time.time()),
        'jti': 'test-jti-123456'
    }
    
    return jwt.encode(
        payload,
        'test-secret-key',
        algorithm='HS256'
    )

def create_mock_response(data=None, status_code=200, success=True):
    """Create a mock response"""
    from flask import Response
    import json
    
    response_data = {
        'success': success,
        'data': data
    }
    
    return Response(
        response=json.dumps(response_data),
        status=status_code,
        mimetype='application/json'
    )

def assert_valid_json_response(response, expected_data=None, status_code=200):
    """Assert valid JSON response"""
    assert response.status_code == status_code
    assert response.content_type == 'application/json'
    
    if expected_data is not None:
        response_data = response.get_json()
        assert response_data['success'] is True
        assert response_data['data'] == expected_data

def assert_error_response(response, expected_error=None, status_code=400):
    """Assert error response"""
    assert response.status_code == status_code
    assert response.content_type == 'application/json'
    
    response_data = response.get_json()
    assert response_data['success'] is False
    
    if expected_error is not None:
        assert expected_error in response_data['error']

def assert_valid_jwt_token(token):
    """Assert valid JWT token"""
    import jwt
    
    try:
        payload = jwt.decode(
            token,
            'test-secret-key',
            algorithms=['HS256']
        )
        assert 'user_id' in payload
        assert 'email' in payload
        assert 'role' in payload
        return True
    except jwt.InvalidTokenError:
        return False

def assert_valid_password_hash(password_hash):
    """Assert valid password hash"""
    import bcrypt
    
    # Should be a string
    assert isinstance(password_hash, str)
    
    # Should be bcrypt format
    assert password_hash.startswith('$2b$')
    assert len(password_hash) == 60  # Standard bcrypt hash length

def assert_valid_email(email):
    """Assert valid email format"""
    import re
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    assert re.match(email_pattern, email) is not None

def assert_valid_phone(phone):
    """Assert valid phone number"""
    import re
    
    # Remove non-digit characters
    digits_only = re.sub(r'[^\d]', '', phone)
    
    # Should have 10-15 digits
    assert len(digits_only) >= 10
    assert len(digits_only) <= 15

def assert_valid_device_fingerprint(fingerprint):
    """Assert valid device fingerprint"""
    assert isinstance(fingerprint, str)
    assert len(fingerprint) >= 10  # Minimum length
    assert len(fingerprint) <= 256  # Maximum length

def assert_valid_location_data(location):
    """Assert valid location data"""
    assert isinstance(location, dict)
    assert 'country' in location
    assert isinstance(location['country'], str)
    assert len(location['country']) == 2  # ISO country code

def assert_valid_audit_data(audit_data):
    """Assert valid audit data"""
    required_fields = ['user_id', 'action', 'resource_type', 'description']
    for field in required_fields:
        assert field in audit_data

def assert_valid_rate_limit_data(rate_limit_data):
    """Assert valid rate limit data"""
    required_fields = ['identifier', 'window_type', 'request_count', 'max_requests']
    for field in required_fields:
        assert field in rate_limit_data

def assert_valid_behavior_event(behavior_event):
    """Assert valid behavior event"""
    required_fields = ['user_id', 'event_type', 'action']
    for field in required_fields:
        assert field in behavior_event

# Mock classes for testing
class MockRedis:
    """Mock Redis client for testing"""
    
    def __init__(self):
        self.data = {}
        self.lists = {}
        self.sets = {}
    
    def get(self, key):
        return self.data.get(key)
    
    def set(self, key, value):
        self.data[key] = value
    
    def setex(self, key, time, value):
        self.data[key] = value
    
    def delete(self, key):
        if key in self.data:
            del self.data[key]
    
    def exists(self, key):
        return key in self.data
    
    def incr(self, key):
        self.data[key] = self.data.get(key, 0) + 1
        return self.data[key]
    
    def lpush(self, key, value):
        if key not in self.lists:
            self.lists[key] = []
        self.lists[key].append(value)
    
    def lrange(self, key, start, end):
        if key in self.lists:
            return self.lists[key][start:end+1]
        return []
    
    def ltrim(self, key, start, end):
        if key in self.lists:
            self.lists[key] = self.lists[key][start:end+1]
    
    def expire(self, key, time):
        pass  # Mock implementation
    
    def smembers(self, key):
        return self.sets.get(key, set())
    
    def sismember(self, key, member):
        return member in self.sets.get(key, set())

class MockDB:
    """Mock database connection for testing"""
    
    def __init__(self):
        self.cursor = Mock()
        self.connected = True
    
    def cursor(self, dictionary=True):
        return self.cursor
    
    def commit(self):
        pass
    
    def rollback(self):
        pass
    
    def close(self):
        self.connected = False

# Test configuration
TEST_CONFIG = {
    'COVERAGE_THRESHOLD': 95.0,
    'TEST_TIMEOUT': 30,
    'MAX_RETRIES': 3,
    'TEST_DATA_SIZE': 100
}