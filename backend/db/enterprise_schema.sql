-- Enhanced Database Schema for Enterprise Authentication and Authorization

-- Enhanced users table with additional security fields
CREATE TABLE IF NOT EXISTS users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('student','librarian','admin') DEFAULT 'student',
    status ENUM('active','inactive','locked','suspended') DEFAULT 'active',
    date_joined DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    email_verified BOOLEAN DEFAULT FALSE,
    phone VARCHAR(20),
    phone_verified BOOLEAN DEFAULT FALSE,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(32),
    failed_login_attempts INT DEFAULT 0,
    account_locked_until DATETIME NULL,
    password_changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    totp_backup_codes TEXT,
    profile_picture_url VARCHAR(255),
    timezone VARCHAR(50) DEFAULT 'UTC',
    language VARCHAR(10) DEFAULT 'en',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_status (status),
    INDEX idx_last_login (last_login)
);

-- Roles and permissions system
CREATE TABLE IF NOT EXISTS roles (
    role_id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    is_system_role BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS permissions (
    permission_id INT AUTO_INCREMENT PRIMARY KEY,
    permission_name VARCHAR(100) UNIQUE NOT NULL,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_resource_action (resource, action)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INT,
    permission_id INT,
    PRIMARY KEY (role_id, permission_id),
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
    FOREIGN KEY (permission_id) REFERENCES permissions(permission_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id INT,
    role_id INT,
    assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    assigned_by INT,
    expires_at DATETIME NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(role_id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_by) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_user_roles (user_id, role_id)
);

-- Password history for preventing reuse
CREATE TABLE IF NOT EXISTS password_history (
    history_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_passwords (user_id, created_at)
);

-- Password reset tokens
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_token_hash (token_hash),
    INDEX idx_user_expires (user_id, expires_at)
);

-- Email verification tokens
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    token_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    ip_address VARCHAR(45),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_token_hash (token_hash),
    INDEX idx_user_expires (user_id, expires_at)
);

-- Device management and fingerprinting
CREATE TABLE IF NOT EXISTS user_devices (
    device_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    device_fingerprint VARCHAR(255) NOT NULL,
    device_name VARCHAR(100),
    device_type ENUM('desktop','mobile','tablet','unknown') DEFAULT 'unknown',
    platform VARCHAR(50),
    browser VARCHAR(50),
    browser_version VARCHAR(20),
    ip_address VARCHAR(45),
    is_trusted BOOLEAN DEFAULT FALSE,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_fingerprint (user_id, device_fingerprint),
    INDEX idx_last_seen (last_seen)
);

-- Session management with Redis-like functionality
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id VARCHAR(128) PRIMARY KEY,
    user_id INT NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_fingerprint VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    refresh_token_hash VARCHAR(255),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_sessions (user_id, is_active),
    INDEX idx_expires (expires_at),
    INDEX idx_last_activity (last_activity)
);

-- Enhanced login attempts with more detailed tracking
CREATE TABLE IF NOT EXISTS login_attempts (
    attempt_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    email VARCHAR(100) NOT NULL,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(50),
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_fingerprint VARCHAR(255),
    attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    country VARCHAR(2),
    city VARCHAR(100),
    is_suspicious BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_email_time (email, attempt_time),
    INDEX idx_ip_time (ip_address, attempt_time),
    INDEX idx_user_time (user_id, attempt_time),
    INDEX idx_suspicious (is_suspicious, attempt_time)
);

-- OAuth and SAML integration
CREATE TABLE IF NOT EXISTS oauth_providers (
    provider_id INT AUTO_INCREMENT PRIMARY KEY,
    provider_name VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret_encrypted TEXT NOT NULL,
    authorization_url VARCHAR(255) NOT NULL,
    token_url VARCHAR(255) NOT NULL,
    user_info_url VARCHAR(255) NOT NULL,
    scope VARCHAR(255),
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_oauth_accounts (
    account_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    provider_id INT NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    access_token_encrypted TEXT,
    refresh_token_encrypted TEXT,
    token_expires_at DATETIME,
    profile_data TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (provider_id) REFERENCES oauth_providers(provider_id) ON DELETE CASCADE,
    UNIQUE KEY unique_provider_user (provider_id, provider_user_id),
    INDEX idx_user_provider (user_id, provider_id)
);

-- SAML identity providers
CREATE TABLE IF NOT EXISTS saml_providers (
    provider_id INT AUTO_INCREMENT PRIMARY KEY,
    provider_name VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100) NOT NULL,
    entity_id VARCHAR(255) NOT NULL,
    sso_url VARCHAR(255) NOT NULL,
    slo_url VARCHAR(255),
    x509_cert TEXT NOT NULL,
    attribute_mapping TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Audit logging with tamper protection
CREATE TABLE IF NOT EXISTS audit_logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(100),
    old_values TEXT,
    new_values TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    session_id VARCHAR(128),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    severity ENUM('low','medium','high','critical') DEFAULT 'medium',
    category ENUM('authentication','authorization','data_access','data_modification','system') DEFAULT 'authentication',
    hash_signature VARCHAR(64), -- For tamper detection
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_user_action (user_id, action),
    INDEX idx_timestamp (timestamp),
    INDEX idx_resource (resource_type, resource_id),
    INDEX idx_severity (severity, timestamp)
);

-- Rate limiting and DDoS protection
CREATE TABLE IF NOT EXISTS rate_limits (
    limit_id INT AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL, -- IP, email, user_id, etc.
    window_type ENUM('minute','hour','day','week','month') NOT NULL,
    window_start DATETIME NOT NULL,
    request_count INT DEFAULT 1,
    max_requests INT NOT NULL,
    block_until DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_identifier_window (identifier, window_type, window_start),
    INDEX idx_identifier (identifier),
    INDEX idx_block_until (block_until)
);

-- Security events and alerts
CREATE TABLE IF NOT EXISTS security_events (
    event_id INT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    severity ENUM('low','medium','high','critical') NOT NULL,
    user_id INT NULL,
    ip_address VARCHAR(45),
    description TEXT,
    metadata TEXT,
    is_resolved BOOLEAN DEFAULT FALSE,
    resolved_by INT NULL,
    resolved_at DATETIME NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    FOREIGN KEY (resolved_by) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_event_type (event_type),
    INDEX idx_severity (severity),
    INDEX idx_user_events (user_id),
    INDEX idx_resolved (is_resolved, created_at)
);

-- User behavior analytics
CREATE TABLE IF NOT EXISTS user_behavior (
    behavior_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    session_id VARCHAR(128),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(100),
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_fingerprint VARCHAR(255),
    duration_ms INT,
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_action (user_id, action),
    INDEX idx_timestamp (timestamp),
    INDEX idx_session (session_id)
);

-- GDPR and CCPA compliance
CREATE TABLE IF NOT EXISTS user_consent (
    consent_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    consent_type VARCHAR(50) NOT NULL, -- 'data_processing', 'marketing', 'analytics', etc.
    granted BOOLEAN NOT NULL,
    granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    revoked_at DATETIME NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    version VARCHAR(20) DEFAULT '1.0',
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_consent (user_id, consent_type),
    INDEX idx_granted (granted, granted_at)
);

CREATE TABLE IF NOT EXISTS data_requests (
    request_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    request_type ENUM('export','delete','restrict','correct') NOT NULL,
    status ENUM('pending','processing','completed','rejected') DEFAULT 'pending',
    request_data TEXT,
    response_data TEXT,
    processed_by INT NULL,
    processed_at DATETIME NULL,
    ip_address VARCHAR(45),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (processed_by) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_user_requests (user_id, request_type),
    INDEX idx_status (status, created_at)
);

-- API keys for service-to-service authentication
CREATE TABLE IF NOT EXISTS api_keys (
    key_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    key_name VARCHAR(100) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(20) NOT NULL, -- First few characters for identification
    permissions TEXT, -- JSON array of permissions
    is_active BOOLEAN DEFAULT TRUE,
    expires_at DATETIME NULL,
    last_used_at DATETIME NULL,
    usage_count INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_key_hash (key_hash),
    INDEX idx_user_keys (user_id, is_active),
    INDEX idx_expires (expires_at)
);

-- SAML user accounts table
CREATE TABLE IF NOT EXISTS user_saml_accounts (
    account_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    provider_id INT NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    name_id VARCHAR(255),
    attributes TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (provider_id) REFERENCES saml_providers(provider_id) ON DELETE CASCADE,
    UNIQUE KEY unique_provider_user (provider_id, provider_user_id),
    INDEX idx_user_provider (user_id, provider_id)
);

-- Insert default roles and permissions
INSERT INTO roles (role_name, description, is_system_role) VALUES
('super_admin', 'Super administrator with all permissions', TRUE),
('admin', 'Administrator with most permissions', TRUE),
('librarian', 'Library staff with limited administrative permissions', TRUE),
('student', 'Regular library user with basic permissions', TRUE),
('guest', 'Unauthenticated user with minimal permissions', TRUE)
ON DUPLICATE KEY UPDATE role_name=role_name;

INSERT INTO permissions (permission_name, resource, action, description) VALUES
-- User management permissions
('users.create', 'users', 'create', 'Create new users'),
('users.read', 'users', 'read', 'View user information'),
('users.update', 'users', 'update', 'Update user information'),
('users.delete', 'users', 'delete', 'Delete users'),
('users.manage_roles', 'users', 'manage_roles', 'Assign and remove user roles'),
('users.lock', 'users', 'lock', 'Lock/unlock user accounts'),
('users.reset_password', 'users', 'reset_password', 'Reset user passwords'),

-- Book management permissions
('books.create', 'books', 'create', 'Add new books'),
('books.read', 'books', 'read', 'View book information'),
('books.update', 'books', 'update', 'Update book information'),
('books.delete', 'books', 'delete', 'Delete books'),
('books.borrow', 'books', 'borrow', 'Borrow books'),
('books.return', 'books', 'return', 'Return books'),
('books.view_history', 'books', 'view_history', 'View borrowing history'),

-- System permissions
('system.audit', 'system', 'audit', 'View audit logs'),
('system.monitor', 'system', 'monitor', 'Access system monitoring'),
('system.configure', 'system', 'configure', 'Configure system settings'),
('system.backup', 'system', 'backup', 'Perform system backups'),
('system.security', 'system', 'security', 'Manage security settings'),

-- Fine management
('fines.create', 'fines', 'create', 'Create fines'),
('fines.read', 'fines', 'read', 'View fine information'),
('fines.update', 'fines', 'update', 'Update fine information'),
('fines.delete', 'fines', 'delete', 'Delete fines'),
('fines.waive', 'fines', 'waive', 'Waive fines'),

-- Reports
('reports.generate', 'reports', 'generate', 'Generate reports'),
('reports.view', 'reports', 'view', 'View reports'),
('reports.export', 'reports', 'export', 'Export reports')
ON DUPLICATE KEY UPDATE permission_name=permission_name;

-- Assign permissions to roles
-- Super Admin gets all permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.role_name = 'super_admin'
ON DUPLICATE KEY UPDATE role_id=role_id;

-- Admin gets most permissions except system configuration
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.role_name = 'admin' AND p.permission_name NOT IN ('system.configure', 'system.backup')
ON DUPLICATE KEY UPDATE role_id=role_id;

-- Librarian gets book and fine management permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.role_name = 'librarian' AND p.permission_name IN (
    'books.create', 'books.read', 'books.update', 'books.delete', 'books.borrow', 'books.return',
    'fines.create', 'fines.read', 'fines.update', 'fines.waive',
    'reports.generate', 'reports.view', 'reports.export'
)
ON DUPLICATE KEY UPDATE role_id=role_id;

-- Student gets basic permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.role_name = 'student' AND p.permission_name IN (
    'books.read', 'books.borrow', 'books.return', 'books.view_history',
    'fines.read', 'reports.view'
)
ON DUPLICATE KEY UPDATE role_id=role_id;

-- Guest gets minimal permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.role_name = 'guest' AND p.permission_name IN (
    'books.read'
)
ON DUPLICATE KEY UPDATE role_id=role_id;