"""
Advanced Rate Limiting and DDoS Protection Service

This module provides enterprise-grade rate limiting with adaptive algorithms,
IP reputation scoring, geographic blocking, and DDoS mitigation.
"""

import time
import json
import hashlib
import redis
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
from collections import defaultdict, deque
import logging
from flask import current_app, request, g
from db.database import get_connection

logger = logging.getLogger(__name__)

class RateLimitService:
    """
    Advanced rate limiting service with DDoS protection
    """
    
    def __init__(self, app=None):
        self.app = app
        self._redis_client = None
        self._ip_reputation_cache = {}
        self._rate_limit_cache = defaultdict(lambda: deque(maxlen=1000))
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize rate limiting service with Flask app"""
        self.app = app
        app.rate_limit_service = self
        
        # Initialize Redis for distributed rate limiting
        self._init_redis()
        
        # Load IP reputation data
        self._load_ip_reputation()
        
        # Create rate limiting tables
        self._create_rate_limit_tables()
    
    def _init_redis(self):
        """Initialize Redis connection for distributed rate limiting"""
        try:
            redis_host = current_app.config.get('REDIS_HOST', 'localhost')
            redis_port = current_app.config.get('REDIS_PORT', 6379)
            redis_password = current_app.config.get('REDIS_PASSWORD')
            redis_db = current_app.config.get('REDIS_DB', 0)
            
            self._redis_client = redis.Redis(
                host=redis_host,
                port=redis_port,
                password=redis_password,
                db=redis_db,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True
            )
            
            # Test connection
            self._redis_client.ping()
            logger.info("Redis connection established for rate limiting")
            
        except Exception as e:
            logger.warning(f"Redis connection failed, using in-memory rate limiting: {str(e)}")
            self._redis_client = None
    
    def _load_ip_reputation(self):
        """Load IP reputation data from database or external sources"""
        try:
            conn = get_connection()
            if not conn:
                return
                
            cursor = conn.cursor()
            
            # Load known malicious IPs
            cursor.execute("""
                SELECT ip_address, reputation_score, threat_type, last_updated
                FROM ip_reputation
                WHERE reputation_score < -50 OR threat_type IN ('BOTNET', 'PROXY', 'TOR')
            """)
            
            for row in cursor.fetchall():
                ip, score, threat_type, last_updated = row
                self._ip_reputation_cache[ip] = {
                    'score': score,
                    'threat_type': threat_type,
                    'last_updated': last_updated
                }
            
            cursor.close()
            conn.close()
            
            logger.info(f"Loaded {len(self._ip_reputation_cache)} IP reputation entries")
            
        except Exception as e:
            logger.error(f"Failed to load IP reputation data: {str(e)}")
    
    def _create_rate_limit_tables(self):
        """Create rate limiting tables if they don't exist"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Create rate_limits table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS rate_limits (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    identifier VARCHAR(255) NOT NULL,
                    limit_type VARCHAR(50) NOT NULL,
                    window_seconds INT NOT NULL,
                    max_requests INT NOT NULL,
                    current_count INT DEFAULT 0,
                    window_start DATETIME NOT NULL,
                    is_blocked BOOLEAN DEFAULT FALSE,
                    block_reason VARCHAR(255),
                    block_until DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    UNIQUE KEY unique_identifier_type (identifier, limit_type),
                    INDEX idx_window_start (window_start),
                    INDEX idx_blocked (is_blocked, block_until)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Create ip_reputation table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    ip_address VARCHAR(45) NOT NULL UNIQUE,
                    reputation_score INT DEFAULT 0,
                    threat_type ENUM('NONE', 'PROXY', 'TOR', 'BOTNET', 'MALICIOUS', 'SUSPICIOUS'),
                    request_count INT DEFAULT 0,
                    last_seen DATETIME,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_reputation_score (reputation_score),
                    INDEX idx_threat_type (threat_type),
                    INDEX idx_last_seen (last_seen)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            # Create ddos_events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ddos_events (
                    id BIGINT PRIMARY KEY AUTO_INCREMENT,
                    event_id VARCHAR(64) UNIQUE NOT NULL,
                    attack_type VARCHAR(50) NOT NULL,
                    source_ip VARCHAR(45) NOT NULL,
                    target_endpoint VARCHAR(255),
                    request_rate INT NOT NULL,
                    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
                    status ENUM('DETECTED', 'MITIGATED', 'RESOLVED') DEFAULT 'DETECTED',
                    details JSON,
                    detected_at DATETIME NOT NULL,
                    resolved_at DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_attack_type (attack_type),
                    INDEX idx_source_ip (source_ip),
                    INDEX idx_detected_at (detected_at),
                    INDEX idx_severity (severity),
                    INDEX idx_status (status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.info("Rate limiting tables created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create rate limiting tables: {str(e)}")
            return False
    
    def get_client_ip(self) -> str:
        """Get client IP address with proxy detection"""
        # Check for forwarded headers
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            # Get the original IP (first in the list)
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip.strip()
        
        # Fall back to remote address
        return request.environ.get('REMOTE_ADDR', '0.0.0.0')
    
    def get_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Get IP reputation score and threat information"""
        # Check cache first
        if ip_address in self._ip_reputation_cache:
            return self._ip_reputation_cache[ip_address]
        
        # Check database
        try:
            conn = get_connection()
            if not conn:
                return {'score': 0, 'threat_type': 'NONE'}
                
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT reputation_score, threat_type, request_count, last_seen
                FROM ip_reputation
                WHERE ip_address = %s
            """, (ip_address,))
            
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if result:
                reputation = {
                    'score': result[0],
                    'threat_type': result[1],
                    'request_count': result[2],
                    'last_seen': result[3]
                }
            else:
                reputation = {'score': 0, 'threat_type': 'NONE'}
            
            # Cache the result
            self._ip_reputation_cache[ip_address] = reputation
            return reputation
            
        except Exception as e:
            logger.error(f"Failed to get IP reputation: {str(e)}")
            return {'score': 0, 'threat_type': 'NONE'}
    
    def update_ip_reputation(self, ip_address: str, score_change: int, 
                          threat_type: str = None) -> bool:
        """Update IP reputation score"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            # Update or insert IP reputation
            cursor.execute("""
                INSERT INTO ip_reputation 
                (ip_address, reputation_score, threat_type, request_count, last_seen)
                VALUES (%s, %s, %s, 1, NOW())
                ON DUPLICATE KEY UPDATE
                reputation_score = reputation_score + %s,
                threat_type = COALESCE(%s, threat_type),
                request_count = request_count + 1,
                last_seen = NOW()
            """, (ip_address, score_change, threat_type, score_change, threat_type))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            # Update cache
            if ip_address in self._ip_reputation_cache:
                self._ip_reputation_cache[ip_address]['score'] += score_change
                if threat_type:
                    self._ip_reputation_cache[ip_address]['threat_type'] = threat_type
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to update IP reputation: {str(e)}")
            return False
    
    def check_rate_limit(self, identifier: str, limit_type: str, 
                       window_seconds: int, max_requests: int) -> Dict[str, Any]:
        """
        Check if request exceeds rate limit
        
        Args:
            identifier: Unique identifier (IP, user ID, etc.)
            limit_type: Type of rate limit (login, api, etc.)
            window_seconds: Time window in seconds
            max_requests: Maximum requests allowed
            
        Returns:
            Dictionary with rate limit status
        """
        current_time = datetime.utcnow()
        window_start = current_time - timedelta(seconds=window_seconds)
        
        # Try Redis first for distributed rate limiting
        if self._redis_client:
            return self._check_redis_rate_limit(
                identifier, limit_type, window_seconds, max_requests, current_time
            )
        
        # Fallback to database
        return self._check_database_rate_limit(
            identifier, limit_type, window_seconds, max_requests, window_start
        )
    
    def _check_redis_rate_limit(self, identifier: str, limit_type: str,
                              window_seconds: int, max_requests: int, 
                              current_time: datetime) -> Dict[str, Any]:
        """Check rate limit using Redis"""
        try:
            key = f"rate_limit:{identifier}:{limit_type}"
            
            # Use Redis pipeline for atomic operations
            pipe = self._redis_client.pipeline()
            
            # Remove old entries
            pipe.zremrangebyscore(key, 0, current_time.timestamp() - window_seconds)
            
            # Count current requests
            pipe.zcard(key)
            
            # Add current request
            pipe.zadd(key, {str(current_time.timestamp()): current_time.timestamp()})
            
            # Set expiration
            pipe.expire(key, window_seconds)
            
            results = pipe.execute()
            current_count = results[1] + 1  # +1 for current request
            
            is_allowed = current_count <= max_requests
            
            return {
                'allowed': is_allowed,
                'current_count': current_count,
                'max_requests': max_requests,
                'window_seconds': window_seconds,
                'reset_time': current_time + timedelta(seconds=window_seconds),
                'retry_after': window_seconds if not is_allowed else 0
            }
            
        except Exception as e:
            logger.error(f"Redis rate limit check failed: {str(e)}")
            # Fallback to database
            window_start = current_time - timedelta(seconds=window_seconds)
            return self._check_database_rate_limit(
                identifier, limit_type, window_seconds, max_requests, window_start
            )
    
    def _check_database_rate_limit(self, identifier: str, limit_type: str,
                                window_seconds: int, max_requests: int,
                                window_start: datetime) -> Dict[str, Any]:
        """Check rate limit using database"""
        try:
            conn = get_connection()
            if not conn:
                return {'allowed': True, 'current_count': 0, 'max_requests': max_requests}
                
            cursor = conn.cursor()
            
            # Clean up old entries
            cursor.execute("""
                DELETE FROM rate_limits 
                WHERE window_start < %s
            """, (window_start,))
            
            # Check current count
            cursor.execute("""
                SELECT COUNT(*) FROM rate_limits 
                WHERE identifier = %s AND limit_type = %s 
                AND window_start >= %s
            """, (identifier, limit_type, window_start))
            
            current_count = cursor.fetchone()[0]
            
            # Add current request
            cursor.execute("""
                INSERT INTO rate_limits 
                (identifier, limit_type, window_seconds, max_requests, 
                 current_count, window_start)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (identifier, limit_type, window_seconds, max_requests,
                  current_count + 1, datetime.utcnow()))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            is_allowed = current_count < max_requests
            
            return {
                'allowed': is_allowed,
                'current_count': current_count + 1,
                'max_requests': max_requests,
                'window_seconds': window_seconds,
                'reset_time': datetime.utcnow() + timedelta(seconds=window_seconds),
                'retry_after': window_seconds if not is_allowed else 0
            }
            
        except Exception as e:
            logger.error(f"Database rate limit check failed: {str(e)}")
            return {'allowed': True, 'current_count': 0, 'max_requests': max_requests}
    
    def detect_ddos_attack(self, ip_address: str, endpoint: str = None) -> Optional[Dict[str, Any]]:
        """
        Detect potential DDoS attack patterns
        
        Args:
            ip_address: Source IP address
            endpoint: Target endpoint
            
        Returns:
            Attack detection result or None
        """
        try:
            current_time = datetime.utcnow()
            time_windows = [
                (60, 100),    # 100 requests per minute
                (300, 500),   # 500 requests per 5 minutes
                (3600, 2000)  # 2000 requests per hour
            ]
            
            attack_detected = False
            attack_type = None
            severity = 'LOW'
            request_rate = 0
            
            for window_seconds, threshold in time_windows:
                window_start = current_time - timedelta(seconds=window_seconds)
                
                # Check request count in window
                if self._redis_client:
                    key = f"requests:{ip_address}"
                    count = self._redis_client.zcount(
                        key, window_start.timestamp(), current_time.timestamp()
                    )
                else:
                    # Fallback to database
                    count = self._get_request_count(ip_address, window_start)
                
                if count > threshold:
                    attack_detected = True
                    request_rate = count
                    attack_type = 'VOLUME_BASED'
                    
                    # Determine severity
                    if count > threshold * 3:
                        severity = 'CRITICAL'
                    elif count > threshold * 2:
                        severity = 'HIGH'
                    elif count > threshold * 1.5:
                        severity = 'MEDIUM'
                    
                    break
            
            if attack_detected:
                # Log DDoS event
                event_id = hashlib.md5(
                    f"{ip_address}:{current_time.isoformat()}".encode()
                ).hexdigest()
                
                ddos_event = {
                    'event_id': event_id,
                    'attack_type': attack_type,
                    'source_ip': ip_address,
                    'target_endpoint': endpoint,
                    'request_rate': request_rate,
                    'severity': severity,
                    'status': 'DETECTED',
                    'details': {
                        'detection_time': current_time.isoformat(),
                        'thresholds_exceeded': time_windows
                    }
                }
                
                self._log_ddos_event(ddos_event)
                return ddos_event
            
            return None
            
        except Exception as e:
            logger.error(f"DDoS detection failed: {str(e)}")
            return None
    
    def _get_request_count(self, ip_address: str, since: datetime) -> int:
        """Get request count for IP since given time"""
        try:
            conn = get_connection()
            if not conn:
                return 0
                
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT COUNT(*) FROM rate_limits 
                WHERE identifier = %s AND window_start >= %s
            """, (ip_address, since))
            
            count = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            
            return count
            
        except Exception as e:
            logger.error(f"Failed to get request count: {str(e)}")
            return 0
    
    def _log_ddos_event(self, event_data: Dict[str, Any]) -> bool:
        """Log DDoS event to database"""
        try:
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO ddos_events 
                (event_id, attack_type, source_ip, target_endpoint, 
                 request_rate, severity, status, details, detected_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                event_data['event_id'],
                event_data['attack_type'],
                event_data['source_ip'],
                event_data['target_endpoint'],
                event_data['request_rate'],
                event_data['severity'],
                event_data['status'],
                json.dumps(event_data['details']),
                event_data['details']['detection_time']
            ))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.warning(f"DDoS attack detected: {event_data['attack_type']} from {event_data['source_ip']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to log DDoS event: {str(e)}")
            return False
    
    def block_ip(self, ip_address: str, reason: str, 
                duration_minutes: int = 60) -> bool:
        """
        Block an IP address for specified duration
        
        Args:
            ip_address: IP address to block
            reason: Reason for blocking
            duration_minutes: Duration in minutes
            
        Returns:
            True if successful, False otherwise
        """
        try:
            block_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
            
            # Store in Redis for fast lookup
            if self._redis_client:
                key = f"blocked_ip:{ip_address}"
                self._redis_client.setex(
                    key, 
                    duration_minutes * 60, 
                    json.dumps({
                        'reason': reason,
                        'blocked_at': datetime.utcnow().isoformat(),
                        'blocked_until': block_until.isoformat()
                    })
                )
            
            # Also store in database
            conn = get_connection()
            if not conn:
                return False
                
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO rate_limits 
                (identifier, limit_type, window_seconds, max_requests,
                 is_blocked, block_reason, block_until, window_start)
                VALUES (%s, 'IP_BLOCK', %s, 0, TRUE, %s, %s, NOW())
                ON DUPLICATE KEY UPDATE
                is_blocked = TRUE,
                block_reason = %s,
                block_until = %s,
                updated_at = NOW()
            """, (ip_address, duration_minutes * 60, reason, block_until, reason, block_until))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            logger.warning(f"IP blocked: {ip_address} - {reason} for {duration_minutes} minutes")
            return True
            
        except Exception as e:
            logger.error(f"Failed to block IP: {str(e)}")
            return False
    
    def is_ip_blocked(self, ip_address: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Check if IP is currently blocked
        
        Args:
            ip_address: IP address to check
            
        Returns:
            Tuple of (is_blocked, block_info)
        """
        try:
            # Check Redis first
            if self._redis_client:
                key = f"blocked_ip:{ip_address}"
                block_data = self._redis_client.get(key)
                if block_data:
                    return True, json.loads(block_data)
            
            # Check database
            conn = get_connection()
            if not conn:
                return False, None
                
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT block_reason, block_until 
                FROM rate_limits 
                WHERE identifier = %s AND limit_type = 'IP_BLOCK' 
                AND is_blocked = TRUE AND block_until > NOW()
            """, (ip_address,))
            
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if result:
                block_info = {
                    'reason': result[0],
                    'blocked_until': result[1].isoformat() if hasattr(result[1], 'isoformat') else result[1]
                }
                return True, block_info
            
            return False, None
            
        except Exception as e:
            logger.error(f"Failed to check IP block status: {str(e)}")
            return False, None
    
    def adaptive_rate_limit(self, ip_address: str, base_limit: int, 
                         window_seconds: int) -> Dict[str, Any]:
        """
        Apply adaptive rate limiting based on IP reputation and traffic patterns
        
        Args:
            ip_address: Client IP address
            base_limit: Base rate limit
            window_seconds: Time window
            
        Returns:
            Adjusted rate limit result
        """
        # Get IP reputation
        reputation = self.get_ip_reputation(ip_address)
        
        # Adjust limit based on reputation
        adjusted_limit = base_limit
        
        if reputation['score'] < -100:  # Known malicious
            adjusted_limit = max(1, base_limit // 10)
        elif reputation['score'] < -50:  # Suspicious
            adjusted_limit = max(5, base_limit // 5)
        elif reputation['score'] < -20:  # Low reputation
            adjusted_limit = max(10, base_limit // 2)
        elif reputation['score'] > 50:  # High reputation
            adjusted_limit = int(base_limit * 1.5)
        
        # Check for DDoS patterns
        ddos_event = self.detect_ddos_attack(ip_address)
        if ddos_event:
            # Significantly reduce limit during attack
            adjusted_limit = max(1, adjusted_limit // 10)
            
            # Block if critical
            if ddos_event['severity'] == 'CRITICAL':
                self.block_ip(
                    ip_address, 
                    f"DDoS attack detected: {ddos_event['attack_type']}",
                    60
                )
                return {
                    'allowed': False,
                    'blocked': True,
                    'reason': 'DDoS attack detected',
                    'retry_after': 3600
                }
        
        # Check rate limit with adjusted values
        result = self.check_rate_limit(ip_address, 'adaptive', window_seconds, adjusted_limit)
        result['adjusted_limit'] = adjusted_limit
        result['base_limit'] = base_limit
        result['reputation_score'] = reputation['score']
        
        return result


# Global rate limit service instance
rate_limit_service = RateLimitService()

# Decorator for rate limiting
def rate_limit(limit: int, window: int, key_func=None, 
               per_method: bool = False, adaptive: bool = True):
    """
    Rate limiting decorator
    
    Args:
        limit: Maximum requests allowed
        window: Time window in seconds
        key_func: Function to generate unique key (defaults to IP)
        per_method: Apply limit per HTTP method
        adaptive: Use adaptive rate limiting
    """
    def decorator(f):
        def decorated_function(*args, **kwargs):
            # Get identifier
            if key_func:
                identifier = key_func()
            else:
                identifier = rate_limit_service.get_client_ip()
            
            # Add method to key if per_method
            if per_method:
                identifier = f"{identifier}:{request.method}"
            
            # Apply adaptive rate limiting
            if adaptive:
                result = rate_limit_service.adaptive_rate_limit(identifier, limit, window)
            else:
                result = rate_limit_service.check_rate_limit(identifier, 'decorator', window, limit)
            
            # Check if IP is blocked
            is_blocked, block_info = rate_limit_service.is_ip_blocked(
                rate_limit_service.get_client_ip()
            )
            
            if is_blocked:
                from flask import jsonify
                return jsonify({
                    'success': False,
                    'message': 'Access blocked due to security policy',
                    'error_code': 'IP_BLOCKED',
                    'retry_after': 3600
                }), 429
            
            # Check rate limit
            if not result.get('allowed', True):
                from flask import jsonify
                return jsonify({
                    'success': False,
                    'message': 'Rate limit exceeded',
                    'error_code': 'RATE_LIMIT_EXCEEDED',
                    'retry_after': result.get('retry_after', window),
                    'limit': result.get('adjusted_limit', limit),
                    'window': window
                }), 429
            
            # Update IP reputation for successful requests
            rate_limit_service.update_ip_reputation(
                rate_limit_service.get_client_ip(), 
                1  # Positive score for legitimate requests
            )
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator