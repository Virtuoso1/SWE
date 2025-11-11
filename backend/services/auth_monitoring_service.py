"""
Real-time Authentication Monitoring Service

This module provides real-time monitoring of authentication attempts,
anomaly detection, and alerting for security events.
"""

import time
import threading
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from enum import Enum
import redis
from flask import current_app
from services.redis_session_service import redis_session_service
from services.audit_service import audit_service

logger = logging.getLogger(__name__)

class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AuthEventType(Enum):
    """Authentication event types"""
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    BRUTE_FORCE_DETECTED = "brute_force_detected"
    ANOMALOUS_LOGIN = "anomalous_login"

@dataclass
class AuthEvent:
    """Authentication event data structure"""
    event_type: AuthEventType
    user_id: Optional[str]
    username: Optional[str]
    ip_address: str
    user_agent: str
    timestamp: datetime
    success: bool
    details: Dict[str, Any]
    risk_score: float = 0.0
    location: Optional[Dict[str, str]] = None
    device_fingerprint: Optional[str] = None

@dataclass
class SecurityAlert:
    """Security alert data structure"""
    alert_id: str
    severity: AlertSeverity
    event_type: AuthEventType
    title: str
    description: str
    timestamp: datetime
    ip_address: str
    user_id: Optional[str]
    username: Optional[str]
    details: Dict[str, Any]
    acknowledged: bool = False
    resolved: bool = False

class AuthMonitoringService:
    """
    Real-time authentication monitoring and alerting service
    """
    
    def __init__(self, app=None):
        self.app = app
        self._redis_client = None
        self._event_handlers = []
        self._alert_handlers = []
        self._monitoring_active = False
        self._monitoring_thread = None
        self._event_buffer = deque(maxlen=1000)
        self._alert_buffer = deque(maxlen=500)
        self._risk_thresholds = {
            'brute_force': 5,  # failures in 5 minutes
            'anomalous_location': 0.7,
            'new_device': 0.5,
            'rapid_attempts': 10,  # attempts in 1 minute
            'off_hours_login': 0.3
        }
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize monitoring service with Flask app"""
        self.app = app
        app.auth_monitoring_service = self
        
        # Initialize Redis client
        self._redis_client = redis_session_service._redis_client
        
        # Start monitoring
        self._start_monitoring()
        
        logger.info("Authentication monitoring service initialized")
    
    def _start_monitoring(self):
        """Start background monitoring thread"""
        if self._monitoring_active:
            return
        
        self._monitoring_active = True
        self._monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self._monitoring_thread.start()
        logger.info("Authentication monitoring thread started")
    
    def _monitoring_loop(self):
        """Background monitoring loop"""
        while self._monitoring_active:
            try:
                # Process events and detect anomalies
                self._process_events()
                self._detect_anomalies()
                self._check_alert_conditions()
                
                # Sleep for a short interval
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"Monitoring loop error: {str(e)}")
                time.sleep(30)  # Wait longer on error
    
    def track_auth_event(self, event_type: AuthEventType, user_id: Optional[str],
                        username: Optional[str], ip_address: str, user_agent: str,
                        success: bool, details: Dict[str, Any] = None,
                        device_fingerprint: Optional[str] = None,
                        location: Optional[Dict[str, str]] = None):
        """
        Track an authentication event
        
        Args:
            event_type: Type of authentication event
            user_id: User ID (if available)
            username: Username (if available)
            ip_address: Client IP address
            user_agent: Client user agent string
            success: Whether the event was successful
            details: Additional event details
            device_fingerprint: Device fingerprint (if available)
            location: Geographic location data
        """
        try:
            # Create event
            event = AuthEvent(
                event_type=event_type,
                user_id=user_id,
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                timestamp=datetime.utcnow(),
                success=success,
                details=details or {},
                device_fingerprint=device_fingerprint,
                location=location
            )
            
            # Calculate risk score
            event.risk_score = self._calculate_risk_score(event)
            
            # Store event
            self._store_event(event)
            
            # Add to buffer
            self._event_buffer.append(event)
            
            # Log to audit service
            audit_service.log_auth_event(
                event_type=event_type.value,
                user_id=user_id,
                username=username,
                ip_address=ip_address,
                success=success,
                details=details,
                risk_score=event.risk_score
            )
            
            # Trigger event handlers
            self._trigger_event_handlers(event)
            
            logger.debug(f"Auth event tracked: {event_type.value} for {username} from {ip_address}")
            
        except Exception as e:
            logger.error(f"Failed to track auth event: {str(e)}")
    
    def _calculate_risk_score(self, event: AuthEvent) -> float:
        """Calculate risk score for an authentication event"""
        risk_score = 0.0
        
        # Base risk for failed attempts
        if not event.success:
            risk_score += 0.3
        
        # Check for suspicious IP
        if self._is_suspicious_ip(event.ip_address):
            risk_score += 0.4
        
        # Check for suspicious user agent
        if self._is_suspicious_user_agent(event.user_agent):
            risk_score += 0.2
        
        # Check for off-hours login
        if self._is_off_hours(event.timestamp):
            risk_score += self._risk_thresholds['off_hours_login']
        
        # Check for new device
        if event.device_fingerprint and self._is_new_device(event.user_id, event.device_fingerprint):
            risk_score += self._risk_thresholds['new_device']
        
        # Check for anomalous location
        if event.location and self._is_anomalous_location(event.user_id, event.location):
            risk_score += self._risk_thresholds['anomalous_location']
        
        # Check for rapid attempts
        if self._is_rapid_attempts(event.ip_address, event.timestamp):
            risk_score += 0.5
        
        return min(risk_score, 1.0)  # Cap at 1.0
    
    def _is_suspicious_ip(self, ip_address: str) -> bool:
        """Check if IP address is suspicious"""
        try:
            # Check against known malicious IPs
            key = f"suspicious_ip:{ip_address}"
            return self._redis_client.exists(key)
        except Exception:
            return False
    
    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is suspicious"""
        suspicious_patterns = [
            'bot', 'crawler', 'spider', 'scraper', 'curl', 'wget',
            'python-requests', 'java', 'perl', 'ruby'
        ]
        
        user_agent_lower = user_agent.lower()
        return any(pattern in user_agent_lower for pattern in suspicious_patterns)
    
    def _is_off_hours(self, timestamp: datetime) -> bool:
        """Check if timestamp is during off-hours"""
        hour = timestamp.hour
        return hour < 6 or hour > 22  # 10 PM to 6 AM
    
    def _is_new_device(self, user_id: str, device_fingerprint: str) -> bool:
        """Check if device fingerprint is new for user"""
        if not user_id or not device_fingerprint:
            return False
        
        try:
            key = f"user_devices:{user_id}"
            return not self._redis_client.sismember(key, device_fingerprint)
        except Exception:
            return False
    
    def _is_anomalous_location(self, user_id: str, location: Dict[str, str]) -> bool:
        """Check if location is anomalous for user"""
        if not user_id or not location:
            return False
        
        try:
            # Get user's known locations
            key = f"user_locations:{user_id}"
            known_locations = self._redis_client.smembers(key)
            
            if not known_locations:
                return False
            
            # Check if current location is known
            location_str = json.dumps(location, sort_keys=True)
            return location_str not in known_locations
        except Exception:
            return False
    
    def _is_rapid_attempts(self, ip_address: str, timestamp: datetime) -> bool:
        """Check if there are rapid attempts from IP"""
        try:
            key = f"rapid_attempts:{ip_address}"
            count = self._redis_client.incr(key)
            
            if count == 1:
                self._redis_client.expire(key, 60)  # 1 minute window
            
            return count > self._risk_thresholds['rapid_attempts']
        except Exception:
            return False
    
    def _store_event(self, event: AuthEvent):
        """Store authentication event in Redis"""
        try:
            # Store event data
            event_data = {
                'event_type': event.event_type.value,
                'user_id': event.user_id,
                'username': event.username,
                'ip_address': event.ip_address,
                'user_agent': event.user_agent,
                'timestamp': event.timestamp.isoformat(),
                'success': event.success,
                'details': event.details,
                'risk_score': event.risk_score,
                'device_fingerprint': event.device_fingerprint,
                'location': event.location
            }
            
            # Store in Redis with expiration
            key = f"auth_event:{event.timestamp.timestamp()}:{hash(event.ip_address)}"
            self._redis_client.setex(
                key, 
                timedelta(days=7),  # Keep for 7 days
                json.dumps(event_data)
            )
            
            # Update counters
            self._update_counters(event)
            
        except Exception as e:
            logger.error(f"Failed to store auth event: {str(e)}")
    
    def _update_counters(self, event: AuthEvent):
        """Update monitoring counters"""
        try:
            # Global counters
            self._redis_client.incr("auth_events:total")
            
            if event.success:
                self._redis_client.incr("auth_events:success")
            else:
                self._redis_client.incr("auth_events:failure")
            
            # IP-based counters
            ip_key = f"ip_events:{event.ip_address}"
            self._redis_client.incr(ip_key)
            self._redis_client.expire(ip_key, 3600)  # 1 hour
            
            # User-based counters
            if event.user_id:
                user_key = f"user_events:{event.user_id}"
                self._redis_client.incr(user_key)
                self._redis_client.expire(user_key, 86400)  # 24 hours
            
        except Exception as e:
            logger.error(f"Failed to update counters: {str(e)}")
    
    def _process_events(self):
        """Process buffered events"""
        # This method can be extended for real-time event processing
        pass
    
    def _detect_anomalies(self):
        """Detect anomalies in authentication patterns"""
        try:
            # Check for brute force attacks
            self._detect_brute_force()
            
            # Check for anomalous login patterns
            self._detect_anomalous_patterns()
            
        except Exception as e:
            logger.error(f"Anomaly detection error: {str(e)}")
    
    def _detect_brute_force(self):
        """Detect brute force attacks"""
        try:
            # Get IPs with high failure rates
            current_time = datetime.utcnow()
            time_window = 300  # 5 minutes
            
            for event in self._event_buffer:
                if (event.event_type == AuthEventType.LOGIN_FAILURE and
                    (current_time - event.timestamp).total_seconds() < time_window):
                    
                    # Count failures from this IP
                    failure_count = sum(
                        1 for e in self._event_buffer
                        if (e.ip_address == event.ip_address and
                            e.event_type == AuthEventType.LOGIN_FAILURE and
                            (current_time - e.timestamp).total_seconds() < time_window)
                    )
                    
                    if failure_count >= self._risk_thresholds['brute_force']:
                        self._create_alert(
                            AlertSeverity.HIGH,
                            AuthEventType.BRUTE_FORCE_DETECTED,
                            "Brute Force Attack Detected",
                            f"Multiple failed login attempts from {event.ip_address}",
                            event.ip_address,
                            event.user_id,
                            event.username,
                            {'failure_count': failure_count, 'time_window': time_window}
                        )
                        break
        
        except Exception as e:
            logger.error(f"Brute force detection error: {str(e)}")
    
    def _detect_anomalous_patterns(self):
        """Detect anomalous authentication patterns"""
        try:
            # Check for high-risk events
            for event in self._event_buffer:
                if event.risk_score > 0.7:
                    self._create_alert(
                        AlertSeverity.MEDIUM,
                        AuthEventType.SUSPICIOUS_ACTIVITY,
                        "Suspicious Authentication Activity",
                        f"High-risk authentication event detected (score: {event.risk_score:.2f})",
                        event.ip_address,
                        event.user_id,
                        event.username,
                        {
                            'risk_score': event.risk_score,
                            'event_type': event.event_type.value,
                            'details': event.details
                        }
                    )
        
        except Exception as e:
            logger.error(f"Anomalous pattern detection error: {str(e)}")
    
    def _check_alert_conditions(self):
        """Check for alert conditions"""
        # This method can be extended for custom alert conditions
        pass
    
    def _create_alert(self, severity: AlertSeverity, event_type: AuthEventType,
                     title: str, description: str, ip_address: str,
                     user_id: Optional[str], username: Optional[str],
                     details: Dict[str, Any]):
        """Create a security alert"""
        try:
            alert = SecurityAlert(
                alert_id=f"alert_{int(time.time())}_{hash(ip_address)}",
                severity=severity,
                event_type=event_type,
                title=title,
                description=description,
                timestamp=datetime.utcnow(),
                ip_address=ip_address,
                user_id=user_id,
                username=username,
                details=details
            )
            
            # Store alert
            self._store_alert(alert)
            
            # Add to buffer
            self._alert_buffer.append(alert)
            
            # Trigger alert handlers
            self._trigger_alert_handlers(alert)
            
            logger.warning(f"Security alert created: {title} - {description}")
            
        except Exception as e:
            logger.error(f"Failed to create alert: {str(e)}")
    
    def _store_alert(self, alert: SecurityAlert):
        """Store security alert in Redis"""
        try:
            alert_data = asdict(alert)
            alert_data['timestamp'] = alert.timestamp.isoformat()
            alert_data['severity'] = alert.severity.value
            alert_data['event_type'] = alert.event_type.value
            
            # Store with expiration
            key = f"security_alert:{alert.alert_id}"
            self._redis_client.setex(
                key,
                timedelta(days=30),  # Keep for 30 days
                json.dumps(alert_data)
            )
            
            # Add to alerts list
            self._redis_client.lpush("security_alerts", alert.alert_id)
            self._redis_client.expire("security_alerts", timedelta(days=30))
            
        except Exception as e:
            logger.error(f"Failed to store alert: {str(e)}")
    
    def _trigger_event_handlers(self, event: AuthEvent):
        """Trigger registered event handlers"""
        for handler in self._event_handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Event handler error: {str(e)}")
    
    def _trigger_alert_handlers(self, alert: SecurityAlert):
        """Trigger registered alert handlers"""
        for handler in self._alert_handlers:
            try:
                handler(alert)
            except Exception as e:
                logger.error(f"Alert handler error: {str(e)}")
    
    def add_event_handler(self, handler: Callable[[AuthEvent], None]):
        """Add an event handler"""
        self._event_handlers.append(handler)
    
    def add_alert_handler(self, handler: Callable[[SecurityAlert], None]):
        """Add an alert handler"""
        self._alert_handlers.append(handler)
    
    def get_recent_events(self, limit: int = 100, user_id: Optional[str] = None,
                        ip_address: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get recent authentication events"""
        try:
            events = []
            
            for event in self._event_buffer:
                if user_id and event.user_id != user_id:
                    continue
                if ip_address and event.ip_address != ip_address:
                    continue
                
                events.append({
                    'event_type': event.event_type.value,
                    'user_id': event.user_id,
                    'username': event.username,
                    'ip_address': event.ip_address,
                    'timestamp': event.timestamp.isoformat(),
                    'success': event.success,
                    'risk_score': event.risk_score,
                    'details': event.details
                })
                
                if len(events) >= limit:
                    break
            
            return events
        
        except Exception as e:
            logger.error(f"Failed to get recent events: {str(e)}")
            return []
    
    def get_recent_alerts(self, limit: int = 50, severity: Optional[AlertSeverity] = None,
                         acknowledged: Optional[bool] = None) -> List[Dict[str, Any]]:
        """Get recent security alerts"""
        try:
            alerts = []
            
            for alert in self._alert_buffer:
                if severity and alert.severity != severity:
                    continue
                if acknowledged is not None and alert.acknowledged != acknowledged:
                    continue
                
                alerts.append({
                    'alert_id': alert.alert_id,
                    'severity': alert.severity.value,
                    'event_type': alert.event_type.value,
                    'title': alert.title,
                    'description': alert.description,
                    'timestamp': alert.timestamp.isoformat(),
                    'ip_address': alert.ip_address,
                    'user_id': alert.user_id,
                    'username': alert.username,
                    'acknowledged': alert.acknowledged,
                    'resolved': alert.resolved,
                    'details': alert.details
                })
                
                if len(alerts) >= limit:
                    break
            
            return alerts
        
        except Exception as e:
            logger.error(f"Failed to get recent alerts: {str(e)}")
            return []
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge a security alert"""
        try:
            key = f"security_alert:{alert_id}"
            alert_data = self._redis_client.get(key)
            
            if alert_data:
                alert = json.loads(alert_data)
                alert['acknowledged'] = True
                
                self._redis_client.setex(
                    key,
                    timedelta(days=30),
                    json.dumps(alert)
                )
                
                return True
            
            return False
        
        except Exception as e:
            logger.error(f"Failed to acknowledge alert: {str(e)}")
            return False
    
    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve a security alert"""
        try:
            key = f"security_alert:{alert_id}"
            alert_data = self._redis_client.get(key)
            
            if alert_data:
                alert = json.loads(alert_data)
                alert['resolved'] = True
                
                self._redis_client.setex(
                    key,
                    timedelta(days=30),
                    json.dumps(alert)
                )
                
                return True
            
            return False
        
        except Exception as e:
            logger.error(f"Failed to resolve alert: {str(e)}")
            return False
    
    def get_monitoring_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        try:
            stats = {
                'total_events': int(self._redis_client.get("auth_events:total") or 0),
                'successful_events': int(self._redis_client.get("auth_events:success") or 0),
                'failed_events': int(self._redis_client.get("auth_events:failure") or 0),
                'active_alerts': len(self._alert_buffer),
                'monitoring_active': self._monitoring_active,
                'buffer_size': len(self._event_buffer)
            }
            
            return stats
        
        except Exception as e:
            logger.error(f"Failed to get monitoring stats: {str(e)}")
            return {}
    
    def stop_monitoring(self):
        """Stop the monitoring service"""
        self._monitoring_active = False
        if self._monitoring_thread:
            self._monitoring_thread.join(timeout=5)
        logger.info("Authentication monitoring service stopped")


# Global monitoring service instance
auth_monitoring_service = AuthMonitoringService()

# Default alert handler for logging
def default_alert_handler(alert: SecurityAlert):
    """Default alert handler that logs alerts"""
    logger.warning(f"SECURITY ALERT [{alert.severity.value.upper()}]: {alert.title}")
    logger.warning(f"Description: {alert.description}")
    logger.warning(f"IP: {alert.ip_address}, User: {alert.username}")
    logger.warning(f"Details: {alert.details}")

# Register default alert handler
auth_monitoring_service.add_alert_handler(default_alert_handler)