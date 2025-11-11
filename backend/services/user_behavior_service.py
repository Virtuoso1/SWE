"""
User Behavior Analytics Service

This module provides comprehensive user behavior analytics, pattern detection,
and behavioral profiling for security and user experience optimization.
"""

import time
import logging
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from enum import Enum
import redis
from flask import current_app
from services.redis_session_service import redis_session_service
from services.auth_monitoring_service import auth_monitoring_service

logger = logging.getLogger(__name__)

class BehaviorPattern(Enum):
    """User behavior pattern types"""
    LOGIN_PATTERN = "login_pattern"
    ACTIVITY_PATTERN = "activity_pattern"
    NAVIGATION_PATTERN = "navigation_pattern"
    FEATURE_USAGE = "feature_usage"
    TIME_PATTERN = "time_pattern"
    LOCATION_PATTERN = "location_pattern"
    DEVICE_PATTERN = "device_pattern"

class RiskLevel(Enum):
    """Risk levels for behavior analysis"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class BehaviorEvent:
    """User behavior event data structure"""
    user_id: str
    event_type: str
    timestamp: datetime
    ip_address: str
    user_agent: str
    device_fingerprint: Optional[str]
    location: Optional[Dict[str, str]]
    session_id: Optional[str]
    action: str
    resource: Optional[str]
    metadata: Dict[str, Any]
    duration: Optional[float] = None

@dataclass
class BehaviorProfile:
    """User behavior profile"""
    user_id: str
    created_at: datetime
    updated_at: datetime
    login_patterns: Dict[str, Any]
    activity_patterns: Dict[str, Any]
    navigation_patterns: Dict[str, Any]
    feature_usage: Dict[str, Any]
    time_patterns: Dict[str, Any]
    location_patterns: Dict[str, Any]
    device_patterns: Dict[str, Any]
    risk_score: float
    anomalies: List[Dict[str, Any]]

@dataclass
class BehaviorAlert:
    """Behavior-based security alert"""
    alert_id: str
    user_id: str
    alert_type: str
    risk_level: RiskLevel
    title: str
    description: str
    timestamp: datetime
    details: Dict[str, Any]
    acknowledged: bool = False
    resolved: bool = False

class UserBehaviorService:
    """
    User behavior analytics and profiling service
    """
    
    def __init__(self, app=None):
        self.app = app
        self._redis_client = None
        self._event_buffer = deque(maxlen=1000)
        self._profile_cache = {}
        self._anomaly_thresholds = {
            'login_time_deviation': 2.0,  # hours
            'location_change_distance': 1000,  # km
            'device_change_frequency': 0.3,  # ratio
            'activity_spike_factor': 3.0,  # multiplier
            'navigation_pattern_deviation': 0.7,  # similarity score
            'feature_usage_anomaly': 0.8  # deviation score
        }
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize behavior service with Flask app"""
        self.app = app
        app.user_behavior_service = self
        
        # Initialize Redis client
        self._redis_client = redis_session_service._redis_client
        
        # Start background processing
        self._start_background_processing()
        
        logger.info("User behavior analytics service initialized")
    
    def _start_background_processing(self):
        """Start background processing thread"""
        def process_events():
            while True:
                try:
                    self._process_behavior_events()
                    self._update_behavior_profiles()
                    self._detect_anomalies()
                    time.sleep(60)  # Process every minute
                except Exception as e:
                    logger.error(f"Behavior processing error: {str(e)}")
                    time.sleep(300)  # Wait 5 minutes on error
        
        processing_thread = threading.Thread(target=process_events, daemon=True)
        processing_thread.start()
        logger.info("User behavior processing thread started")
    
    def track_behavior_event(self, user_id: str, event_type: str, action: str,
                           resource: Optional[str] = None, metadata: Dict[str, Any] = None,
                           duration: Optional[float] = None, session_id: Optional[str] = None):
        """
        Track a user behavior event
        
        Args:
            user_id: User ID
            event_type: Type of event (login, activity, navigation, etc.)
            action: Specific action performed
            resource: Resource accessed (if applicable)
            metadata: Additional event metadata
            duration: Event duration in seconds
            session_id: Session ID
        """
        try:
            from flask import request
            
            # Create behavior event
            event = BehaviorEvent(
                user_id=user_id,
                event_type=event_type,
                timestamp=datetime.utcnow(),
                ip_address=request.remote_addr if request else 'unknown',
                user_agent=request.headers.get('User-Agent', '') if request else '',
                device_fingerprint=metadata.get('device_fingerprint') if metadata else None,
                location=metadata.get('location') if metadata else None,
                session_id=session_id,
                action=action,
                resource=resource,
                metadata=metadata or {},
                duration=duration
            )
            
            # Store event
            self._store_behavior_event(event)
            
            # Add to buffer
            self._event_buffer.append(event)
            
            logger.debug(f"Behavior event tracked: {event_type} - {action} for user {user_id}")
            
        except Exception as e:
            logger.error(f"Failed to track behavior event: {str(e)}")
    
    def _store_behavior_event(self, event: BehaviorEvent):
        """Store behavior event in Redis"""
        try:
            # Create event data
            event_data = {
                'user_id': event.user_id,
                'event_type': event.event_type,
                'timestamp': event.timestamp.isoformat(),
                'ip_address': event.ip_address,
                'user_agent': event.user_agent,
                'device_fingerprint': event.device_fingerprint,
                'location': event.location,
                'session_id': event.session_id,
                'action': event.action,
                'resource': event.resource,
                'metadata': event.metadata,
                'duration': event.duration
            }
            
            # Store in Redis with expiration
            key = f"behavior_event:{event.user_id}:{event.timestamp.timestamp()}"
            self._redis_client.setex(
                key,
                timedelta(days=30),  # Keep for 30 days
                json.dumps(event_data)
            )
            
            # Add to user's event list
            user_events_key = f"user_behavior_events:{event.user_id}"
            self._redis_client.lpush(user_events_key, key)
            self._redis_client.expire(user_events_key, timedelta(days=30))
            
            # Limit to last 1000 events per user
            self._redis_client.ltrim(user_events_key, 0, 999)
            
        except Exception as e:
            logger.error(f"Failed to store behavior event: {str(e)}")
    
    def _process_behavior_events(self):
        """Process buffered behavior events"""
        # This method can be extended for real-time event processing
        pass
    
    def _update_behavior_profiles(self):
        """Update user behavior profiles"""
        try:
            # Get unique user IDs from buffer
            user_ids = set(event.user_id for event in self._event_buffer)
            
            for user_id in user_ids:
                profile = self._generate_behavior_profile(user_id)
                if profile:
                    self._store_behavior_profile(profile)
                    self._profile_cache[user_id] = profile
        
        except Exception as e:
            logger.error(f"Failed to update behavior profiles: {str(e)}")
    
    def _generate_behavior_profile(self, user_id: str) -> Optional[BehaviorProfile]:
        """Generate behavior profile for a user"""
        try:
            # Get user's recent events
            events = self._get_user_events(user_id, limit=500)
            
            if not events:
                return None
            
            # Analyze different behavior patterns
            login_patterns = self._analyze_login_patterns(events)
            activity_patterns = self._analyze_activity_patterns(events)
            navigation_patterns = self._analyze_navigation_patterns(events)
            feature_usage = self._analyze_feature_usage(events)
            time_patterns = self._analyze_time_patterns(events)
            location_patterns = self._analyze_location_patterns(events)
            device_patterns = self._analyze_device_patterns(events)
            
            # Calculate overall risk score
            risk_score = self._calculate_behavior_risk(
                login_patterns, activity_patterns, navigation_patterns,
                feature_usage, time_patterns, location_patterns, device_patterns
            )
            
            # Detect anomalies
            anomalies = self._detect_profile_anomalies(
                user_id, events, login_patterns, activity_patterns,
                navigation_patterns, feature_usage, time_patterns,
                location_patterns, device_patterns
            )
            
            return BehaviorProfile(
                user_id=user_id,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                login_patterns=login_patterns,
                activity_patterns=activity_patterns,
                navigation_patterns=navigation_patterns,
                feature_usage=feature_usage,
                time_patterns=time_patterns,
                location_patterns=location_patterns,
                device_patterns=device_patterns,
                risk_score=risk_score,
                anomalies=anomalies
            )
        
        except Exception as e:
            logger.error(f"Failed to generate behavior profile for {user_id}: {str(e)}")
            return None
    
    def _get_user_events(self, user_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get user's behavior events"""
        try:
            user_events_key = f"user_behavior_events:{user_id}"
            event_keys = self._redis_client.lrange(user_events_key, 0, limit - 1)
            
            events = []
            for key in event_keys:
                event_data = self._redis_client.get(key)
                if event_data:
                    events.append(json.loads(event_data))
            
            return events
        
        except Exception as e:
            logger.error(f"Failed to get user events: {str(e)}")
            return []
    
    def _analyze_login_patterns(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze login patterns"""
        login_events = [e for e in events if e.get('event_type') == 'login']
        
        if not login_events:
            return {}
        
        # Calculate login frequency
        login_times = [datetime.fromisoformat(e['timestamp']) for e in login_events]
        login_frequency = len(login_times) / 30.0  # per day for last 30 days
        
        # Calculate typical login hours
        login_hours = [t.hour for t in login_times]
        typical_hours = self._calculate_mode(login_hours)
        
        # Calculate typical login days
        login_days = [t.weekday() for t in login_times]
        typical_days = self._calculate_mode(login_days)
        
        # Calculate IP diversity
        login_ips = [e['ip_address'] for e in login_events]
        unique_ips = len(set(login_ips))
        ip_diversity = unique_ips / len(login_events)
        
        return {
            'frequency': login_frequency,
            'typical_hours': typical_hours,
            'typical_days': typical_days,
            'ip_diversity': ip_diversity,
            'unique_ips': unique_ips,
            'total_logins': len(login_events)
        }
    
    def _analyze_activity_patterns(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze activity patterns"""
        activity_events = [e for e in events if e.get('event_type') == 'activity']
        
        if not activity_events:
            return {}
        
        # Calculate activity frequency
        activity_frequency = len(activity_events) / 30.0  # per day
        
        # Calculate session durations
        durations = [e.get('duration', 0) for e in activity_events if e.get('duration')]
        avg_session_duration = sum(durations) / len(durations) if durations else 0
        
        # Calculate most active hours
        activity_hours = [datetime.fromisoformat(e['timestamp']).hour for e in activity_events]
        most_active_hours = self._calculate_top_frequencies(activity_hours, 3)
        
        return {
            'frequency': activity_frequency,
            'avg_session_duration': avg_session_duration,
            'most_active_hours': most_active_hours,
            'total_activities': len(activity_events)
        }
    
    def _analyze_navigation_patterns(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze navigation patterns"""
        nav_events = [e for e in events if e.get('event_type') == 'navigation']
        
        if not nav_events:
            return {}
        
        # Calculate common paths
        paths = [e.get('resource', '') for e in nav_events if e.get('resource')]
        path_frequency = self._calculate_frequencies(paths)
        
        # Calculate navigation depth
        navigation_depths = [len(path.split('/')) for path in paths if path]
        avg_depth = sum(navigation_depths) / len(navigation_depths) if navigation_depths else 0
        
        return {
            'common_paths': path_frequency[:10],  # Top 10 paths
            'avg_navigation_depth': avg_depth,
            'total_navigations': len(nav_events)
        }
    
    def _analyze_feature_usage(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze feature usage patterns"""
        feature_events = [e for e in events if e.get('event_type') == 'feature']
        
        if not feature_events:
            return {}
        
        # Calculate feature frequency
        features = [e.get('action', '') for e in feature_events if e.get('action')]
        feature_frequency = self._calculate_frequencies(features)
        
        # Calculate usage distribution
        total_usage = len(feature_events)
        usage_distribution = {
            feature: count / total_usage 
            for feature, count in feature_frequency
        }
        
        return {
            'feature_frequency': feature_frequency,
            'usage_distribution': usage_distribution,
            'total_feature_usage': total_usage
        }
    
    def _analyze_time_patterns(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze time-based patterns"""
        if not events:
            return {}
        
        # Calculate hourly distribution
        timestamps = [datetime.fromisoformat(e['timestamp']) for e in events]
        hours = [t.hour for t in timestamps]
        hourly_distribution = self._calculate_frequencies(hours)
        
        # Calculate daily distribution
        days = [t.weekday() for t in timestamps]
        daily_distribution = self._calculate_frequencies(days)
        
        # Calculate peak activity times
        peak_hour = max(hourly_distribution, key=hourly_distribution.get)
        peak_day = max(daily_distribution, key=daily_distribution.get)
        
        return {
            'hourly_distribution': hourly_distribution,
            'daily_distribution': daily_distribution,
            'peak_hour': peak_hour,
            'peak_day': peak_day
        }
    
    def _analyze_location_patterns(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze location patterns"""
        events_with_location = [e for e in events if e.get('location')]
        
        if not events_with_location:
            return {}
        
        # Calculate location frequency
        locations = [e['location'] for e in events_with_location]
        location_strings = [json.dumps(loc, sort_keys=True) for loc in locations]
        location_frequency = self._calculate_frequencies(location_strings)
        
        # Calculate unique locations
        unique_locations = len(set(location_strings))
        location_diversity = unique_locations / len(events_with_location)
        
        return {
            'location_frequency': location_frequency,
            'unique_locations': unique_locations,
            'location_diversity': location_diversity,
            'total_location_events': len(events_with_location)
        }
    
    def _analyze_device_patterns(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze device patterns"""
        events_with_device = [e for e in events if e.get('device_fingerprint')]
        
        if not events_with_device:
            return {}
        
        # Calculate device frequency
        devices = [e['device_fingerprint'] for e in events_with_device]
        device_frequency = self._calculate_frequencies(devices)
        
        # Calculate device diversity
        unique_devices = len(set(devices))
        device_diversity = unique_devices / len(events_with_device)
        
        # Calculate user agent frequency
        user_agents = [e.get('user_agent', '') for e in events_with_device]
        ua_frequency = self._calculate_frequencies(user_agents)
        
        return {
            'device_frequency': device_frequency,
            'device_diversity': device_diversity,
            'user_agent_frequency': ua_frequency,
            'unique_devices': unique_devices,
            'total_device_events': len(events_with_device)
        }
    
    def _calculate_frequencies(self, items: List[str]) -> List[Tuple[str, int]]:
        """Calculate frequency of items"""
        frequency = defaultdict(int)
        for item in items:
            frequency[item] += 1
        
        return sorted(frequency.items(), key=lambda x: x[1], reverse=True)
    
    def _calculate_mode(self, items: List[int]) -> List[int]:
        """Calculate mode(s) of a list"""
        frequency = defaultdict(int)
        for item in items:
            frequency[item] += 1
        
        if not frequency:
            return []
        
        max_freq = max(frequency.values())
        modes = [item for item, freq in frequency.items() if freq == max_freq]
        return modes
    
    def _calculate_top_frequencies(self, items: List[int], top_n: int) -> List[int]:
        """Calculate top N most frequent items"""
        frequency = defaultdict(int)
        for item in items:
            frequency[item] += 1
        
        sorted_items = sorted(frequency.items(), key=lambda x: x[1], reverse=True)
        return [item for item, _ in sorted_items[:top_n]]
    
    def _calculate_behavior_risk(self, *patterns) -> float:
        """Calculate overall behavior risk score"""
        risk_score = 0.0
        
        for pattern in patterns:
            if not pattern:
                continue
            
            # Check for high-risk indicators
            if 'ip_diversity' in pattern and pattern['ip_diversity'] > 0.5:
                risk_score += 0.2
            
            if 'device_diversity' in pattern and pattern['device_diversity'] > 0.4:
                risk_score += 0.15
            
            if 'location_diversity' in pattern and pattern['location_diversity'] > 0.3:
                risk_score += 0.1
            
            if 'frequency' in pattern:
                freq = pattern['frequency']
                if freq > 100:  # Very high activity
                    risk_score += 0.1
                elif freq < 0.1:  # Very low activity
                    risk_score += 0.05
        
        return min(risk_score, 1.0)
    
    def _detect_profile_anomalies(self, user_id: str, events: List[Dict[str, Any]], 
                               *patterns) -> List[Dict[str, Any]]:
        """Detect anomalies in behavior profile"""
        anomalies = []
        
        # Get user's baseline profile
        baseline_profile = self._profile_cache.get(user_id)
        
        if not baseline_profile:
            return anomalies
        
        # Compare current patterns with baseline
        for i, pattern in enumerate(patterns):
            if not pattern:
                continue
            
            pattern_names = ['login', 'activity', 'navigation', 'feature', 
                          'time', 'location', 'device']
            
            if i < len(pattern_names):
                pattern_name = pattern_names[i]
                anomaly = self._detect_pattern_anomaly(
                    pattern_name, pattern, baseline_profile
                )
                
                if anomaly:
                    anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_pattern_anomaly(self, pattern_name: str, current_pattern: Dict[str, Any],
                             baseline_profile: BehaviorProfile) -> Optional[Dict[str, Any]]:
        """Detect anomaly in a specific pattern"""
        baseline_pattern = getattr(baseline_profile, f"{pattern_name}_patterns", {})
        
        if not baseline_pattern:
            return None
        
        # Check for significant deviations
        if pattern_name == 'login':
            return self._detect_login_anomaly(current_pattern, baseline_pattern)
        elif pattern_name == 'location':
            return self._detect_location_anomaly(current_pattern, baseline_pattern)
        elif pattern_name == 'device':
            return self._detect_device_anomaly(current_pattern, baseline_pattern)
        
        return None
    
    def _detect_login_anomaly(self, current: Dict[str, Any], 
                           baseline: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect login pattern anomalies"""
        # Check for unusual login time
        if 'typical_hours' in baseline and 'typical_hours' in current:
            current_hours = current['typical_hours']
            baseline_hours = baseline['typical_hours']
            
            if not any(hour in baseline_hours for hour in current_hours):
                return {
                    'type': 'unusual_login_time',
                    'severity': 'medium',
                    'description': 'Login at unusual time',
                    'details': {
                        'current_hours': current_hours,
                        'baseline_hours': baseline_hours
                    }
                }
        
        return None
    
    def _detect_location_anomaly(self, current: Dict[str, Any], 
                              baseline: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect location pattern anomalies"""
        # Check for new location
        if 'location_frequency' in current and 'location_frequency' in baseline:
            current_locations = set(current['location_frequency'].keys())
            baseline_locations = set(baseline['location_frequency'].keys())
            
            new_locations = current_locations - baseline_locations
            if new_locations:
                return {
                    'type': 'new_location',
                    'severity': 'high',
                    'description': 'Login from new location',
                    'details': {
                        'new_locations': list(new_locations)
                    }
                }
        
        return None
    
    def _detect_device_anomaly(self, current: Dict[str, Any], 
                             baseline: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect device pattern anomalies"""
        # Check for new device
        if 'device_frequency' in current and 'device_frequency' in baseline:
            current_devices = set(current['device_frequency'].keys())
            baseline_devices = set(baseline['device_frequency'].keys())
            
            new_devices = current_devices - baseline_devices
            if new_devices:
                return {
                    'type': 'new_device',
                    'severity': 'medium',
                    'description': 'Login from new device',
                    'details': {
                        'new_devices': list(new_devices)
                    }
                }
        
        return None
    
    def _store_behavior_profile(self, profile: BehaviorProfile):
        """Store behavior profile in Redis"""
        try:
            profile_data = asdict(profile)
            profile_data['created_at'] = profile.created_at.isoformat()
            profile_data['updated_at'] = profile.updated_at.isoformat()
            
            key = f"behavior_profile:{profile.user_id}"
            self._redis_client.setex(
                key,
                timedelta(days=7),  # Keep for 7 days
                json.dumps(profile_data)
            )
            
        except Exception as e:
            logger.error(f"Failed to store behavior profile: {str(e)}")
    
    def _detect_anomalies(self):
        """Detect anomalies across all users"""
        try:
            # Get all user profiles
            profile_keys = self._redis_client.keys("behavior_profile:*")
            
            for key in profile_keys:
                user_id = key.split(":")[-1]
                profile_data = self._redis_client.get(key)
                
                if profile_data:
                    profile = json.loads(profile_data)
                    
                    # Check for high-risk profiles
                    if profile.get('risk_score', 0) > 0.7:
                        self._create_behavior_alert(
                            user_id, 'high_risk_profile', RiskLevel.HIGH,
                            "High Risk Behavior Profile",
                            f"User behavior profile indicates high risk (score: {profile['risk_score']:.2f})",
                            profile
                        )
                    
                    # Check for multiple anomalies
                    anomalies = profile.get('anomalies', [])
                    if len(anomalies) > 3:
                        self._create_behavior_alert(
                            user_id, 'multiple_anomalies', RiskLevel.MEDIUM,
                            "Multiple Behavior Anomalies",
                            f"Multiple behavior anomalies detected ({len(anomalies)} anomalies)",
                            {'anomalies': anomalies}
                        )
        
        except Exception as e:
            logger.error(f"Failed to detect anomalies: {str(e)}")
    
    def _create_behavior_alert(self, user_id: str, alert_type: str, risk_level: RiskLevel,
                           title: str, description: str, details: Dict[str, Any]):
        """Create a behavior-based alert"""
        try:
            alert = BehaviorAlert(
                alert_id=f"behavior_alert_{int(time.time())}_{hash(user_id)}",
                user_id=user_id,
                alert_type=alert_type,
                risk_level=risk_level,
                title=title,
                description=description,
                timestamp=datetime.utcnow(),
                details=details
            )
            
            # Store alert
            self._store_behavior_alert(alert)
            
            # Trigger monitoring service alert
            auth_monitoring_service.track_auth_event(
                event_type=AuthEventType.SUSPICIOUS_ACTIVITY,
                user_id=user_id,
                username=None,
                ip_address=details.get('ip_address', 'unknown'),
                user_agent=details.get('user_agent', ''),
                success=False,
                details={
                    'alert_type': alert_type,
                    'risk_level': risk_level.value,
                    'title': title,
                    'description': description
                }
            )
            
            logger.warning(f"Behavior alert created: {title} - {description}")
            
        except Exception as e:
            logger.error(f"Failed to create behavior alert: {str(e)}")
    
    def _store_behavior_alert(self, alert: BehaviorAlert):
        """Store behavior alert in Redis"""
        try:
            alert_data = asdict(alert)
            alert_data['timestamp'] = alert.timestamp.isoformat()
            alert_data['risk_level'] = alert.risk_level.value
            
            key = f"behavior_alert:{alert.alert_id}"
            self._redis_client.setex(
                key,
                timedelta(days=30),  # Keep for 30 days
                json.dumps(alert_data)
            )
            
            # Add to alerts list
            self._redis_client.lpush("behavior_alerts", alert.alert_id)
            self._redis_client.expire("behavior_alerts", timedelta(days=30))
            
        except Exception as e:
            logger.error(f"Failed to store behavior alert: {str(e)}")
    
    def get_user_profile(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get behavior profile for a user"""
        try:
            # Check cache first
            if user_id in self._profile_cache:
                return self._profile_cache[user_id]
            
            # Get from Redis
            key = f"behavior_profile:{user_id}"
            profile_data = self._redis_client.get(key)
            
            if profile_data:
                profile = json.loads(profile_data)
                self._profile_cache[user_id] = profile
                return profile
            
            return None
        
        except Exception as e:
            logger.error(f"Failed to get user profile: {str(e)}")
            return None
    
    def get_user_insights(self, user_id: str) -> Dict[str, Any]:
        """Get behavioral insights for a user"""
        try:
            profile = self.get_user_profile(user_id)
            if not profile:
                return {}
            
            # Generate insights
            insights = {
                'risk_assessment': {
                    'score': profile.get('risk_score', 0),
                    'level': self._get_risk_level(profile.get('risk_score', 0)),
                    'factors': self._get_risk_factors(profile)
                },
                'behavioral_patterns': {
                    'login_consistency': self._assess_login_consistency(profile),
                    'activity_level': self._assess_activity_level(profile),
                    'device_familiarity': self._assess_device_familiarity(profile),
                    'location_stability': self._assess_location_stability(profile)
                },
                'recommendations': self._generate_recommendations(profile),
                'anomalies': profile.get('anomalies', []),
                'last_updated': profile.get('updated_at')
            }
            
            return insights
        
        except Exception as e:
            logger.error(f"Failed to get user insights: {str(e)}")
            return {}
    
    def _get_risk_level(self, risk_score: float) -> str:
        """Get risk level from score"""
        if risk_score >= 0.8:
            return RiskLevel.CRITICAL.value
        elif risk_score >= 0.6:
            return RiskLevel.HIGH.value
        elif risk_score >= 0.4:
            return RiskLevel.MEDIUM.value
        else:
            return RiskLevel.LOW.value
    
    def _get_risk_factors(self, profile: Dict[str, Any]) -> List[str]:
        """Get risk factors from profile"""
        factors = []
        
        login_patterns = profile.get('login_patterns', {})
        if login_patterns.get('ip_diversity', 0) > 0.5:
            factors.append('High IP diversity')
        
        device_patterns = profile.get('device_patterns', {})
        if device_patterns.get('device_diversity', 0) > 0.4:
            factors.append('High device diversity')
        
        location_patterns = profile.get('location_patterns', {})
        if location_patterns.get('location_diversity', 0) > 0.3:
            factors.append('High location diversity')
        
        return factors
    
    def _assess_login_consistency(self, profile: Dict[str, Any]) -> str:
        """Assess login consistency"""
        login_patterns = profile.get('login_patterns', {})
        
        if not login_patterns:
            return 'insufficient_data'
        
        ip_diversity = login_patterns.get('ip_diversity', 0)
        frequency = login_patterns.get('frequency', 0)
        
        if ip_diversity < 0.2 and frequency > 0:
            return 'consistent'
        elif ip_diversity < 0.5:
            return 'moderately_consistent'
        else:
            return 'inconsistent'
    
    def _assess_activity_level(self, profile: Dict[str, Any]) -> str:
        """Assess activity level"""
        activity_patterns = profile.get('activity_patterns', {})
        
        if not activity_patterns:
            return 'insufficient_data'
        
        frequency = activity_patterns.get('frequency', 0)
        
        if frequency > 10:
            return 'high'
        elif frequency > 5:
            return 'medium'
        elif frequency > 1:
            return 'low'
        else:
            return 'very_low'
    
    def _assess_device_familiarity(self, profile: Dict[str, Any]) -> str:
        """Assess device familiarity"""
        device_patterns = profile.get('device_patterns', {})
        
        if not device_patterns:
            return 'insufficient_data'
        
        device_diversity = device_patterns.get('device_diversity', 0)
        
        if device_diversity < 0.2:
            return 'very_familiar'
        elif device_diversity < 0.4:
            return 'familiar'
        elif device_diversity < 0.6:
            return 'moderately_familiar'
        else:
            return 'unfamiliar'
    
    def _assess_location_stability(self, profile: Dict[str, Any]) -> str:
        """Assess location stability"""
        location_patterns = profile.get('location_patterns', {})
        
        if not location_patterns:
            return 'insufficient_data'
        
        location_diversity = location_patterns.get('location_diversity', 0)
        
        if location_diversity < 0.1:
            return 'very_stable'
        elif location_diversity < 0.3:
            return 'stable'
        elif location_diversity < 0.5:
            return 'moderately_stable'
        else:
            return 'unstable'
    
    def _generate_recommendations(self, profile: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on profile"""
        recommendations = []
        
        risk_score = profile.get('risk_score', 0)
        
        if risk_score > 0.7:
            recommendations.append('Consider enabling additional security verification')
        
        login_patterns = profile.get('login_patterns', {})
        if login_patterns.get('ip_diversity', 0) > 0.5:
            recommendations.append('Review login locations for unauthorized access')
        
        device_patterns = profile.get('device_patterns', {})
        if device_patterns.get('device_diversity', 0) > 0.4:
            recommendations.append('Consider registering trusted devices')
        
        activity_patterns = profile.get('activity_patterns', {})
        if activity_patterns.get('frequency', 0) < 1:
            recommendations.append('Account appears inactive - consider reach out')
        
        return recommendations


# Global user behavior service instance
user_behavior_service = UserBehaviorService()