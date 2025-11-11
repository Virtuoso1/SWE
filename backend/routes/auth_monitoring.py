"""
Authentication Monitoring API Routes

This module provides REST API endpoints for real-time authentication monitoring,
security alerts, and event tracking.
"""

import logging
from flask import Blueprint, request, jsonify, current_app
from functools import wraps
from services.auth_monitoring_service import (
    auth_monitoring_service, AuthEventType, AlertSeverity
)
from services.jwt_service import jwt_required, role_required, permission_required
from utils.enterprise_validators import validate_pagination, validate_sort_order

logger = logging.getLogger(__name__)

# Create blueprint
monitoring_bp = Blueprint('monitoring', __name__, url_prefix='/api/monitoring')

def security_admin_required(f):
    """Decorator to require security admin permissions"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for admin role or specific security permission
        if not (hasattr(request, 'user') and 
                (request.user.get('role') == 'admin' or 
                 'security_admin' in request.user.get('permissions', []))):
            return jsonify({'error': 'Security admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

@monitoring_bp.route('/events', methods=['GET'])
@jwt_required
@permission_required('security', 'view')
def get_auth_events():
    """Get recent authentication events"""
    try:
        # Validate pagination parameters
        page, per_page = validate_pagination(request.args)
        limit = request.args.get('limit', per_page, type=int)
        
        # Get filter parameters
        user_id = request.args.get('user_id')
        ip_address = request.args.get('ip_address')
        event_type = request.args.get('event_type')
        
        # Get events
        events = auth_monitoring_service.get_recent_events(
            limit=limit,
            user_id=user_id,
            ip_address=ip_address
        )
        
        # Filter by event type if specified
        if event_type:
            events = [e for e in events if e.get('event_type') == event_type]
        
        return jsonify({
            'success': True,
            'data': events,
            'count': len(events)
        })
    except Exception as e:
        logger.error(f"Failed to get auth events: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve authentication events'
        }), 500

@monitoring_bp.route('/events/track', methods=['POST'])
@jwt_required
@permission_required('security', 'monitor')
def track_auth_event():
    """Track an authentication event (internal use)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'Event data is required'
            }), 400
        
        # Validate required fields
        required_fields = ['event_type', 'ip_address', 'user_agent', 'success']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400
        
        # Parse event type
        try:
            event_type = AuthEventType(data['event_type'])
        except ValueError:
            return jsonify({
                'success': False,
                'error': 'Invalid event type'
            }), 400
        
        # Track event
        auth_monitoring_service.track_auth_event(
            event_type=event_type,
            user_id=data.get('user_id'),
            username=data.get('username'),
            ip_address=data['ip_address'],
            user_agent=data['user_agent'],
            success=data['success'],
            details=data.get('details'),
            device_fingerprint=data.get('device_fingerprint'),
            location=data.get('location')
        )
        
        return jsonify({
            'success': True,
            'message': 'Event tracked successfully'
        })
    except Exception as e:
        logger.error(f"Failed to track auth event: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to track authentication event'
        }), 500

@monitoring_bp.route('/alerts', methods=['GET'])
@jwt_required
@permission_required('security', 'view')
def get_security_alerts():
    """Get recent security alerts"""
    try:
        # Validate pagination parameters
        page, per_page = validate_pagination(request.args)
        limit = request.args.get('limit', per_page, type=int)
        
        # Get filter parameters
        severity = request.args.get('severity')
        acknowledged = request.args.get('acknowledged')
        
        # Parse severity
        severity_enum = None
        if severity:
            try:
                severity_enum = AlertSeverity(severity)
            except ValueError:
                return jsonify({
                    'success': False,
                    'error': 'Invalid severity level'
                }), 400
        
        # Parse acknowledged
        acknowledged_bool = None
        if acknowledged is not None:
            acknowledged_bool = acknowledged.lower() == 'true'
        
        # Get alerts
        alerts = auth_monitoring_service.get_recent_alerts(
            limit=limit,
            severity=severity_enum,
            acknowledged=acknowledged_bool
        )
        
        return jsonify({
            'success': True,
            'data': alerts,
            'count': len(alerts)
        })
    except Exception as e:
        logger.error(f"Failed to get security alerts: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve security alerts'
        }), 500

@monitoring_bp.route('/alerts/<alert_id>/acknowledge', methods=['POST'])
@jwt_required
@security_admin_required
def acknowledge_alert(alert_id):
    """Acknowledge a security alert"""
    try:
        success = auth_monitoring_service.acknowledge_alert(alert_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Alert acknowledged successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Alert not found'
            }), 404
    except Exception as e:
        logger.error(f"Failed to acknowledge alert: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to acknowledge alert'
        }), 500

@monitoring_bp.route('/alerts/<alert_id>/resolve', methods=['POST'])
@jwt_required
@security_admin_required
def resolve_alert(alert_id):
    """Resolve a security alert"""
    try:
        success = auth_monitoring_service.resolve_alert(alert_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Alert resolved successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Alert not found'
            }), 404
    except Exception as e:
        logger.error(f"Failed to resolve alert: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to resolve alert'
        }), 500

@monitoring_bp.route('/stats', methods=['GET'])
@jwt_required
@permission_required('security', 'view')
def get_monitoring_stats():
    """Get monitoring statistics"""
    try:
        stats = auth_monitoring_service.get_monitoring_stats()
        
        return jsonify({
            'success': True,
            'data': stats
        })
    except Exception as e:
        logger.error(f"Failed to get monitoring stats: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve monitoring statistics'
        }), 500

@monitoring_bp.route('/dashboard', methods=['GET'])
@jwt_required
@permission_required('security', 'view')
def get_security_dashboard():
    """Get security dashboard data"""
    try:
        # Get monitoring stats
        stats = auth_monitoring_service.get_monitoring_stats()
        
        # Get recent alerts
        recent_alerts = auth_monitoring_service.get_recent_alerts(limit=10)
        
        # Get recent events
        recent_events = auth_monitoring_service.get_recent_events(limit=20)
        
        # Calculate metrics
        total_events = stats.get('total_events', 0)
        success_rate = 0
        if total_events > 0:
            success_rate = (stats.get('successful_events', 0) / total_events) * 100
        
        # Get alert counts by severity
        alert_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for alert in recent_alerts:
            severity = alert.get('severity', 'low')
            if severity in alert_counts:
                alert_counts[severity] += 1
        
        dashboard_data = {
            'stats': stats,
            'success_rate': round(success_rate, 2),
            'recent_alerts': recent_alerts,
            'recent_events': recent_events,
            'alert_counts': alert_counts,
            'timestamp': current_app.config.get('CURRENT_TIME')
        }
        
        return jsonify({
            'success': True,
            'data': dashboard_data
        })
    except Exception as e:
        logger.error(f"Failed to get security dashboard: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve security dashboard data'
        }), 500

@monitoring_bp.route('/threat-intelligence', methods=['GET'])
@jwt_required
@permission_required('security', 'view')
def get_threat_intelligence():
    """Get threat intelligence data"""
    try:
        # Get recent failed attempts
        failed_events = auth_monitoring_service.get_recent_events(
            limit=100,
            event_type='login_failure'
        )
        
        # Analyze threat patterns
        threat_data = {
            'top_attack_ips': _get_top_attack_ips(failed_events),
            'attack_patterns': _analyze_attack_patterns(failed_events),
            'geographic_threats': _analyze_geographic_threats(failed_events),
            'time_based_attacks': _analyze_time_based_attacks(failed_events)
        }
        
        return jsonify({
            'success': True,
            'data': threat_data
        })
    except Exception as e:
        logger.error(f"Failed to get threat intelligence: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve threat intelligence'
        }), 500

@monitoring_bp.route('/settings', methods=['GET'])
@jwt_required
@security_admin_required
def get_monitoring_settings():
    """Get monitoring settings"""
    try:
        settings = {
            'risk_thresholds': auth_monitoring_service._risk_thresholds,
            'monitoring_active': auth_monitoring_service._monitoring_active,
            'buffer_sizes': {
                'event_buffer': len(auth_monitoring_service._event_buffer),
                'alert_buffer': len(auth_monitoring_service._alert_buffer)
            }
        }
        
        return jsonify({
            'success': True,
            'data': settings
        })
    except Exception as e:
        logger.error(f"Failed to get monitoring settings: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve monitoring settings'
        }), 500

@monitoring_bp.route('/settings', methods=['PUT'])
@jwt_required
@security_admin_required
def update_monitoring_settings():
    """Update monitoring settings"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'Settings data is required'
            }), 400
        
        # Update risk thresholds
        if 'risk_thresholds' in data:
            thresholds = data['risk_thresholds']
            for key, value in thresholds.items():
                if key in auth_monitoring_service._risk_thresholds:
                    auth_monitoring_service._risk_thresholds[key] = value
        
        return jsonify({
            'success': True,
            'message': 'Monitoring settings updated successfully'
        })
    except Exception as e:
        logger.error(f"Failed to update monitoring settings: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to update monitoring settings'
        }), 500

@monitoring_bp.route('/export/events', methods=['GET'])
@jwt_required
@permission_required('security', 'export')
def export_events():
    """Export authentication events"""
    try:
        # Get filter parameters
        limit = request.args.get('limit', 1000, type=int)
        user_id = request.args.get('user_id')
        ip_address = request.args.get('ip_address')
        event_type = request.args.get('event_type')
        
        # Get events
        events = auth_monitoring_service.get_recent_events(
            limit=limit,
            user_id=user_id,
            ip_address=ip_address
        )
        
        # Filter by event type if specified
        if event_type:
            events = [e for e in events if e.get('event_type') == event_type]
        
        return jsonify({
            'success': True,
            'data': events,
            'exported_at': current_app.config.get('CURRENT_TIME'),
            'total_records': len(events)
        })
    except Exception as e:
        logger.error(f"Failed to export events: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to export events'
        }), 500

@monitoring_bp.route('/export/alerts', methods=['GET'])
@jwt_required
@permission_required('security', 'export')
def export_alerts():
    """Export security alerts"""
    try:
        # Get filter parameters
        limit = request.args.get('limit', 500, type=int)
        severity = request.args.get('severity')
        acknowledged = request.args.get('acknowledged')
        
        # Parse severity
        severity_enum = None
        if severity:
            try:
                severity_enum = AlertSeverity(severity)
            except ValueError:
                return jsonify({
                    'success': False,
                    'error': 'Invalid severity level'
                }), 400
        
        # Parse acknowledged
        acknowledged_bool = None
        if acknowledged is not None:
            acknowledged_bool = acknowledged.lower() == 'true'
        
        # Get alerts
        alerts = auth_monitoring_service.get_recent_alerts(
            limit=limit,
            severity=severity_enum,
            acknowledged=acknowledged_bool
        )
        
        return jsonify({
            'success': True,
            'data': alerts,
            'exported_at': current_app.config.get('CURRENT_TIME'),
            'total_records': len(alerts)
        })
    except Exception as e:
        logger.error(f"Failed to export alerts: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to export alerts'
        }), 500

def _get_top_attack_ips(events):
    """Get top attacking IP addresses"""
    ip_counts = {}
    for event in events:
        ip = event.get('ip_address')
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
    
    # Sort by count and return top 10
    sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    return [{'ip': ip, 'count': count} for ip, count in sorted_ips[:10]]

def _analyze_attack_patterns(events):
    """Analyze attack patterns"""
    patterns = {
        'user_agent_patterns': {},
        'time_patterns': {},
        'failure_reasons': {}
    }
    
    for event in events:
        # User agent patterns
        user_agent = event.get('details', {}).get('user_agent', 'Unknown')
        patterns['user_agent_patterns'][user_agent] = patterns['user_agent_patterns'].get(user_agent, 0) + 1
        
        # Time patterns
        timestamp = event.get('timestamp')
        if timestamp:
            hour = timestamp.split('T')[1].split(':')[0] if 'T' in timestamp else '00'
            patterns['time_patterns'][hour] = patterns['time_patterns'].get(hour, 0) + 1
        
        # Failure reasons
        reason = event.get('details', {}).get('reason', 'Unknown')
        patterns['failure_reasons'][reason] = patterns['failure_reasons'].get(reason, 0) + 1
    
    return patterns

def _analyze_geographic_threats(events):
    """Analyze geographic threats"""
    geo_counts = {}
    for event in events:
        location = event.get('location')
        if location and 'country' in location:
            country = location['country']
            geo_counts[country] = geo_counts.get(country, 0) + 1
    
    # Sort by count and return top countries
    sorted_countries = sorted(geo_counts.items(), key=lambda x: x[1], reverse=True)
    return [{'country': country, 'count': count} for country, count in sorted_countries[:10]]

def _analyze_time_based_attacks(events):
    """Analyze time-based attack patterns"""
    hourly_counts = {}
    for event in events:
        timestamp = event.get('timestamp')
        if timestamp:
            hour = timestamp.split('T')[1].split(':')[0] if 'T' in timestamp else '00'
            hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
    
    return hourly_counts

@monitoring_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'success': False,
        'error': 'Monitoring endpoint not found'
    }), 404

@monitoring_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Monitoring internal error: {str(error)}")
    return jsonify({
        'success': False,
        'error': 'Internal server error in monitoring service'
    }), 500