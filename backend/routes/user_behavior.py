"""
User Behavior Analytics API Routes

This module provides REST API endpoints for user behavior analytics,
behavioral profiling, and insights generation.
"""

import logging
from flask import Blueprint, request, jsonify, current_app
from functools import wraps
from services.user_behavior_service import (
    user_behavior_service, RiskLevel
)
from services.jwt_service import jwt_required, role_required, permission_required
from utils.enterprise_validators import validate_pagination, validate_sort_order

logger = logging.getLogger(__name__)

# Create blueprint
behavior_bp = Blueprint('behavior', __name__, url_prefix='/api/behavior')

def analytics_admin_required(f):
    """Decorator to require analytics admin permissions"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for admin role or specific analytics permission
        if not (hasattr(request, 'user') and 
                (request.user.get('role') == 'admin' or 
                 'analytics_admin' in request.user.get('permissions', []))):
            return jsonify({'error': 'Analytics admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function

@behavior_bp.route('/track', methods=['POST'])
@jwt_required
@permission_required('analytics', 'track')
def track_behavior_event():
    """Track a user behavior event"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'Event data is required'
            }), 400
        
        # Validate required fields
        required_fields = ['user_id', 'event_type', 'action']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400
        
        # Track event
        user_behavior_service.track_behavior_event(
            user_id=data['user_id'],
            event_type=data['event_type'],
            action=data['action'],
            resource=data.get('resource'),
            metadata=data.get('metadata'),
            duration=data.get('duration'),
            session_id=data.get('session_id')
        )
        
        return jsonify({
            'success': True,
            'message': 'Behavior event tracked successfully'
        })
    except Exception as e:
        logger.error(f"Failed to track behavior event: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to track behavior event'
        }), 500

@behavior_bp.route('/profile/<user_id>', methods=['GET'])
@jwt_required
@permission_required('analytics', 'view')
def get_user_profile(user_id):
    """Get behavior profile for a user"""
    try:
        # Check if user can access this profile
        if (request.user.get('user_id') != user_id and 
            request.user.get('role') not in ['admin', 'security_admin']):
            return jsonify({
                'success': False,
                'error': 'Access denied'
            }), 403
        
        profile = user_behavior_service.get_user_profile(user_id)
        
        if not profile:
            return jsonify({
                'success': False,
                'error': 'Profile not found'
            }), 404
        
        return jsonify({
            'success': True,
            'data': profile
        })
    except Exception as e:
        logger.error(f"Failed to get user profile: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve user profile'
        }), 500

@behavior_bp.route('/insights/<user_id>', methods=['GET'])
@jwt_required
@permission_required('analytics', 'view')
def get_user_insights(user_id):
    """Get behavioral insights for a user"""
    try:
        # Check if user can access these insights
        if (request.user.get('user_id') != user_id and 
            request.user.get('role') not in ['admin', 'security_admin']):
            return jsonify({
                'success': False,
                'error': 'Access denied'
            }), 403
        
        insights = user_behavior_service.get_user_insights(user_id)
        
        return jsonify({
            'success': True,
            'data': insights
        })
    except Exception as e:
        logger.error(f"Failed to get user insights: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve user insights'
        }), 500

@behavior_bp.route('/events/<user_id>', methods=['GET'])
@jwt_required
@permission_required('analytics', 'view')
def get_user_events(user_id):
    """Get behavior events for a user"""
    try:
        # Check if user can access these events
        if (request.user.get('user_id') != user_id and 
            request.user.get('role') not in ['admin', 'security_admin']):
            return jsonify({
                'success': False,
                'error': 'Access denied'
            }), 403
        
        # Validate pagination parameters
        page, per_page = validate_pagination(request.args)
        limit = request.args.get('limit', per_page, type=int)
        
        # Get filter parameters
        event_type = request.args.get('event_type')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # Get events from behavior service
        events = user_behavior_service._get_user_events(user_id, limit=limit)
        
        # Apply filters
        if event_type:
            events = [e for e in events if e.get('event_type') == event_type]
        
        if start_date:
            events = [e for e in events if e.get('timestamp', '') >= start_date]
        
        if end_date:
            events = [e for e in events if e.get('timestamp', '') <= end_date]
        
        return jsonify({
            'success': True,
            'data': events,
            'count': len(events)
        })
    except Exception as e:
        logger.error(f"Failed to get user events: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve user events'
        }), 500

@behavior_bp.route('/patterns', methods=['GET'])
@jwt_required
@permission_required('analytics', 'view')
def get_behavior_patterns():
    """Get aggregated behavior patterns"""
    try:
        # Get filter parameters
        pattern_type = request.args.get('type')  # login, activity, navigation, etc.
        user_id = request.args.get('user_id')
        
        if not pattern_type:
            return jsonify({
                'success': False,
                'error': 'Pattern type is required'
            }), 400
        
        # Get patterns based on type
        if pattern_type == 'login':
            patterns = user_behavior_service._analyze_login_patterns([])
        elif pattern_type == 'activity':
            patterns = user_behavior_service._analyze_activity_patterns([])
        elif pattern_type == 'navigation':
            patterns = user_behavior_service._analyze_navigation_patterns([])
        elif pattern_type == 'feature':
            patterns = user_behavior_service._analyze_feature_usage([])
        elif pattern_type == 'time':
            patterns = user_behavior_service._analyze_time_patterns([])
        elif pattern_type == 'location':
            patterns = user_behavior_service._analyze_location_patterns([])
        elif pattern_type == 'device':
            patterns = user_behavior_service._analyze_device_patterns([])
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid pattern type'
            }), 400
        
        return jsonify({
            'success': True,
            'data': {
                'type': pattern_type,
                'patterns': patterns
            }
        })
    except Exception as e:
        logger.error(f"Failed to get behavior patterns: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve behavior patterns'
        }), 500

@behavior_bp.route('/anomalies', methods=['GET'])
@jwt_required
@permission_required('analytics', 'view')
def get_behavior_anomalies():
    """Get behavior anomalies"""
    try:
        # Get filter parameters
        user_id = request.args.get('user_id')
        severity = request.args.get('severity')
        limit = request.args.get('limit', 50, type=int)
        
        # Get anomalies from behavior service
        anomalies = []
        
        # This would typically query the behavior_alerts in Redis
        # For now, return a placeholder structure
        return jsonify({
            'success': True,
            'data': anomalies,
            'count': len(anomalies)
        })
    except Exception as e:
        logger.error(f"Failed to get behavior anomalies: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve behavior anomalies'
        }), 500

@behavior_bp.route('/dashboard', methods=['GET'])
@jwt_required
@permission_required('analytics', 'view')
def get_behavior_dashboard():
    """Get behavior analytics dashboard"""
    try:
        # Get filter parameters
        user_id = request.args.get('user_id')
        
        # Get user insights if user_id is provided
        user_insights = None
        if user_id:
            user_insights = user_behavior_service.get_user_insights(user_id)
        
        # Get overall statistics
        dashboard_data = {
            'user_insights': user_insights,
            'overall_stats': {
                'total_profiles': len(user_behavior_service._profile_cache),
                'active_users': len([p for p in user_behavior_service._profile_cache.values() 
                                  if p.get('risk_score', 0) < 0.5]),
                'high_risk_users': len([p for p in user_behavior_service._profile_cache.values() 
                                     if p.get('risk_score', 0) > 0.7]),
                'total_events': len(user_behavior_service._event_buffer)
            },
            'risk_distribution': _get_risk_distribution(),
            'pattern_summary': _get_pattern_summary(),
            'timestamp': current_app.config.get('CURRENT_TIME')
        }
        
        return jsonify({
            'success': True,
            'data': dashboard_data
        })
    except Exception as e:
        logger.error(f"Failed to get behavior dashboard: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve behavior dashboard'
        }), 500

@behavior_bp.route('/risk-assessment', methods=['GET'])
@jwt_required
@permission_required('analytics', 'view')
def get_risk_assessment():
    """Get risk assessment data"""
    try:
        # Get filter parameters
        risk_level = request.args.get('risk_level')
        limit = request.args.get('limit', 100, type=int)
        
        # Get risk assessment data
        risk_data = {
            'risk_levels': {
                'low': 0,
                'medium': 0,
                'high': 0,
                'critical': 0
            },
            'high_risk_users': [],
            'risk_factors': _get_common_risk_factors(),
            'recommendations': _get_risk_recommendations()
        }
        
        # Analyze cached profiles for risk assessment
        for user_id, profile in user_behavior_service._profile_cache.items():
            risk_score = profile.get('risk_score', 0)
            
            # Categorize risk level
            if risk_score >= 0.8:
                risk_data['risk_levels']['critical'] += 1
                risk_data['high_risk_users'].append({
                    'user_id': user_id,
                    'risk_score': risk_score,
                    'risk_factors': profile.get('anomalies', [])
                })
            elif risk_score >= 0.6:
                risk_data['risk_levels']['high'] += 1
            elif risk_score >= 0.4:
                risk_data['risk_levels']['medium'] += 1
            else:
                risk_data['risk_levels']['low'] += 1
        
        # Apply filters
        if risk_level:
            risk_data['high_risk_users'] = [
                u for u in risk_data['high_risk_users']
                if _get_risk_level_from_score(u['risk_score']) == risk_level
            ]
        
        # Limit results
        risk_data['high_risk_users'] = risk_data['high_risk_users'][:limit]
        
        return jsonify({
            'success': True,
            'data': risk_data
        })
    except Exception as e:
        logger.error(f"Failed to get risk assessment: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve risk assessment'
        }), 500

@behavior_bp.route('/export/profiles', methods=['GET'])
@jwt_required
@permission_required('analytics', 'export')
def export_behavior_profiles():
    """Export behavior profiles"""
    try:
        # Get filter parameters
        risk_level = request.args.get('risk_level')
        limit = request.args.get('limit', 1000, type=int)
        
        # Get profiles to export
        profiles = []
        
        for user_id, profile in user_behavior_service._profile_cache.items():
            # Apply risk level filter
            if risk_level:
                profile_risk_level = _get_risk_level_from_score(profile.get('risk_score', 0))
                if profile_risk_level != risk_level:
                    continue
            
            profiles.append({
                'user_id': user_id,
                'profile': profile
            })
            
            if len(profiles) >= limit:
                break
        
        return jsonify({
            'success': True,
            'data': profiles,
            'exported_at': current_app.config.get('CURRENT_TIME'),
            'total_records': len(profiles)
        })
    except Exception as e:
        logger.error(f"Failed to export behavior profiles: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to export behavior profiles'
        }), 500

@behavior_bp.route('/settings', methods=['GET'])
@jwt_required
@analytics_admin_required
def get_behavior_settings():
    """Get behavior analytics settings"""
    try:
        settings = {
            'anomaly_thresholds': user_behavior_service._anomaly_thresholds,
            'buffer_sizes': {
                'event_buffer': len(user_behavior_service._event_buffer),
                'profile_cache': len(user_behavior_service._profile_cache)
            },
            'processing_active': True  # Would be tracked in real implementation
        }
        
        return jsonify({
            'success': True,
            'data': settings
        })
    except Exception as e:
        logger.error(f"Failed to get behavior settings: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve behavior settings'
        }), 500

@behavior_bp.route('/settings', methods=['PUT'])
@jwt_required
@analytics_admin_required
def update_behavior_settings():
    """Update behavior analytics settings"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'Settings data is required'
            }), 400
        
        # Update anomaly thresholds
        if 'anomaly_thresholds' in data:
            thresholds = data['anomaly_thresholds']
            for key, value in thresholds.items():
                if key in user_behavior_service._anomaly_thresholds:
                    user_behavior_service._anomaly_thresholds[key] = value
        
        return jsonify({
            'success': True,
            'message': 'Behavior analytics settings updated successfully'
        })
    except Exception as e:
        logger.error(f"Failed to update behavior settings: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to update behavior settings'
        }), 500

def _get_risk_distribution():
    """Get risk level distribution"""
    distribution = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
    
    for profile in user_behavior_service._profile_cache.values():
        risk_score = profile.get('risk_score', 0)
        
        if risk_score >= 0.8:
            distribution['critical'] += 1
        elif risk_score >= 0.6:
            distribution['high'] += 1
        elif risk_score >= 0.4:
            distribution['medium'] += 1
        else:
            distribution['low'] += 1
    
    return distribution

def _get_pattern_summary():
    """Get summary of behavior patterns"""
    summary = {
        'login_patterns': {},
        'activity_patterns': {},
        'device_patterns': {},
        'location_patterns': {}
    }
    
    # Aggregate patterns across all users
    for profile in user_behavior_service._profile_cache.values():
        for pattern_type in summary.keys():
            if pattern_type in profile:
                pattern_data = profile[pattern_type]
                
                # Aggregate key metrics
                for key, value in pattern_data.items():
                    if key not in summary[pattern_type]:
                        summary[pattern_type][key] = []
                    summary[pattern_type][key].append(value)
    
    # Calculate averages and totals
    for pattern_type, patterns in summary.items():
        for key, values in patterns.items():
            if isinstance(values, list) and values:
                if all(isinstance(v, (int, float)) for v in values):
                    summary[pattern_type][key] = {
                        'average': sum(values) / len(values),
                        'total': sum(values),
                        'count': len(values)
                    }
                else:
                    # For non-numeric data, just keep the list
                    summary[pattern_type][key] = {
                        'values': values,
                        'count': len(values)
                    }
    
    return summary

def _get_common_risk_factors():
    """Get common risk factors across all users"""
    risk_factors = defaultdict(int)
    
    for profile in user_behavior_service._profile_cache.values():
        anomalies = profile.get('anomalies', [])
        for anomaly in anomalies:
            anomaly_type = anomaly.get('type', 'unknown')
            risk_factors[anomaly_type] += 1
    
    # Sort by frequency
    sorted_factors = sorted(risk_factors.items(), key=lambda x: x[1], reverse=True)
    return [{'factor': factor, 'count': count} for factor, count in sorted_factors[:10]]

def _get_risk_recommendations():
    """Get risk-based recommendations"""
    recommendations = []
    
    # Analyze overall risk distribution
    risk_dist = _get_risk_distribution()
    total_users = sum(risk_dist.values())
    
    if total_users == 0:
        return recommendations
    
    high_risk_percentage = (risk_dist['high'] + risk_dist['critical']) / total_users
    
    if high_risk_percentage > 0.2:
        recommendations.append({
            'priority': 'high',
            'category': 'security',
            'title': 'High number of high-risk users detected',
            'description': 'Consider implementing additional security measures'
        })
    
    if risk_dist['critical'] > 0:
        recommendations.append({
            'priority': 'critical',
            'category': 'security',
            'title': 'Critical risk users detected',
            'description': 'Immediate security review required'
        })
    
    return recommendations

def _get_risk_level_from_score(risk_score: float) -> str:
    """Get risk level from score"""
    if risk_score >= 0.8:
        return RiskLevel.CRITICAL.value
    elif risk_score >= 0.6:
        return RiskLevel.HIGH.value
    elif risk_score >= 0.4:
        return RiskLevel.MEDIUM.value
    else:
        return RiskLevel.LOW.value

@behavior_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'success': False,
        'error': 'Behavior analytics endpoint not found'
    }), 404

@behavior_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Behavior analytics internal error: {str(error)}")
    return jsonify({
        'success': False,
        'error': 'Internal server error in behavior analytics service'
    }), 500