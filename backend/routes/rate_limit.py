"""
Rate Limiting and DDoS Protection Routes

This module provides API endpoints for managing rate limiting policies,
monitoring DDoS attacks, and IP reputation management.
"""

from flask import Blueprint, request, jsonify, make_response
from flask_cors import cross_origin
from datetime import datetime, timedelta
from typing import Optional
import logging

from services.jwt_service import jwt_required, role_required, permission_required
from services.rate_limit_service import rate_limit_service
from services.audit_service import log_security_event
from utils.enterprise_validators import InputValidator

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
rate_limit_bp = Blueprint('rate_limit', __name__, url_prefix='/rate-limit')

@rate_limit_bp.route('/status', methods=['GET'])
@jwt_required
@permission_required('security', 'read')
@cross_origin(supports_credentials=True)
def get_rate_limit_status():
    """
    Get current rate limiting status for an IP or user
    
    Query Parameters:
        ip_address: IP address to check (optional, defaults to client IP)
        limit_type: Type of rate limit to check (optional)
    
    Returns:
        {
            "success": true,
            "status": {
                "ip_address": "192.168.1.1",
                "is_blocked": false,
                "reputation": { ... },
                "current_limits": [ ... ],
                "adaptive_limits": { ... }
            }
        }
    """
    try:
        # Get query parameters
        ip_address = request.args.get('ip_address')
        limit_type = request.args.get('limit_type')
        
        # Use client IP if not provided
        if not ip_address:
            ip_address = rate_limit_service.get_client_ip()
        
        # Validate IP address
        if not InputValidator.validate_ip_address(ip_address):
            return jsonify({
                "success": False,
                "message": "Invalid IP address format",
                "error_code": "INVALID_IP_ADDRESS"
            }), 400
        
        # Check if IP is blocked
        is_blocked, block_info = rate_limit_service.is_ip_blocked(ip_address)
        
        # Get IP reputation
        reputation = rate_limit_service.get_ip_reputation(ip_address)
        
        # Get current rate limits
        current_limits = []
        if limit_type:
            # Check specific limit type
            result = rate_limit_service.check_rate_limit(
                ip_address, limit_type, 3600, 1000
            )
            current_limits.append({
                'limit_type': limit_type,
                'current_count': result.get('current_count', 0),
                'max_requests': result.get('max_requests', 1000),
                'window_seconds': result.get('window_seconds', 3600),
                'allowed': result.get('allowed', True),
                'reset_time': result.get('reset_time'),
                'retry_after': result.get('retry_after', 0)
            })
        else:
            # Check common limit types
            common_limits = [
                ('login', 300, 5),      # 5 login attempts per 5 minutes
                ('api', 60, 1000),       # 1000 API calls per minute
                ('password_reset', 3600, 3)  # 3 password resets per hour
            ]
            
            for limit_type_name, window, max_req in common_limits:
                result = rate_limit_service.check_rate_limit(
                    ip_address, limit_type_name, window, max_req
                )
                current_limits.append({
                    'limit_type': limit_type_name,
                    'current_count': result.get('current_count', 0),
                    'max_requests': result.get('max_requests', max_req),
                    'window_seconds': result.get('window_seconds', window),
                    'allowed': result.get('allowed', True),
                    'reset_time': result.get('reset_time'),
                    'retry_after': result.get('retry_after', 0)
                })
        
        # Get adaptive limits
        adaptive_limits = {}
        for limit_type_name, window, base_limit in common_limits:
            adaptive_result = rate_limit_service.adaptive_rate_limit(
                ip_address, base_limit, window
            )
            adaptive_limits[limit_type_name] = {
                'base_limit': base_limit,
                'adjusted_limit': adaptive_result.get('adjusted_limit', base_limit),
                'reputation_score': adaptive_result.get('reputation_score', 0),
                'allowed': adaptive_result.get('allowed', True)
            }
        
        # Log this access
        log_security_event(
            event_type='RATE_LIMIT_STATUS_CHECK',
            user_id=request.current_user['user_id'],
            severity='LOW',
            details={
                'checked_ip': ip_address,
                'limit_type': limit_type,
                'is_blocked': is_blocked
            }
        )
        
        return jsonify({
            "success": True,
            "status": {
                "ip_address": ip_address,
                "is_blocked": is_blocked,
                "block_info": block_info,
                "reputation": reputation,
                "current_limits": current_limits,
                "adaptive_limits": adaptive_limits
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Rate limit status check error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred while checking rate limit status",
            "error_code": "RATE_LIMIT_STATUS_ERROR"
        }), 500

@rate_limit_bp.route('/block', methods=['POST'])
@jwt_required
@permission_required('security', 'manage')
@cross_origin(supports_credentials=True)
def block_ip_address():
    """
    Block an IP address
    
    Expected JSON payload:
    {
        "ip_address": "192.168.1.1",
        "reason": "Malicious activity detected",
        "duration_minutes": 60
    }
    
    Returns:
        {
            "success": true,
            "message": "IP address blocked successfully"
        }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "success": False,
                "message": "Request data is required",
                "error_code": "MISSING_REQUEST_DATA"
            }), 400
        
        ip_address = data.get('ip_address')
        reason = data.get('reason', 'Manual block')
        duration_minutes = data.get('duration_minutes', 60)
        
        # Validate IP address
        if not InputValidator.validate_ip_address(ip_address):
            return jsonify({
                "success": False,
                "message": "Invalid IP address format",
                "error_code": "INVALID_IP_ADDRESS"
            }), 400
        
        # Validate duration
        if not isinstance(duration_minutes, int) or duration_minutes < 1 or duration_minutes > 1440:
            return jsonify({
                "success": False,
                "message": "Duration must be between 1 and 1440 minutes",
                "error_code": "INVALID_DURATION"
            }), 400
        
        # Block the IP
        success = rate_limit_service.block_ip(ip_address, reason, duration_minutes)
        
        if success:
            # Log the block action
            log_security_event(
                event_type='IP_BLOCKED',
                user_id=request.current_user['user_id'],
                severity='HIGH',
                details={
                    'blocked_ip': ip_address,
                    'reason': reason,
                    'duration_minutes': duration_minutes,
                    'blocked_by': request.current_user['user_id']
                }
            )
            
            return jsonify({
                "success": True,
                "message": "IP address blocked successfully",
                "ip_address": ip_address,
                "duration_minutes": duration_minutes,
                "reason": reason
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": "Failed to block IP address",
                "error_code": "BLOCK_FAILED"
            }), 500
        
    except Exception as e:
        logger.error(f"IP block error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred while blocking IP address",
            "error_code": "IP_BLOCK_ERROR"
        }), 500

@rate_limit_bp.route('/unblock', methods=['POST'])
@jwt_required
@permission_required('security', 'manage')
@cross_origin(supports_credentials=True)
def unblock_ip_address():
    """
    Unblock an IP address
    
    Expected JSON payload:
    {
        "ip_address": "192.168.1.1"
    }
    
    Returns:
        {
            "success": true,
            "message": "IP address unblocked successfully"
        }
    """
    try:
        data = request.get_json()
        
        if not data or not data.get('ip_address'):
            return jsonify({
                "success": False,
                "message": "IP address is required",
                "error_code": "MISSING_IP_ADDRESS"
            }), 400
        
        ip_address = data.get('ip_address')
        
        # Validate IP address
        if not InputValidator.validate_ip_address(ip_address):
            return jsonify({
                "success": False,
                "message": "Invalid IP address format",
                "error_code": "INVALID_IP_ADDRESS"
            }), 400
        
        # Unblock the IP by removing from Redis and database
        try:
            # Remove from Redis
            if rate_limit_service._redis_client:
                key = f"blocked_ip:{ip_address}"
                rate_limit_service._redis_client.delete(key)
            
            # Remove from database
            from db.database import get_connection
            conn = get_connection()
            if conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE rate_limits 
                    SET is_blocked = FALSE, block_until = NULL
                    WHERE identifier = %s AND limit_type = 'IP_BLOCK'
                """, (ip_address,))
                conn.commit()
                cursor.close()
                conn.close()
            
            # Log the unblock action
            log_security_event(
                event_type='IP_UNBLOCKED',
                user_id=request.current_user['user_id'],
                severity='MEDIUM',
                details={
                    'unblocked_ip': ip_address,
                    'unblocked_by': request.current_user['user_id']
                }
            )
            
            return jsonify({
                "success": True,
                "message": "IP address unblocked successfully",
                "ip_address": ip_address
            }), 200
            
        except Exception as e:
            logger.error(f"Failed to unblock IP: {str(e)}")
            return jsonify({
                "success": False,
                "message": "Failed to unblock IP address",
                "error_code": "UNBLOCK_FAILED"
            }), 500
        
    except Exception as e:
        logger.error(f"IP unblock error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred while unblocking IP address",
            "error_code": "IP_UNBLOCK_ERROR"
        }), 500

@rate_limit_bp.route('/ddos-events', methods=['GET'])
@jwt_required
@permission_required('security', 'read')
@cross_origin(supports_credentials=True)
def get_ddos_events():
    """
    Get DDoS attack events
    
    Query Parameters:
        start_date: Filter by start date (ISO format)
        end_date: Filter by end date (ISO format)
        severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
        status: Filter by status (DETECTED, MITIGATED, RESOLVED)
        limit: Maximum number of records (default: 100)
        offset: Number of records to skip (default: 0)
    
    Returns:
        {
            "success": true,
            "events": [ ... ],
            "total_count": 123,
            "filters_applied": { ... }
        }
    """
    try:
        # Get query parameters
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        severity = request.args.get('severity')
        status = request.args.get('status')
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        # Validate parameters
        if limit > 1000:
            return jsonify({
                "success": False,
                "message": "Limit cannot exceed 1000 records",
                "error_code": "INVALID_LIMIT"
            }), 400
        
        if severity and severity not in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
            return jsonify({
                "success": False,
                "message": "Invalid severity level",
                "error_code": "INVALID_SEVERITY"
            }), 400
        
        if status and status not in ['DETECTED', 'MITIGATED', 'RESOLVED']:
            return jsonify({
                "success": False,
                "message": "Invalid status",
                "error_code": "INVALID_STATUS"
            }), 400
        
        # Parse dates
        parsed_start_date = None
        parsed_end_date = None
        
        if start_date:
            try:
                parsed_start_date = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            except ValueError:
                return jsonify({
                    "success": False,
                    "message": "Invalid start_date format. Use ISO format.",
                    "error_code": "INVALID_DATE_FORMAT"
                }), 400
        
        if end_date:
            try:
                parsed_end_date = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            except ValueError:
                return jsonify({
                    "success": False,
                    "message": "Invalid end_date format. Use ISO format.",
                    "error_code": "INVALID_DATE_FORMAT"
                }), 400
        
        # Get DDoS events from database
        from db.database import get_connection
        conn = get_connection()
        if not conn:
            return jsonify({
                "success": False,
                "message": "Database connection failed",
                "error_code": "DATABASE_ERROR"
            }), 500
        
        cursor = conn.cursor()
        
        # Build query
        query = """
            SELECT event_id, attack_type, source_ip, target_endpoint,
                   request_rate, severity, status, details, detected_at, resolved_at
            FROM ddos_events
            WHERE 1=1
        """
        params = []
        
        if parsed_start_date:
            query += " AND detected_at >= %s"
            params.append(parsed_start_date)
        
        if parsed_end_date:
            query += " AND detected_at <= %s"
            params.append(parsed_end_date)
        
        if severity:
            query += " AND severity = %s"
            params.append(severity)
        
        if status:
            query += " AND status = %s"
            params.append(status)
        
        query += " ORDER BY detected_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        events = []
        
        for row in cursor.fetchall():
            (event_id, attack_type, source_ip, target_endpoint,
             request_rate, severity, status, details, detected_at, resolved_at) = row
            
            events.append({
                'event_id': event_id,
                'attack_type': attack_type,
                'source_ip': source_ip,
                'target_endpoint': target_endpoint,
                'request_rate': request_rate,
                'severity': severity,
                'status': status,
                'details': details,
                'detected_at': detected_at.isoformat() if hasattr(detected_at, 'isoformat') else detected_at,
                'resolved_at': resolved_at.isoformat() if resolved_at and hasattr(resolved_at, 'isoformat') else resolved_at
            })
        
        cursor.close()
        conn.close()
        
        # Log this access
        log_security_event(
            event_type='DDOS_EVENTS_ACCESS',
            user_id=request.current_user['user_id'],
            severity='LOW',
            details={
                'filters': {
                    'start_date': start_date,
                    'end_date': end_date,
                    'severity': severity,
                    'status': status,
                    'limit': limit,
                    'offset': offset
                },
                'results_count': len(events)
            }
        )
        
        return jsonify({
            "success": True,
            "events": events,
            "total_count": len(events),
            "filters_applied": {
                "start_date": start_date,
                "end_date": end_date,
                "severity": severity,
                "status": status,
                "limit": limit,
                "offset": offset
            }
        }), 200
        
    except Exception as e:
        logger.error(f"DDoS events retrieval error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred while retrieving DDoS events",
            "error_code": "DDOS_EVENTS_ERROR"
        }), 500

@rate_limit_bp.route('/reputation', methods=['GET'])
@jwt_required
@permission_required('security', 'read')
@cross_origin(supports_credentials=True)
def get_ip_reputation():
    """
    Get IP reputation information
    
    Query Parameters:
        ip_address: IP address to check (required)
    
    Returns:
        {
            "success": true,
            "reputation": {
                "ip_address": "192.168.1.1",
                "score": 25,
                "threat_type": "NONE",
                "request_count": 1234,
                "last_seen": "2023-12-31T23:59:59Z"
            }
        }
    """
    try:
        ip_address = request.args.get('ip_address')
        
        if not ip_address:
            return jsonify({
                "success": False,
                "message": "IP address is required",
                "error_code": "MISSING_IP_ADDRESS"
            }), 400
        
        # Validate IP address
        if not InputValidator.validate_ip_address(ip_address):
            return jsonify({
                "success": False,
                "message": "Invalid IP address format",
                "error_code": "INVALID_IP_ADDRESS"
            }), 400
        
        # Get IP reputation
        reputation = rate_limit_service.get_ip_reputation(ip_address)
        
        # Log this access
        log_security_event(
            event_type='IP_REPUTATION_CHECK',
            user_id=request.current_user['user_id'],
            severity='LOW',
            details={
                'checked_ip': ip_address,
                'reputation_score': reputation.get('score', 0),
                'threat_type': reputation.get('threat_type', 'NONE')
            }
        )
        
        return jsonify({
            "success": True,
            "reputation": {
                "ip_address": ip_address,
                "score": reputation.get('score', 0),
                "threat_type": reputation.get('threat_type', 'NONE'),
                "request_count": reputation.get('request_count', 0),
                "last_seen": reputation.get('last_seen')
            }
        }), 200
        
    except Exception as e:
        logger.error(f"IP reputation check error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred while checking IP reputation",
            "error_code": "IP_REPUTATION_ERROR"
        }), 500

@rate_limit_bp.route('/update-reputation', methods=['POST'])
@jwt_required
@permission_required('security', 'manage')
@cross_origin(supports_credentials=True)
def update_ip_reputation():
    """
    Update IP reputation score
    
    Expected JSON payload:
    {
        "ip_address": "192.168.1.1",
        "score_change": -10,
        "threat_type": "SUSPICIOUS"
    }
    
    Returns:
        {
            "success": true,
            "message": "IP reputation updated successfully"
        }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "success": False,
                "message": "Request data is required",
                "error_code": "MISSING_REQUEST_DATA"
            }), 400
        
        ip_address = data.get('ip_address')
        score_change = data.get('score_change')
        threat_type = data.get('threat_type')
        
        # Validate IP address
        if not InputValidator.validate_ip_address(ip_address):
            return jsonify({
                "success": False,
                "message": "Invalid IP address format",
                "error_code": "INVALID_IP_ADDRESS"
            }), 400
        
        # Validate score change
        if not isinstance(score_change, int):
            return jsonify({
                "success": False,
                "message": "Score change must be an integer",
                "error_code": "INVALID_SCORE_CHANGE"
            }), 400
        
        # Validate threat type
        valid_threat_types = ['NONE', 'PROXY', 'TOR', 'BOTNET', 'MALICIOUS', 'SUSPICIOUS']
        if threat_type and threat_type not in valid_threat_types:
            return jsonify({
                "success": False,
                "message": f"Invalid threat type. Valid types: {', '.join(valid_threat_types)}",
                "error_code": "INVALID_THREAT_TYPE"
            }), 400
        
        # Update IP reputation
        success = rate_limit_service.update_ip_reputation(
            ip_address, score_change, threat_type
        )
        
        if success:
            # Log the update
            log_security_event(
                event_type='IP_REPUTATION_UPDATED',
                user_id=request.current_user['user_id'],
                severity='MEDIUM',
                details={
                    'updated_ip': ip_address,
                    'score_change': score_change,
                    'threat_type': threat_type,
                    'updated_by': request.current_user['user_id']
                }
            )
            
            return jsonify({
                "success": True,
                "message": "IP reputation updated successfully",
                "ip_address": ip_address,
                "score_change": score_change,
                "threat_type": threat_type
            }), 200
        else:
            return jsonify({
                "success": False,
                "message": "Failed to update IP reputation",
                "error_code": "REPUTATION_UPDATE_FAILED"
            }), 500
        
    except Exception as e:
        logger.error(f"IP reputation update error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred while updating IP reputation",
            "error_code": "REPUTATION_UPDATE_ERROR"
        }), 500