"""
Audit Log Management Routes

This module provides API endpoints for accessing, managing, and verifying
audit logs with proper authorization and security controls.
"""

from flask import Blueprint, request, jsonify, make_response
from flask_cors import cross_origin
from datetime import datetime, timedelta
from typing import Optional
import logging

from services.jwt_service import jwt_required, role_required, permission_required
from services.audit_service import audit_service, log_security_event
from utils.enterprise_validators import InputValidator

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
audit_bp = Blueprint('audit', __name__, url_prefix='/audit')

@audit_bp.route('/logs', methods=['GET'])
@jwt_required
@permission_required('audit', 'read')
@cross_origin(supports_credentials=True)
def get_audit_logs():
    """
    Retrieve audit logs with filtering options
    
    Query Parameters:
        event_type: Filter by event type
        category: Filter by category
        severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
        user_id: Filter by user ID
        start_date: Filter by start date (ISO format)
        end_date: Filter by end date (ISO format)
        limit: Maximum number of records (default: 100, max: 1000)
        offset: Number of records to skip (default: 0)
    
    Returns:
        {
            "success": true,
            "logs": [ ... ],
            "total_count": 123,
            "filters_applied": { ... }
        }
    """
    try:
        # Get query parameters
        event_type = request.args.get('event_type')
        category = request.args.get('category')
        severity = request.args.get('severity')
        user_id = request.args.get('user_id')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        # Validate parameters
        if limit > 1000:
            return jsonify({
                "success": False,
                "message": "Limit cannot exceed 1000 records",
                "error_code": "INVALID_LIMIT"
            }), 400
        
        if limit < 1:
            return jsonify({
                "success": False,
                "message": "Limit must be at least 1",
                "error_code": "INVALID_LIMIT"
            }), 400
        
        if offset < 0:
            return jsonify({
                "success": False,
                "message": "Offset cannot be negative",
                "error_code": "INVALID_OFFSET"
            }), 400
        
        # Validate severity if provided
        if severity and severity not in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
            return jsonify({
                "success": False,
                "message": "Invalid severity level",
                "error_code": "INVALID_SEVERITY"
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
        
        # Validate user ID if provided
        parsed_user_id = None
        if user_id:
            try:
                parsed_user_id = int(user_id)
            except ValueError:
                return jsonify({
                    "success": False,
                    "message": "Invalid user ID format",
                    "error_code": "INVALID_USER_ID"
                }), 400
        
        # Get audit logs
        logs = audit_service.get_audit_logs(
            event_type=event_type,
            category=category,
            severity=severity,
            user_id=parsed_user_id,
            start_date=parsed_start_date,
            end_date=parsed_end_date,
            limit=limit,
            offset=offset
        )
        
        # Log this access
        log_security_event(
            event_type='AUDIT_LOG_ACCESS',
            user_id=request.current_user['user_id'],
            details={
                'filters': {
                    'event_type': event_type,
                    'category': category,
                    'severity': severity,
                    'user_id': parsed_user_id,
                    'start_date': start_date,
                    'end_date': end_date,
                    'limit': limit,
                    'offset': offset
                },
                'results_count': len(logs)
            }
        )
        
        return jsonify({
            "success": True,
            "logs": logs,
            "total_count": len(logs),
            "filters_applied": {
                "event_type": event_type,
                "category": category,
                "severity": severity,
                "user_id": parsed_user_id,
                "start_date": start_date,
                "end_date": end_date,
                "limit": limit,
                "offset": offset
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Get audit logs error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred while retrieving audit logs",
            "error_code": "AUDIT_LOGS_ERROR"
        }), 500

@audit_bp.route('/verify', methods=['POST'])
@jwt_required
@permission_required('audit', 'verify')
@cross_origin(supports_credentials=True)
def verify_audit_integrity():
    """
    Verify audit log integrity for tamper detection
    
    Expected JSON payload:
    {
        "start_date": "2023-01-01T00:00:00Z",  // Optional
        "end_date": "2023-12-31T23:59:59Z"    // Optional
    }
    
    Returns:
        {
            "success": true,
            "verification": {
                "valid": true,
                "total_records": 1234,
                "issues": [],
                "verified_at": "2023-12-31T23:59:59Z"
            }
        }
    """
    try:
        data = request.get_json()
        
        if not data:
            # Verify all logs if no date range provided
            result = audit_service.verify_integrity()
        else:
            # Parse date range
            start_date = None
            end_date = None
            
            if data.get('start_date'):
                try:
                    start_date = datetime.fromisoformat(data['start_date'].replace('Z', '+00:00'))
                except ValueError:
                    return jsonify({
                        "success": False,
                        "message": "Invalid start_date format. Use ISO format.",
                        "error_code": "INVALID_DATE_FORMAT"
                    }), 400
            
            if data.get('end_date'):
                try:
                    end_date = datetime.fromisoformat(data['end_date'].replace('Z', '+00:00'))
                except ValueError:
                    return jsonify({
                        "success": False,
                        "message": "Invalid end_date format. Use ISO format.",
                        "error_code": "INVALID_DATE_FORMAT"
                    }), 400
            
            result = audit_service.verify_integrity(start_date=start_date, end_date=end_date)
        
        # Log this verification
        log_security_event(
            event_type='AUDIT_INTEGRITY_VERIFICATION',
            user_id=request.current_user['user_id'],
            severity='LOW',
            details={
                'verification_result': result,
                'date_range': {
                    'start_date': data.get('start_date') if data else None,
                    'end_date': data.get('end_date') if data else None
                }
            }
        )
        
        return jsonify({
            "success": True,
            "verification": result
        }), 200
        
    except Exception as e:
        logger.error(f"Audit integrity verification error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred during integrity verification",
            "error_code": "INTEGRITY_VERIFICATION_ERROR"
        }), 500

@audit_bp.route('/cleanup', methods=['POST'])
@jwt_required
@permission_required('audit', 'manage')
@cross_origin(supports_credentials=True)
def cleanup_audit_logs():
    """
    Clean up old audit logs based on retention policy
    
    Expected JSON payload:
    {
        "retention_days": 365  // Optional, uses config default if not provided
    }
    
    Returns:
        {
            "success": true,
            "cleanup": {
                "success": true,
                "deleted_count": 1234,
                "cutoff_date": "2022-12-31T23:59:59Z",
                "retention_days": 365
            }
        }
    """
    try:
        data = request.get_json() or {}
        
        # Get retention days
        retention_days = data.get('retention_days')
        if retention_days is not None:
            if not isinstance(retention_days, int) or retention_days < 1:
                return jsonify({
                    "success": False,
                    "message": "Retention days must be a positive integer",
                    "error_code": "INVALID_RETENTION_DAYS"
                }), 400
        
        # Perform cleanup
        result = audit_service.cleanup_old_logs(retention_days)
        
        # Log this cleanup
        log_security_event(
            event_type='AUDIT_LOG_CLEANUP',
            user_id=request.current_user['user_id'],
            severity='MEDIUM',
            details={
                'cleanup_result': result,
                'requested_retention_days': retention_days
            }
        )
        
        return jsonify({
            "success": True,
            "cleanup": result
        }), 200
        
    except Exception as e:
        logger.error(f"Audit cleanup error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred during audit log cleanup",
            "error_code": "AUDIT_CLEANUP_ERROR"
        }), 500

@audit_bp.route('/export', methods=['POST'])
@jwt_required
@permission_required('audit', 'export')
@cross_origin(supports_credentials=True)
def export_audit_logs():
    """
    Export audit logs in various formats
    
    Expected JSON payload:
    {
        "format": "json",  // json, csv, xml
        "filters": {
            "event_type": "LOGIN",
            "category": "AUTHENTICATION",
            "start_date": "2023-01-01T00:00:00Z",
            "end_date": "2023-12-31T23:59:59Z"
        }
    }
    
    Returns:
        File download with audit logs
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "success": False,
                "message": "Export parameters are required",
                "error_code": "MISSING_EXPORT_PARAMS"
            }), 400
        
        export_format = data.get('format', 'json')
        if export_format not in ['json', 'csv', 'xml']:
            return jsonify({
                "success": False,
                "message": "Invalid export format. Supported formats: json, csv, xml",
                "error_code": "INVALID_EXPORT_FORMAT"
            }), 400
        
        filters = data.get('filters', {})
        
        # Parse filters
        event_type = filters.get('event_type')
        category = filters.get('category')
        severity = filters.get('severity')
        user_id = filters.get('user_id')
        start_date = filters.get('start_date')
        end_date = filters.get('end_date')
        
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
        
        # Validate user ID if provided
        parsed_user_id = None
        if user_id:
            try:
                parsed_user_id = int(user_id)
            except ValueError:
                return jsonify({
                    "success": False,
                    "message": "Invalid user ID format",
                    "error_code": "INVALID_USER_ID"
                }), 400
        
        # Get audit logs (limit to reasonable number for export)
        logs = audit_service.get_audit_logs(
            event_type=event_type,
            category=category,
            severity=severity,
            user_id=parsed_user_id,
            start_date=parsed_start_date,
            end_date=parsed_end_date,
            limit=10000,  # Limit for export
            offset=0
        )
        
        # Log this export
        log_security_event(
            event_type='AUDIT_LOG_EXPORT',
            user_id=request.current_user['user_id'],
            severity='MEDIUM',
            details={
                'export_format': export_format,
                'filters': filters,
                'records_exported': len(logs)
            }
        )
        
        # Generate export based on format
        if export_format == 'json':
            import json as json_module
            export_data = json_module.dumps(logs, indent=2, default=str)
            filename = f"audit_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
            mimetype = 'application/json'
        
        elif export_format == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            if logs:
                fieldnames = logs[0].keys()
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(logs)
            
            export_data = output.getvalue()
            filename = f"audit_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
            mimetype = 'text/csv'
        
        elif export_format == 'xml':
            # Simple XML export
            xml_data = ['<?xml version="1.0" encoding="UTF-8"?>', '<audit_logs>']
            for log in logs:
                xml_data.append('<log>')
                for key, value in log.items():
                    xml_data.append(f'<{key}>{value}</{key}>')
                xml_data.append('</log>')
            xml_data.append('</audit_logs>')
            
            export_data = '\n'.join(xml_data)
            filename = f"audit_logs_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xml"
            mimetype = 'application/xml'
        
        # Create response
        response = make_response(export_data)
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        response.headers['Content-Type'] = mimetype
        
        return response
        
    except Exception as e:
        logger.error(f"Audit export error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred during audit log export",
            "error_code": "AUDIT_EXPORT_ERROR"
        }), 500

@audit_bp.route('/stats', methods=['GET'])
@jwt_required
@permission_required('audit', 'read')
@cross_origin(supports_credentials=True)
def get_audit_stats():
    """
    Get audit log statistics and metrics
    
    Query Parameters:
        period: Time period for stats (24h, 7d, 30d, 90d)
        
    Returns:
        {
            "success": true,
            "stats": {
                "total_events": 1234,
                "by_category": { ... },
                "by_severity": { ... },
                "by_outcome": { ... },
                "top_events": [ ... ],
                "period": "7d"
            }
        }
    """
    try:
        period = request.args.get('period', '7d')
        
        # Validate period
        valid_periods = ['24h', '7d', '30d', '90d']
        if period not in valid_periods:
            return jsonify({
                "success": False,
                "message": f"Invalid period. Valid periods: {', '.join(valid_periods)}",
                "error_code": "INVALID_PERIOD"
            }), 400
        
        # Calculate start date based on period
        if period == '24h':
            start_date = datetime.utcnow() - timedelta(hours=24)
        elif period == '7d':
            start_date = datetime.utcnow() - timedelta(days=7)
        elif period == '30d':
            start_date = datetime.utcnow() - timedelta(days=30)
        elif period == '90d':
            start_date = datetime.utcnow() - timedelta(days=90)
        
        # Get logs for the period
        logs = audit_service.get_audit_logs(
            start_date=start_date,
            limit=50000  # Large limit for stats
        )
        
        # Calculate statistics
        stats = {
            'total_events': len(logs),
            'by_category': {},
            'by_severity': {},
            'by_outcome': {},
            'top_events': {},
            'period': period
        }
        
        for log in logs:
            # Count by category
            category = log.get('category', 'UNKNOWN')
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
            
            # Count by severity
            severity = log.get('severity', 'UNKNOWN')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            # Count by outcome
            outcome = log.get('outcome', 'UNKNOWN')
            stats['by_outcome'][outcome] = stats['by_outcome'].get(outcome, 0) + 1
            
            # Count by event type
            event_type = log.get('event_type', 'UNKNOWN')
            stats['top_events'][event_type] = stats['top_events'].get(event_type, 0) + 1
        
        # Sort top events
        stats['top_events'] = dict(
            sorted(stats['top_events'].items(), key=lambda x: x[1], reverse=True)[:10]
        )
        
        return jsonify({
            "success": True,
            "stats": stats
        }), 200
        
    except Exception as e:
        logger.error(f"Audit stats error: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "message": "An error occurred while retrieving audit statistics",
            "error_code": "AUDIT_STATS_ERROR"
        }), 500