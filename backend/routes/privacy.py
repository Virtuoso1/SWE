from flask import Blueprint, request, jsonify, make_response
from flask_cors import cross_origin
from services.privacy_service import PrivacyService
from services.jwt_service import JWTService, jwt_required
from utils.security import get_client_ip
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
privacy_bp = Blueprint('privacy', __name__, url_prefix='/privacy')

@privacy_bp.route('/consent', methods=['POST'])
@jwt_required
@cross_origin(supports_credentials=True)
def record_consent():
    """
    Record user consent
    
    Expected JSON payload:
    {
        "consent_type": "data_processing",
        "granted": true,
        "consent_data": {}
    }
    
    Returns:
        Success: {
            "success": true,
            "message": "Consent recorded successfully"
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'message': 'Invalid request format. JSON data required.',
                'error_code': 'INVALID_REQUEST'
            }), 400
        
        consent_type = data.get('consent_type')
        granted = data.get('granted', False)
        consent_data = data.get('consent_data')
        
        if not consent_type:
            return jsonify({
                'success': False,
                'message': 'Consent type is required',
                'error_code': 'MISSING_CONSENT_TYPE'
            }), 400
        
        user_id = request.current_user['user_id']
        
        success = PrivacyService.record_consent(user_id, consent_type, granted, consent_data)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Consent recorded successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to record consent',
                'error_code': 'CONSENT_RECORD_FAILED'
            }), 500
            
    except Exception as e:
        logger.error(f"Record consent error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An internal server error occurred',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@privacy_bp.route('/consents', methods=['GET'])
@jwt_required
@cross_origin(supports_credentials=True)
def get_consents():
    """
    Get all user consents
    
    Returns:
        Success: {
            "success": true,
            "consents": [...]
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        user_id = request.current_user['user_id']
        consents = PrivacyService.get_user_consents(user_id)
        
        return jsonify({
            'success': True,
            'consents': consents
        }), 200
        
    except Exception as e:
        logger.error(f"Get consents error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An internal server error occurred',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@privacy_bp.route('/data-request', methods=['POST'])
@jwt_required
@cross_origin(supports_credentials=True)
def create_data_request():
    """
    Create data access/deletion request
    
    Expected JSON payload:
    {
        "request_type": "export",
        "request_data": {}
    }
    
    Returns:
        Success: {
            "success": true,
            "message": "Data request created successfully",
            "request_id": "request_id"
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'message': 'Invalid request format. JSON data required.',
                'error_code': 'INVALID_REQUEST'
            }), 400
        
        request_type = data.get('request_type')
        request_data = data.get('request_data')
        
        if not request_type:
            return jsonify({
                'success': False,
                'message': 'Request type is required',
                'error_code': 'MISSING_REQUEST_TYPE'
            }), 400
        
        valid_types = ['export', 'delete', 'restrict', 'correct']
        if request_type not in valid_types:
            return jsonify({
                'success': False,
                'message': 'Invalid request type',
                'error_code': 'INVALID_REQUEST_TYPE'
            }), 400
        
        user_id = request.current_user['user_id']
        
        request_id = PrivacyService.create_data_request(user_id, request_type, request_data)
        
        if request_id:
            return jsonify({
                'success': True,
                'message': 'Data request created successfully',
                'request_id': request_id
            }), 201
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to create data request',
                'error_code': 'REQUEST_CREATION_FAILED'
            }), 500
            
    except Exception as e:
        logger.error(f"Create data request error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An internal server error occurred',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@privacy_bp.route('/data-requests', methods=['GET'])
@jwt_required
@cross_origin(supports_credentials=True)
def get_data_requests():
    """
    Get user data requests
    
    Returns:
        Success: {
            "success": true,
            "requests": [...]
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        user_id = request.current_user['user_id']
        status = request.args.get('status')
        
        requests = PrivacyService.get_data_requests(user_id, status)
        
        return jsonify({
            'success': True,
            'requests': requests
        }), 200
        
    except Exception as e:
        logger.error(f"Get data requests error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An internal server error occurred',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@privacy_bp.route('/data-export', methods=['GET'])
@jwt_required
@cross_origin(supports_credentials=True)
def export_data():
    """
    Export user data
    
    Returns:
        Success: JSON response with user data
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        user_id = request.current_user['user_id']
        
        user_data = PrivacyService.export_user_data(user_id)
        
        if not user_data:
            return jsonify({
                'success': False,
                'message': 'Failed to export user data',
                'error_code': 'EXPORT_FAILED'
            }), 500
        
        # Create response with appropriate headers for data download
        response = make_response(jsonify({
            'success': True,
            'data': user_data
        }))
        
        response.headers['Content-Disposition'] = f'attachment; filename={user_data["email"]}_data.json'
        response.headers['Content-Type'] = 'application/json'
        
        return response
        
    except Exception as e:
        logger.error(f"Export data error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An internal server error occurred',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@privacy_bp.route('/data-delete', methods=['POST'])
@jwt_required
@cross_origin(supports_credentials=True)
def delete_data():
    """
    Request user data deletion
    
    Expected JSON payload:
    {
        "deletion_reason": "User requested deletion"
    }
    
    Returns:
        Success: {
            "success": true,
            "message": "Data deletion request processed"
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'message': 'Invalid request format. JSON data required.',
                'error_code': 'INVALID_REQUEST'
            }), 400
        
        deletion_reason = data.get('deletion_reason', 'User requested deletion')
        
        user_id = request.current_user['user_id']
        
        success = PrivacyService.delete_user_data(user_id, deletion_reason)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Data deletion request processed successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to process data deletion request',
                'error_code': 'DELETION_FAILED'
            }), 500
            
    except Exception as e:
        logger.error(f"Delete data error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An internal server error occurred',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@privacy_bp.route('/policy', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_privacy_policy():
    """
    Get privacy policy
    
    Query Parameters:
        version: Policy version (default: latest)
    
    Returns:
        Success: {
            "success": true,
            "policy": {...}
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        version = request.args.get('version', 'latest')
        
        policy = PrivacyService.get_privacy_policy(version)
        
        if policy:
            return jsonify({
                'success': True,
                'policy': policy
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Privacy policy not found',
                'error_code': 'POLICY_NOT_FOUND'
            }), 404
        
    except Exception as e:
        logger.error(f"Get privacy policy error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An internal server error occurred',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@privacy_bp.route('/anonymize', methods=['POST'])
@jwt_required
@cross_origin(supports_credentials=True)
def anonymize_data():
    """
    Anonymize user data (pseudonymization)
    
    Returns:
        Success: {
            "success": true,
            "message": "Data anonymized successfully"
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        user_id = request.current_user['user_id']
        
        success = PrivacyService.anonymize_user_data(user_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Data anonymized successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to anonymize data',
                'error_code': 'ANONYMIZATION_FAILED'
            }), 500
        
    except Exception as e:
        logger.error(f"Anonymize data error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An internal server error occurred',
            'error_code': 'INTERNAL_ERROR'
        }), 500

# Admin-only endpoints
@privacy_bp.route('/admin/data-requests', methods=['GET'])
@jwt_required
@cross_origin(supports_credentials=True)
def admin_get_data_requests():
    """
    Get all data requests (admin only)
    
    Query Parameters:
        status: Filter by status
        user_id: Filter by user ID
    
    Returns:
        Success: {
            "success": true,
            "requests": [...]
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        # Check if user is admin
        if request.current_user.get('role') not in ['admin', 'super_admin']:
            return jsonify({
                'success': False,
                'message': 'Admin access required',
                'error_code': 'INSUFFICIENT_PERMISSIONS'
            }), 403
        
        status = request.args.get('status')
        user_id = request.args.get('user_id')
        
        requests = PrivacyService.get_data_requests(
            int(user_id) if user_id else None, 
            status
        )
        
        return jsonify({
            'success': True,
            'requests': requests
        }), 200
        
    except Exception as e:
        logger.error(f"Admin get data requests error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An internal server error occurred',
            'error_code': 'INTERNAL_ERROR'
        }), 500

@privacy_bp.route('/admin/data-request/<request_id>', methods=['PUT'])
@jwt_required
@cross_origin(supports_credentials=True)
def admin_update_data_request(request_id):
    """
    Update data request status (admin only)
    
    Expected JSON payload:
    {
        "status": "completed",
        "response_data": {}
    }
    
    Returns:
        Success: {
            "success": true,
            "message": "Data request updated successfully"
        }
        
        Error: {
            "success": false,
            "message": "Error description",
            "error_code": "ERROR_CODE"
        }
    """
    try:
        # Check if user is admin
        if request.current_user.get('role') not in ['admin', 'super_admin']:
            return jsonify({
                'success': False,
                'message': 'Admin access required',
                'error_code': 'INSUFFICIENT_PERMISSIONS'
            }), 403
        
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'message': 'Invalid request format. JSON data required.',
                'error_code': 'INVALID_REQUEST'
            }), 400
        
        status = data.get('status')
        response_data = data.get('response_data')
        
        valid_statuses = ['pending', 'processing', 'completed', 'rejected']
        if status not in valid_statuses:
            return jsonify({
                'success': False,
                'message': 'Invalid status',
                'error_code': 'INVALID_STATUS'
            }), 400
        
        success = PrivacyService.update_data_request(
            request_id, status, response_data, request.current_user['user_id']
        )
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Data request updated successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to update data request',
                'error_code': 'UPDATE_FAILED'
            }), 500
        
    except Exception as e:
        logger.error(f"Admin update data request error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'An internal server error occurred',
            'error_code': 'INTERNAL_ERROR'
        }), 500