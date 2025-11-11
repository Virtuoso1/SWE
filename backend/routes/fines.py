"""
Fines routes for Library Management System
Handles HTTP requests and responses for fine operations
"""

from flask import Blueprint, request, jsonify, session
from flask_cors import cross_origin
import logging

from services.fine_service import FineService

logger = logging.getLogger(__name__)

# Create blueprint
fines_bp = Blueprint('fines', __name__, url_prefix='/fines')

def require_auth():
    """Check if user is authenticated"""
    if not session.get('authenticated') or not session.get('user_id'):
        return False
    return True

@fines_bp.route('/my-fines', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_user_fines():
    """
    Get current user's fines
    
    Returns:
        Success: List of user's fines
        Error: Error message
    """
    try:
        # Check authentication
        if not require_auth():
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        
        # Get user's fines
        user_id = session.get('user_id')
        fines = FineService.get_user_fines(user_id)
        
        return jsonify({
            'success': True,
            'fines': fines
        }), 200
        
    except Exception as e:
        logger.error(f"Get user fines error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@fines_bp.route('/all', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_all_fines():
    """
    Get all fines (admin/librarian only)
    
    Query Parameters:
        paid_status: Filter by paid status ('paid', 'unpaid')
        
    Returns:
        Success: List of fines
        Error: Error message
    """
    try:
        # Check authentication and authorization
        if not require_auth():
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        
        # Check if user is librarian or admin
        user_role = session.get('role')
        if user_role not in ['librarian', 'admin']:
            return jsonify({
                'success': False,
                'error': 'Access denied. Librarian or admin role required.'
            }), 403
        
        # Get query parameters
        paid_status = request.args.get('paid_status')
        
        # Get fines
        fines = FineService.get_all_fines(paid_status)
        
        return jsonify({
            'success': True,
            'fines': fines
        }), 200
        
    except Exception as e:
        logger.error(f"Get all fines error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@fines_bp.route('/<int:fine_id>', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_fine_by_id(fine_id):
    """
    Get fine by ID
    
    Args:
        fine_id: ID of fine
        
    Returns:
        Success: Fine data
        Error: Error message
    """
    try:
        # Check authentication
        if not require_auth():
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        
        # Get fine
        fine = FineService.get_fine_by_id(fine_id)
        
        if fine:
            # Check if user can access this fine
            user_id = session.get('user_id')
            user_role = session.get('role')
            
            # Users can only see their own fines, librarians/admins can see all
            if fine.get('user_id') != user_id and user_role not in ['librarian', 'admin']:
                return jsonify({
                    'success': False,
                    'error': 'Access denied'
                }), 403
            
            return jsonify({
                'success': True,
                'fine': fine
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Fine not found'
            }), 404
            
    except Exception as e:
        logger.error(f"Get fine error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@fines_bp.route('/pay/<int:fine_id>', methods=['POST'])
@cross_origin(supports_credentials=True)
def pay_fine(fine_id):
    """
    Pay a fine
    
    Args:
        fine_id: ID of fine to pay
        
    Returns:
        Success: Success message
        Error: Error message
    """
    try:
        # Check authentication
        if not require_auth():
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        
        # Get fine to check ownership
        fine = FineService.get_fine_by_id(fine_id)
        if not fine:
            return jsonify({
                'success': False,
                'error': 'Fine not found'
            }), 404
        
        # Check if user can pay this fine
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        # Users can only pay their own fines, librarians/admins can pay any
        if fine.get('user_id') != user_id and user_role not in ['librarian', 'admin']:
            return jsonify({
                'success': False,
                'error': 'Access denied'
            }), 403
        
        # Pay fine
        success = FineService.pay_fine(fine_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Fine paid successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to pay fine. Fine may already be paid.'
            }), 400
            
    except Exception as e:
        logger.error(f"Pay fine error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@fines_bp.route('/waive/<int:fine_id>', methods=['POST'])
@cross_origin(supports_credentials=True)
def waive_fine(fine_id):
    """
    Waive a fine (admin/librarian only)
    
    Args:
        fine_id: ID of fine to waive
        
    Returns:
        Success: Success message
        Error: Error message
    """
    try:
        # Check authentication and authorization
        if not require_auth():
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        
        # Check if user is librarian or admin
        user_role = session.get('role')
        if user_role not in ['librarian', 'admin']:
            return jsonify({
                'success': False,
                'error': 'Access denied. Librarian or admin role required.'
            }), 403
        
        # Waive fine
        success = FineService.waive_fine(fine_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Fine waived successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to waive fine. Fine may not exist or already paid.'
            }), 400
            
    except Exception as e:
        logger.error(f"Waive fine error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@fines_bp.route('/create', methods=['POST'])
@cross_origin(supports_credentials=True)
def create_fine():
    """
    Create a new fine (admin/librarian only)
    
    Expected JSON payload:
    {
        "borrow_id": 1,
        "amount": 10.50
    }
    
    Returns:
        Success: Fine data
        Error: Error message
    """
    try:
        # Check authentication and authorization
        if not require_auth():
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        
        # Check if user is librarian or admin
        user_role = session.get('role')
        if user_role not in ['librarian', 'admin']:
            return jsonify({
                'success': False,
                'error': 'Access denied. Librarian or admin role required.'
            }), 403
        
        # Get JSON data
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'Invalid request format. JSON data required.'
            }), 400
        
        # Extract data
        borrow_id = data.get('borrow_id')
        amount = data.get('amount')
        
        # Validate data
        if not borrow_id:
            return jsonify({
                'success': False,
                'error': 'Borrow ID is required'
            }), 400
        
        if not isinstance(amount, (int, float)) or amount <= 0:
            return jsonify({
                'success': False,
                'error': 'Amount must be a positive number'
            }), 400
        
        # Create fine
        fine = FineService.create_fine(borrow_id, float(amount))
        
        if fine:
            return jsonify({
                'success': True,
                'message': 'Fine created successfully',
                'fine': fine
            }), 201
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to create fine. Borrow record may not exist or fine already exists.'
            }), 400
            
    except Exception as e:
        logger.error(f"Create fine error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@fines_bp.route('/update/<int:fine_id>', methods=['PUT'])
@cross_origin(supports_credentials=True)
def update_fine(fine_id):
    """
    Update fine amount (admin/librarian only)
    
    Args:
        fine_id: ID of fine to update
        
    Expected JSON payload:
    {
        "amount": 15.75
    }
    
    Returns:
        Success: Success message
        Error: Error message
    """
    try:
        # Check authentication and authorization
        if not require_auth():
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        
        # Check if user is librarian or admin
        user_role = session.get('role')
        if user_role not in ['librarian', 'admin']:
            return jsonify({
                'success': False,
                'error': 'Access denied. Librarian or admin role required.'
            }), 403
        
        # Get JSON data
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'Invalid request format. JSON data required.'
            }), 400
        
        # Extract data
        amount = data.get('amount')
        
        # Validate data
        if not isinstance(amount, (int, float)) or amount <= 0:
            return jsonify({
                'success': False,
                'error': 'Amount must be a positive number'
            }), 400
        
        # Update fine
        success = FineService.update_fine_amount(fine_id, float(amount))
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Fine updated successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to update fine. Fine may not exist or already paid.'
            }), 400
            
    except Exception as e:
        logger.error(f"Update fine error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@fines_bp.route('/calculate-overdue', methods=['POST'])
@cross_origin(supports_credentials=True)
def calculate_overdue_fines():
    """
    Calculate and create fines for overdue books (admin/librarian only)
    
    Returns:
        Success: Number of fines created
        Error: Error message
    """
    try:
        # Check authentication and authorization
        if not require_auth():
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        
        # Check if user is librarian or admin
        user_role = session.get('role')
        if user_role not in ['librarian', 'admin']:
            return jsonify({
                'success': False,
                'error': 'Access denied. Librarian or admin role required.'
            }), 403
        
        # Calculate overdue fines
        fines_created = FineService.calculate_overdue_fines()
        
        return jsonify({
            'success': True,
            'message': f'Created {fines_created} overdue fines',
            'fines_created': fines_created
        }), 200
        
    except Exception as e:
        logger.error(f"Calculate overdue fines error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@fines_bp.route('/statistics', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_fine_statistics():
    """
    Get fine statistics (admin/librarian only)
    
    Returns:
        Success: Fine statistics
        Error: Error message
    """
    try:
        # Check authentication and authorization
        if not require_auth():
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        
        # Check if user is librarian or admin
        user_role = session.get('role')
        if user_role not in ['librarian', 'admin']:
            return jsonify({
                'success': False,
                'error': 'Access denied. Librarian or admin role required.'
            }), 403
        
        # Get statistics
        stats = FineService.get_fine_statistics()
        
        return jsonify({
            'success': True,
            'statistics': stats
        }), 200
        
    except Exception as e:
        logger.error(f"Get fine statistics error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500