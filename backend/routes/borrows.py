"""
Borrow routes for Library Management System
Handles HTTP requests and responses for borrow operations
"""

from flask import Blueprint, request, jsonify, session
from flask_cors import cross_origin
import logging
from datetime import datetime, timedelta

from services.borrow_service import BorrowService
from services.auth_service import AuthService

logger = logging.getLogger(__name__)

# Create blueprint
borrows_bp = Blueprint('borrows', __name__, url_prefix='/borrows')

def require_auth():
    """Check if user is authenticated"""
    if not session.get('authenticated') or not session.get('user_id'):
        return False
    return True

@borrows_bp.route('/borrow', methods=['POST'])
@cross_origin(supports_credentials=True)
def borrow_book():
    """
    Borrow a book
    
    Expected JSON payload:
    {
        "book_id": 1,
        "due_days": 14
    }
    
    Returns:
        Success: Borrow record data
        Error: Error message
    """
    try:
        # Check authentication
        if not require_auth():
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        
        # Get JSON data
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'Invalid request format. JSON data required.'
            }), 400
        
        # Extract data
        user_id = session.get('user_id')
        book_id = data.get('book_id')
        due_days = data.get('due_days', 14)
        
        # Validate data
        if not book_id:
            return jsonify({
                'success': False,
                'error': 'Book ID is required'
            }), 400
        
        if not isinstance(due_days, int) or due_days <= 0:
            return jsonify({
                'success': False,
                'error': 'Due days must be a positive integer'
            }), 400
        
        # Borrow book
        borrow_record = BorrowService.borrow_book(user_id, book_id, due_days)
        
        if borrow_record:
            return jsonify({
                'success': True,
                'message': 'Book borrowed successfully',
                'borrow': borrow_record
            }), 201
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to borrow book. Book may not be available or already borrowed.'
            }), 400
            
    except Exception as e:
        logger.error(f"Borrow book error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@borrows_bp.route('/return/<int:borrow_id>', methods=['POST'])
@cross_origin(supports_credentials=True)
def return_book(borrow_id):
    """
    Return a borrowed book
    
    Args:
        borrow_id: ID of the borrow record
        
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
        
        # Return book
        success = BorrowService.return_book(borrow_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Book returned successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to return book. Borrow record may not exist or already returned.'
            }), 400
            
    except Exception as e:
        logger.error(f"Return book error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@borrows_bp.route('/my-borrows', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_user_borrows():
    """
    Get current user's active borrows
    
    Returns:
        Success: List of user's active borrow records
        Error: Error message
    """
    try:
        # Check authentication
        if not require_auth():
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        
        # Get user's active borrows
        user_id = session.get('user_id')
        borrows = BorrowService.get_user_active_borrows(user_id)
        
        return jsonify({
            'success': True,
            'borrows': borrows
        }), 200
        
    except Exception as e:
        logger.error(f"Get user borrows error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@borrows_bp.route('/all', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_all_borrows():
    """
    Get all borrow records (admin/librarian only)
    
    Query Parameters:
        status: Filter by status ('borrowed', 'returned', 'overdue')
        
    Returns:
        Success: List of borrow records
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
        status = request.args.get('status')
        
        # Get borrows
        borrows = BorrowService.get_all_borrows(status)
        
        return jsonify({
            'success': True,
            'borrows': borrows
        }), 200
        
    except Exception as e:
        logger.error(f"Get all borrows error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@borrows_bp.route('/overdue', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_overdue_borrows():
    """
    Get overdue borrow records (admin/librarian only)
    
    Returns:
        Success: List of overdue borrow records
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
        
        # Get overdue borrows
        borrows = BorrowService.get_overdue_borrows()
        
        return jsonify({
            'success': True,
            'borrows': borrows
        }), 200
        
    except Exception as e:
        logger.error(f"Get overdue borrows error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@borrows_bp.route('/<int:borrow_id>', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_borrow_by_id(borrow_id):
    """
    Get borrow record by ID
    
    Args:
        borrow_id: ID of the borrow record
        
    Returns:
        Success: Borrow record data
        Error: Error message
    """
    try:
        # Check authentication
        if not require_auth():
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        
        # Get borrow record
        borrow = BorrowService.get_borrow_by_id(borrow_id)
        
        if borrow:
            # Check if user can access this record
            user_id = session.get('user_id')
            user_role = session.get('role')
            
            # Users can only see their own borrows, librarians/admins can see all
            if borrow['user_id'] != user_id and user_role not in ['librarian', 'admin']:
                return jsonify({
                    'success': False,
                    'error': 'Access denied'
                }), 403
            
            return jsonify({
                'success': True,
                'borrow': borrow
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Borrow record not found'
            }), 404
            
    except Exception as e:
        logger.error(f"Get borrow error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@borrows_bp.route('/extend/<int:borrow_id>', methods=['POST'])
@cross_origin(supports_credentials=True)
def extend_due_date(borrow_id):
    """
    Extend due date for a borrow record
    
    Args:
        borrow_id: ID of the borrow record
        
    Expected JSON payload:
    {
        "additional_days": 7
    }
    
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
        
        # Get JSON data
        data = request.get_json()
        additional_days = data.get('additional_days', 7) if data else 7
        
        # Validate data
        if not isinstance(additional_days, int) or additional_days <= 0:
            return jsonify({
                'success': False,
                'error': 'Additional days must be a positive integer'
            }), 400
        
        # Get borrow record to check ownership
        borrow = BorrowService.get_borrow_by_id(borrow_id)
        if not borrow:
            return jsonify({
                'success': False,
                'error': 'Borrow record not found'
            }), 404
        
        # Check if user can extend this record
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        # Users can only extend their own borrows, librarians/admins can extend any
        if borrow['user_id'] != user_id and user_role not in ['librarian', 'admin']:
            return jsonify({
                'success': False,
                'error': 'Access denied'
            }), 403
        
        # Extend due date
        success = BorrowService.extend_due_date(borrow_id, additional_days)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Due date extended successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to extend due date'
            }), 400
            
    except Exception as e:
        logger.error(f"Extend due date error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@borrows_bp.route('/statistics', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_borrow_statistics():
    """
    Get borrowing statistics (admin/librarian only)
    
    Returns:
        Success: Borrowing statistics
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
        stats = BorrowService.get_borrow_statistics()
        
        return jsonify({
            'success': True,
            'statistics': stats
        }), 200
        
    except Exception as e:
        logger.error(f"Get borrow statistics error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500