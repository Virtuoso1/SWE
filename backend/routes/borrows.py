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
        
        # Convert book_id to integer if it's a string
        try:
            book_id = int(book_id)
        except (ValueError, TypeError):
            return jsonify({
                'success': False,
                'error': 'Book ID must be a valid integer'
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
        Success: Return result with details
        Error: Error message with error code
    """
    try:
        # Check authentication
        if not require_auth():
            return jsonify({
                'success': False,
                'error': 'Authentication required',
                'error_code': 'AUTH_REQUIRED'
            }), 401
        
        # Get current user ID for validation
        user_id = session.get('user_id')
        
        # Return book with enhanced functionality
        result = BorrowService.return_book(borrow_id, user_id)
        
        if result['success']:
            return jsonify(result), 200
        else:
            # Return appropriate HTTP status based on error code
            status_code = 400
            if result.get('error_code') == 'NOT_FOUND':
                status_code = 404
            elif result.get('error_code') == 'UNAUTHORIZED':
                status_code = 403
                
            return jsonify(result), status_code
            
    except Exception as e:
        logger.error(f"Return book error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred',
            'error_code': 'INTERNAL_ERROR'
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

@borrows_bp.route('/overdue-books', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_overdue_books():
    """
    Get overdue books with filtering and pagination
    
    Query Parameters:
        page: Page number (default: 1)
        limit: Number of items per page (default: 10)
        sort_by: Sort field ('days_overdue', 'user_name', 'book_title', 'due_date')
        order: Sort order ('asc', 'desc')
        
    Returns:
        Success: Paginated list of overdue books
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
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        sort_by = request.args.get('sort_by', 'days_overdue')
        order = request.args.get('order', 'desc')
        
        # Get overdue books
        overdue_books = BorrowService.get_overdue_books_with_details(page, limit, sort_by, order)
        
        return jsonify({
            'success': True,
            'overdue_books': overdue_books,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': len(overdue_books) if overdue_books else 0
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Get overdue books error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500