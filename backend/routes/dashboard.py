"""
Dashboard routes for Library Management System
Handles HTTP requests and responses for dashboard operations
"""

from flask import Blueprint, request, jsonify, session
from flask_cors import cross_origin
import logging

from services.library_service import LibraryService

logger = logging.getLogger(__name__)

# Create blueprint
dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

def require_auth():
    """Check if user is authenticated"""
    if not session.get('authenticated') or not session.get('user_id'):
        return False
    return True

@dashboard_bp.route('/statistics', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_library_statistics():
    """
    Get library statistics (admin/librarian only)
    
    Returns:
        Success: Library statistics
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
        stats = LibraryService.get_library_statistics()
        
        return jsonify({
            'success': True,
            'statistics': stats
        }), 200
        
    except Exception as e:
        logger.error(f"Get library statistics error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@dashboard_bp.route('/data', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_dashboard_data():
    """
    Get dashboard data (admin/librarian only)
    
    Returns:
        Success: Dashboard data including statistics and recent activity
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
        
        # Get dashboard data
        dashboard_data = LibraryService.get_dashboard_data()
        
        return jsonify({
            'success': True,
            'dashboard': dashboard_data
        }), 200
        
    except Exception as e:
        logger.error(f"Get dashboard data error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@dashboard_bp.route('/health', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_system_health():
    """
    Get system health status (admin only)
    
    Returns:
        Success: System health information
        Error: Error message
    """
    try:
        # Check authentication and authorization
        if not require_auth():
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        
        # Check if user is admin
        user_role = session.get('role')
        if user_role != 'admin':
            return jsonify({
                'success': False,
                'error': 'Access denied. Admin role required.'
            }), 403
        
        # Get system health
        health = LibraryService.get_system_health()
        
        return jsonify({
            'success': True,
            'health': health
        }), 200
        
    except Exception as e:
        logger.error(f"Get system health error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@dashboard_bp.route('/user-summary', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_user_summary():
    """
    Get user-specific dashboard summary
    
    Returns:
        Success: User summary data
        Error: Error message
    """
    try:
        # Check authentication
        if not require_auth():
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        
        # Get user-specific data
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        # Get user's active borrows
        from services.borrow_service import BorrowService
        active_borrows = BorrowService.get_user_active_borrows(user_id)
        
        # Get user's fines
        from services.fine_service import FineService
        user_fines = FineService.get_user_fines(user_id)
        
        # Get user's view history
        from services.book_service import BookService
        view_history = BookService.get_user_view_history(user_id, 5)
        
        # Calculate summary
        unpaid_fines = [fine for fine in user_fines if fine.get('paid_status') == 'unpaid']
        total_unpaid = sum(fine.get('amount', 0) for fine in unpaid_fines)
        
        summary = {
            'user_id': user_id,
            'role': user_role,
            'active_borrows_count': len(active_borrows),
            'unpaid_fines_count': len(unpaid_fines),
            'total_unpaid_amount': total_unpaid,
            'recent_borrows': active_borrows[:3],  # Last 3 active borrows
            'recent_fines': user_fines[:3],  # Last 3 fines
            'recent_views': view_history[:5]  # Last 5 views
        }
        
        return jsonify({
            'success': True,
            'summary': summary
        }), 200
        
    except Exception as e:
        logger.error(f"Get user summary error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@dashboard_bp.route('/borrow-stats', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_borrow_statistics():
    """
    Get borrowing statistics (admin/librarian only)
    
    Query Parameters:
        period: Time period ('day', 'week', 'month', 'year')
        
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
        
        # Get query parameters
        period = request.args.get('period', 'month')
        
        # Get borrow statistics
        from services.borrow_service import BorrowService
        stats = BorrowService.get_borrow_statistics()
        
        # Add period-specific analysis if needed
        if period in ['day', 'week', 'month', 'year']:
            # This could be extended with time-based filtering
            stats['period'] = period
        
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

@dashboard_bp.route('/fine-stats', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_fine_statistics():
    """
    Get fine statistics (admin/librarian only)
    
    Query Parameters:
        period: Time period ('day', 'week', 'month', 'year')
        
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
        
        # Get query parameters
        period = request.args.get('period', 'month')
        
        # Get fine statistics
        from services.fine_service import FineService
        stats = FineService.get_fine_statistics()
        
        # Add period-specific analysis if needed
        if period in ['day', 'week', 'month', 'year']:
            # This could be extended with time-based filtering
            stats['period'] = period
        
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