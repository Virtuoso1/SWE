"""
Users routes for Library Management System
Handles HTTP requests and responses for user operations
"""

from flask import Blueprint, request, jsonify, session
from flask_cors import cross_origin
import logging

from services.auth_service import AuthService

logger = logging.getLogger(__name__)

# Create blueprint
users_bp = Blueprint('users', __name__, url_prefix='/users')

def require_auth():
    """Check if user is authenticated"""
    if not session.get('authenticated') or not session.get('user_id'):
        return False
    return True

@users_bp.route('/profile', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_user_profile():
    """
    Get current user's profile
    
    Returns:
        Success: User profile data
        Error: Error message
    """
    try:
        # Check authentication
        if not require_auth():
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        
        # Get user profile
        user_id = session.get('user_id')
        profile = AuthService.get_user_profile(user_id)
        
        if profile:
            return jsonify({
                'success': True,
                'user': profile
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'User profile not found'
            }), 404
            
    except Exception as e:
        logger.error(f"Get user profile error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@users_bp.route('/profile', methods=['PUT'])
@cross_origin(supports_credentials=True)
def update_user_profile():
    """
    Update current user's profile
    
    Expected JSON payload:
    {
        "full_name": "Updated Name",
        "email": "updated@example.com"
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
        if not data:
            return jsonify({
                'success': False,
                'error': 'Invalid request format. JSON data required.'
            }), 400
        
        # Extract data
        user_id = session.get('user_id')
        full_name = data.get('full_name')
        email = data.get('email')
        
        # Update profile
        success = AuthService.update_user_profile(user_id, full_name, email)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Profile updated successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to update profile'
            }), 400
            
    except Exception as e:
        logger.error(f"Update user profile error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@users_bp.route('/change-password', methods=['POST'])
@cross_origin(supports_credentials=True)
def change_password():
    """
    Change user password
    
    Expected JSON payload:
    {
        "current_password": "oldpassword",
        "new_password": "newpassword"
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
        if not data:
            return jsonify({
                'success': False,
                'error': 'Invalid request format. JSON data required.'
            }), 400
        
        # Extract data
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        # Validate data
        if not current_password or not new_password:
            return jsonify({
                'success': False,
                'error': 'Current password and new password are required'
            }), 400
        
        # Get current user
        user_id = session.get('user_id')
        email = session.get('email')
        
        # Verify current password
        user_data = AuthService.authenticate_user(email, current_password)
        if not user_data:
            return jsonify({
                'success': False,
                'error': 'Current password is incorrect'
            }), 400
        
        # Update password
        success = AuthService.reset_password(user_id, new_password)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Password changed successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to change password'
            }), 400
            
    except Exception as e:
        logger.error(f"Change password error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@users_bp.route('/all', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_all_users():
    """
    Get all users (admin/librarian only)
    
    Returns:
        Success: List of users
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
        
        # Get all users
        from db.repositories import get_repositories
        repos = get_repositories()
        users = repos['user'].get_all()
        
        # Convert to dict and remove sensitive data
        users_data = []
        for user in users:
            user_dict = user.to_dict()
            users_data.append(user_dict)
        
        return jsonify({
            'success': True,
            'users': users_data
        }), 200
        
    except Exception as e:
        logger.error(f"Get all users error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@users_bp.route('/<int:user_id>/suspend', methods=['POST'])
@cross_origin(supports_credentials=True)
def suspend_user(user_id):
    """
    Suspend a user (admin only)
    
    Args:
        user_id: ID of user to suspend
        
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
        
        # Check if user is admin
        user_role = session.get('role')
        if user_role != 'admin':
            return jsonify({
                'success': False,
                'error': 'Access denied. Admin role required.'
            }), 403
        
        # Suspend user
        success = AuthService.change_user_status(user_id, 'inactive')
        
        if success:
            return jsonify({
                'success': True,
                'message': 'User suspended successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to suspend user or user not found'
            }), 400
            
    except Exception as e:
        logger.error(f"Suspend user error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@users_bp.route('/<int:user_id>/activate', methods=['POST'])
@cross_origin(supports_credentials=True)
def activate_user(user_id):
    """
    Activate a user (admin only)
    
    Args:
        user_id: ID of user to activate
        
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
        
        # Check if user is admin
        user_role = session.get('role')
        if user_role != 'admin':
            return jsonify({
                'success': False,
                'error': 'Access denied. Admin role required.'
            }), 403
        
        # Activate user
        success = AuthService.change_user_status(user_id, 'active')
        
        if success:
            return jsonify({
                'success': True,
                'message': 'User activated successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to activate user or user not found'
            }), 400
            
    except Exception as e:
        logger.error(f"Activate user error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@users_bp.route('/<int:user_id>/reset-password', methods=['POST'])
@cross_origin(supports_credentials=True)
def reset_user_password(user_id):
    """
    Reset user password (admin only)
    
    Args:
        user_id: ID of user whose password to reset
        
    Expected JSON payload:
    {
        "new_password": "newpassword"
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
        
        # Check if user is admin
        user_role = session.get('role')
        if user_role != 'admin':
            return jsonify({
                'success': False,
                'error': 'Access denied. Admin role required.'
            }), 403
        
        # Get JSON data
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'Invalid request format. JSON data required.'
            }), 400
        
        # Extract data
        new_password = data.get('new_password')
        
        # Validate data
        if not new_password:
            return jsonify({
                'success': False,
                'error': 'New password is required'
            }), 400
        
        # Reset password
        success = AuthService.reset_password(user_id, new_password)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Password reset successfully'
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to reset password or user not found'
            }), 400
            
    except Exception as e:
        logger.error(f"Reset user password error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@users_bp.route('/my-profile', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_my_profile():
    """
    Get current user's profile (for students to view their own info)
    
    Returns:
        Success: User profile data
        Error: Error message
    """
    try:
        # Check authentication
        if not require_auth():
            return jsonify({
                'success': False,
                'error': 'Authentication required'
            }), 401
        
        # Get current user's profile
        user_id = session.get('user_id')
        profile = AuthService.get_user_profile(user_id)
        
        if profile:
            return jsonify({
                'success': True,
                'user': profile
            }), 200
        else:
            return jsonify({
                'success': False,
                'error': 'User profile not found'
            }), 404
            
    except Exception as e:
        logger.error(f"Get my profile error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500

@users_bp.route('/create', methods=['POST'])
@cross_origin(supports_credentials=True)
def create_user():
    """
    Create a new user (librarian/admin only)
    
    Expected JSON payload:
    {
        "full_name": "John Doe",
        "email": "john@example.com",
        "password": "password123",
        "role": "student"
    }
    
    Returns:
        Success: User creation success message
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
        
        # Extract required fields
        full_name = data.get('full_name')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'student')
        
        # Validate required fields
        if not full_name or not email or not password:
            return jsonify({
                'success': False,
                'error': 'Full name, email, and password are required'
            }), 400
        
        # Validate role
        if role not in ['student', 'librarian', 'admin']:
            return jsonify({
                'success': False,
                'error': 'Invalid role. Must be student, librarian, or admin'
            }), 400
        
        # Create user
        success = AuthService.create_user(full_name, email, password, role)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'User created successfully'
            }), 201
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to create user. Email may already exist.'
            }), 400
            
    except Exception as e:
        logger.error(f"Create user error: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An internal error occurred'
        }), 500