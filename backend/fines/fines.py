"""
Fines module for Library Management System
Refactored to integrate with the new centralized architecture
"""

from flask import Flask, request, jsonify
from flask_cors import cross_origin
import logging
import sys
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from services.fine_service import FineService

logger = logging.getLogger(__name__)

app = Flask(__name__)

# ------------------------
# ROUTE 1: Get user fines
# ------------------------
@app.route('/fine', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_user_fines():
    """
    Get fines for a user
    
    Query Parameters:
        user_id: ID of the user
        
    Returns:
        Success: List of fines
        Error: Error message
    """
    try:
        user_id = request.args.get('user_id')
        
        if not user_id:
            return jsonify({'error': 'user_id is required'}), 400
        
        # Convert to int
        try:
            user_id = int(user_id)
        except ValueError:
            return jsonify({'error': 'user_id must be a valid integer'}), 400
        
        # Get user's fines
        fines = FineService.get_user_fines(user_id)
        
        return jsonify(fines), 200
        
    except Exception as e:
        logger.error(f"Get user fines error: {str(e)}")
        return jsonify({'error': 'An internal error occurred'}), 500

# ------------------------
# ROUTE 2: Mark fine as paid
# ------------------------
@app.route('/pay', methods=['POST'])
@cross_origin(supports_credentials=True)
def mark_fine_as_paid():
    """
    Mark a fine as paid
    
    Expected JSON payload:
    {
        "fine_id": 1
    }
    
    Returns:
        Success: Success message
        Error: Error message
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Invalid request format. JSON data required.'}), 400
        
        fine_id = data.get('fine_id')
        
        if not fine_id:
            return jsonify({'error': 'fine_id is required'}), 400
        
        # Convert to int
        try:
            fine_id = int(fine_id)
        except ValueError:
            return jsonify({'error': 'fine_id must be a valid integer'}), 400
        
        # Pay fine
        success = FineService.pay_fine(fine_id)
        
        if success:
            return jsonify({'message': 'Fine marked as paid successfully'}), 200
        else:
            return jsonify({'error': 'Fine not found or already paid'}), 404
        
    except Exception as e:
        logger.error(f"Pay fine error: {str(e)}")
        return jsonify({'error': 'An internal error occurred'}), 500

# ------------------------
# ROUTE 3: Get fine by ID
# ------------------------
@app.route('/fine/<int:fine_id>', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_fine_by_id(fine_id):
    """
    Get fine by ID
    
    Args:
        fine_id: ID of the fine
        
    Returns:
        Success: Fine data
        Error: Error message
    """
    try:
        fine = FineService.get_fine_by_id(fine_id)
        
        if fine:
            return jsonify(fine), 200
        else:
            return jsonify({'error': 'Fine not found'}), 404
        
    except Exception as e:
        logger.error(f"Get fine error: {str(e)}")
        return jsonify({'error': 'An internal error occurred'}), 500

# ------------------------
# ROUTE 4: Create fine
# ------------------------
@app.route('/create', methods=['POST'])
@cross_origin(supports_credentials=True)
def create_fine():
    """
    Create a new fine
    
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
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Invalid request format. JSON data required.'}), 400
        
        borrow_id = data.get('borrow_id')
        amount = data.get('amount')
        
        if not borrow_id:
            return jsonify({'error': 'borrow_id is required'}), 400
        
        if not amount:
            return jsonify({'error': 'amount is required'}), 400
        
        # Convert to proper types
        try:
            borrow_id = int(borrow_id)
            amount = float(amount)
        except ValueError:
            return jsonify({'error': 'Invalid data types'}), 400
        
        if amount <= 0:
            return jsonify({'error': 'amount must be positive'}), 400
        
        # Create fine
        fine = FineService.create_fine(borrow_id, amount)
        
        if fine:
            return jsonify({'message': 'Fine created successfully', 'fine': fine}), 201
        else:
            return jsonify({'error': 'Failed to create fine'}), 400
        
    except Exception as e:
        logger.error(f"Create fine error: {str(e)}")
        return jsonify({'error': 'An internal error occurred'}), 500

# ------------------------
# ROUTE 5: Get all fines
# ------------------------
@app.route('/all', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_all_fines():
    """
    Get all fines
    
    Query Parameters:
        paid_status: Filter by paid status ('paid', 'unpaid')
        
    Returns:
        Success: List of fines
        Error: Error message
    """
    try:
        paid_status = request.args.get('paid_status')
        
        # Validate paid_status if provided
        if paid_status and paid_status not in ['paid', 'unpaid']:
            return jsonify({'error': 'paid_status must be "paid" or "unpaid"'}), 400
        
        # Get fines
        fines = FineService.get_all_fines(paid_status)
        
        return jsonify(fines), 200
        
    except Exception as e:
        logger.error(f"Get all fines error: {str(e)}")
        return jsonify({'error': 'An internal error occurred'}), 500

# ------------------------
# Run the Flask app
# ------------------------
if __name__ == '__main__':
    app.run(debug=True)
