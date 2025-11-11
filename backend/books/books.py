"""
Books routes for Library Management System
Handles HTTP requests and responses for book operations
"""

from flask import Blueprint, request, jsonify
from flask_cors import cross_origin
import logging
import sys
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from services.book_service import BookService
from utils.validators import validate_name

logger = logging.getLogger(__name__)

# Create blueprint
books_bp = Blueprint("books", __name__)

@books_bp.route('/books', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_books():
    """
    Get all books
    
    Returns:
        Success: List of book objects
        Error: Error message
    """
    try:
        books = BookService.get_all_books()
        return jsonify(books), 200
    except Exception as e:
        logger.error(f"Get books error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@books_bp.route('/books/<int:book_id>', methods=['GET'])
@cross_origin(supports_credentials=True)
def get_book(book_id):
    """
    Get book by ID
    
    Args:
        book_id: ID of the book
        
    Returns:
        Success: Book object
        Error: Error message
    """
    try:
        book = BookService.get_book_by_id(book_id)
        if book:
            return jsonify(book), 200
        else:
            return jsonify({'error': 'Book not found'}), 404
    except Exception as e:
        logger.error(f"Get book error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@books_bp.route('/books', methods=['POST'])
@cross_origin(supports_credentials=True)
def add_new_book():
    """
    Add a new book
    
    Expected JSON payload:
    {
        "title": "Book Title",
        "author": "Author Name",
        "category": "Fiction",
        "isbn": "1234567890",
        "publisher": "Publisher",
        "year": 2023,
        "quantity": 5
    }
    
    Returns:
        Success: Success message
        Error: Error message
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        if not data:
            return jsonify({'error': 'Invalid request format. JSON data required.'}), 400
        
        title = data.get('title', '').strip()
        author = data.get('author', '').strip()
        category = data.get('category', '').strip() or None
        isbn = data.get('isbn', '').strip() or None
        publisher = data.get('publisher', '').strip() or None
        year = data.get('year')
        quantity = data.get('quantity', 1)
        
        # Validate required fields
        if not title:
            return jsonify({'error': 'Title is required'}), 400
        if not author:
            return jsonify({'error': 'Author is required'}), 400
        if not isinstance(quantity, int) or quantity <= 0:
            return jsonify({'error': 'Quantity must be a positive integer'}), 400
        
        # Create book
        book = BookService.create_book(
            title=title,
            author=author,
            category=category,
            isbn=isbn,
            publisher=publisher,
            year=year,
            quantity=quantity
        )
        
        if book:
            return jsonify({'message': 'Book added successfully', 'book': book}), 201
        else:
            return jsonify({'error': 'Failed to add book'}), 400
            
    except Exception as e:
        logger.error(f"Add book error: {str(e)}")
        return jsonify({'error': str(e)}), 400

@books_bp.route('/books/<int:book_id>', methods=['PUT'])
@cross_origin(supports_credentials=True)
def update_book(book_id):
    """
    Update an existing book
    
    Args:
        book_id: ID of the book to update
        
    Expected JSON payload:
    {
        "title": "Updated Title",
        "author": "Updated Author",
        "category": "Updated Category",
        "isbn": "Updated ISBN",
        "publisher": "Updated Publisher",
        "year": 2024,
        "quantity_total": 10,
        "quantity_available": 8
    }
    
    Returns:
        Success: Success message
        Error: Error message
    """
    try:
        data = request.get_json()
        
        # Validate request
        if not data:
            return jsonify({'error': 'Invalid request format. JSON data required.'}), 400
        
        # Extract fields (all optional)
        title = data.get('title')
        author = data.get('author')
        category = data.get('category')
        isbn = data.get('isbn')
        publisher = data.get('publisher')
        year = data.get('year')
        quantity_total = data.get('quantity_total')
        quantity_available = data.get('quantity_available')
        
        # Update book
        success = BookService.update_book(
            book_id=book_id,
            title=title,
            author=author,
            category=category,
            isbn=isbn,
            publisher=publisher,
            year=year,
            quantity_total=quantity_total,
            quantity_available=quantity_available
        )
        
        if success:
            return jsonify({'message': 'Book updated successfully'}), 200
        else:
            return jsonify({'error': 'Failed to update book or book not found'}), 400
            
    except Exception as e:
        logger.error(f"Update book error: {str(e)}")
        return jsonify({'error': str(e)}), 400

@books_bp.route('/books/<int:book_id>', methods=['DELETE'])
@cross_origin(supports_credentials=True)
def remove_book(book_id):
    """
    Delete a book
    
    Args:
        book_id: ID of the book to delete
        
    Returns:
        Success: Success message
        Error: Error message
    """
    try:
        success = BookService.delete_book(book_id)
        
        if success:
            return jsonify({'message': 'Book deleted successfully'}), 200
        else:
            return jsonify({'error': 'Book not found or could not be deleted'}), 404
            
    except Exception as e:
        logger.error(f"Delete book error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@books_bp.route('/books/filter', methods=['GET'])
@cross_origin(supports_credentials=True)
def filter_books_route():
    """
    Filter books by various criteria
    
    Query Parameters:
        title: Filter by title (partial match)
        author: Filter by author (partial match)
        category: Filter by category (partial match)
        isbn: Filter by ISBN (partial match)
        year: Filter by publication year (exact match)
        
    Returns:
        Success: List of matching books
        Error: Error message
    """
    try:
        title = request.args.get('title')
        author = request.args.get('author')
        category = request.args.get('category')
        isbn = request.args.get('isbn')
        year = request.args.get('year')
        
        # Convert year to int if provided
        if year:
            try:
                year = int(year)
            except ValueError:
                return jsonify({'error': 'Year must be a valid integer'}), 400
        
        books = BookService.search_books(
            title=title,
            author=author,
            category=category,
            isbn=isbn,
            year=year
        )
        
        return jsonify(books), 200
        
    except Exception as e:
        logger.error(f"Filter books error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@books_bp.route('/books/<int:book_id>/view', methods=['POST'])
@cross_origin(supports_credentials=True)
def log_book_view(book_id):
    """
    Log that a user viewed a book
    
    Args:
        book_id: ID of the book being viewed
        
    Returns:
        Success: Success message
        Error: Error message
    """
    try:
        # Get user ID from session
        from flask import session
        user_id = session.get('user_id')
        
        if not user_id:
            return jsonify({'error': 'User not authenticated'}), 401
        
        success = BookService.log_book_view(user_id, book_id)
        
        if success:
            return jsonify({'message': 'View logged successfully'}), 200
        else:
            return jsonify({'error': 'Failed to log view or book not found'}), 400
            
    except Exception as e:
        logger.error(f"Log book view error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@books_bp.route('/books/<int:book_id>/availability', methods=['GET'])
@cross_origin(supports_credentials=True)
def check_book_availability(book_id):
    """
    Check if a book is available for borrowing
    
    Args:
        book_id: ID of the book to check
        
    Returns:
        Success: Availability status
        Error: Error message
    """
    try:
        available = BookService.check_book_availability(book_id)
        
        return jsonify({
            'book_id': book_id,
            'available': available
        }), 200
        
    except Exception as e:
        logger.error(f"Check availability error: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app = Flask(__name__)
    app.register_blueprint(books_bp)
    app.run(debug=True)
