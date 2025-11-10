
from flask import Flask, request, jsonify
import sys
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from db.helpers import list_books, get_book_by_id, add_book, delete_book, filter_books

# Standard import for helpers
#from db.helpers import list_books, get_book_by_id, add_book, delete_book, filter_books
from mysql.connector import Error  # type: ignore
from typing import List, Dict, Any

app = Flask(__name__)

# Route: List all books
@app.route('/books', methods=['GET'])
def get_books():
	try:
		books = list_books()
		return jsonify(books), 200
	except Error as e:
		return jsonify({'error': str(e)}), 500

# Route: Get book by ID
@app.route('/books/<int:book_id>', methods=['GET'])
def get_book(book_id):
	try:
		book = get_book_by_id(book_id)
		if book:
			return jsonify(book), 200
		else:
			return jsonify({'error': 'Book not found'}), 404
	except Error as e:
		return jsonify({'error': str(e)}), 500

# Route: Add a new book
@app.route('/books', methods=['POST'])
def add_new_book():
	data = request.get_json()
	try:
		add_book(
			data.get('title'),
			data.get('author'),
			data.get('category'),
			data.get('isbn'),
			data.get('publisher'),
			data.get('year'),
			data.get('quantity')
		)
		return jsonify({'message': 'Book added successfully'}), 201
	except Exception as e:
		return jsonify({'error': str(e)}), 400

# Route: Delete a book
@app.route('/books/<int:book_id>', methods=['DELETE'])
def remove_book(book_id):
	try:
		delete_book(book_id)
		return jsonify({'message': 'Book deleted successfully'}), 200
	except Error as e:
		return jsonify({'error': str(e)}), 500

# Route: Filter books
@app.route('/books/filter', methods=['GET'])
def filter_books_route():
	title = request.args.get('title')
	author = request.args.get('author')
	category = request.args.get('category')
	isbn = request.args.get('isbn')
	year = request.args.get('year')
	try:
		results = filter_books(title, author, category, isbn, year)
		return jsonify(results), 200
	except Error as e:
		return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
	app.run(debug=True)
