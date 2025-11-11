"""
Book service for the Library Management System
Handles all book-related business logic
"""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime

from db.repositories import get_repositories
from db.models import Book, ViewLog

logger = logging.getLogger(__name__)

class BookService:
    """Service class for handling book operations"""
    
    @staticmethod
    def create_book(title: str, author: str, category: str = None, isbn: str = None, 
                   publisher: str = None, year: int = None, quantity: int = 1) -> Optional[Dict[str, Any]]:
        """
        Create a new book
        
        Args:
            title: Book title
            author: Book author
            category: Book category
            isbn: ISBN number
            publisher: Publisher name
            year: Publication year
            quantity: Total quantity
            
        Returns:
            Dict containing book data if creation successful, None otherwise
        """
        try:
            # Validate input
            if not title or not author or quantity <= 0:
                logger.warning("Book creation failed: Missing required fields or invalid quantity")
                return None
            
            # Create book
            book = Book(
                title=title,
                author=author,
                category=category,
                isbn=isbn,
                publisher=publisher,
                year_published=year,
                quantity_total=quantity,
                quantity_available=quantity
            )
            
            repos = get_repositories()
            book_id = repos['book'].create(book)
            
            if book_id:
                # Get the created book
                created_book = repos['book'].get_by_id(book_id)
                if created_book:
                    logger.info(f"Book created successfully: {title}")
                    return created_book.to_dict()
                else:
                    logger.error(f"Failed to retrieve created book: {title}")
                    return None
            else:
                logger.error(f"Failed to create book: {title}")
                return None
                
        except Exception as e:
            logger.error(f"Book creation error: {str(e)}")
            return None
    
    @staticmethod
    def get_book_by_id(book_id: int) -> Optional[Dict[str, Any]]:
        """
        Get book by ID
        
        Args:
            book_id: ID of the book
            
        Returns:
            Dict containing book data if found, None otherwise
        """
        try:
            repos = get_repositories()
            book = repos['book'].get_by_id(book_id)
            if book:
                return book.to_dict()
            return None
        except Exception as e:
            logger.error(f"Get book error: {str(e)}")
            return None
    
    @staticmethod
    def get_all_books() -> List[Dict[str, Any]]:
        """
        Get all books
        
        Returns:
            List of dictionaries containing book data
        """
        try:
            repos = get_repositories()
            books = repos['book'].get_all()
            return [book.to_dict() for book in books]
        except Exception as e:
            logger.error(f"Get all books error: {str(e)}")
            return []
    
    @staticmethod
    def search_books(title: str = None, author: str = None, category: str = None, 
                    isbn: str = None, year: int = None) -> List[Dict[str, Any]]:
        """
        Search books by various criteria
        
        Args:
            title: Book title to search
            author: Book author to search
            category: Book category to search
            isbn: ISBN to search
            year: Publication year to search
            
        Returns:
            List of dictionaries containing matching book data
        """
        try:
            repos = get_repositories()
            books = repos['book'].filter(title, author, category, isbn, year)
            return [book.to_dict() for book in books]
        except Exception as e:
            logger.error(f"Search books error: {str(e)}")
            return []
    
    @staticmethod
    def update_book(book_id: int, title: str = None, author: str = None, category: str = None,
                  isbn: str = None, publisher: str = None, year: int = None, 
                  quantity_total: int = None, quantity_available: int = None) -> bool:
        """
        Update book information
        
        Args:
            book_id: ID of the book to update
            title: New title (optional)
            author: New author (optional)
            category: New category (optional)
            isbn: New ISBN (optional)
            publisher: New publisher (optional)
            year: New publication year (optional)
            quantity_total: New total quantity (optional)
            quantity_available: New available quantity (optional)
            
        Returns:
            bool: True if update successful, False otherwise
        """
        try:
            repos = get_repositories()
            book = repos['book'].get_by_id(book_id)
            if not book:
                logger.warning(f"Book update failed: Book {book_id} not found")
                return False
            
            # Update fields if provided
            if title is not None:
                book.title = title
            if author is not None:
                book.author = author
            if category is not None:
                book.category = category
            if isbn is not None:
                book.isbn = isbn
            if publisher is not None:
                book.publisher = publisher
            if year is not None:
                book.year_published = year
            if quantity_total is not None:
                book.quantity_total = quantity_total
            if quantity_available is not None:
                book.quantity_available = quantity_available
            
            repos = get_repositories()
            return repos['book'].update(book)
        except Exception as e:
            logger.error(f"Book update error: {str(e)}")
            return False
    
    @staticmethod
    def delete_book(book_id: int) -> bool:
        """
        Delete a book
        
        Args:
            book_id: ID of the book to delete
            
        Returns:
            bool: True if deletion successful, False otherwise
        """
        try:
            repos = get_repositories()
            book = repos['book'].get_by_id(book_id)
            if not book:
                logger.warning(f"Book deletion failed: Book {book_id} not found")
                return False
            
            return repos['book'].delete(book_id)
        except Exception as e:
            logger.error(f"Book deletion error: {str(e)}")
            return False
    
    @staticmethod
    def adjust_book_quantity(book_id: int, total_change: int = 0, available_change: int = 0) -> bool:
        """
        Adjust book quantity
        
        Args:
            book_id: ID of the book
            total_change: Change to total quantity
            available_change: Change to available quantity
            
        Returns:
            bool: True if adjustment successful, False otherwise
        """
        try:
            repos = get_repositories()
            book = repos['book'].get_by_id(book_id)
            if not book:
                logger.warning(f"Quantity adjustment failed: Book {book_id} not found")
                return False
            
            # Check if new quantities would be valid
            new_total = book.quantity_total + total_change
            new_available = book.quantity_available + available_change
            
            if new_total < 0 or new_available < 0:
                logger.warning(f"Quantity adjustment failed: Invalid quantities for book {book_id}")
                return False
            
            return repos['book'].adjust_quantity(book_id, total_change, available_change)
        except Exception as e:
            logger.error(f"Quantity adjustment error: {str(e)}")
            return False
    
    @staticmethod
    def log_book_view(user_id: int, book_id: int) -> bool:
        """
        Log that a user viewed a book
        
        Args:
            user_id: ID of the user
            book_id: ID of the book
            
        Returns:
            bool: True if logging successful, False otherwise
        """
        try:
            # Verify book exists
            repos = get_repositories()
            book = repos['book'].get_by_id(book_id)
            if not book:
                logger.warning(f"View logging failed: Book {book_id} not found")
                return False
            
            # Create view log entry
            view_log = ViewLog(
                user_id=user_id,
                book_id=book_id,
                view_date=datetime.now()
            )
            
            repos = get_repositories()
            repos['view_log'].create(view_log)
            return True
        except Exception as e:
            logger.error(f"View logging error: {str(e)}")
            return False
    
    @staticmethod
    def get_user_view_history(user_id: int, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get user's book view history
        
        Args:
            user_id: ID of the user
            limit: Maximum number of records to return
            
        Returns:
            List of dictionaries containing view history
        """
        try:
            repos = get_repositories()
            view_logs = repos['view_log'].get_user_history(user_id, limit)
            return [view_log.to_dict() for view_log in view_logs]
        except Exception as e:
            logger.error(f"Get view history error: {str(e)}")
            return []
    
    @staticmethod
    def check_book_availability(book_id: int) -> bool:
        """
        Check if a book is available for borrowing
        
        Args:
            book_id: ID of the book
            
        Returns:
            bool: True if book is available, False otherwise
        """
        try:
            repos = get_repositories()
            book = repos['book'].get_by_id(book_id)
            if not book:
                return False
            
            return book.quantity_available > 0
        except Exception as e:
            logger.error(f"Check availability error: {str(e)}")
            return False