"""
Borrow service for the Library Management System
Handles all borrowing-related business logic
"""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta

from db.repositories import get_repositories
from db.models import BorrowRecord

logger = logging.getLogger(__name__)

class BorrowService:
    """Service class for handling borrow operations"""
    
    @staticmethod
    def borrow_book(user_id: int, book_id: int, due_days: int = 14) -> Optional[Dict[str, Any]]:
        """
        Borrow a book for a user
        
        Args:
            user_id: ID of the user
            book_id: ID of the book
            due_days: Number of days until due date (default: 14)
            
        Returns:
            Dict containing borrow record data if successful, None otherwise
        """
        try:
            # Verify user exists and is active
            repos = get_repositories()
            user = repos['user'].get_by_id(user_id)
            if not user:
                logger.warning(f"Borrow failed: User {user_id} not found")
                return None
            
            if user.status != 'active':
                logger.warning(f"Borrow failed: User {user_id} is not active")
                return None
            
            # Verify book exists
            repos = get_repositories()
            book = repos['book'].get_by_id(book_id)
            if not book:
                logger.warning(f"Borrow failed: Book {book_id} not found")
                return None
            
            # Check if book is available
            if book.quantity_available <= 0:
                logger.warning(f"Borrow failed: Book {book_id} is not available")
                return None
            
            # Check if user already has an active borrow for this book
            if repos['borrow'].check_existing_borrow(user_id, book_id):
                logger.warning(f"Borrow failed: User {user_id} already has an active borrow for book {book_id}")
                return None
            
            # Calculate due date
            due_date = datetime.now() + timedelta(days=due_days)
            
            # Create borrow record
            borrow_record = BorrowRecord(
                user_id=user_id,
                book_id=book_id,
                borrow_date=datetime.now(),
                due_date=due_date,
                status='borrowed'
            )
            
            borrow_id = repos['borrow'].create(borrow_record)
            
            if borrow_id:
                # Update book quantity
                if repos['book'].adjust_quantity(book_id, 0, -1):
                    logger.info(f"Book {book_id} borrowed successfully by user {user_id}")
                    
                    # Get the created borrow record
                    created_borrow = repos['borrow'].get_by_id(borrow_id)
                    if created_borrow:
                        return created_borrow.to_dict()
                
                logger.error(f"Failed to update book quantity for book {book_id}")
                return None
            else:
                logger.error(f"Failed to create borrow record for user {user_id}, book {book_id}")
                return None
                
        except Exception as e:
            logger.error(f"Borrow book error: {str(e)}")
            return None
    
    @staticmethod
    def return_book(borrow_id: int) -> bool:
        """
        Return a borrowed book
        
        Args:
            borrow_id: ID of the borrow record
            
        Returns:
            bool: True if return successful, False otherwise
        """
        try:
            repos = get_repositories()
            # Get borrow record
            borrow_record = repos['borrow'].get_by_id(borrow_id)
            if not borrow_record:
                logger.warning(f"Return failed: Borrow record {borrow_id} not found")
                return False
            
            if borrow_record.status != 'borrowed':
                logger.warning(f"Return failed: Borrow record {borrow_id} is not active")
                return False
            
            # Update borrow record
            if not repos['borrow'].return_book(borrow_id):
                logger.error(f"Failed to update borrow record {borrow_id}")
                return False
            
            # Update book quantity
            if not repos['book'].adjust_quantity(borrow_record.book_id, 0, 1):
                logger.error(f"Failed to update book quantity for book {borrow_record.book_id}")
                return False
            
            logger.info(f"Book returned successfully for borrow record {borrow_id}")
            return True
        except Exception as e:
            logger.error(f"Return book error: {str(e)}")
            return False
    
    @staticmethod
    def get_user_active_borrows(user_id: int) -> List[Dict[str, Any]]:
        """
        Get all active borrows for a user
        
        Args:
            user_id: ID of the user
            
        Returns:
            List of dictionaries containing active borrow records
        """
        try:
            repos = get_repositories()
            borrows = repos['borrow'].get_active_by_user(user_id)
            return [borrow.to_dict() for borrow in borrows]
        except Exception as e:
            logger.error(f"Get user borrows error: {str(e)}")
            return []
    
    @staticmethod
    def get_all_borrows(status: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get all borrow records, optionally filtered by status
        
        Args:
            status: Filter by status ('borrowed', 'returned', 'overdue')
            
        Returns:
            List of dictionaries containing borrow records
        """
        try:
            repos = get_repositories()
            borrows = repos['borrow'].get_all(status)
            return [borrow.to_dict() for borrow in borrows]
        except Exception as e:
            logger.error(f"Get all borrows error: {str(e)}")
            return []
    
    @staticmethod
    def get_overdue_borrows() -> List[Dict[str, Any]]:
        """
        Get all overdue borrow records
        
        Returns:
            List of dictionaries containing overdue borrow records
        """
        try:
            repos = get_repositories()
            borrows = repos['borrow'].get_overdue()
            return [borrow.to_dict() for borrow in borrows]
        except Exception as e:
            logger.error(f"Get overdue borrows error: {str(e)}")
            return []
    
    @staticmethod
    def get_borrow_by_id(borrow_id: int) -> Optional[Dict[str, Any]]:
        """
        Get borrow record by ID
        
        Args:
            borrow_id: ID of the borrow record
            
        Returns:
            Dict containing borrow record data if found, None otherwise
        """
        try:
            repos = get_repositories()
            borrow = repos['borrow'].get_by_id(borrow_id)
            if borrow:
                return borrow.to_dict()
            return None
        except Exception as e:
            logger.error(f"Get borrow error: {str(e)}")
            return None
    
    @staticmethod
    def extend_due_date(borrow_id: int, additional_days: int = 7) -> bool:
        """
        Extend the due date for a borrow record
        
        Args:
            borrow_id: ID of the borrow record
            additional_days: Number of days to extend (default: 7)
            
        Returns:
            bool: True if extension successful, False otherwise
        """
        try:
            repos = get_repositories()
            borrow = repos['borrow'].get_by_id(borrow_id)
            if not borrow:
                logger.warning(f"Extension failed: Borrow record {borrow_id} not found")
                return False
            
            if borrow.status != 'borrowed':
                logger.warning(f"Extension failed: Borrow record {borrow_id} is not active")
                return False
            
            # Calculate new due date
            new_due_date = borrow.due_date + timedelta(days=additional_days) if borrow.due_date else datetime.now() + timedelta(days=additional_days)
            
            # Update borrow record
            if repos['borrow'].extend_due_date(borrow_id, new_due_date):
                logger.info(f"Due date extended for borrow record {borrow_id}")
                return True
            
            return False
        except Exception as e:
            logger.error(f"Extend due date error: {str(e)}")
            return False
    
    @staticmethod
    def get_borrow_statistics() -> Dict[str, Any]:
        """
        Get borrowing statistics
        
        Returns:
            Dict containing borrowing statistics
        """
        try:
            repos = get_repositories()
            all_borrows = repos['borrow'].get_all()
            active_borrows = repos['borrow'].get_all('borrowed')
            overdue_borrows = repos['borrow'].get_overdue()
            
            total_borrows = len(all_borrows)
            active_count = len(active_borrows)
            overdue_count = len(overdue_borrows)
            returned_count = total_borrows - active_count
            
            return {
                'total_borrows': total_borrows,
                'active_borrows': active_count,
                'returned_borrows': returned_count,
                'overdue_borrows': overdue_count
            }
        except Exception as e:
            logger.error(f"Get borrow statistics error: {str(e)}")
            return {
                'total_borrows': 0,
                'active_borrows': 0,
                'returned_borrows': 0,
                'overdue_borrows': 0
            }