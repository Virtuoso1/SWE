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
            
            # Note: Allowing users to borrow the same book multiple times
            # This check is removed to allow multiple copies of the same book to be borrowed
            
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
                    
                    # Get the created borrow record with JOIN data
                    created_borrow = repos['borrow'].get_by_id(borrow_id)
                    if created_borrow:
                        # Convert to dictionary and add JOIN data
                        borrow_dict = created_borrow.to_dict()
                        
                        # Add book and user details
                        book = repos['book'].get_by_id(book_id)
                        user = repos['user'].get_by_id(user_id)
                        
                        if book:
                            borrow_dict['book_title'] = book.title
                            borrow_dict['book_author'] = book.author
                        if user:
                            borrow_dict['user_name'] = user.full_name
                            borrow_dict['user_email'] = user.email
                            
                        return borrow_dict
                
                logger.error(f"Failed to update book quantity for book {book_id}")
                return None
            else:
                logger.error(f"Failed to create borrow record for user {user_id}, book {book_id}")
                return None
                
        except Exception as e:
            logger.error(f"Borrow book error: {str(e)}")
            return None
    
    @staticmethod
    def return_book(borrow_id: int, user_id: int = None) -> Dict[str, Any]:
        """
        Return a borrowed book with comprehensive validation and penalty calculation
        
        Args:
            borrow_id: ID of the borrow record
            user_id: ID of the user attempting to return (for validation)
            
        Returns:
            Dict containing return result with details
        """
        try:
            repos = get_repositories()
            # Get borrow record with JOIN data
            borrow_record = repos['borrow'].get_by_id(borrow_id)
            if not borrow_record:
                logger.warning(f"Return failed: Borrow record {borrow_id} not found")
                return {
                    'success': False,
                    'error': 'Borrow record not found',
                    'error_code': 'NOT_FOUND'
                }
            
            # Validate user can return this book (only borrower or admin/librarian can return)
            if user_id and borrow_record.user_id != user_id:
                # Check if user is admin or librarian
                user = repos['user'].get_by_id(user_id)
                if not user or user.role not in ['admin', 'librarian']:
                    logger.warning(f"Return failed: User {user_id} not authorized to return borrow record {borrow_id}")
                    return {
                        'success': False,
                        'error': 'You can only return books that you borrowed',
                        'error_code': 'UNAUTHORIZED'
                    }
            
            if borrow_record.status != 'borrowed':
                logger.warning(f"Return failed: Borrow record {borrow_id} is not active (status: {borrow_record.status})")
                return {
                    'success': False,
                    'error': 'This book has already been returned',
                    'error_code': 'ALREADY_RETURNED'
                }
            
            # Calculate days overdue and penalty if applicable
            current_date = datetime.now()
            days_overdue = 0
            penalty_amount = 0.0
            
            if borrow_record.due_date and current_date > borrow_record.due_date:
                days_overdue = (current_date - borrow_record.due_date).days
                # Calculate penalty: $0.50 per day overdue
                penalty_amount = days_overdue * 0.50
                
                # Create fine record if penalty > 0
                if penalty_amount > 0:
                    from services.fine_service import FineService
                    fine_result = FineService.create_fine(
                        borrow_id=borrow_id,
                        amount=penalty_amount,
                        reason=f"Late return: {days_overdue} days overdue"
                    )
                    if not fine_result['success']:
                        logger.error(f"Failed to create fine for overdue book: {fine_result.get('error', 'Unknown error')}")
            
            # Update borrow record with return date and status
            if not repos['borrow'].return_book(borrow_id):
                logger.error(f"Failed to update borrow record {borrow_id}")
                return {
                    'success': False,
                    'error': 'Failed to update borrow record',
                    'error_code': 'UPDATE_FAILED'
                }
            
            # Update book quantity (increment available copies)
            if not repos['book'].adjust_quantity(borrow_record.book_id, 0, 1):
                logger.error(f"Failed to update book quantity for book {borrow_record.book_id}")
                return {
                    'success': False,
                    'error': 'Failed to update book availability',
                    'error_code': 'QUANTITY_UPDATE_FAILED'
                }
            
            # Get book and user details for response
            book = repos['book'].get_by_id(borrow_record.book_id)
            user = repos['user'].get_by_id(borrow_record.user_id)
            
            logger.info(f"Book returned successfully for borrow record {borrow_id}")
            
            return {
                'success': True,
                'message': 'Book returned successfully',
                'borrow_id': borrow_id,
                'book_title': book.title if book else 'Unknown Book',
                'book_author': book.author if book else 'Unknown Author',
                'user_name': user.full_name if user else 'Unknown User',
                'return_date': current_date.isoformat(),
                'days_overdue': days_overdue,
                'penalty_amount': penalty_amount,
                'fine_created': penalty_amount > 0
            }
            
        except Exception as e:
            logger.error(f"Return book error: {str(e)}")
            return {
                'success': False,
                'error': 'An internal error occurred during book return',
                'error_code': 'INTERNAL_ERROR'
            }
    
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
            return {}
    
    @staticmethod
    def get_overdue_books_with_details(page: int = 1, limit: int = 10, sort_by: str = 'days_overdue', order: str = 'desc') -> List[Dict[str, Any]]:
        """
        Get overdue books with detailed information for dashboard
        
        Args:
            page: Page number for pagination
            limit: Number of items per page
            sort_by: Field to sort by ('days_overdue', 'user_name', 'book_title', 'due_date')
            order: Sort order ('asc', 'desc')
            
        Returns:
            List of dictionaries containing overdue book information
        """
        try:
            repos = get_repositories()
            
            # Get all overdue borrow records
            overdue_borrows = repos['borrow'].get_overdue()
            
            # Calculate days overdue for each record
            current_date = datetime.now()
            overdue_books_with_details = []
            
            for borrow in overdue_borrows:
                # Calculate days overdue
                if borrow.due_date:
                    days_overdue = (current_date - borrow.due_date).days
                else:
                    days_overdue = 0
                
                # Get book details
                book = repos['book'].get_by_id(borrow.book_id)
                
                # Get user details
                user = repos['user'].get_by_id(borrow.user_id)
                
                overdue_books_with_details.append({
                    'borrow_id': borrow.borrow_id,
                    'book_id': borrow.book_id,
                    'book_title': book.title if book else 'Unknown Book',
                    'book_author': book.author if book else 'Unknown Author',
                    'user_id': borrow.user_id,
                    'user_name': user.full_name if user else 'Unknown User',
                    'due_date': borrow.due_date.isoformat() if borrow.due_date else None,
                    'days_overdue': days_overdue,
                    'borrow_date': borrow.borrow_date.isoformat() if borrow.borrow_date else None
                })
            
            # Sort the results
            if sort_by == 'days_overdue':
                overdue_books_with_details.sort(key=lambda x: x['days_overdue'], reverse=(order == 'desc'))
            elif sort_by == 'user_name':
                overdue_books_with_details.sort(key=lambda x: x['user_name'], reverse=(order == 'desc'))
            elif sort_by == 'book_title':
                overdue_books_with_details.sort(key=lambda x: x['book_title'], reverse=(order == 'desc'))
            elif sort_by == 'due_date':
                overdue_books_with_details.sort(key=lambda x: x['due_date'], reverse=(order == 'desc'))
            else:
                # Default sort by days overdue
                overdue_books_with_details.sort(key=lambda x: x['days_overdue'], reverse=(order == 'desc'))
            
            # Apply pagination
            start_index = (page - 1) * limit
            end_index = start_index + limit
            paginated_results = overdue_books_with_details[start_index:end_index]
            
            return paginated_results
            
        except Exception as e:
            logger.error(f"Get overdue books with details error: {str(e)}")
            return []