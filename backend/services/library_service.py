"""
Library service for Library Management System
Handles overall library statistics and operations
"""

import logging
from typing import Dict, Any

from db.repositories import get_repositories

logger = logging.getLogger(__name__)

class LibraryService:
    """Service class for handling library-wide operations"""
    
    @staticmethod
    def get_library_statistics() -> Dict[str, Any]:
        """
        Get comprehensive library statistics
        
        Returns:
            Dict containing library statistics
        """
        try:
            # Get basic stats from repository
            repos = get_repositories()
            stats = repos['library_stats'].get_stats()
            
            if not stats:
                logger.error("Failed to get library statistics")
                return LibraryService._get_empty_stats()
            
            # Get additional statistics
            user_stats = LibraryService._get_user_statistics()
            book_stats = LibraryService._get_book_statistics()
            borrow_stats = LibraryService._get_borrow_statistics()
            fine_stats = LibraryService._get_fine_statistics()
            
            # Combine all statistics
            combined_stats = {
                # Basic stats
                'active_users': stats.active_users,
                'total_books': stats.total_books,
                'active_borrows': stats.active_borrows,
                'unpaid_fines': stats.unpaid_fines,
                
                # Detailed stats
                'users': user_stats,
                'books': book_stats,
                'borrows': borrow_stats,
                'fines': fine_stats
            }
            
            return combined_stats
        except Exception as e:
            logger.error(f"Get library statistics error: {str(e)}")
            return LibraryService._get_empty_stats()
    
    @staticmethod
    def _get_empty_stats() -> Dict[str, Any]:
        """Get empty statistics structure"""
        return {
            'active_users': 0,
            'total_books': 0,
            'active_borrows': 0,
            'unpaid_fines': 0,
            'users': {
                'total_users': 0,
                'active_users': 0,
                'inactive_users': 0,
                'students': 0,
                'librarians': 0,
                'admins': 0
            },
            'books': {
                'total_books': 0,
                'available_books': 0,
                'borrowed_books': 0,
                'total_copies': 0,
                'available_copies': 0
            },
            'borrows': {
                'total_borrows': 0,
                'active_borrows': 0,
                'returned_borrows': 0,
                'overdue_borrows': 0
            },
            'fines': {
                'total_fines': 0,
                'paid_fines': 0,
                'unpaid_fines': 0,
                'total_amount': 0.0,
                'paid_amount': 0.0,
                'unpaid_amount': 0.0
            }
        }
    
    @staticmethod
    def _get_user_statistics() -> Dict[str, Any]:
        """Get user statistics"""
        try:
            repos = get_repositories()
            all_users = repos['user'].get_all()
            
            total_users = len(all_users)
            active_users = len([u for u in all_users if u.status == 'active'])
            inactive_users = len([u for u in all_users if u.status == 'inactive'])
            students = len([u for u in all_users if u.role == 'student'])
            librarians = len([u for u in all_users if u.role == 'librarian'])
            admins = len([u for u in all_users if u.role == 'admin'])
            
            return {
                'total_users': total_users,
                'active_users': active_users,
                'inactive_users': inactive_users,
                'students': students,
                'librarians': librarians,
                'admins': admins
            }
        except Exception as e:
            logger.error(f"Get user statistics error: {str(e)}")
            return {
                'total_users': 0,
                'active_users': 0,
                'inactive_users': 0,
                'students': 0,
                'librarians': 0,
                'admins': 0
            }
    
    @staticmethod
    def _get_book_statistics() -> Dict[str, Any]:
        """Get book statistics"""
        try:
            repos = get_repositories()
            all_books = repos['book'].get_all()
            
            total_books = len(all_books)
            total_copies = sum(book.quantity_total for book in all_books)
            available_copies = sum(book.quantity_available for book in all_books)
            borrowed_copies = total_copies - available_copies
            
            return {
                'total_books': total_books,
                'available_books': len([b for b in all_books if b.quantity_available > 0]),
                'borrowed_books': len([b for b in all_books if b.quantity_available < b.quantity_total]),
                'total_copies': total_copies,
                'available_copies': available_copies
            }
        except Exception as e:
            logger.error(f"Get book statistics error: {str(e)}")
            return {
                'total_books': 0,
                'available_books': 0,
                'borrowed_books': 0,
                'total_copies': 0,
                'available_copies': 0
            }
    
    @staticmethod
    def _get_borrow_statistics() -> Dict[str, Any]:
        """Get borrow statistics"""
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
    
    @staticmethod
    def _get_fine_statistics() -> Dict[str, Any]:
        """Get fine statistics"""
        try:
            repos = get_repositories()
            all_fines = repos['fine'].get_all()
            unpaid_fines = repos['fine'].get_all('unpaid')
            paid_fines = repos['fine'].get_all('paid')
            
            total_fines = len(all_fines)
            unpaid_count = len(unpaid_fines)
            paid_count = len(paid_fines)
            
            # Calculate total amounts
            total_amount = sum(fine.amount for fine in all_fines if fine.amount)
            unpaid_amount = sum(fine.amount for fine in unpaid_fines if fine.amount)
            paid_amount = sum(fine.amount for fine in paid_fines if fine.amount)
            
            return {
                'total_fines': total_fines,
                'paid_fines': paid_count,
                'unpaid_fines': unpaid_count,
                'total_amount': total_amount,
                'paid_amount': paid_amount,
                'unpaid_amount': unpaid_amount
            }
        except Exception as e:
            logger.error(f"Get fine statistics error: {str(e)}")
            return {
                'total_fines': 0,
                'paid_fines': 0,
                'unpaid_fines': 0,
                'total_amount': 0.0,
                'paid_amount': 0.0,
                'unpaid_amount': 0.0
            }
    
    @staticmethod
    def get_dashboard_data() -> Dict[str, Any]:
        """
        Get dashboard data for admin view
        
        Returns:
            Dict containing dashboard data
        """
        try:
            # Get basic statistics
            stats = LibraryService.get_library_statistics()
            
            # Get recent activity
            recent_borrows = LibraryService._get_recent_borrows(5)
            recent_fines = LibraryService._get_recent_fines(5)
            overdue_books = LibraryService._get_overdue_books(5)
            
            # Combine dashboard data
            dashboard_data = {
                'statistics': stats,
                'recent_activity': {
                    'recent_borrows': recent_borrows,
                    'recent_fines': recent_fines,
                    'overdue_books': overdue_books
                }
            }
            
            return dashboard_data
        except Exception as e:
            logger.error(f"Get dashboard data error: {str(e)}")
            return {
                'statistics': LibraryService._get_empty_stats(),
                'recent_activity': {
                    'recent_borrows': [],
                    'recent_fines': [],
                    'overdue_books': []
                }
            }
    
    @staticmethod
    def _get_recent_borrows(limit: int = 5) -> list:
        """Get recent borrow records"""
        try:
            repos = get_repositories()
            all_borrows = repos['borrow'].get_all()
            # Sort by borrow date (newest first) and limit
            recent_borrows = sorted(all_borrows, key=lambda x: x.borrow_date or '', reverse=True)[:limit]
            return [borrow.to_dict() for borrow in recent_borrows]
        except Exception as e:
            logger.error(f"Get recent borrows error: {str(e)}")
            return []
    
    @staticmethod
    def _get_recent_fines(limit: int = 5) -> list:
        """Get recent fine records"""
        try:
            repos = get_repositories()
            all_fines = repos['fine'].get_all()
            # Sort by payment date (newest first) and limit
            recent_fines = sorted(all_fines, key=lambda x: x.payment_date or '', reverse=True)[:limit]
            return [fine.to_dict() for fine in recent_fines]
        except Exception as e:
            logger.error(f"Get recent fines error: {str(e)}")
            return []
    
    @staticmethod
    def _get_overdue_books(limit: int = 5) -> list:
        """Get overdue books"""
        try:
            repos = get_repositories()
            overdue_borrows = repos['borrow'].get_overdue()
            # Limit results
            overdue_books = overdue_borrows[:limit]
            return [borrow.to_dict() for borrow in overdue_books]
        except Exception as e:
            logger.error(f"Get overdue books error: {str(e)}")
            return []
    
    @staticmethod
    def get_system_health() -> Dict[str, Any]:
        """
        Get system health status
        
        Returns:
            Dict containing system health information
        """
        try:
            # Check database connectivity
            from db.database import get_connection
            db_connection = get_connection(silent=True)
            db_status = "connected" if db_connection else "disconnected"
            if db_connection:
                db_connection.close()
            
            # Get basic stats
            stats = LibraryService.get_library_statistics()
            
            # Determine overall health
            health_status = "healthy"
            if db_status != "connected":
                health_status = "unhealthy"
            elif stats.get('active_users', 0) == 0:
                health_status = "warning"
            
            return {
                'status': health_status,
                'database': db_status,
                'timestamp': str(datetime.now()),
                'statistics': stats
            }
        except Exception as e:
            logger.error(f"Get system health error: {str(e)}")
            return {
                'status': 'unhealthy',
                'database': 'error',
                'timestamp': str(datetime.now()),
                'error': str(e)
            }