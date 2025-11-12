"""
Database repository layer for the Library Management System
Provides ORM-like patterns for data access operations
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import logging
from .database import get_connection

logger = logging.getLogger(__name__)


class BaseRepository:
    """Base repository class with common database operations"""
    
    def __init__(self):
        self.connection = None
    
    def _get_connection(self):
        """Get database connection"""
        return get_connection()
    
    def _execute_query(self, query: str, params: tuple = None, fetch_one: bool = False, fetch_all: bool = True):
        """Execute a database query and return results"""
        conn = self._get_connection()
        if not conn:
            logger.error("Failed to get database connection")
            return None
        
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute(query, params or ())
            
            if fetch_one:
                result = cursor.fetchone()
            elif fetch_all:
                result = cursor.fetchall()
            else:
                result = cursor.lastrowid
            
            if not fetch_one and not fetch_all:
                conn.commit()
            
            cursor.close()
            conn.close()
            return result
        except Exception as e:
            logger.error(f"Database query error: {str(e)}")
            if conn:
                conn.close()
            raise


class UserRepository(BaseRepository):
    """Repository for User operations"""
    
    def create(self, user: User) -> Optional[int]:
        """Create a new user"""
        user.hash_password(user.password)
        query = """
            INSERT INTO users (full_name, email, password, role, status)
            VALUES (%s, %s, %s, %s, %s)
        """
        return self._execute_query(
            query, 
            (user.full_name, user.email, user.password, user.role, user.status),
            fetch_one=False, fetch_all=False
        )
    
    def get_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        query = "SELECT * FROM users WHERE user_id = %s"
        result = self._execute_query(query, (user_id,), fetch_one=True)
        return User.from_dict(result) if result else None
    
    def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        query = "SELECT * FROM users WHERE email = %s"
        result = self._execute_query(query, (email,), fetch_one=True)
        return User.from_dict(result) if result else None
    
    def get_all(self) -> List[User]:
        """Get all users"""
        query = "SELECT * FROM users ORDER BY date_joined DESC"
        results = self._execute_query(query)
        return [User.from_dict(result) for result in results] if results else []
    
    def update(self, user: User) -> bool:
        """Update user"""
        query = """
            UPDATE users 
            SET full_name = %s, email = %s, role = %s, status = %s
            WHERE user_id = %s
        """
        try:
            self._execute_query(
                query, 
                (user.full_name, user.email, user.role, user.status, user.user_id),
                fetch_one=False, fetch_all=False
            )
            return True
        except Exception:
            return False
    
    def update_password(self, user_id: int, new_password: str) -> bool:
        """Update user password"""
        user = User()
        user.hash_password(new_password)
        query = "UPDATE users SET password = %s WHERE user_id = %s"
        try:
            self._execute_query(query, (user.password, user_id), fetch_one=False, fetch_all=False)
            return True
        except Exception:
            return False
    
    def delete(self, user_id: int) -> bool:
        """Delete user"""
        query = "DELETE FROM users WHERE user_id = %s"
        try:
            self._execute_query(query, (user_id,), fetch_one=False, fetch_all=False)
            return True
        except Exception:
            return False
    
    def suspend(self, user_id: int) -> bool:
        """Suspend user"""
        query = "UPDATE users SET status = 'inactive' WHERE user_id = %s"
        try:
            self._execute_query(query, (user_id,), fetch_one=False, fetch_all=False)
            return True
        except Exception:
            return False
    
    def activate(self, user_id: int) -> bool:
        """Activate user"""
        query = "UPDATE users SET status = 'active' WHERE user_id = %s"
        try:
            self._execute_query(query, (user_id,), fetch_one=False, fetch_all=False)
            return True
        except Exception:
            return False


class BookRepository(BaseRepository):
    """Repository for Book operations"""
    
    def create(self, book: Book) -> Optional[int]:
        """Create a new book"""
        query = """
            INSERT INTO books (title, author, category, isbn, publisher, year_published, quantity_total, quantity_available)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        return self._execute_query(
            query,
            (book.title, book.author, book.category, book.isbn, book.publisher, 
             book.year_published, book.quantity_total, book.quantity_available),
            fetch_one=False, fetch_all=False
        )
    
    def get_by_id(self, book_id: int) -> Optional[Book]:
        """Get book by ID"""
        query = "SELECT * FROM books WHERE book_id = %s"
        result = self._execute_query(query, (book_id,), fetch_one=True)
        return Book.from_dict(result) if result else None
    
    def get_all(self) -> List[Book]:
        """Get all books"""
        query = "SELECT * FROM books"
        results = self._execute_query(query)
        return [Book.from_dict(result) for result in results] if results else []
    
    def filter(self, title=None, author=None, category=None, isbn=None, year=None) -> List[Book]:
        """Filter books by various criteria"""
        query = "SELECT * FROM books WHERE 1=1"
        params = []
        
        if title:
            query += " AND title LIKE %s"
            params.append(f"%{title}%")
        if author:
            query += " AND author LIKE %s"
            params.append(f"%{author}%")
        if category:
            query += " AND category LIKE %s"
            params.append(f"%{category}%")
        if isbn:
            query += " AND isbn LIKE %s"
            params.append(f"%{isbn}%")
        if year:
            query += " AND year_published = %s"
            params.append(year)
        
        results = self._execute_query(query, tuple(params))
        return [Book.from_dict(result) for result in results] if results else []
    
    def update(self, book: Book) -> bool:
        """Update book"""
        query = """
            UPDATE books 
            SET title = %s, author = %s, category = %s, isbn = %s, publisher = %s, 
                year_published = %s, quantity_total = %s, quantity_available = %s
            WHERE book_id = %s
        """
        try:
            self._execute_query(
                query,
                (book.title, book.author, book.category, book.isbn, book.publisher,
                 book.year_published, book.quantity_total, book.quantity_available, book.book_id),
                fetch_one=False, fetch_all=False
            )
            return True
        except Exception:
            return False
    
    def delete(self, book_id: int) -> bool:
        """Delete book"""
        query = "DELETE FROM books WHERE book_id = %s"
        try:
            self._execute_query(query, (book_id,), fetch_one=False, fetch_all=False)
            return True
        except Exception:
            return False
    
    def adjust_quantity(self, book_id: int, total_change: int = 0, available_change: int = 0) -> bool:
        """Adjust book quantity"""
        query = """
            UPDATE books
            SET quantity_total = quantity_total + %s,
                quantity_available = quantity_available + %s
            WHERE book_id = %s
        """
        try:
            self._execute_query(query, (total_change, available_change, book_id), fetch_one=False, fetch_all=False)
            return True
        except Exception:
            return False


class BorrowRepository(BaseRepository):
    """Repository for BorrowRecord operations"""
    
    def create(self, borrow: BorrowRecord) -> Optional[int]:
        """Create a new borrow record"""
        query = """
            INSERT INTO borrow_records (user_id, book_id, due_date)
            VALUES (%s, %s, %s)
        """
        return self._execute_query(
            query,
            (borrow.user_id, borrow.book_id, borrow.due_date),
            fetch_one=False, fetch_all=False
        )
    
    def get_by_id(self, borrow_id: int) -> Optional[BorrowRecord]:
        """Get borrow record by ID"""
        query = "SELECT * FROM borrow_records WHERE borrow_id = %s"
        result = self._execute_query(query, (borrow_id,), fetch_one=True)
        return BorrowRecord.from_dict(result) if result else None
    
    def get_active_by_user(self, user_id: int) -> List[BorrowRecord]:
        """Get active borrows for a user"""
        query = """
            SELECT br.*, b.title, b.author
            FROM borrow_records br
            JOIN books b ON br.book_id = b.book_id
            WHERE br.user_id = %s AND br.status = 'borrowed'
            ORDER BY br.borrow_date DESC
        """
        results = self._execute_query(query, (user_id,))
        return [BorrowRecord.from_dict(result) for result in results] if results else []
    
    def get_overdue(self) -> List[BorrowRecord]:
        """Get overdue borrow records"""
        query = """
            SELECT br.*, u.full_name, b.title
            FROM borrow_records br
            JOIN users u ON br.user_id = u.user_id
            JOIN books b ON br.book_id = b.book_id
            WHERE br.status = 'borrowed' AND br.due_date < NOW()
        """
        results = self._execute_query(query)
        return [BorrowRecord.from_dict(result) for result in results] if results else []
    
    def get_all(self, status: Optional[str] = None) -> List[BorrowRecord]:
        """Get all borrow records, optionally filtered by status"""
        query = """
            SELECT br.*, u.full_name AS user_name, u.email, b.title AS book_title, b.author
            FROM borrow_records br
            JOIN users u ON br.user_id = u.user_id
            JOIN books b ON br.book_id = b.book_id
        """
        params = ()
        
        if status:
            query += " WHERE br.status = %s"
            params = (status,)
        
        query += " ORDER BY br.borrow_date DESC"
        
        results = self._execute_query(query, params)
        return [BorrowRecord.from_dict(result) for result in results] if results else []
    
    def return_book(self, borrow_id: int) -> bool:
        """Return a borrowed book"""
        query = """
            UPDATE borrow_records
            SET status = 'returned', return_date = NOW()
            WHERE borrow_id = %s
        """
        try:
            self._execute_query(query, (borrow_id,), fetch_one=False, fetch_all=False)
            return True
        except Exception:
            return False
    
    def check_existing_borrow(self, user_id: int, book_id: int) -> bool:
        """Check if user already has an active borrow for this book"""
        query = """
            SELECT COUNT(*) FROM borrow_records
            WHERE user_id = %s AND book_id = %s AND status = 'borrowed'
        """
        result = self._execute_query(query, (user_id, book_id), fetch_one=True)
        return result['COUNT(*)'] > 0 if result else False
    
    def extend_due_date(self, borrow_id: int, new_due_date: datetime) -> bool:
        """Extend due date for a borrow record"""
        query = """
            UPDATE borrow_records
            SET due_date = %s
            WHERE borrow_id = %s
        """
        try:
            self._execute_query(query, (new_due_date, borrow_id), fetch_one=False, fetch_all=False)
            return True
        except Exception:
            return False


class FineRepository(BaseRepository):
    """Repository for Fine operations"""
    
    def create(self, fine: Fine) -> Optional[int]:
        """Create a new fine"""
        query = """
            INSERT INTO fines (borrow_id, amount, paid_status)
            VALUES (%s, %s, %s)
        """
        return self._execute_query(
            query,
            (fine.borrow_id, fine.amount, fine.paid_status),
            fetch_one=False, fetch_all=False
        )
    
    def get_by_id(self, fine_id: int) -> Optional[Fine]:
        """Get fine by ID"""
        query = "SELECT * FROM fines WHERE fine_id = %s"
        result = self._execute_query(query, (fine_id,), fetch_one=True)
        return Fine.from_dict(result) if result else None
    
    def get_by_user(self, user_id: int) -> List[Fine]:
        """Get fines for a user"""
        query = """
            SELECT f.*, b.title
            FROM fines f
            JOIN borrow_records br ON f.borrow_id = br.borrow_id
            JOIN books b ON br.book_id = b.book_id
            WHERE br.user_id = %s
            ORDER BY f.paid_status, f.payment_date DESC
        """
        results = self._execute_query(query, (user_id,))
        return [Fine.from_dict(result) for result in results] if results else []
    
    def get_all(self, paid_status: Optional[str] = None) -> List[Fine]:
        """Get all fines, optionally filtered by paid status"""
        query = """
            SELECT f.*, u.full_name AS user_name, b.title AS book_title, br.borrow_id
            FROM fines f
            JOIN borrow_records br ON f.borrow_id = br.borrow_id
            JOIN users u ON br.user_id = u.user_id
            JOIN books b ON br.book_id = b.book_id
        """
        params = ()
        
        if paid_status:
            query += " WHERE f.paid_status = %s"
            params = (paid_status,)
        
        query += " ORDER BY f.payment_date DESC, f.paid_status ASC"
        
        results = self._execute_query(query, params)
        return [Fine.from_dict(result) for result in results] if results else []
    
    def mark_as_paid(self, fine_id: int) -> bool:
        """Mark fine as paid"""
        query = """
            UPDATE fines
            SET paid_status = 'paid', payment_date = NOW()
            WHERE fine_id = %s
        """
        try:
            self._execute_query(query, (fine_id,), fetch_one=False, fetch_all=False)
            return True
        except Exception:
            return False
    
    def waive_fine(self, fine_id: int) -> bool:
        """Waive a fine"""
        query = """
            UPDATE fines
            SET paid_status = 'waived', payment_date = NOW()
            WHERE fine_id = %s
        """
        try:
            self._execute_query(query, (fine_id,), fetch_one=False, fetch_all=False)
            return True
        except Exception:
            return False
    
    def update_amount(self, fine_id: int, amount: float) -> bool:
        """Update fine amount"""
        query = """
            UPDATE fines
            SET amount = %s
            WHERE fine_id = %s AND paid_status = 'unpaid'
        """
        try:
            self._execute_query(query, (amount, fine_id), fetch_one=False, fetch_all=False)
            return True
        except Exception:
            return False
    
    def calculate_overdue_fines(self) -> int:
        """Calculate and create fines for overdue books"""
        query = """
            INSERT INTO fines (borrow_id, amount, paid_status)
            SELECT br.borrow_id,
                   DATEDIFF(NOW(), br.due_date) * 0.50 AS amount,
                   'unpaid' AS paid_status
            FROM borrow_records br
            LEFT JOIN fines f ON br.borrow_id = f.borrow_id
            WHERE br.status = 'borrowed'
              AND br.due_date < NOW()
              AND f.fine_id IS NULL
        """
        try:
            result = self._execute_query(query, fetch_one=False, fetch_all=False)
            return result if result else 0
        except Exception:
            return 0
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get fine statistics"""
        query = """
            SELECT
                COUNT(*) AS total_fines,
                SUM(CASE WHEN paid_status = 'paid' THEN 1 ELSE 0 END) AS paid_fines,
                SUM(CASE WHEN paid_status = 'unpaid' THEN 1 ELSE 0 END) AS unpaid_fines,
                SUM(CASE WHEN paid_status = 'waived' THEN 1 ELSE 0 END) AS waived_fines,
                SUM(CASE WHEN paid_status = 'paid' THEN amount ELSE 0 END) AS total_paid,
                SUM(CASE WHEN paid_status = 'unpaid' THEN amount ELSE 0 END) AS total_unpaid
            FROM fines
        """
        result = self._execute_query(query, fetch_one=True)
        return result if result else {}


class ViewLogRepository(BaseRepository):
    """Repository for ViewLog operations"""
    
    def create(self, view_log: ViewLog) -> Optional[int]:
        """Create a new view log entry"""
        query = """
            INSERT INTO view_log (user_id, book_id, view_date)
            VALUES (%s, %s, %s)
        """
        return self._execute_query(
            query,
            (view_log.user_id, view_log.book_id, view_log.view_date or datetime.now()),
            fetch_one=False, fetch_all=False
        )
    
    def get_user_history(self, user_id: int, limit: int = 10) -> List[ViewLog]:
        """Get user's view history"""
        query = """
            SELECT v.*, b.title, b.author, b.category
            FROM view_log v
            JOIN books b ON v.book_id = b.book_id
            WHERE v.user_id = %s
            ORDER BY v.view_date DESC
            LIMIT %s
        """
        results = self._execute_query(query, (user_id, limit))
        return [ViewLog.from_dict(result) for result in results] if results else []


class LoginAttemptRepository(BaseRepository):
    """Repository for LoginAttempt operations"""
    
    def create(self, attempt: LoginAttempt) -> Optional[int]:
        """Create a new login attempt record"""
        query = """
            INSERT INTO login_attempts (user_id, email, success, ip_address, user_agent, attempt_time)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        return self._execute_query(
            query,
            (attempt.user_id, attempt.email, attempt.success, attempt.ip_address, 
             attempt.user_agent, attempt.attempt_time or datetime.now()),
            fetch_one=False, fetch_all=False
        )
    
    def get_failed_attempts(self, email: str, window_minutes: int = 15) -> int:
        """Get count of failed login attempts within time window"""
        query = """
            SELECT COUNT(*) FROM login_attempts 
            WHERE email = %s AND success = 0 
            AND attempt_time > DATE_SUB(NOW(), INTERVAL %s MINUTE)
        """
        result = self._execute_query(query, (email, window_minutes), fetch_one=True)
        return result['COUNT(*)'] if result else 0


class LibraryStatsRepository(BaseRepository):
    """Repository for Library statistics"""
    
    def get_stats(self) -> Optional[LibraryStats]:
        """Get library statistics"""
        query = """
            SELECT
                (SELECT COUNT(*) FROM users WHERE status='active') AS active_users,
                (SELECT COUNT(*) FROM books) AS total_books,
                (SELECT COUNT(*) FROM borrow_records WHERE status='borrowed') AS active_borrows,
                (SELECT COUNT(*) FROM fines WHERE paid_status='unpaid') AS unpaid_fines
        """
        result = self._execute_query(query, fetch_one=True)
        return LibraryStats.from_dict(result) if result else None


# Repository instances for easy access - initialized lazily
user_repository = None
book_repository = None
borrow_repository = None
fine_repository = None
view_log_repository = None
login_attempt_repository = None
library_stats_repository = None

def get_repositories():
    """Get repository instances, initializing them if needed"""
    global user_repository, book_repository, borrow_repository, fine_repository
    global view_log_repository, login_attempt_repository, library_stats_repository
    
    if user_repository is None:
        from .models import User, Book, BorrowRecord, Fine, ViewLog, LoginAttempt, LibraryStats
        
        user_repository = UserRepository()
        book_repository = BookRepository()
        borrow_repository = BorrowRepository()
        fine_repository = FineRepository()
        view_log_repository = ViewLogRepository()
        login_attempt_repository = LoginAttemptRepository()
        library_stats_repository = LibraryStatsRepository()
    
    return {
        'user': user_repository,
        'book': book_repository,
        'borrow': borrow_repository,
        'fine': fine_repository,
        'view_log': view_log_repository,
        'login_attempt': login_attempt_repository,
        'library_stats': library_stats_repository
    }