"""
Database models for the Library Management System
Centralized model definitions based on database schema
"""

from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass
import bcrypt


@dataclass
class User:
    """User model representing the users table"""
    user_id: Optional[int] = None
    full_name: str = ""
    email: str = ""
    password: str = ""
    role: str = "student"
    status: str = "active"
    date_joined: Optional[datetime] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """Create User instance from dictionary"""
        return cls(
            user_id=data.get('user_id'),
            full_name=data.get('full_name', ''),
            email=data.get('email', ''),
            password=data.get('password', ''),
            role=data.get('role', 'student'),
            status=data.get('status', 'active'),
            date_joined=data.get('date_joined')
        )
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert User to dictionary"""
        data = {
            'user_id': self.user_id,
            'full_name': self.full_name,
            'email': self.email,
            'role': self.role,
            'status': self.status,
            'date_joined': self.date_joined.isoformat() if self.date_joined else None
        }
        if include_sensitive:
            data['password'] = self.password
        return data
    
    def hash_password(self, password: str) -> None:
        """Hash and set the password"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        self.password = hashed.decode("utf-8")
    
    def verify_password(self, password: str) -> bool:
        """Verify password against stored hash"""
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                self.password.encode('utf-8')
            )
        except Exception:
            return False


@dataclass
class Book:
    """Book model representing the books table"""
    book_id: Optional[int] = None
    title: str = ""
    author: str = ""
    category: Optional[str] = None
    isbn: Optional[str] = None
    publisher: Optional[str] = None
    year_published: Optional[int] = None
    quantity_total: int = 1
    quantity_available: int = 1
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Book':
        """Create Book instance from dictionary"""
        return cls(
            book_id=data.get('book_id'),
            title=data.get('title', ''),
            author=data.get('author', ''),
            category=data.get('category'),
            isbn=data.get('isbn'),
            publisher=data.get('publisher'),
            year_published=data.get('year_published'),
            quantity_total=data.get('quantity_total', 1),
            quantity_available=data.get('quantity_available', 1)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert Book to dictionary"""
        return {
            'book_id': self.book_id,
            'title': self.title,
            'author': self.author,
            'category': self.category,
            'isbn': self.isbn,
            'publisher': self.publisher,
            'year_published': self.year_published,
            'quantity_total': self.quantity_total,
            'quantity_available': self.quantity_available
        }


@dataclass
class BorrowRecord:
    """BorrowRecord model representing the borrow_records table"""
    borrow_id: Optional[int] = None
    user_id: Optional[int] = None
    book_id: Optional[int] = None
    borrow_date: Optional[datetime] = None
    due_date: Optional[datetime] = None
    return_date: Optional[datetime] = None
    status: str = "borrowed"
    
    # Additional fields for joins
    user_name: Optional[str] = None
    user_email: Optional[str] = None
    book_title: Optional[str] = None
    book_author: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BorrowRecord':
        """Create BorrowRecord instance from dictionary"""
        return cls(
            borrow_id=data.get('borrow_id'),
            user_id=data.get('user_id'),
            book_id=data.get('book_id'),
            borrow_date=data.get('borrow_date'),
            due_date=data.get('due_date'),
            return_date=data.get('return_date'),
            status=data.get('status', 'borrowed'),
            user_name=data.get('user_name'),
            user_email=data.get('user_email'),
            book_title=data.get('book_title'),
            book_author=data.get('book_author')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert BorrowRecord to dictionary"""
        data = {
            'borrow_id': self.borrow_id,
            'user_id': self.user_id,
            'book_id': self.book_id,
            'borrow_date': self.borrow_date.isoformat() if self.borrow_date else None,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'return_date': self.return_date.isoformat() if self.return_date else None,
            'status': self.status
        }
        
        # Include join fields if present
        if self.user_name:
            data['user_name'] = self.user_name
        if self.user_email:
            data['user_email'] = self.user_email
        if self.book_title:
            data['book_title'] = self.book_title
        if self.book_author:
            data['book_author'] = self.book_author
            
        return data


@dataclass
class Fine:
    """Fine model representing the fines table"""
    fine_id: Optional[int] = None
    borrow_id: Optional[int] = None
    amount: Optional[float] = None
    paid_status: str = "unpaid"
    payment_date: Optional[datetime] = None
    
    # Additional fields for joins
    user_name: Optional[str] = None
    book_title: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Fine':
        """Create Fine instance from dictionary"""
        return cls(
            fine_id=data.get('fine_id'),
            borrow_id=data.get('borrow_id'),
            amount=data.get('amount'),
            paid_status=data.get('paid_status', 'unpaid'),
            payment_date=data.get('payment_date'),
            user_name=data.get('user_name'),
            book_title=data.get('book_title')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert Fine to dictionary"""
        data = {
            'fine_id': self.fine_id,
            'borrow_id': self.borrow_id,
            'amount': self.amount,
            'paid_status': self.paid_status,
            'payment_date': self.payment_date.isoformat() if self.payment_date else None
        }
        
        # Include join fields if present
        if self.user_name:
            data['user_name'] = self.user_name
        if self.book_title:
            data['book_title'] = self.book_title
            
        return data


@dataclass
class ViewLog:
    """ViewLog model representing the view_log table"""
    view_id: Optional[int] = None
    user_id: Optional[int] = None
    book_id: Optional[int] = None
    view_date: Optional[datetime] = None
    
    # Additional fields for joins
    book_title: Optional[str] = None
    book_author: Optional[str] = None
    book_category: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ViewLog':
        """Create ViewLog instance from dictionary"""
        return cls(
            view_id=data.get('view_id'),
            user_id=data.get('user_id'),
            book_id=data.get('book_id'),
            view_date=data.get('view_date'),
            book_title=data.get('book_title'),
            book_author=data.get('book_author'),
            book_category=data.get('book_category')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert ViewLog to dictionary"""
        data = {
            'view_id': self.view_id,
            'user_id': self.user_id,
            'book_id': self.book_id,
            'view_date': self.view_date.isoformat() if self.view_date else None
        }
        
        # Include join fields if present
        if self.book_title:
            data['book_title'] = self.book_title
        if self.book_author:
            data['book_author'] = self.book_author
        if self.book_category:
            data['book_category'] = self.book_category
            
        return data


@dataclass
class LoginAttempt:
    """LoginAttempt model representing the login_attempts table"""
    attempt_id: Optional[int] = None
    user_id: Optional[int] = None
    email: str = ""
    success: bool = False
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    attempt_time: Optional[datetime] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LoginAttempt':
        """Create LoginAttempt instance from dictionary"""
        return cls(
            attempt_id=data.get('attempt_id'),
            user_id=data.get('user_id'),
            email=data.get('email', ''),
            success=bool(data.get('success', False)),
            ip_address=data.get('ip_address'),
            user_agent=data.get('user_agent'),
            attempt_time=data.get('attempt_time')
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert LoginAttempt to dictionary"""
        return {
            'attempt_id': self.attempt_id,
            'user_id': self.user_id,
            'email': self.email,
            'success': self.success,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'attempt_time': self.attempt_time.isoformat() if self.attempt_time else None
        }


@dataclass
class LibraryStats:
    """Library statistics model"""
    active_users: int = 0
    total_books: int = 0
    active_borrows: int = 0
    unpaid_fines: int = 0
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LibraryStats':
        """Create LibraryStats instance from dictionary"""
        return cls(
            active_users=data.get('active_users', 0),
            total_books=data.get('total_books', 0),
            active_borrows=data.get('active_borrows', 0),
            unpaid_fines=data.get('unpaid_fines', 0)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert LibraryStats to dictionary"""
        return {
            'active_users': self.active_users,
            'total_books': self.total_books,
            'active_borrows': self.active_borrows,
            'unpaid_fines': self.unpaid_fines
        }