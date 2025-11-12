"""
Repository factory for the Library Management System
Provides lazy initialization of repository instances to avoid circular imports
"""

def get_repositories():
    """Get repository instances, initializing them if needed"""
    from .repository import (
        UserRepository, BookRepository, BorrowRepository, FineRepository,
        ViewLogRepository, LoginAttemptRepository, LibraryStatsRepository
    )
    
    return {
        'user': UserRepository(),
        'book': BookRepository(),
        'borrow': BorrowRepository(),
        'fine': FineRepository(),
        'view_log': ViewLogRepository(),
        'login_attempt': LoginAttemptRepository(),
        'library_stats': LibraryStatsRepository()
    }