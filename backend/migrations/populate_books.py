#!/usr/bin/env python3
"""
Comprehensive Database Migration Script for Library Management System
Populates the database with 20 diverse book entries with complete bibliographic data
"""

import sys
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
import mysql.connector
from mysql.connector import Error
from pathlib import Path
import os

# Add the backend directory to Python path for imports
sys.path.append(str(Path(__file__).parent.parent))

from db.database import get_connection, create_database_if_missing
from db.models import Book

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('book_migration.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class BookMigration:
    """Comprehensive book migration class with transaction management and error handling"""
    
    def __init__(self):
        self.connection = None
        self.books_data = self._prepare_diverse_books_data()
        
    def _prepare_diverse_books_data(self) -> List[Dict[str, Any]]:
        """Prepare 20 diverse book entries across various genres"""
        return [
            {
                'title': 'To Kill a Mockingbird',
                'author': 'Harper Lee',
                'category': 'Fiction',
                'isbn': '978-0-06-112008-4',
                'publisher': 'J.B. Lippincott & Co.',
                'year_published': 1960,
                'quantity_total': 3,
                'quantity_available': 3,
                'description': 'A gripping tale of racial injustice and childhood innocence in the American South.',
                'language': 'English',
                'page_count': 324,
                'shelf_location': 'A1-101',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9780061120084-L.jpg'
            },
            {
                'title': '1984',
                'author': 'George Orwell',
                'category': 'Science Fiction',
                'isbn': '978-0-452-28423-4',
                'publisher': 'Secker & Warburg',
                'year_published': 1949,
                'quantity_total': 2,
                'quantity_available': 2,
                'description': 'A dystopian social science fiction novel and cautionary tale about totalitarianism.',
                'language': 'English',
                'page_count': 328,
                'shelf_location': 'B2-205',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9780452284234-L.jpg'
            },
            {
                'title': 'Sapiens: A Brief History of Humankind',
                'author': 'Yuval Noah Harari',
                'category': 'Non-Fiction',
                'isbn': '978-0-06-231609-7',
                'publisher': 'Harper',
                'year_published': 2011,
                'quantity_total': 4,
                'quantity_available': 4,
                'description': 'An exploration of how Homo sapiens came to dominate the world.',
                'language': 'English',
                'page_count': 443,
                'shelf_location': 'C3-301',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9780062316097-L.jpg'
            },
            {
                'title': 'The Catcher in the Rye',
                'author': 'J.D. Salinger',
                'category': 'Fiction',
                'isbn': '978-0-316-76948-0',
                'publisher': 'Little, Brown and Company',
                'year_published': 1951,
                'quantity_total': 2,
                'quantity_available': 2,
                'description': 'The story of teenage rebellion and angst narrated by Holden Caulfield.',
                'language': 'English',
                'page_count': 234,
                'shelf_location': 'A1-102',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9780316769480-L.jpg'
            },
            {
                'title': 'A Brief History of Time',
                'author': 'Stephen Hawking',
                'category': 'Science',
                'isbn': '978-0-553-38016-3',
                'publisher': 'Bantam Books',
                'year_published': 1988,
                'quantity_total': 3,
                'quantity_available': 3,
                'description': 'A landmark volume in science writing about the universe and its origins.',
                'language': 'English',
                'page_count': 256,
                'shelf_location': 'D4-401',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9780553380163-L.jpg'
            },
            {
                'title': 'Pride and Prejudice',
                'author': 'Jane Austen',
                'category': 'Literature',
                'isbn': '978-0-14-143951-8',
                'publisher': 'T. Egerton',
                'year_published': 1813 if False else None,  # Handle old publications
                'quantity_total': 2,
                'quantity_available': 2,
                'description': 'A romantic novel of manners written by Jane Austen.',
                'language': 'English',
                'page_count': 432,
                'shelf_location': 'E5-501',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9780141439518-L.jpg'
            },
            {
                'title': 'The Diary of a Young Girl',
                'author': 'Anne Frank',
                'category': 'Biography',
                'isbn': '978-0-553-29698-3',
                'publisher': 'Contact Publishing',
                'year_published': 1947,
                'quantity_total': 3,
                'quantity_available': 3,
                'description': 'The diary of a Jewish teenage girl during the Holocaust.',
                'language': 'English',
                'page_count': 283,
                'shelf_location': 'F6-601',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9780553296983-L.jpg'
            },
            {
                'title': 'Clean Code: A Handbook of Agile Software Craftsmanship',
                'author': 'Robert C. Martin',
                'category': 'Technology',
                'isbn': '978-0-13-235088-4',
                'publisher': 'Prentice Hall',
                'year_published': 2008,
                'quantity_total': 5,
                'quantity_available': 5,
                'description': 'A handbook of agile software craftsmanship for writing clean, maintainable code.',
                'language': 'English',
                'page_count': 464,
                'shelf_location': 'G7-701',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9780132350884-L.jpg'
            },
            {
                'title': 'The Great Gatsby',
                'author': 'F. Scott Fitzgerald',
                'category': 'Fiction',
                'isbn': '978-0-7432-7356-5',
                'publisher': 'Charles Scribner\'s Sons',
                'year_published': 1925,
                'quantity_total': 2,
                'quantity_available': 2,
                'description': 'A story of the Jazz Age in the United States.',
                'language': 'English',
                'page_count': 180,
                'shelf_location': 'A1-103',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9780743273565-L.jpg'
            },
            {
                'title': 'Thinking, Fast and Slow',
                'author': 'Daniel Kahneman',
                'category': 'Non-Fiction',
                'isbn': '978-0-374-53355-7',
                'publisher': 'Farrar, Straus and Giroux',
                'year_published': 2011,
                'quantity_total': 3,
                'quantity_available': 3,
                'description': 'A tour of the mind that explains the two systems that drive the way we think.',
                'language': 'English',
                'page_count': 499,
                'shelf_location': 'C3-302',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9780374533557-L.jpg'
            },
            {
                'title': 'The Art of War',
                'author': 'Sun Tzu',
                'category': 'History',
                'isbn': '978-1-59030-225-5',
                'publisher': 'Various',
                'year_published': None,  # Use None for ancient texts
                'quantity_total': 2,
                'quantity_available': 2,
                'description': 'An ancient Chinese military treatise dating from the Late Spring and Autumn period.',
                'language': 'English',
                'page_count': 273,
                'shelf_location': 'H8-801',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9781590302255-L.jpg'
            },
            {
                'title': 'Steve Jobs',
                'author': 'Walter Isaacson',
                'category': 'Biography',
                'isbn': '978-1-4516-4853-9',
                'publisher': 'Simon & Schuster',
                'year_published': 2011,
                'quantity_total': 3,
                'quantity_available': 3,
                'description': 'The authorized biography of Steve Jobs, co-founder of Apple Inc.',
                'language': 'English',
                'page_count': 656,
                'shelf_location': 'F6-602',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9781451648539-L.jpg'
            },
            {
                'title': 'The Lean Startup',
                'author': 'Eric Ries',
                'category': 'Business',
                'isbn': '978-0-307-88789-4',
                'publisher': 'Crown Business',
                'year_published': 2011,
                'quantity_total': 4,
                'quantity_available': 4,
                'description': 'How today\'s entrepreneurs use continuous innovation to create radically successful businesses.',
                'language': 'English',
                'page_count': 336,
                'shelf_location': 'I9-901',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9780307887894-L.jpg'
            },
            {
                'title': 'The Hobbit',
                'author': 'J.R.R. Tolkien',
                'category': 'Fantasy',
                'isbn': '978-0-547-92822-7',
                'publisher': 'George Allen & Unwin',
                'year_published': 1937,
                'quantity_total': 3,
                'quantity_available': 3,
                'description': 'A fantasy novel about the adventures of hobbit Bilbo Baggins.',
                'language': 'English',
                'page_count': 310,
                'shelf_location': 'J10-1001',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9780547928227-L.jpg'
            },
            {
                'title': 'Cosmos',
                'author': 'Carl Sagan',
                'category': 'Science',
                'isbn': '978-0-345-53943-4',
                'publisher': 'Random House',
                'year_published': 1980,
                'quantity_total': 2,
                'quantity_available': 2,
                'description': 'A journey through the universe and our place within it.',
                'language': 'English',
                'page_count': 365,
                'shelf_location': 'D4-402',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9780345539434-L.jpg'
            },
            {
                'title': 'The Alchemist',
                'author': 'Paulo Coelho',
                'category': 'Fiction',
                'isbn': '978-0-06-250217-4',
                'publisher': 'HarperCollins',
                'year_published': 1988,
                'quantity_total': 4,
                'quantity_available': 4,
                'description': 'A mystical story about Santiago, an Andalusian shepherd boy.',
                'language': 'English',
                'page_count': 208,
                'shelf_location': 'A1-104',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9780062502174-L.jpg'
            },
            {
                'title': 'Guns, Germs, and Steel',
                'author': 'Jared Diamond',
                'category': 'History',
                'isbn': '978-0-393-31755-8',
                'publisher': 'W. W. Norton & Company',
                'year_published': 1997,
                'quantity_total': 2,
                'quantity_available': 2,
                'description': 'A multidisciplinary study of why Eurasian civilizations have survived and conquered others.',
                'language': 'English',
                'page_count': 480,
                'shelf_location': 'H8-802',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9780393317558-L.jpg'
            },
            {
                'title': 'The Design of Everyday Things',
                'author': 'Don Norman',
                'category': 'Technology',
                'isbn': '978-0-465-05065-9',
                'publisher': 'Basic Books',
                'year_published': 1988,
                'quantity_total': 3,
                'quantity_available': 3,
                'description': 'A primer on how—and why—some products satisfy customers while others only frustrate them.',
                'language': 'English',
                'page_count': 257,
                'shelf_location': 'G7-702',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9780465050659-L.jpg'
            },
            {
                'title': 'Long Walk to Freedom',
                'author': 'Nelson Mandela',
                'category': 'Biography',
                'isbn': '978-0-316-54818-2',
                'publisher': 'Little, Brown and Company',
                'year_published': 1994,
                'quantity_total': 2,
                'quantity_available': 2,
                'description': 'The autobiography of Nelson Mandela, global icon of peace and reconciliation.',
                'language': 'English',
                'page_count': 630,
                'shelf_location': 'F6-603',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9780316548182-L.jpg'
            },
            {
                'title': 'The Silent Patient',
                'author': 'Alex Michaelides',
                'category': 'Mystery',
                'isbn': '978-1-250-30169-7',
                'publisher': 'Celadon Books',
                'year_published': 2019,
                'quantity_total': 3,
                'quantity_available': 3,
                'description': 'A psychological thriller about a woman who shoots her husband and then never speaks again.',
                'language': 'English',
                'page_count': 336,
                'shelf_location': 'K11-1101',
                'cover_image_url': 'https://covers.openlibrary.org/b/isbn/9781250301697-L.jpg'
            }
        ]
    
    def _validate_book_data(self, book_data: Dict[str, Any]) -> bool:
        """Validate book data before insertion"""
        required_fields = ['title', 'author', 'category', 'isbn']
        
        for field in required_fields:
            if not book_data.get(field):
                logger.error(f"Missing required field: {field}")
                return False
        
        # Validate ISBN format (basic check)
        isbn = book_data['isbn']
        if not isbn or len(isbn.replace('-', '')) < 10:
            logger.error(f"Invalid ISBN format: {isbn}")
            return False
        
        # Validate year_published
        year = book_data.get('year_published')
        if year and (year < 0 or year > datetime.now().year + 1):
            logger.error(f"Invalid publication year: {year}")
            return False
        
        # Validate quantities
        total = book_data.get('quantity_total', 1)
        available = book_data.get('quantity_available', 1)
        if total < 0 or available < 0 or available > total:
            logger.error(f"Invalid quantities: total={total}, available={available}")
            return False
        
        return True
    
    def _check_existing_book(self, isbn: str) -> Optional[Dict[str, Any]]:
        """Check if a book with the given ISBN already exists"""
        try:
            cursor = self.connection.cursor(dictionary=True)
            query = "SELECT * FROM books WHERE isbn = %s"
            cursor.execute(query, (isbn,))
            result = cursor.fetchone()
            cursor.close()
            return result
        except Error as e:
            logger.error(f"Error checking existing book: {e}")
            return None
    
    def _insert_book(self, book_data: Dict[str, Any]) -> Optional[int]:
        """Insert a single book record using parameterized query"""
        try:
            cursor = self.connection.cursor()
            
            # Prepare the query based on available columns in the schema
            query = """
                INSERT INTO books (
                    title, author, category, isbn, publisher, 
                    year_published, quantity_total, quantity_available
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            params = (
                book_data['title'],
                book_data['author'],
                book_data['category'],
                book_data['isbn'],
                book_data.get('publisher'),
                book_data.get('year_published'),
                book_data['quantity_total'],
                book_data['quantity_available']
            )
            
            cursor.execute(query, params)
            book_id = cursor.lastrowid
            cursor.close()
            
            logger.info(f"Successfully inserted book: {book_data['title']} (ID: {book_id})")
            return book_id
            
        except Error as e:
            logger.error(f"Error inserting book {book_data['title']}: {e}")
            return None
    
    def _create_additional_tables_if_needed(self):
        """Create additional tables for extended book information if they don't exist"""
        try:
            cursor = self.connection.cursor()
            
            # Create book_details table for additional information
            create_details_table = """
                CREATE TABLE IF NOT EXISTS book_details (
                    detail_id INT AUTO_INCREMENT PRIMARY KEY,
                    book_id INT UNIQUE,
                    description TEXT,
                    language VARCHAR(50) DEFAULT 'English',
                    page_count INT,
                    shelf_location VARCHAR(50),
                    cover_image_url VARCHAR(500),
                    date_added DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (book_id) REFERENCES books(book_id) ON DELETE CASCADE
                )
            """
            cursor.execute(create_details_table)
            
            # Create genres table for better categorization
            create_genres_table = """
                CREATE TABLE IF NOT EXISTS genres (
                    genre_id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) UNIQUE NOT NULL,
                    description TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """
            cursor.execute(create_genres_table)
            
            # Create publishers table
            create_publishers_table = """
                CREATE TABLE IF NOT EXISTS publishers (
                    publisher_id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(200) UNIQUE NOT NULL,
                    address TEXT,
                    contact_email VARCHAR(100),
                    website VARCHAR(200),
                    founded_year YEAR,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """
            cursor.execute(create_publishers_table)
            
            self.connection.commit()
            cursor.close()
            logger.info("Additional tables created or verified successfully")
            
        except Error as e:
            logger.error(f"Error creating additional tables: {e}")
            raise
    
    def _populate_reference_tables(self):
        """Populate genres and publishers reference tables"""
        try:
            cursor = self.connection.cursor()
            
            # Extract unique genres and publishers from books data
            genres = set()
            publishers = set()
            
            for book in self.books_data:
                if book.get('category'):
                    genres.add(book['category'])
                if book.get('publisher'):
                    publishers.add(book['publisher'])
            
            # Insert genres
            for genre in sorted(genres):
                cursor.execute("INSERT IGNORE INTO genres (name) VALUES (%s)", (genre,))
            
            # Insert publishers
            for publisher in sorted(publishers):
                cursor.execute("INSERT IGNORE INTO publishers (name) VALUES (%s)", (publisher,))
            
            self.connection.commit()
            cursor.close()
            logger.info(f"Populated {len(genres)} genres and {len(publishers)} publishers")
            
        except Error as e:
            logger.error(f"Error populating reference tables: {e}")
            raise
    
    def _insert_book_details(self, book_id: int, book_data: Dict[str, Any]):
        """Insert additional book details into the book_details table"""
        try:
            cursor = self.connection.cursor()
            
            query = """
                INSERT INTO book_details (
                    book_id, description, language, page_count, 
                    shelf_location, cover_image_url
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """
            
            params = (
                book_id,
                book_data.get('description'),
                book_data.get('language', 'English'),
                book_data.get('page_count'),
                book_data.get('shelf_location'),
                book_data.get('cover_image_url')
            )
            
            cursor.execute(query, params)
            cursor.close()
            
        except Error as e:
            logger.error(f"Error inserting book details for book ID {book_id}: {e}")
            # Don't raise here as this is supplementary data
    
    def migrate(self) -> Dict[str, Any]:
        """Execute the complete migration process with transaction management"""
        migration_stats = {
            'total_books': len(self.books_data),
            'successful_inserts': 0,
            'skipped_duplicates': 0,
            'failed_inserts': 0,
            'errors': [],
            'start_time': datetime.now(),
            'end_time': None
        }
        
        try:
            # Initialize database connection
            logger.info("Initializing database connection...")
            create_database_if_missing()
            self.connection = get_connection()
            
            if not self.connection:
                raise Exception("Failed to establish database connection")
            
            # Start transaction
            self.connection.start_transaction()
            logger.info("Transaction started")
            
            # Create additional tables if needed
            self._create_additional_tables_if_needed()
            
            # Populate reference tables
            self._populate_reference_tables()
            
            # Process each book
            for i, book_data in enumerate(self.books_data, 1):
                logger.info(f"Processing book {i}/{len(self.books_data)}: {book_data['title']}")
                
                # Validate book data
                if not self._validate_book_data(book_data):
                    migration_stats['failed_inserts'] += 1
                    migration_stats['errors'].append(f"Validation failed for {book_data['title']}")
                    continue
                
                # Check for existing book by ISBN
                existing_book = self._check_existing_book(book_data['isbn'])
                if existing_book:
                    logger.info(f"Book already exists: {book_data['title']} (ISBN: {book_data['isbn']})")
                    migration_stats['skipped_duplicates'] += 1
                    continue
                
                # Insert the book
                book_id = self._insert_book(book_data)
                if book_id:
                    # Insert additional details
                    self._insert_book_details(book_id, book_data)
                    migration_stats['successful_inserts'] += 1
                else:
                    migration_stats['failed_inserts'] += 1
                    migration_stats['errors'].append(f"Insertion failed for {book_data['title']}")
            
            # Commit transaction
            self.connection.commit()
            logger.info("Transaction committed successfully")
            
        except Exception as e:
            # Rollback on error
            if self.connection:
                try:
                    self.connection.rollback()
                    logger.error("Transaction rolled back due to error")
                except Error as rollback_error:
                    logger.error(f"Error during rollback: {rollback_error}")
            
            migration_stats['errors'].append(f"Migration failed: {str(e)}")
            logger.error(f"Migration failed: {e}")
            
        finally:
            # Close connection
            if self.connection:
                try:
                    self.connection.close()
                    logger.info("Database connection closed")
                except Error as e:
                    logger.error(f"Error closing connection: {e}")
        
        migration_stats['end_time'] = datetime.now()
        migration_stats['duration'] = migration_stats['end_time'] - migration_stats['start_time']
        
        return migration_stats
    
    def rollback_migration(self) -> bool:
        """Rollback the migration by removing inserted books"""
        try:
            self.connection = get_connection()
            if not self.connection:
                return False
            
            cursor = self.connection.cursor()
            
            # Get ISBNs of books to be removed
            isbn_list = [book['isbn'] for book in self.books_data]
            placeholders = ','.join(['%s'] * len(isbn_list))
            
            # Delete from book_details first (foreign key constraint)
            cursor.execute(f"""
                DELETE bd FROM book_details bd
                JOIN books b ON bd.book_id = b.book_id
                WHERE b.isbn IN ({placeholders})
            """, isbn_list)
            
            # Delete from books
            cursor.execute(f"DELETE FROM books WHERE isbn IN ({placeholders})", isbn_list)
            
            self.connection.commit()
            cursor.close()
            self.connection.close()
            
            logger.info("Migration rollback completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error during rollback: {e}")
            return False


def main():
    """Main execution function"""
    logger.info("=" * 80)
    logger.info("STARTING BOOK MIGRATION")
    logger.info("=" * 80)
    
    migration = BookMigration()
    
    try:
        # Execute migration
        stats = migration.migrate()
        
        # Log results
        logger.info("=" * 80)
        logger.info("MIGRATION RESULTS")
        logger.info("=" * 80)
        logger.info(f"Total books processed: {stats['total_books']}")
        logger.info(f"Successfully inserted: {stats['successful_inserts']}")
        logger.info(f"Skipped duplicates: {stats['skipped_duplicates']}")
        logger.info(f"Failed insertions: {stats['failed_inserts']}")
        logger.info(f"Duration: {stats['duration']}")
        
        if stats['errors']:
            logger.error("Errors encountered:")
            for error in stats['errors']:
                logger.error(f"  - {error}")
        
        logger.info("=" * 80)
        
        # Return appropriate exit code
        if stats['failed_inserts'] > 0:
            logger.warning("Migration completed with some failures")
            return 1
        else:
            logger.info("Migration completed successfully")
            return 0
            
    except Exception as e:
        logger.error(f"Migration failed with exception: {e}")
        return 1


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)