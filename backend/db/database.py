import mysql.connector #type: ignore
from mysql.connector import Error #type: ignore
from dotenv import load_dotenv #type: ignore
from pathlib import Path
import os
import logging

# Load env from backend directory
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

# Configure logging
logger = logging.getLogger(__name__)

def create_database_if_missing(silent = False):
    """Create database if it doesn't exist"""
    db_name = os.getenv("DB_NAME")
    try:
        # Validate required environment variables
        db_host = os.getenv("DB_HOST")
        db_port = os.getenv("DB_PORT", "3306")
        db_user = os.getenv("DB_USER")
        db_password = os.getenv("DB_PASSWORD")
        
        if not all([db_host, db_user, db_password, db_name]):
            error_msg = "Missing required database configuration. Please check DB_HOST, DB_USER, DB_PASSWORD, and DB_NAME environment variables."
            if not silent:
                logger.error(error_msg)
            raise ValueError(error_msg)
        
        conn = mysql.connector.connect(
            host=db_host,
            port=int(db_port),
            user=db_user,
            password=db_password
        )
        
        # Test the connection
        if not conn.is_connected():
            error_msg = "Failed to establish database connection. Please verify your credentials and database server status."
            if not silent:
                logger.error(error_msg)
            raise ConnectionError(error_msg)
            
        cursor = conn.cursor()
        if not silent:
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
            logger.info(f"Database '{db_name}' is ready.")
        cursor.close()
        conn.close()
    except Error as e:
        error_msg = f"Error while creating database: {e}"
        if not silent:
            logger.error(error_msg)
            # Provide specific guidance for authentication errors
            if "Access denied" in str(e) or "authentication" in str(e).lower():
                logger.error("Authentication failed. Please verify DB_USER and DB_PASSWORD in your .env file.")
            elif "Can't connect" in str(e):
                logger.error("Connection failed. Please verify DB_HOST and DB_PORT, and ensure MySQL server is running.")

def get_connection(silent = False):
    """Get database connection"""
    try:
        # Validate required environment variables
        db_host = os.getenv("DB_HOST")
        db_port = os.getenv("DB_PORT", "3306")
        db_user = os.getenv("DB_USER")
        db_password = os.getenv("DB_PASSWORD")
        db_name = os.getenv("DB_NAME")
        
        if not all([db_host, db_user, db_password, db_name]):
            error_msg = "Missing required database configuration. Please check DB_HOST, DB_USER, DB_PASSWORD, and DB_NAME environment variables."
            if not silent:
                logger.error(error_msg)
            raise ValueError(error_msg)
        
        conn = mysql.connector.connect(
            host=db_host,
            port=int(db_port),
            user=db_user,
            password=db_password,
            database=db_name
        )
        
        # Test the connection
        if not conn.is_connected():
            error_msg = "Failed to establish database connection. Please verify your credentials and database server status."
            if not silent:
                logger.error(error_msg)
            raise ConnectionError(error_msg)
            
        return conn
    except Error as e:
        error_msg = f"Database connection error: {e}"
        if not silent:
            logger.error(error_msg)
            # Provide specific guidance for authentication errors
            if "Access denied" in str(e) or "authentication" in str(e).lower():
                logger.error("Authentication failed. Please verify DB_USER and DB_PASSWORD in your .env file.")
            elif "Can't connect" in str(e):
                logger.error("Connection failed. Please verify DB_HOST and DB_PORT, and ensure MySQL server is running.")
        return None

def init_db(silent = False):
    """Initialize database with schema"""
    create_database_if_missing(silent)
    conn = get_connection(silent)
    if not conn:
        if not silent:
            logger.error("Could not connect to database.")
        return

    cursor = conn.cursor()
    schema_path = Path(__file__).resolve().parent / "schema.sql"
    with open(schema_path, "r", encoding="utf-8") as schema_file:
        sql_script = schema_file.read()

    for statement in sql_script.split(";"):
        stmt = statement.strip()
        if stmt:
            try:
                cursor.execute(stmt)
            except Error as e:
                if not silent:
                    logger.error(f"Error executing SQL statement: {e}")

    conn.commit()
    cursor.close()
    conn.close()
    if not silent:
        logger.info("Tables initialized successfully.")

# Import models and repositories for easy access
from .models import User, Book, BorrowRecord, Fine, ViewLog, LoginAttempt, LibraryStats
from .repositories import get_repositories

# Export all models and repositories
__all__ = [
    # Models
    'User', 'Book', 'BorrowRecord', 'Fine', 'ViewLog', 'LoginAttempt', 'LibraryStats',
    # Repositories
    'user_repository', 'book_repository', 'borrow_repository',
    'fine_repository', 'view_log_repository', 'login_attempt_repository',
    'library_stats_repository',
    # Database functions
    'create_database_if_missing', 'get_connection', 'init_db'
]