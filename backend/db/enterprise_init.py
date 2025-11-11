import mysql.connector
from db.database import get_connection
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

def create_enterprise_tables():
    """Create all enterprise authentication tables"""
    try:
        conn = get_connection()
        if not conn:
            return False
            
        cursor = conn.cursor()
        
        # Read and execute the enterprise schema
        schema_path = Path(__file__).resolve().parent / 'enterprise_schema.sql'
        with open(schema_path, "r", encoding="utf-8") as schema_file:
            sql_script = schema_file.read()
        
        # Split into individual statements and execute
        statements = sql_script.split(';')
        for statement in statements:
            stmt = statement.strip()
            if stmt and not stmt.startswith('--') and not stmt.startswith('def'):
                try:
                    cursor.execute(stmt)
                except mysql.connector.Error as e:
                    # Ignore "already exists" errors
                    if "already exists" not in str(e).lower():
                        logger.warning(f"Error executing SQL statement: {e}")
                        logger.warning(f"Statement: {stmt}")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info("Enterprise database tables created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error creating enterprise tables: {e}")
        return False

def create_token_blacklist_table():
    """Create JWT token blacklist table"""
    try:
        conn = get_connection()
        if not conn:
            return False
                
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS token_blacklist (
                id INT AUTO_INCREMENT PRIMARY KEY,
                jti VARCHAR(255) NOT NULL,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_jti (jti),
                INDEX idx_expires (expires_at)
            )
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        
        logger.info("JWT token blacklist table created successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error creating token blacklist table: {str(e)}")
        return False