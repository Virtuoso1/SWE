#!/usr/bin/env python3
"""
Database connection test script
Tests the database configuration and connection with proper error handling
"""

import sys
import os
from pathlib import Path

# Add the backend directory to the Python path
backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

from db.database import get_connection, create_database_if_missing, init_db
from config import get_config, Config
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_config():
    """Test configuration loading"""
    print("Testing configuration...")
    try:
        config = get_config()
        print("[PASS] Configuration loaded successfully")
        print(f"  - Environment: {config.FLASK_ENV}")
        print(f"  - Database Host: {config.DB_HOST}")
        print(f"  - Database Port: {config.DB_PORT}")
        print(f"  - Database User: {config.DB_USER}")
        print(f"  - Database Name: {config.DB_NAME}")
        print(f"  - Database Password: {'*' * len(config.DB_PASSWORD)}")
        
        # Validate database configuration
        config.validate_database_config()
        print("[PASS] Database configuration validated")
        return True
    except Exception as e:
        print(f"[FAIL] Configuration test failed: {e}")
        return False

def test_database_connection():
    """Test database connection"""
    print("\nTesting database connection...")
    try:
        conn = get_connection()
        if conn and conn.is_connected():
            print("[PASS] Database connection successful")
            
            # Get database info
            cursor = conn.cursor()
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()[0]
            print(f"  - MySQL Version: {version}")
            
            cursor.execute("SELECT DATABASE()")
            database = cursor.fetchone()[0]
            print(f"  - Current Database: {database}")
            
            cursor.close()
            conn.close()
            return True
        else:
            print("[FAIL] Database connection failed")
            return False
    except Exception as e:
        print(f"[FAIL] Database connection test failed: {e}")
        return False

def test_database_creation():
    """Test database creation"""
    print("\nTesting database creation...")
    try:
        create_database_if_missing()
        print("[PASS] Database creation test passed")
        return True
    except Exception as e:
        print(f"[FAIL] Database creation test failed: {e}")
        return False

def test_database_initialization():
    """Test database initialization"""
    print("\nTesting database initialization...")
    try:
        init_db()
        print("[PASS] Database initialization test passed")
        return True
    except Exception as e:
        print(f"[FAIL] Database initialization test failed: {e}")
        return False

def main():
    """Main test function"""
    print("=" * 60)
    print("DATABASE CONNECTION AND CONFIGURATION TEST")
    print("=" * 60)
    
    tests = [
        ("Configuration", test_config),
        ("Database Connection", test_database_connection),
        ("Database Creation", test_database_creation),
        ("Database Initialization", test_database_initialization)
    ]
    
    results = []
    for test_name, test_func in tests:
        result = test_func()
        results.append((test_name, result))
    
    print("\n" + "=" * 60)
    print("TEST RESULTS SUMMARY")
    print("=" * 60)
    
    passed = 0
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\nTotal: {passed}/{len(tests)} tests passed")
    
    if passed == len(tests):
        print("[PASS] All tests passed! Database is properly configured.")
        return 0
    else:
        print("[FAIL] Some tests failed. Please check the configuration.")
        return 1

if __name__ == "__main__":
    sys.exit(main())