#!/usr/bin/env python3
"""
Script to check existing users and their IDs in the database
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from db.database import get_connection
from db.repositories import get_repositories

def check_users():
    """Check all users and their IDs"""
    try:
        # Get database connection
        conn = get_connection()
        if not conn:
            print("❌ Failed to connect to database")
            return
        
        cursor = conn.cursor(dictionary=True)
        
        # Check all users
        print("Checking all users in database...")
        cursor.execute("SELECT user_id, full_name, email, role, status, date_joined FROM users ORDER BY user_id")
        users = cursor.fetchall()
        
        if not users:
            print("No users found in database")
            cursor.close()
            conn.close()
            return
        
        print(f"Found {len(users)} users:")
        print("-" * 80)
        print(f"{'ID':<5} {'Name':<20} {'Email':<25} {'Role':<10} {'Status':<10} {'Joined':<20}")
        print("-" * 80)
        
        for user in users:
            user_id = user.get('user_id')
            full_name = user.get('full_name', 'N/A')
            email = user.get('email', 'N/A')
            role = user.get('role', 'N/A')
            status = user.get('status', 'N/A')
            date_joined = str(user.get('date_joined', 'N/A'))
            
            print(f"{user_id:<5} {full_name:<20} {email:<25} {role:<10} {status:<10} {date_joined:<20}")
        
        print("-" * 80)
        
        # Check for any users without IDs
        users_without_ids = [user for user in users if not user.get('user_id')]
        if users_without_ids:
            print(f"Found {len(users_without_ids)} users without IDs:")
            for user in users_without_ids:
                print(f"   - {user.get('full_name', 'Unknown')} ({user.get('email', 'Unknown')})")
        else:
            print("All users have IDs assigned")
        
        # Check using repository
        print("\nChecking using repository...")
        repos = get_repositories()
        repo_users = repos['user'].get_all()
        
        print(f"Repository found {len(repo_users)} users:")
        for user in repo_users:
            print(f"   ID: {user.user_id}, Name: {user.full_name}, Email: {user.email}")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"Error checking users: {str(e)}")

if __name__ == "__main__":
    check_users()