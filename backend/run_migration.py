#!/usr/bin/env python3
"""
Simple runner script for book migration
"""

import sys
import os
from pathlib import Path

# Add backend directory to Python path
sys.path.append(str(Path(__file__).parent))

from migrations.populate_books import main

if __name__ == "__main__":
    print("Starting book migration...")
    exit_code = main()
    print(f"Migration completed with exit code: {exit_code}")
    sys.exit(exit_code)