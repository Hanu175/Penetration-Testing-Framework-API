#!/usr/bin/env python3
"""
Database Initialization Script
Creates the SQLite database and sets up all tables
"""

import sqlite3
import os
from pathlib import Path

# Define paths
BASE_DIR = Path(__file__).parent.parent
DB_DIR = BASE_DIR / 'database'
DB_PATH = DB_DIR / 'pentest.db'
SCHEMA_PATH = DB_DIR / 'schema.sql'

def init_database():
    """Initialize the database with schema"""
    
    # Create database directory if it doesn't exist
    DB_DIR.mkdir(parents=True, exist_ok=True)
    
    # Check if schema file exists
    if not SCHEMA_PATH.exists():
        print(f" Error: Schema file not found at {SCHEMA_PATH}")
        return False
    
    # Read schema SQL
    with open(SCHEMA_PATH, 'r') as f:
        schema_sql = f.read()
    
    # Connect to database (creates it if doesn't exist)
    print(f" Creating database at: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Execute schema SQL
        cursor.executescript(schema_sql)
        conn.commit()
        print("Database schema created successfully!")
        
        # Verify tables were created
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        print(f"\n Created {len(tables)} tables:")
        for table in tables:
            print(f"   - {table[0]}")
        
        # Show default admin credentials
        print("\n Default admin credentials:")
        print("   Username: admin")
        print("   Password: admin123")
        print("   CHANGE THIS PASSWORD IMMEDIATELY!")
        
        return True
        
    except sqlite3.Error as e:
        print(f" Error creating database: {e}")
        return False
        
    finally:
        conn.close()

if __name__ == "__main__":
    print("=" * 60)
    print("Penetration Testing Framework - Database Initialization")
    print("=" * 60)
    print()
    
    success = init_database()
    
    if success:
        print("\n Database initialization complete!")
        print(f" Database location: {DB_PATH}")
    else:
        print("\n Database initialization failed!")
        exit(1)