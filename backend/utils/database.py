"""
Database Utility Module
"""

import sqlite3
from contextlib import contextmanager
from typing import List, Dict, Any, Optional
from datetime import datetime
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import get_config

config = get_config()

class Database:
    """Database connection manager"""
    
    # At the very top, add to existing Database class:
    def get_all(self, table: str, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Get all records from a table with pagination"""
        query = f"SELECT * FROM {table} ORDER BY id DESC LIMIT ? OFFSET ?"
        return self.execute_query(query, (limit, offset))
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or config.DATABASE_PATH
        print("DB PATH USED:", self.db_path)   #added extra remove when done doesn't basically do anything
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def execute_query(self, query: str, params: tuple = ()) -> List[Dict]:
        """Execute SELECT query"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
    
    def execute_insert(self, query: str, params: tuple = ()) -> int:
        """Execute INSERT query and return last row ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.lastrowid
    
    def execute_update(self, query: str, params: tuple = ()) -> int:
        """Execute UPDATE/DELETE query"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.rowcount

# Database instance
db = Database()

# Specialized functions

def create_scan(project_id: int, scan_name: str, target: str, scan_type: str, created_by: int) -> int:
    """Create a new scan"""
    query = """
    INSERT INTO scans (project_id, scan_name, target, scan_type, status, created_by)
    VALUES (?, ?, ?, ?, 'pending', ?)
    """
    return db.execute_insert(query, (project_id, scan_name, target, scan_type, created_by))

def update_scan_status(scan_id: int, status: str, **kwargs) -> int:
    """Update scan status"""
    fields = ['status = ?']
    values = [status]
    
    for key, value in kwargs.items():
        fields.append(f"{key} = ?")
        values.append(value)
    
    query = f"UPDATE scans SET {', '.join(fields)} WHERE id = ?"
    values.append(scan_id)
    
    return db.execute_update(query, tuple(values))

def get_scan_with_details(scan_id: int) -> Optional[Dict]:
    """Get scan with details"""
    query = """
    SELECT s.*, p.name as project_name
    FROM scans s
    LEFT JOIN projects p ON s.project_id = p.id
    WHERE s.id = ?
    """
    results = db.execute_query(query, (scan_id,))
    return results[0] if results else None

def add_target(scan_id: int, ip_address: str, hostname: str = None, **kwargs) -> int:
    """Add a discovered target"""
    fields = ['scan_id', 'ip_address', 'hostname']
    values = [scan_id, ip_address, hostname]
    
    for key, value in kwargs.items():
        fields.append(key)
        values.append(value)
    
    placeholders = ', '.join(['?' for _ in fields])
    query = f"INSERT INTO targets ({', '.join(fields)}) VALUES ({placeholders})"
    
    return db.execute_insert(query, tuple(values))

def add_port(target_id: int, port: int, protocol: str, state: str, **kwargs) -> int:
    """Add a discovered port"""
    fields = ['target_id', 'port', 'protocol', 'state']
    values = [target_id, port, protocol, state]
    
    for key, value in kwargs.items():
        fields.append(key)
        values.append(value)
    
    placeholders = ', '.join(['?' for _ in fields])
    query = f"INSERT INTO ports ({', '.join(fields)}) VALUES ({placeholders})"
    
    return db.execute_insert(query, tuple(values))

def add_vulnerability(target_id: int, title: str, description: str, severity: str, **kwargs) -> int:
    """Add a vulnerability"""
    fields = ['target_id', 'title', 'description', 'severity']
    values = [target_id, title, description, severity]
    
    for key, value in kwargs.items():
        fields.append(key)
        values.append(value)
    
    placeholders = ', '.join(['?' for _ in fields])
    query = f"INSERT INTO vulnerabilities ({', '.join(fields)}) VALUES ({placeholders})"
    
    return db.execute_insert(query, tuple(values))

def add_scan_log(scan_id: int, level: str, message: str, module: str = None):
    """Add a log entry"""
    query = "INSERT INTO scan_logs (scan_id, log_level, message, module) VALUES (?, ?, ?, ?)"
    return db.execute_insert(query, (scan_id, level, message, module))

def get_vulnerabilities_by_scan(scan_id: int) -> List[Dict]:
    """Get vulnerabilities for a scan"""
    query = """
    SELECT v.*, t.ip_address, t.hostname, p.port, p.service
    FROM vulnerabilities v
    JOIN targets t ON v.target_id = t.id
    LEFT JOIN ports p ON v.port_id = p.id
    WHERE t.scan_id = ?
    ORDER BY 
        CASE v.severity
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
            ELSE 5
        END
    """
    return db.execute_query(query, (scan_id,))

def get_dashboard_stats() -> Dict:
    """Get dashboard statistics"""
    with db.get_connection() as conn:
        cursor = conn.cursor()
        
        # Total scans
        cursor.execute("SELECT COUNT(*) as count FROM scans")
        total_scans = cursor.fetchone()['count']
        
        # Vulnerabilities by severity
        cursor.execute("SELECT severity, COUNT(*) as count FROM vulnerabilities GROUP BY severity")
        vuln_by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}
        
        # Recent scans
        cursor.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 5")
        recent_scans = [dict(row) for row in cursor.fetchall()]
        
        return {
            'total_scans': total_scans,
            'vulnerabilities': vuln_by_severity,
            'recent_scans': recent_scans
        }
        
def get_scan_logs(scan_id: int, level: str = None) -> List[Dict]:
    """Get logs for a scan"""
    if level:
        query = "SELECT * FROM scan_logs WHERE scan_id = ? AND log_level = ? ORDER BY timestamp DESC"
        return db.execute_query(query, (scan_id, level))
    else:
        query = "SELECT * FROM scan_logs WHERE scan_id = ? ORDER BY timestamp DESC"
        return db.execute_query(query, (scan_id,))

def get_all(table: str, limit: int = 100, offset: int = 0) -> List[Dict]:
    """Get all records from a table with pagination"""
    query = f"SELECT * FROM {table} ORDER BY id DESC LIMIT ? OFFSET ?"
    return db.execute_query(query, (limit, offset))