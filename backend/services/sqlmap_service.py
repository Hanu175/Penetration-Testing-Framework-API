"""
SQLMap Integration Service
Automated SQL injection detection and exploitation
"""

import subprocess
import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import sys
import re

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import get_config
from utils.logger import setup_logger
from utils.database import db

config = get_config()
logger = setup_logger('sqlmap')

class SQLMapService:
    """SQLMap integration for automated SQL injection testing"""
    
    def __init__(self):
        self.logger = logger
        self.sqlmap_path = self._find_sqlmap()
        self.output_dir = Path(config.REPORTS_DIR) / 'sqlmap_output'
        self.output_dir.mkdir(exist_ok=True, parents=True)
    
    def _find_sqlmap(self) -> str:
        """Find SQLMap installation"""
        # Check project tools directory first
        project_root = Path(__file__).parent.parent.parent
        project_sqlmap = project_root / 'tools' / 'sqlmap' / 'sqlmap.py'
        
        if project_sqlmap.exists():
            self.logger.info(f"Found SQLMap at: {project_sqlmap}")
            return str(project_sqlmap)
        
        # Try common locations
        possible_paths = [
            Path.home() / 'sqlmap' / 'sqlmap.py',
            Path('C:/tools/sqlmap/sqlmap.py'),
            Path('C:/sqlmap/sqlmap.py'),
            Path('/usr/share/sqlmap/sqlmap.py'),
        ]
        
        for path in possible_paths:
            if path.exists():
                self.logger.info(f"Found SQLMap at: {path}")
                return str(path)
        
        # Not found - will need manual installation
        self.logger.error("SQLMap not found! Please install: git clone https://github.com/sqlmapproject/sqlmap.git tools/sqlmap")
        return None
    
    def test_url(self, url: str, scan_id: int, options: Dict = None) -> Dict:
        """
        Test URL for SQL injection vulnerabilities
        
        Args:
            url: Target URL to test
            scan_id: Associated scan ID
            options: Additional SQLMap options
        
        Returns:
            Dictionary with test results
        """
        if not self.sqlmap_path:
            return {
                'error': 'SQLMap not installed',
                'message': 'Please install SQLMap: git clone https://github.com/sqlmapproject/sqlmap.git tools/sqlmap',
                'status': 'error'
            }
        
        self.logger.info(f"Starting SQLMap test on {url}")
        
        result = {
            'url': url,
            'scan_id': scan_id,
            'started_at': datetime.now().isoformat(),
            'vulnerable': False,
            'injections': [],
            'databases': [],
            'tables': [],
            'status': 'running'
        }
        
        try:
            # Create output directory for this test
            test_id = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = self.output_dir / f"scan_{scan_id}_{test_id}"
            output_path.mkdir(exist_ok=True)
            
            # Build SQLMap command
            cmd = self._build_command(url, output_path, options)
            
            self.logger.info(f"Executing SQLMap: {' '.join(cmd)}")
            
            # Run SQLMap
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=str(Path(self.sqlmap_path).parent)  # Run from sqlmap directory
            )
            
            # Parse output
            stdout = process.stdout
            stderr = process.stderr
            
            result['stdout'] = stdout
            result['stderr'] = stderr
            result['exit_code'] = process.returncode
            
            # Check if vulnerable
            if 'sqlmap identified the following injection point' in stdout.lower():
                result['vulnerable'] = True
                result['status'] = 'vulnerable'
                
                # Extract injection details
                result['injections'] = self._parse_injections(stdout)
                
                # Extract backend DBMS if found
                result['dbms'] = self._extract_dbms(stdout)
                
                # If we found injections, try to enumerate databases
                if result['injections'] and options and options.get('enumerate_dbs'):
                    db_result = self._enumerate_databases(url, output_path)
                    result['databases'] = db_result.get('databases', [])
            
            elif 'all tested parameters do not appear to be injectable' in stdout.lower():
                result['status'] = 'not_vulnerable'
                result['message'] = 'No SQL injection vulnerabilities found'
            
            else:
                result['status'] = 'completed'
                result['message'] = 'Scan completed - check output for details'
            
            result['completed_at'] = datetime.now().isoformat()
            
            # Save results to database
            self._save_results(scan_id, result)
            
            return result
            
        except subprocess.TimeoutExpired:
            self.logger.error("SQLMap test timed out")
            result['status'] = 'timeout'
            result['error'] = 'Test timed out after 5 minutes'
            self._save_results(scan_id, result)
            return result
            
        except Exception as e:
            self.logger.error(f"SQLMap test error: {str(e)}")
            result['status'] = 'error'
            result['error'] = str(e)
            self._save_results(scan_id, result)
            return result
    
    def _build_command(self, url: str, output_path: Path, options: Dict = None) -> List[str]:
        """Build SQLMap command with options"""
        
        # Base command - run with Python
        cmd = ['python', str(self.sqlmap_path)]
        
        # Target URL
        cmd.extend(['-u', url])
        
        # Output directory
        cmd.extend(['--output-dir', str(output_path)])
        
        # Batch mode (non-interactive)
        cmd.append('--batch')
        
        # Parse tables if requested
        cmd.append('--parse-errors')
        
        # Default options for faster testing
        if not options or 'level' not in options:
            cmd.extend(['--level=1'])      # Test level (1-5, default 1)
        
        if not options or 'risk' not in options:
            cmd.extend(['--risk=1'])       # Risk level (1-3, default 1)
        
        # Threads for speed
        cmd.extend(['--threads=5'])
        
        # Add custom options if provided
        if options:
            if options.get('level'):
                cmd.extend(['--level', str(options['level'])])
            
            if options.get('risk'):
                cmd.extend(['--risk', str(options['risk'])])
            
            if options.get('technique'):
                cmd.extend(['--technique', options['technique']])
            
            if options.get('dbms'):
                cmd.extend(['--dbms', options['dbms']])
            
            if options.get('enumerate_dbs'):
                cmd.append('--dbs')
            
            if options.get('current_db'):
                cmd.append('--current-db')
            
            if options.get('current_user'):
                cmd.append('--current-user')
            
            if options.get('is_dba'):
                cmd.append('--is-dba')
            
            if options.get('tables') and options.get('database'):
                cmd.extend(['-D', options['database'], '--tables'])
            
            if options.get('dump') and options.get('database') and options.get('table'):
                cmd.extend(['-D', options['database'], '-T', options['table'], '--dump'])
        
        return cmd
    
    def _parse_injections(self, output: str) -> List[Dict]:
        """Parse injection points from SQLMap output"""
        injections = []
        
        # Look for injection markers
        lines = output.split('\n')
        current_injection = {}
        
        for i, line in enumerate(lines):
            line = line.strip()
            
            if 'Parameter:' in line:
                if current_injection:
                    injections.append(current_injection)
                current_injection = {'parameter': line.split('Parameter:')[1].strip()}
            
            elif 'Type:' in line and current_injection:
                current_injection['type'] = line.split('Type:')[1].strip()
            
            elif 'Title:' in line and current_injection:
                current_injection['title'] = line.split('Title:')[1].strip()
            
            elif 'Payload:' in line and current_injection:
                current_injection['payload'] = line.split('Payload:')[1].strip()
        
        if current_injection:
            injections.append(current_injection)
        
        return injections
    
    def _extract_dbms(self, output: str) -> Optional[str]:
        """Extract backend DBMS from output"""
        # Look for patterns like "back-end DBMS: MySQL"
        match = re.search(r'back-end DBMS:\s*(\w+)', output, re.IGNORECASE)
        if match:
            return match.group(1)
        return None
    
    def _enumerate_databases(self, url: str, output_path: Path) -> Dict:
        """Enumerate databases if injection found"""
        try:
            cmd = self._build_command(url, output_path, {'enumerate_dbs': True})
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(Path(self.sqlmap_path).parent)
            )
            
            databases = []
            if 'available databases' in process.stdout.lower():
                # Parse database names
                lines = process.stdout.split('\n')
                in_db_section = False
                
                for line in lines:
                    if 'available databases' in line.lower():
                        in_db_section = True
                        continue
                    
                    if in_db_section:
                        # Look for lines starting with [*]
                        if line.strip().startswith('[*]'):
                            db_name = line.strip()[3:].strip()
                            if db_name:
                                databases.append(db_name)
                        # Stop at empty line or next section
                        elif not line.strip() or line.startswith('['):
                            break
            
            return {'databases': databases}
            
        except Exception as e:
            self.logger.error(f"Database enumeration error: {str(e)}")
            return {'databases': []}
    
    def _save_results(self, scan_id: int, result: Dict):
        """Save SQLMap results to database"""
        try:
            # Create table if doesn't exist
            create_table = """
            CREATE TABLE IF NOT EXISTS sqlmap_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                url TEXT NOT NULL,
                vulnerable INTEGER DEFAULT 0,
                status TEXT,
                dbms TEXT,
                injections TEXT,
                databases TEXT,
                started_at TEXT,
                completed_at TEXT,
                error TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
            """
            db.execute_update(create_table)
            
            # Insert result
            insert_query = """
            INSERT INTO sqlmap_results 
            (scan_id, url, vulnerable, status, dbms, injections, databases, started_at, completed_at, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            db.execute_insert(insert_query, (
                scan_id,
                result['url'],
                1 if result.get('vulnerable') else 0,
                result.get('status'),
                result.get('dbms'),
                json.dumps(result.get('injections', [])),
                json.dumps(result.get('databases', [])),
                result['started_at'],
                result.get('completed_at'),
                result.get('error')
            ))
            
            self.logger.info(f"Saved SQLMap results for scan {scan_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to save SQLMap results: {str(e)}")

# Create service instance
sqlmap_service = SQLMapService()