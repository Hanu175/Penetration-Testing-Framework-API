"""
Hashcat Integration Service
GPU-accelerated password cracking
"""

import subprocess
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import sys
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import get_config
from utils.logger import setup_logger
from utils.database import db

config = get_config()
logger = setup_logger('hashcat')

class HashcatService:
    """Hashcat integration for password cracking"""
    
    # Hash type reference
    HASH_TYPES = {
        'MD5': 0,
        'SHA1': 100,
        'SHA256': 1400,
        'SHA512': 1700,
        'NTLM': 1000,
        'bcrypt': 3200,
        'MD5(Unix)': 500,
        'sha512crypt': 1800,
    }
    
    def __init__(self):
        self.logger = logger
        self.hashcat_path = self._find_hashcat()
        self.output_dir = Path(config.REPORTS_DIR) / 'hashcat_output'
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        # Wordlists directory
        self.wordlists_dir = Path(config.REPORTS_DIR) / 'wordlists'
        self.wordlists_dir.mkdir(exist_ok=True, parents=True)
        
        # Create default wordlist
        self._create_default_wordlist()
    
    def _find_hashcat(self) -> Optional[str]:
        """Find Hashcat executable"""
        # Check project tools directory
        project_root = Path(__file__).parent.parent.parent
        project_hashcat = project_root / 'tools' / 'hashcat' / 'hashcat.exe'
        
        if project_hashcat.exists():
            self.logger.info(f"Found Hashcat at: {project_hashcat}")
            return str(project_hashcat)
        
        # Try common locations
        possible_paths = [
            'hashcat.exe',  # In PATH
            'hashcat',
            Path('C:/hashcat/hashcat.exe'),
            Path('C:/Program Files/hashcat/hashcat.exe'),
            Path.home() / 'hashcat' / 'hashcat.exe',
        ]
        
        for path in possible_paths:
            try:
                if isinstance(path, str):
                    # Check if in PATH
                    result = subprocess.run(['where', path], capture_output=True)
                    if result.returncode == 0:
                        self.logger.info(f"Found Hashcat in PATH: {path}")
                        return path
                elif path.exists():
                    self.logger.info(f"Found Hashcat at: {path}")
                    return str(path)
            except:
                continue
        
        self.logger.warning("Hashcat not found - password cracking features will be unavailable")
        return None
    
    def _create_default_wordlist(self):
        """Create a default wordlist with common passwords"""
        wordlist_path = self.wordlists_dir / 'common_passwords.txt'
        
        if not wordlist_path.exists():
            # Top 1000 common passwords (subset shown for brevity)
            common_passwords = [
                # Very common
                'password', '123456', '12345678', 'qwerty', 'abc123',
                'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
                'baseball', '111111', 'iloveyou', 'master', 'sunshine',
                'ashley', 'bailey', 'passw0rd', 'shadow', '123123',
                
                # Admin/default
                'admin', 'password1', 'password123', 'welcome', 'login',
                'admin123', 'root', 'toor', 'pass', 'test',
                'guest', 'oracle', 'user', 'changeme', 'default',
                
                # Patterns
                'Password1', 'P@ssw0rd', 'Welcome1', 'Admin123', 'Passw0rd!',
                'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1q2w3e4r', 'qazwsx',
                
                # Names
                'michael', 'jennifer', 'jordan', 'michelle', 'jessica',
                'matthew', 'ashley', 'daniel', 'amanda', 'christopher',
                
                # Sports/Entertainment
                'football', 'baseball', 'basketball', 'hockey', 'soccer',
                'starwars', 'batman', 'superman', 'pokemon', 'minecraft',
                
                # Seasonal/Temporal
                'summer', 'winter', 'spring', 'autumn', 'summer2024',
                'january', 'february', 'march', 'april', 'may',
                'monday', 'tuesday', 'wednesday', 'thursday', 'friday',
                
                # Keyboard patterns
                'qwerty123', '1qaz2wsx', 'zaq12wsx', 'qazwsxedc',
                
                # Common with numbers
                'password!', 'password@', 'password#', 'password$',
                'qwerty1', 'qwerty12', 'qwerty123', 'abc123!',
                
                # Simple sequences
                '1234', '12345', '123456789', '1234567890',
                'abcdef', 'abcdefg', 'abcdefgh',
            ]
            
            with open(wordlist_path, 'w') as f:
                for pwd in common_passwords:
                    f.write(f"{pwd}\n")
            
            self.logger.info(f"Created default wordlist with {len(common_passwords)} passwords: {wordlist_path}")
    
    def crack_hashes(self, hashes: List[str], scan_id: int, hash_type: int = 0, 
                     attack_mode: int = 0, wordlist: str = None) -> Dict:
        """
        Crack password hashes using Hashcat
        
        Args:
            hashes: List of password hashes to crack
            scan_id: Associated scan ID
            hash_type: Hash type (0=MD5, 100=SHA1, 1000=NTLM, etc.)
            attack_mode: Attack mode (0=Dictionary, 3=Bruteforce, etc.)
            wordlist: Path to wordlist file (optional)
        
        Returns:
            Dictionary with cracking results
        """
        if not self.hashcat_path:
            return {
                'error': 'Hashcat not installed',
                'message': 'Please install Hashcat from https://hashcat.net/hashcat/',
                'status': 'error'
            }
        
        self.logger.info(f"Starting Hashcat crack job for {len(hashes)} hashes (type: {hash_type})")
        
        result = {
            'scan_id': scan_id,
            'started_at': datetime.now().isoformat(),
            'hash_type': hash_type,
            'attack_mode': attack_mode,
            'hash_count': len(hashes),
            'cracked_count': 0,
            'cracked_hashes': [],
            'status': 'running'
        }
        
        try:
            # Create temporary files
            test_id = datetime.now().strftime('%Y%m%d_%H%M%S')
            hash_file = self.output_dir / f"hashes_{test_id}.txt"
            output_file = self.output_dir / f"cracked_{test_id}.txt"
            
            # Write hashes to file
            with open(hash_file, 'w') as f:
                for hash_val in hashes:
                    f.write(f"{hash_val.strip()}\n")
            
            # Use default wordlist if none provided
            if not wordlist:
                wordlist = str(self.wordlists_dir / 'common_passwords.txt')
            
            # Build Hashcat command
            cmd = [
                str(self.hashcat_path),
                '-m', str(hash_type),      # Hash type
                '-a', str(attack_mode),    # Attack mode
                str(hash_file),            # Hash file
                wordlist,                  # Wordlist
                '-o', str(output_file),    # Output file
                '--force',                 # Force run (ignore warnings)
                '--quiet',                 # Quiet mode
                '--potfile-disable',       # Don't use potfile
                '--outfile-format=2',      # Format: hash:password
            ]
            
            self.logger.info(f"Executing Hashcat: {' '.join(cmd)}")
            
            # Run Hashcat
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            result['exit_code'] = process.returncode
            
            # Parse cracked hashes from output file
            if output_file.exists():
                with open(output_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if ':' in line:
                            parts = line.split(':', 1)
                            if len(parts) == 2:
                                hash_val, password = parts
                                result['cracked_hashes'].append({
                                    'hash': hash_val.strip(),
                                    'password': password.strip()
                                })
                
                result['cracked_count'] = len(result['cracked_hashes'])
            
            # Determine status
            if result['cracked_count'] > 0:
                result['status'] = 'success'
                result['message'] = f"Cracked {result['cracked_count']} out of {result['hash_count']} hashes"
            elif result['cracked_count'] == 0:
                result['status'] = 'no_cracks'
                result['message'] = 'No hashes cracked - try a larger wordlist or different attack mode'
            else:
                result['status'] = 'completed'
            
            result['completed_at'] = datetime.now().isoformat()
            
            # Save results to database
            self._save_results(scan_id, result)
            
            # Cleanup temporary files
            try:
                hash_file.unlink(missing_ok=True)
                # Keep output file for reference
            except:
                pass
            
            return result
            
        except subprocess.TimeoutExpired:
            self.logger.error("Hashcat cracking timed out")
            result['status'] = 'timeout'
            result['error'] = 'Cracking timed out after 5 minutes'
            self._save_results(scan_id, result)
            return result
            
        except Exception as e:
            self.logger.error(f"Hashcat error: {str(e)}")
            result['status'] = 'error'
            result['error'] = str(e)
            self._save_results(scan_id, result)
            return result
    
    def _save_results(self, scan_id: int, result: Dict):
        """Save Hashcat results to database"""
        try:
            # Create table if doesn't exist
            create_table = """
            CREATE TABLE IF NOT EXISTS hashcat_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                hash_type INTEGER,
                attack_mode INTEGER,
                hash_count INTEGER,
                cracked_count INTEGER,
                cracked_hashes TEXT,
                status TEXT,
                message TEXT,
                started_at TEXT,
                completed_at TEXT,
                error TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
            """
            db.execute_update(create_table)
            
            # Insert result
            insert_query = """
            INSERT INTO hashcat_results 
            (scan_id, hash_type, attack_mode, hash_count, cracked_count, cracked_hashes, status, message, started_at, completed_at, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            
            db.execute_insert(insert_query, (
                scan_id,
                result.get('hash_type'),
                result.get('attack_mode'),
                result.get('hash_count'),
                result.get('cracked_count', 0),
                json.dumps(result.get('cracked_hashes', [])),
                result.get('status'),
                result.get('message'),
                result['started_at'],
                result.get('completed_at'),
                result.get('error')
            ))
            
            self.logger.info(f"Saved Hashcat results for scan {scan_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to save Hashcat results: {str(e)}")

# Create service instance
hashcat_service = HashcatService()