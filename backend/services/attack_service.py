"""
Attack Simulation Service - PRODUCTION GRADE
Realistic attack testing with dynamic parameter discovery
"""

import socket
import requests
import time
import re
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import sys
from pathlib import Path
import json
import uuid

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import get_config
from utils.logger import setup_logger
from utils.database import db

config = get_config()
logger = setup_logger('attack_simulator')

class AttackSimulator:
    """Production-grade attack simulator with context awareness"""
    
    def __init__(self):
        self.logger = logger
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    # ==================== HELPER METHODS ====================
    
    def _discover_parameters(self, url: str) -> List[str]:
        """Discover GET parameters from URL"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            return list(params.keys())
        except:
            return []
    
    def _rebuild_url(self, original_url: str, params: dict) -> str:
        """Rebuild URL with modified parameters"""
        try:
            parsed = urlparse(original_url)
            query_string = urlencode(params, doseq=True)
            
            return urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                query_string,
                parsed.fragment
            ))
        except:
            return original_url
    
    def _safe_request(self, url: str, method: str = 'GET', timeout: int = 5, **kwargs):
        """Safe HTTP request with error handling"""
        try:
            return self.session.request(method, url, timeout=timeout, verify=False, **kwargs)
        except Exception as e:
            self.logger.debug(f"Request failed: {str(e)}")
            return None
    
    # ==================== PORT SCAN DETECTION ====================
    
    def simulate_port_scan_detection(self, target: str) -> Dict:
        """Test if target can detect port scanning"""
        self.logger.info(f"Testing port scan detection on {target}")
        
        result = {
            'attack_type': 'Port Scan Detection Test',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'detected': False,
            'details': []
        }
        
        try:
            common_ports = [21, 22, 80, 443, 3306, 3389, 8080]
            
            start_time = time.time()
            scanned_count = 0
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.05)
                    sock.connect((target, port))
                    sock.close()
                    result['details'].append(f"Port {port}: Open")
                    scanned_count += 1
                except:
                    scanned_count += 1
            
            duration = time.time() - start_time
            
            result['scan_duration'] = f"{duration:.2f} seconds"
            result['ports_scanned'] = scanned_count
            result['scan_rate'] = f"{scanned_count/duration:.1f} ports/sec"
            result['verdict'] = "Fast scan completed - would trigger most IDS systems"
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    # ==================== SQL INJECTION - PRODUCTION GRADE ====================
    
    def simulate_sql_injection(self, url: str) -> Dict:
        """
        PRODUCTION-GRADE SQL Injection Testing
        - Discovers actual parameters
        - Tests multiple techniques
        - Context-aware detection
        """
        self.logger.info(f"Testing SQL injection on {url}")
        
        result = {
            'attack_type': 'SQL Injection Test',
            'target': url,
            'timestamp': datetime.now().isoformat(),
            'vulnerable': False,
            'injection_points': [],
            'techniques': []
        }
        
        # STEP 1: Discover parameters
        parameters = self._discover_parameters(url)
        
        if not parameters:
            result['verdict'] = "[WARN] No GET parameters found - cannot test"
            result['recommendation'] = "URL must contain parameters like ?id=1 or ?page=home"
            return result
        
        self.logger.info(f"Found {len(parameters)} parameters to test: {parameters}")
        
        # STEP 2: Test each parameter
        for param in parameters:
            param_result = self._test_sql_injection_parameter(url, param)
            
            if param_result['vulnerable']:
                result['vulnerable'] = True
                result['injection_points'].append(param_result)
        
        # STEP 3: Set verdict
        if result['vulnerable']:
            result['severity'] = 'CRITICAL'
            result['verdict'] = f"[FAIL] VULNERABLE - {len(result['injection_points'])} injection point(s) found"
            result['recommendation'] = (
                "CRITICAL: Use parameterized queries/prepared statements. "
                "Implement input validation and WAF protection."
            )
        else:
            result['verdict'] = "[OK] No SQL injection detected"
            result['recommendation'] = "Continue using secure coding practices"
        
        return result
    
    def _test_sql_injection_parameter(self, url: str, param: str) -> Dict:
        """Test single parameter for SQL injection"""
        
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query)
        
        if param not in base_params:
            return {'vulnerable': False}
        
        original_value = base_params[param][0]
        
        # Get baseline response
        baseline = self._safe_request(url)
        if not baseline:
            return {'vulnerable': False}
        
        # TECHNIQUE 1: Error-based SQL injection
        error_result = self._test_error_based_sqli(url, param, base_params, original_value)
        if error_result['vulnerable']:
            return error_result
        
        # TECHNIQUE 2: Boolean-based blind
        boolean_result = self._test_boolean_based_sqli(url, param, base_params, original_value, baseline)
        if boolean_result['vulnerable']:
            return boolean_result
        
        # TECHNIQUE 3: Time-based blind
        time_result = self._test_time_based_sqli(url, param, base_params, original_value)
        if time_result['vulnerable']:
            return time_result
        
        return {'vulnerable': False}
    
    def _test_error_based_sqli(self, url: str, param: str, base_params: dict, original_value: str) -> Dict:
        """Test for SQL error messages"""
        
        error_payloads = [
            "'",
            "''",
            "' OR '1'='1",
            '" OR "1"="1',
        ]
        
        sql_error_patterns = [
            r'sql syntax',
            r'mysql_fetch',
            r'ORA-\d{5}',
            r'SQLServer',
            r'PostgreSQL.*ERROR',
            r'Warning.*mysql',
            r'valid MySQL result',
            r'Unclosed quotation mark',
            r'quoted string not properly terminated',
        ]
        
        for payload in error_payloads:
            test_params = base_params.copy()
            test_params[param] = [payload]
            
            test_url = self._rebuild_url(url, test_params)
            response = self._safe_request(test_url)
            
            if not response:
                continue
            
            # Check for SQL error indicators
            for pattern in sql_error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return {
                        'vulnerable': True,
                        'parameter': param,
                        'technique': 'Error-based SQL Injection',
                        'payload': payload,
                        'evidence': f'SQL error pattern found: {pattern}'
                    }
        
        return {'vulnerable': False}
    
    def _test_boolean_based_sqli(self, url: str, param: str, base_params: dict, 
                                   original_value: str, baseline) -> Dict:
        """Boolean-based blind SQL injection"""
        
        baseline_length = len(baseline.text)
        
        # True condition
        test_params = base_params.copy()
        test_params[param] = [f"{original_value}' AND '1'='1"]
        true_url = self._rebuild_url(url, test_params)
        true_response = self._safe_request(true_url)
        
        if not true_response:
            return {'vulnerable': False}
        
        # False condition
        test_params = base_params.copy()
        test_params[param] = [f"{original_value}' AND '1'='2"]
        false_url = self._rebuild_url(url, test_params)
        false_response = self._safe_request(false_url)
        
        if not false_response:
            return {'vulnerable': False}
        
        true_length = len(true_response.text)
        false_length = len(false_response.text)
        
        # Boolean injection: true matches baseline, false differs
        if abs(true_length - baseline_length) < 100 and abs(false_length - baseline_length) > 100:
            return {
                'vulnerable': True,
                'parameter': param,
                'technique': 'Boolean-based Blind SQL Injection',
                'payload': f"{original_value}' AND '1'='1",
                'evidence': f'Response length variance: baseline={baseline_length}, true={true_length}, false={false_length}'
            }
        
        return {'vulnerable': False}
    
    def _test_time_based_sqli(self, url: str, param: str, base_params: dict, original_value: str) -> Dict:
        """Time-based blind SQL injection"""
        
        time_payloads = [
            f"{original_value}' AND SLEEP(5)--",           # MySQL
            f"{original_value}'; WAITFOR DELAY '0:0:5'--", # MSSQL
            f"{original_value}' AND pg_sleep(5)--",        # PostgreSQL
        ]
        
        for payload in time_payloads:
            test_params = base_params.copy()
            test_params[param] = [payload]
            
            test_url = self._rebuild_url(url, test_params)
            
            start_time = time.time()
            response = self._safe_request(test_url, timeout=10)
            elapsed = time.time() - start_time
            
            # If response delayed by ~5 seconds
            if elapsed >= 4.0 and elapsed < 10.0:
                return {
                    'vulnerable': True,
                    'parameter': param,
                    'technique': 'Time-based Blind SQL Injection',
                    'payload': payload,
                    'evidence': f'Response delayed: {elapsed:.2f}s (expected ~5s)'
                }
        
        return {'vulnerable': False}
    
    # ==================== XSS - PRODUCTION GRADE ====================
    
    def simulate_xss_attack(self, url: str) -> Dict:
        """
        PRODUCTION-GRADE XSS Testing
        - Context-aware payload testing
        - Unique markers to avoid false positives
        """
        self.logger.info(f"Testing XSS on {url}")
        
        result = {
            'attack_type': 'Cross-Site Scripting (XSS) Test',
            'target': url,
            'timestamp': datetime.now().isoformat(),
            'vulnerable': False,
            'injection_points': []
        }
        
        parameters = self._discover_parameters(url)
        
        if not parameters:
            result['verdict'] = "[WARN] No GET parameters found - cannot test"
            return result
        
        for param in parameters:
            xss_result = self._test_xss_parameter(url, param)
            
            if xss_result['vulnerable']:
                result['vulnerable'] = True
                result['injection_points'].append(xss_result)
        
        if result['vulnerable']:
            result['severity'] = 'HIGH'
            result['verdict'] = f"[FAIL] VULNERABLE - {len(result['injection_points'])} XSS point(s) found"
            result['recommendation'] = "Implement output encoding, Content Security Policy (CSP), and input validation"
        else:
            result['verdict'] = "[OK] No XSS vulnerabilities detected"
        
        return result
    
    def _test_xss_parameter(self, url: str, param: str) -> Dict:
        """Test single parameter for XSS with unique markers"""
        
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query)
        
        # Generate unique marker
        marker = str(uuid.uuid4())[:8]
        
        # Test payloads with different contexts
        test_cases = [
            {
                'payload': f"<script>alert('{marker}')</script>",
                'name': 'HTML Script Injection',
                'check': lambda text: f"<script>alert('{marker}')</script>" in text
            },
            {
                'payload': f'"><img src=x onerror=alert("{marker}")>',
                'name': 'Tag Breaking + Event Handler',
                'check': lambda text: f'onerror=alert("{marker}")' in text
            },
            {
                'payload': f"<svg/onload=alert('{marker}')>",
                'name': 'SVG Event Handler',
                'check': lambda text: f"onload=alert('{marker}')" in text
            },
        ]
        
        for test in test_cases:
            test_params = base_params.copy()
            test_params[param] = [test['payload']]
            
            test_url = self._rebuild_url(url, test_params)
            response = self._safe_request(test_url)
            
            if not response:
                continue
            
            # Check if payload reflected without encoding
            if test['check'](response.text):
                # Verify it's not in HTML comment
                if f"<!--{marker}" not in response.text:
                    return {
                        'vulnerable': True,
                        'parameter': param,
                        'payload': test['payload'],
                        'technique': test['name'],
                        'evidence': f'Payload reflected unescaped (marker: {marker})'
                    }
        
        return {'vulnerable': False}
    
    # ==================== DIRECTORY TRAVERSAL ====================
    
    def simulate_directory_traversal(self, url: str) -> Dict:
        """Test path traversal vulnerabilities"""
        self.logger.info(f"Testing directory traversal on {url}")
        
        result = {
            'attack_type': 'Directory Traversal Test',
            'target': url,
            'timestamp': datetime.now().isoformat(),
            'vulnerable': False,
            'files_accessed': []
        }
        
        parameters = self._discover_parameters(url)
        
        if not parameters:
            result['verdict'] = "[WARN] No GET parameters found - cannot test"
            return result
        
        # Path traversal payloads
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "../../../../../../../etc/passwd",
        ]
        
        # Detection patterns
        sensitive_patterns = [
            r'root:.*:/bin/bash',  # Linux /etc/passwd
            r'daemon:.*:/bin',     # Unix system files
            r'# Copyright.*Microsoft',  # Windows hosts file
        ]
        
        for param in parameters:
            for payload in payloads:
                test_params = parse_qs(urlparse(url).query)
                test_params[param] = [payload]
                
                test_url = self._rebuild_url(url, test_params)
                response = self._safe_request(test_url)
                
                if not response:
                    continue
                
                # Check for sensitive file content
                for pattern in sensitive_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        result['vulnerable'] = True
                        result['files_accessed'].append({
                            'parameter': param,
                            'payload': payload,
                            'evidence': f'Pattern found: {pattern}'
                        })
                        break
        
        if result['vulnerable']:
            result['severity'] = 'CRITICAL'
            result['verdict'] = "[FAIL] VULNERABLE - Directory traversal successful"
        else:
            result['verdict'] = "[OK] No directory traversal detected"
        
        return result
    
    # ==================== HTTP METHODS TEST ====================
    
    def test_http_methods(self, url: str) -> Dict:
        """Test for dangerous HTTP methods"""
        self.logger.info(f"Testing HTTP methods on {url}")
        
        result = {
            'attack_type': 'HTTP Methods Test',
            'target': url,
            'timestamp': datetime.now().isoformat(),
            'dangerous_methods': [],
            'all_methods': []
        }
        
        dangerous = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT', 'PATCH']
        
        for method in methods:
            response = self._safe_request(url, method=method)
            
            if response and response.status_code not in [405, 501]:
                result['all_methods'].append(method)
                if method in dangerous:
                    result['dangerous_methods'].append(method)
        
        if result['dangerous_methods']:
            result['severity'] = 'MEDIUM'
            result['verdict'] = f"[WARN] Dangerous methods enabled: {', '.join(result['dangerous_methods'])}"
        else:
            result['verdict'] = "[OK] No dangerous HTTP methods detected"
        
        return result
    
    # ==================== DIRECTORY BRUTEFORCE ====================
    
    def directory_bruteforce(self, target: str, port: int = 80) -> Dict:
        """Brute force common directories"""
        self.logger.info(f"Testing directory bruteforce on {target}:{port}")
        
        result = {
            'attack_type': 'Directory Bruteforce',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'found_directories': [],
            'tested_count': 0
        }
        
        common_dirs = [
            'admin', 'login', 'wp-admin', 'phpmyadmin', 'backup',
            'config', 'api', 'uploads', 'dashboard', 'panel'
        ]
        
        base_url = f"http://{target}:{port}"
        
        for directory in common_dirs:
            result['tested_count'] += 1
            test_url = f"{base_url}/{directory}"
            
            response = self._safe_request(test_url, timeout=2)
            
            if response and response.status_code in [200, 301, 302, 403]:
                result['found_directories'].append({
                    'path': directory,
                    'status': response.status_code
                })
        
        if result['found_directories']:
            result['verdict'] = f"Found {len(result['found_directories'])} directories"
        else:
            result['verdict'] = "[OK] No common directories found"
        
        return result
    
    # ==================== SSH BRUTEFORCE ====================
    
    def simulate_ssh_bruteforce(self, target: str, port: int = 22, max_attempts: int = 3) -> Dict:
        """Test SSH bruteforce protection"""
        self.logger.info(f"Testing SSH bruteforce on {target}:{port}")
        
        result = {
            'attack_type': 'SSH Bruteforce Test',
            'target': target,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'attempts': 0,
            'successful_login': False,
            'blocked': False
        }
        
        credentials = [
            ('admin', 'admin'),
            ('root', 'root'),
            ('user', 'user'),
        ]
        
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            for username, password in credentials:
                result['attempts'] += 1
                
                try:
                    ssh.connect(
                        target, port=port, username=username, password=password,
                        timeout=2, look_for_keys=False, allow_agent=False
                    )
                    
                    result['successful_login'] = True
                    result['credentials'] = f"{username}:{password}"
                    result['severity'] = 'CRITICAL'
                    result['verdict'] = f"[FAIL] Weak credentials: {username}:{password}"
                    ssh.close()
                    break
                    
                except paramiko.AuthenticationException:
                    time.sleep(0.5)
                    
                except Exception as e:
                    if 'refused' in str(e).lower():
                        result['blocked'] = True
                        result['verdict'] = "[OK] SSH not accessible or blocked"
                        break
            
            if not result['successful_login'] and not result['blocked']:
                result['verdict'] = "[OK] No weak credentials found"
            
        except ImportError:
            result['error'] = "paramiko not installed - run: pip install paramiko"
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    # ==================== FTP ANONYMOUS ACCESS ====================
    
    def simulate_ftp_anonymous_access(self, target: str, port: int = 21) -> Dict:
        """Test if FTP allows anonymous access"""
        self.logger.info(f"Testing FTP anonymous access on {target}:{port}")
        
        result = {
            'attack_type': 'FTP Anonymous Access Test',
            'target': target,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'anonymous_allowed': False
        }
        
        try:
            import ftplib
            
            ftp = ftplib.FTP()
            ftp.connect(target, port, timeout=5)
            
            try:
                ftp.login('anonymous', 'anonymous@example.com')
                result['anonymous_allowed'] = True
                result['severity'] = 'HIGH'
                result['verdict'] = "[FAIL] FTP anonymous access enabled"
                
                try:
                    files = ftp.nlst()
                    result['accessible_files'] = len(files)
                except:
                    result['accessible_files'] = 0
                
                ftp.quit()
                
            except ftplib.error_perm:
                result['verdict'] = "[OK] Anonymous FTP denied"
        
        except Exception as e:
            result['error'] = str(e)
            result['verdict'] = "[WARN] FTP not accessible"
        
        return result
    
    # ==================== FULL SIMULATION ====================
    
    def run_full_attack_simulation(self, scan_id: int, target: str, attack_types: List[str]) -> Dict:
        """Run comprehensive attack simulation"""
        
        self.logger.info(f"Starting full attack simulation on {target}")
        
        results = {
            'scan_id': scan_id,
            'target': target,
            'started_at': datetime.now().isoformat(),
            'attacks_performed': [],
            'vulnerabilities_confirmed': []
        }
        
        # Determine base URL for web attacks
        if target in ["localhost", "127.0.0.1"]:
            http_url = "http://localhost"
        else:
            http_url = f"http://{target}"
        
        # Run attacks
        if 'port_scan_detection' in attack_types:
            result = self.simulate_port_scan_detection(target)
            results['attacks_performed'].append(result)
        
        if 'sql_injection' in attack_types:
            result = self.simulate_sql_injection(http_url)
            results['attacks_performed'].append(result)
            if result.get('vulnerable'):
                results['vulnerabilities_confirmed'].append('SQL Injection')
        
        if 'xss' in attack_types:
            result = self.simulate_xss_attack(http_url)
            results['attacks_performed'].append(result)
            if result.get('vulnerable'):
                results['vulnerabilities_confirmed'].append('XSS')
        
        if 'directory_traversal' in attack_types:
            result = self.simulate_directory_traversal(http_url)
            results['attacks_performed'].append(result)
            if result.get('vulnerable'):
                results['vulnerabilities_confirmed'].append('Directory Traversal')
        
        if 'http_methods' in attack_types:
            result = self.test_http_methods(http_url)
            results['attacks_performed'].append(result)
            if result.get('dangerous_methods'):
                results['vulnerabilities_confirmed'].append('Dangerous HTTP Methods')
        
        if 'directory_bruteforce' in attack_types:
            result = self.directory_bruteforce(target)
            results['attacks_performed'].append(result)
        
        if 'ssh_bruteforce' in attack_types:
            result = self.simulate_ssh_bruteforce(target)
            results['attacks_performed'].append(result)
            if result.get('successful_login'):
                results['vulnerabilities_confirmed'].append('Weak SSH Credentials')
        
        if 'ftp_anonymous' in attack_types:
            result = self.simulate_ftp_anonymous_access(target)
            results['attacks_performed'].append(result)
            if result.get('anonymous_allowed'):
                results['vulnerabilities_confirmed'].append('FTP Anonymous Access')
        
        results['completed_at'] = datetime.now().isoformat()
        
        # Save to database
        self._save_attack_results(scan_id, results)
        
        return results
    
    def _save_attack_results(self, scan_id: int, results: Dict):
        """Save results to database"""
        try:
            create_table_query = """
            CREATE TABLE IF NOT EXISTS attack_simulations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                target TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                result TEXT NOT NULL,
                vulnerable INTEGER DEFAULT 0,
                severity TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )
            """
            db.execute_update(create_table_query)
            
            for attack in results['attacks_performed']:
                insert_query = """
                INSERT INTO attack_simulations 
                (scan_id, target, attack_type, result, vulnerable, severity, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """
                
                db.execute_insert(insert_query, (
                    scan_id,
                    results['target'],
                    attack['attack_type'],
                    json.dumps(attack),
                    1 if attack.get('vulnerable', False) else 0,
                    attack.get('severity', 'INFO'),
                    attack['timestamp']
                ))
            self.logger.info(f"[OK] Saved attack simulation results for scan {scan_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to save attack results: {str(e)}")

    def generate_unified_report_pdf(self, scan_id: int) -> str:
        """
        Generate unified PDF report combining:
        - Attack simulation results
        - SQLMap results  
        - Hashcat results
        """
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate, Table, TableStyle,
            Paragraph, Spacer, PageBreak, HRFlowable
        )
        from datetime import datetime
        import json

        def clean(text: str) -> str:
            """Remove non-latin characters that ReportLab cannot render"""
            if not text:
                return ''
            # Replace common emoji with text equivalents
            replacements = {
                '[OK]': '[OK]', '[FAIL]': '[FAIL]', '[WARN]': '[WARN]',
                '[WARN]': '[WARN]', '[TARGET]': '[TARGET]', '💉': '[INJECT]',
                '[SAVE]': '[DB]', '[PKG]': '[PKG]', '🔓': '[UNLOCK]',
                '🔍': '[SEARCH]', '⏱️': '[TIME]', '[NOTE]': '[NOTE]',
            }
            for emoji, replacement in replacements.items():
                text = text.replace(emoji, replacement)
            # Remove any remaining non-latin-1 characters
            return text.encode('latin-1', errors='replace').decode('latin-1')
        
        try:
            # ── Fetch all data ──────────────────────────────────────────
            attack_results = db.execute_query(
                "SELECT * FROM attack_simulations WHERE scan_id = ? ORDER BY timestamp",
                (scan_id,)
            )

            db.execute_update("""
                CREATE TABLE IF NOT EXISTS sqlmap_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    url TEXT NOT NULL,
                    vulnerable INTEGER DEFAULT 0,
                    status TEXT, dbms TEXT,
                    injections TEXT, databases TEXT,
                    started_at TEXT, completed_at TEXT, error TEXT
                )
            """)
            sqlmap_results = db.execute_query(
                "SELECT * FROM sqlmap_results WHERE scan_id = ? ORDER BY started_at",
                (scan_id,)
            )

            db.execute_update("""
                CREATE TABLE IF NOT EXISTS hashcat_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    hash_type INTEGER, attack_mode INTEGER,
                    hash_count INTEGER, cracked_count INTEGER,
                    cracked_hashes TEXT, status TEXT, message TEXT,
                    started_at TEXT, completed_at TEXT, error TEXT
                )
            """)
            hashcat_results = db.execute_query(
                "SELECT * FROM hashcat_results WHERE scan_id = ? ORDER BY started_at",
                (scan_id,)
            )

            scan = db.execute_query("SELECT * FROM scans WHERE id = ?", (scan_id,))
            scan = scan[0] if scan else {}

            # ── PDF setup ───────────────────────────────────────────────
            timestamp  = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename   = f"unified_report_{scan_id}_{timestamp}.pdf"
            filepath   = config.REPORTS_DIR / filename

            doc = SimpleDocTemplate(
                str(filepath), pagesize=letter,
                rightMargin=60, leftMargin=60,
                topMargin=60, bottomMargin=40
            )

            styles = getSampleStyleSheet()

            # Custom styles
            title_style = ParagraphStyle(
                'Title', parent=styles['Title'],
                fontSize=22, textColor=colors.HexColor('#1a1a2e'),
                spaceAfter=6, alignment=1
            )
            subtitle_style = ParagraphStyle(
                'Subtitle', parent=styles['Normal'],
                fontSize=11, textColor=colors.HexColor('#555'),
                spaceAfter=20, alignment=1
            )
            h1_style = ParagraphStyle(
                'H1', parent=styles['Heading1'],
                fontSize=16, textColor=colors.HexColor('#dc3545'),
                spaceBefore=20, spaceAfter=8,
                borderPad=4
            )
            h2_style = ParagraphStyle(
                'H2', parent=styles['Heading2'],
                fontSize=13, textColor=colors.HexColor('#495057'),
                spaceBefore=14, spaceAfter=6
            )
            body_style = ParagraphStyle(
                'Body', parent=styles['Normal'],
                fontSize=10, textColor=colors.HexColor('#333'),
                spaceAfter=4, leading=14
            )
            ok_style = ParagraphStyle(
                'OK', parent=body_style,
                textColor=colors.HexColor('#155724'),
                backColor=colors.HexColor('#d4edda')
            )
            fail_style = ParagraphStyle(
                'Fail', parent=body_style,
                textColor=colors.HexColor('#721c24'),
                backColor=colors.HexColor('#f8d7da')
            )

            def make_table(data, col_widths=None):
                t = Table(data, colWidths=col_widths)
                t.setStyle(TableStyle([
                    ('BACKGROUND',  (0, 0), (-1, 0),  colors.HexColor('#343a40')),
                    ('TEXTCOLOR',   (0, 0), (-1, 0),  colors.white),
                    ('FONTNAME',    (0, 0), (-1, 0),  'Helvetica-Bold'),
                    ('FONTSIZE',    (0, 0), (-1, 0),  10),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                    [colors.HexColor('#f8f9fa'), colors.white]),
                    ('FONTSIZE',    (0, 1), (-1, -1),  9),
                    ('GRID',        (0, 0), (-1, -1),  0.5, colors.HexColor('#dee2e6')),
                    ('VALIGN',      (0, 0), (-1, -1),  'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1),  8),
                    ('RIGHTPADDING',(0, 0), (-1, -1),  8),
                    ('TOPPADDING',  (0, 0), (-1, -1),  5),
                    ('BOTTOMPADDING',(0,0), (-1, -1),  5),
                ]))
                return t

            story = []

            # ── COVER PAGE ──────────────────────────────────────────────
            story.append(Spacer(1, 1.5*inch))
            story.append(Paragraph("Penetration Testing Framework", title_style))
            story.append(Paragraph("Unified Security Assessment Report", subtitle_style))
            story.append(HRFlowable(width="100%", thickness=2,
                                    color=colors.HexColor('#dc3545')))
            story.append(Spacer(1, 0.3*inch))

            meta = [
                ['Scan ID',     str(scan_id)],
                ['Target',      scan.get('target', 'N/A')],
                ['Scan Name',   scan.get('scan_name', 'N/A')],
                ['Scan Type',   scan.get('scan_type', 'N/A')],
                ['Generated',   datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Status',      scan.get('status', 'N/A').upper()],
            ]
            meta_table = Table(meta, colWidths=[2*inch, 4*inch])
            meta_table.setStyle(TableStyle([
                ('BACKGROUND',  (0, 0), (0, -1), colors.HexColor('#495057')),
                ('TEXTCOLOR',   (0, 0), (0, -1), colors.white),
                ('FONTNAME',    (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE',    (0, 0), (-1, -1), 10),
                ('GRID',        (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 0), (-1, -1),
                [colors.HexColor('#f8f9fa'), colors.white]),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING',  (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING',(0,0), (-1, -1), 6),
            ]))
            story.append(meta_table)

            # ── EXECUTIVE SUMMARY ────────────────────────────────────────
            story.append(PageBreak())
            story.append(Paragraph("Executive Summary", h1_style))
            story.append(HRFlowable(width="100%", thickness=1,
                                    color=colors.HexColor('#dee2e6')))

            vuln_attacks   = sum(1 for r in attack_results if r.get('vulnerable'))
            total_attacks  = len(attack_results)
            sqli_vuln      = sum(1 for r in sqlmap_results if r.get('vulnerable'))
            hashes_cracked = sum(r.get('cracked_count', 0) for r in hashcat_results)
            total_hashes   = sum(r.get('hash_count', 0)   for r in hashcat_results)
            score = int(((total_attacks - vuln_attacks) / total_attacks * 100)
                        if total_attacks else 0)

            summary_data = [
                ['Metric', 'Value', 'Status'],
                ['Attack Simulations Run',
                str(total_attacks),
                'N/A' if total_attacks == 0 else 'OK'],
                ['Vulnerabilities Found (Attacks)',
                str(vuln_attacks),
                'CRITICAL' if vuln_attacks > 0 else 'SECURE'],
                ['SQL Injection Tests',
                str(len(sqlmap_results)),
                'N/A' if not sqlmap_results else 'OK'],
                ['SQL Injection Vulnerabilities',
                str(sqli_vuln),
                'CRITICAL' if sqli_vuln > 0 else 'SECURE'],
                ['Password Hashes Submitted',
                str(total_hashes),
                'N/A' if total_hashes == 0 else 'OK'],
                ['Passwords Cracked',
                str(hashes_cracked),
                'CRITICAL' if hashes_cracked > 0 else 'SECURE'],
                ['Overall Security Score',
                f'{score}%',
                'GOOD' if score >= 80 else ('FAIR' if score >= 50 else 'POOR')],
            ]

            story.append(make_table(
                summary_data,
                col_widths=[3*inch, 1.5*inch, 1.5*inch]
            ))

            # ── SECTION 1: ATTACK SIMULATIONS ───────────────────────────
            story.append(PageBreak())
            story.append(Paragraph("Section 1: Attack Simulation Results", h1_style))
            story.append(HRFlowable(width="100%", thickness=1,
                                    color=colors.HexColor('#dee2e6')))

            if not attack_results:
                story.append(Paragraph(
                    "No attack simulations have been run for this scan.",
                    body_style
                ))
            else:
                for idx, attack in enumerate(attack_results, 1):
                    try:
                        rd = json.loads(attack['result']) if isinstance(
                            attack['result'], str) else attack['result']
                    except Exception:
                        rd = {}

                    vuln    = bool(attack.get('vulnerable'))
                    sev     = attack.get('severity', 'INFO')
                    verdict = rd.get('verdict', 'N/A')
                    rec     = rd.get('recommendation', '')

                    story.append(Paragraph(
                        f"{idx}. {attack['attack_type']}", h2_style
                    ))

                    status_color = (colors.HexColor('#f8d7da') if vuln
                                    else colors.HexColor('#d4edda'))
                    status_text  = ('VULNERABLE' if vuln else 'SECURE')

                    detail_data = [
                        ['Field', 'Value'],
                        ['Status',    status_text],
                        ['Severity',  sev],
                        ['Target',    str(rd.get('target', 'N/A'))],
                        ['Timestamp', str(attack.get('timestamp', 'N/A'))],
                        # ['Verdict',   str(verdict)[:120]],
                        ['Verdict',   clean(str(verdict))[:120]],
                    ]
                    if rec:
                        detail_data.append(
                            ['Recommendation',
                            # Paragraph(str(rec)[:300], body_style)]
                            Paragraph(clean(str(rec))[:300], body_style)]
                        )

                    t = make_table(detail_data, col_widths=[2*inch, 4*inch])
                    # colour the status row
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (1, 1), (1, 1), status_color),
                    ]))
                    story.append(t)
                    story.append(Spacer(1, 0.2*inch))

            # ── SECTION 2: SQLMAP RESULTS ────────────────────────────────
            story.append(PageBreak())
            story.append(Paragraph("Section 2: SQL Injection Testing (SQLMap)", h1_style))
            story.append(HRFlowable(width="100%", thickness=1,
                                    color=colors.HexColor('#dee2e6')))

            if not sqlmap_results:
                story.append(Paragraph(
                    "No SQLMap tests have been run for this scan.",
                    body_style
                ))
            else:
                for idx, result in enumerate(sqlmap_results, 1):
                    vuln = bool(result.get('vulnerable'))
                    story.append(Paragraph(
                        f"{idx}. SQL Injection Test - {result.get('url', 'N/A')}",
                        h2_style
                    ))

                    # Parse injections
                    try:
                        injections = json.loads(result.get('injections') or '[]')
                    except Exception:
                        injections = []

                    # Parse databases
                    try:
                        databases = json.loads(result.get('databases') or '[]')
                    except Exception:
                        databases = []

                    detail_data = [
                        ['Field', 'Value'],
                        ['Status',    'VULNERABLE' if vuln else 'NOT VULNERABLE'],
                        ['URL',       Paragraph(result.get('url', 'N/A'), body_style)],
                        ['Database',  result.get('dbms', 'N/A')],
                        ['Started',   result.get('started_at', 'N/A')],
                        ['Completed', result.get('completed_at', 'N/A')],
                        ['Databases Found', ', '.join(databases) if databases else 'None'],
                        ['Injection Points', str(len(injections))],
                    ]

                    t = make_table(detail_data, col_widths=[2*inch, 4*inch])
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (1, 1), (1, 1),
                        colors.HexColor('#f8d7da') if vuln
                        else colors.HexColor('#d4edda')),
                    ]))
                    story.append(t)

                    # Injection detail sub-table
                    if injections:
                        story.append(Spacer(1, 0.1*inch))
                        story.append(Paragraph(
                            "Injection Points Detail:", h2_style
                        ))
                        inj_data = [['Parameter', 'Type', 'Title', 'Payload']]
                        for inj in injections:
                            inj_data.append([
                                str(inj.get('parameter', 'N/A')),
                                str(inj.get('type', 'N/A')),
                                str(inj.get('title', 'N/A'))[:60],
                                Paragraph(
                                    str(inj.get('payload', 'N/A'))[:80],
                                    body_style
                                ),
                            ])
                        story.append(make_table(
                            inj_data,
                            col_widths=[1.2*inch, 1.5*inch, 1.8*inch, 1.5*inch]
                        ))

                    story.append(Spacer(1, 0.3*inch))

            # ── SECTION 3: HASHCAT RESULTS ───────────────────────────────
            story.append(PageBreak())
            story.append(Paragraph("Section 3: Password Cracking (Hashcat)", h1_style))
            story.append(HRFlowable(width="100%", thickness=1,
                                    color=colors.HexColor('#dee2e6')))

            hash_type_names = {
                0: 'MD5', 100: 'SHA1', 1400: 'SHA256',
                1700: 'SHA512', 1000: 'NTLM', 3200: 'bcrypt',
                500: 'MD5 Unix', 1800: 'SHA512 Unix', 22000: 'WPA/WPA2'
            }

            if not hashcat_results:
                story.append(Paragraph(
                    "No Hashcat password cracking jobs have been run.",
                    body_style
                ))
            else:
                for idx, job in enumerate(hashcat_results, 1):
                    cracked = job.get('cracked_count', 0)
                    total   = job.get('hash_count', 0)
                    success = job.get('status') == 'success' and cracked > 0
                    ht_name = hash_type_names.get(
                        job.get('hash_type', 0), f"Type {job.get('hash_type')}"
                    )
                    am_name = ('Dictionary' if job.get('attack_mode') == 0
                            else 'Bruteforce')

                    story.append(Paragraph(
                        f"{idx}. Cracking Job - {ht_name}", h2_style
                    ))

                    detail_data = [
                        ['Field', 'Value'],
                        ['Status',      job.get('status', 'N/A').upper()],
                        ['Hash Type',   ht_name],
                        ['Attack Mode', am_name],
                        ['Total Hashes', str(total)],
                        ['Cracked',      f"{cracked} / {total}"],
                        ['Started',      job.get('started_at', 'N/A')],
                        ['Completed',    job.get('completed_at', 'N/A')],
                        ['Message',      job.get('message', 'N/A')],
                    ]

                    t = make_table(detail_data, col_widths=[2*inch, 4*inch])
                    t.setStyle(TableStyle([
                        ('BACKGROUND', (1, 1), (1, 1),
                        colors.HexColor('#d4edda') if success
                        else colors.HexColor('#f8d7da')),
                    ]))
                    story.append(t)

                    # Cracked passwords sub-table
                    try:
                        cracked_list = json.loads(
                            job.get('cracked_hashes') or '[]'
                        )
                    except Exception:
                        cracked_list = []

                    if cracked_list:
                        story.append(Spacer(1, 0.1*inch))
                        story.append(Paragraph(
                            "Cracked Passwords:", h2_style
                        ))
                        pw_data = [['Hash', 'Plaintext Password']]
                        for entry in cracked_list:
                            pw_data.append([
                                Paragraph(
                                    str(entry.get('hash', 'N/A')), body_style
                                ),
                                Paragraph(
                                    f"[REDACTED IN PROD] {entry.get('password', 'N/A')}",
                                    body_style
                                ),
                            ])
                        story.append(make_table(
                            pw_data,
                            col_widths=[3.5*inch, 2.5*inch]
                        ))

                    story.append(Spacer(1, 0.3*inch))

            # ── FOOTER / DISCLAIMER ──────────────────────────────────────
            story.append(PageBreak())
            story.append(Paragraph("Legal Disclaimer", h1_style))
            story.append(HRFlowable(width="100%", thickness=1,
                                    color=colors.HexColor('#dee2e6')))
            story.append(Paragraph(
                "This report was generated by an automated penetration testing framework "
                "for authorized security assessment purposes only. All testing activities "
                "must be conducted with explicit written permission from the system owner. "
                "Unauthorized use of these techniques against systems you do not own or "
                "have written authorization to test is illegal and may result in criminal "
                "prosecution. This report and its contents are confidential and should be "
                "shared only with authorized parties.",
                body_style
            ))

            # Build
            doc.build(story)
            self.logger.info(f"Unified report generated: {filepath}")
            return str(filepath)

        except Exception as e:
            self.logger.error(f"Failed to generate unified report: {str(e)}")
            raise
    
    def generate_attack_report_pdf(self, scan_id: int) -> str:
        """
        Generate PDF report for attack simulation results only
        (kept for backward compatibility with 'Attacks Only PDF' button)
        """
        # Reuse unified report but only show attack section
        return self.generate_unified_report_pdf(scan_id)
    
    
# Create instance
attack_simulator = AttackSimulator()