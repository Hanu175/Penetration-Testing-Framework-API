"""
Attack Simulation Service
Simulates real-world attacks to test security defenses
"""

import socket
import requests
import time
import subprocess
import re
from datetime import datetime
from typing import Dict, List
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import get_config
from utils.logger import setup_logger
from utils.database import db

config = get_config()
logger = setup_logger('attack_simulator')

class AttackSimulator:
    """Simulates various attack types to test defenses"""
    
    def __init__(self):
        self.logger = logger
        self.results = []
    
    # # ==================== NETWORK ATTACKS ====================
    
    # def simulate_port_scan_detection(self, target: str) -> Dict:
    #     """
    #     Test if target can detect port scanning
    #     Performs aggressive scan to trigger IDS
    #     """
    #     self.logger.info(f"Testing port scan detection on {target}")
        
    #     result = {
    #         'attack_type': 'Port Scan Detection Test',
    #         'target': target,
    #         'timestamp': datetime.now().isoformat(),
    #         'detected': False,
    #         'details': []
    #     }
        
    #     try:
    #         # Aggressive rapid port scan (should trigger IDS)
    #         common_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]
            
    #         start_time = time.time()
    #         scanned_count = 0
            
    #         for port in common_ports:
    #             try:
    #                 sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #                 sock.settimeout(0.1)  # Very fast = suspicious
    #                 sock.connect((target, port))
    #                 sock.close()
    #                 result['details'].append(f"Port {port}: Open")
    #                 scanned_count += 1
    #             except:
    #                 scanned_count += 1
            
    #         duration = time.time() - start_time
            
    #         result['scan_duration'] = f"{duration:.2f} seconds"
    #         result['ports_scanned'] = scanned_count
    #         result['scan_rate'] = f"{scanned_count/duration:.1f} ports/sec"
    #         result['verdict'] = "Fast scan completed - would trigger most IDS systems"
    #         result['recommendation'] = (
    #             "If this scan was not detected by your IDS/IPS, "
    #             "consider tuning detection rules for rapid port scanning."
    #         )
            
    #     except Exception as e:
    #         result['error'] = str(e)
        
    #     return result
    
    # # ==================== WEB APPLICATION ATTACKS ====================
    
    # def simulate_sql_injection(self, url: str) -> Dict:
    #     """
    #     Test SQL injection vulnerabilities
    #     Attempts common SQL injection payloads
    #     """
    #     self.logger.info(f"Testing SQL injection on {url}")
        
    #     result = {
    #         'attack_type': 'SQL Injection Test',
    #         'target': url,
    #         'timestamp': datetime.now().isoformat(),
    #         'vulnerable': False,
    #         'payloads_tested': [],
    #         'successful_payloads': []
    #     }
        
    #     # Common SQL injection payloads
    #     payloads = [
    #         "' OR '1'='1",
    #         "' OR '1'='1' --",
    #         "' OR '1'='1' /*",
    #         "admin' --",
    #         "admin' #",
    #         "' UNION SELECT NULL--",
    #         "1' AND '1'='2",
    #         "1 OR 1=1",
    #     ]
        
    #     try:
    #         # Get baseline response
    #         try:
    #             baseline = requests.get(url, timeout=5)
    #             baseline_length = len(baseline.text)
    #         except:
    #             baseline_length = 0
            
    #         for payload in payloads:
    #             result['payloads_tested'].append(payload)
                
    #             # Test in URL parameter
    #             test_url = f"{url}?id={payload}"
                
    #             try:
    #                 response = requests.get(test_url, timeout=5)
                    
    #                 # Check for SQL error messages (indicates vulnerability)
    #                 error_indicators = [
    #                     'sql', 'mysql', 'sqlite', 'postgresql', 'oracle',
    #                     'syntax error', 'database error', 'query failed',
    #                     'you have an error in your sql syntax',
    #                     'warning: mysql', 'unclosed quotation mark',
    #                     'quoted string not properly terminated'
    #                 ]
                    
    #                 response_lower = response.text.lower()
                    
    #                 for indicator in error_indicators:
    #                     if indicator in response_lower:
    #                         result['vulnerable'] = True
    #                         result['successful_payloads'].append(payload)
    #                         result['evidence'] = f"Found '{indicator}' in response"
    #                         break
                    
    #                 # Check for boolean-based injection (length change)
    #                 if abs(len(response.text) - baseline_length) > 100:
    #                     if payload not in result['successful_payloads']:
    #                         result['vulnerable'] = True
    #                         result['successful_payloads'].append(payload)
    #                         result['evidence'] = "Response length changed significantly"
                
    #             except requests.RequestException:
    #                 pass
            
    #         if result['vulnerable']:
    #             result['severity'] = 'CRITICAL'
    #             result['recommendation'] = (
    #                 "CRITICAL: SQL injection vulnerability detected! "
    #                 "Use parameterized queries/prepared statements. "
    #                 "Implement input validation and WAF rules."
    #             )
    #         else:
    #             result['verdict'] = "✅ No SQL injection detected"
    #             result['recommendation'] = "Continue using secure coding practices"
            
    #     except Exception as e:
    #         result['error'] = str(e)
        
    #     return result
    
    
    def simulate_port_scan_detection(self, target: str) -> Dict:
        """
        Test if target can detect port scanning
        Performs aggressive scan to trigger IDS
        """
        self.logger.info(f"Testing port scan detection on {target}")
        
        result = {
            'attack_type': 'Port Scan Detection Test',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'detected': False,
            'details': []
        }
        
        try:
            # REDUCED: Only scan 7 ports instead of 10
            common_ports = [21, 22, 80, 443, 3306, 3389, 8080]
            
            start_time = time.time()
            scanned_count = 0
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.05)  # REDUCED: 0.05 instead of 0.1
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
            result['recommendation'] = (
                "If this scan was not detected by your IDS/IPS, "
                "consider tuning detection rules for rapid port scanning."
            )
            
        except Exception as e:
            result['error'] = str(e)
        
        return result

    def simulate_sql_injection(self, url: str) -> Dict:
        """Test SQL injection - FASTER VERSION"""
        self.logger.info(f"Testing SQL injection on {url}")
        
        result = {
            'attack_type': 'SQL Injection Test',
            'target': url,
            'timestamp': datetime.now().isoformat(),
            'vulnerable': False,
            'payloads_tested': [],
            'successful_payloads': []
        }
        
        # REDUCED: Only 5 payloads instead of 8
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "admin' --",
            "1' AND '1'='2",
            "1 OR 1=1",
        ]
        
        try:
            # OPTIMIZED: Skip baseline check, just test payloads
            for payload in payloads:
                result['payloads_tested'].append(payload)
                test_url = f"{url}?id={payload}"
                
                try:
                    response = requests.get(test_url, timeout=2)  # REDUCED: 2 instead of 5
                    
                    error_indicators = [
                        'sql', 'mysql', 'sqlite', 'syntax error', 'database error'
                    ]
                    
                    response_lower = response.text.lower()
                    
                    for indicator in error_indicators:
                        if indicator in response_lower:
                            result['vulnerable'] = True
                            result['successful_payloads'].append(payload)
                            result['evidence'] = f"Found '{indicator}' in response"
                            # OPTIMIZATION: Stop after first success
                            break
                    
                    if result['vulnerable']:
                        break  # No need to test more
                
                except requests.RequestException:
                    pass
            
            if result['vulnerable']:
                result['severity'] = 'CRITICAL'
                result['recommendation'] = (
                    "CRITICAL: SQL injection vulnerability detected! "
                    "Use parameterized queries/prepared statements."
                )
            else:
                result['verdict'] = "✅ No SQL injection detected"
                result['recommendation'] = "Continue using secure coding practices"
            
        except Exception as e:
            result['error'] = str(e)
        
        return result

    def simulate_xss_attack(self, url: str) -> Dict:
        """Test XSS - FASTER VERSION"""
        self.logger.info(f"Testing XSS on {url}")
        
        result = {
            'attack_type': 'Cross-Site Scripting (XSS) Test',
            'target': url,
            'timestamp': datetime.now().isoformat(),
            'vulnerable': False,
            'payloads_tested': [],
            'successful_payloads': []
        }
        
        # REDUCED: Only 4 payloads instead of 8
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "';alert('XSS');//",
        ]
        
        try:
            for payload in payloads:
                result['payloads_tested'].append(payload)
                test_url = f"{url}?q={payload}"
                
                try:
                    response = requests.get(test_url, timeout=2)  # REDUCED: 2 instead of 5
                    
                    if payload in response.text:
                        result['vulnerable'] = True
                        result['successful_payloads'].append(payload)
                        result['evidence'] = "Payload reflected in response without encoding"
                        break  # OPTIMIZATION: Stop after first success
                
                except requests.RequestException:
                    pass
            
            if result['vulnerable']:
                result['severity'] = 'HIGH'
                result['recommendation'] = (
                    "HIGH: XSS vulnerability detected! "
                    "Implement output encoding and CSP."
                )
            else:
                result['verdict'] = "✅ No XSS vulnerabilities detected"
            
        except Exception as e:
            result['error'] = str(e)
        
        return result

    def simulate_ssh_bruteforce(self, target: str, port: int = 22, max_attempts: int = 3) -> Dict:
        """Test SSH - FASTER with FEWER attempts"""
        self.logger.info(f"Testing SSH bruteforce protection on {target}:{port}")
        
        result = {
            'attack_type': 'SSH Bruteforce Test',
            'target': target,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'attempts': 0,
            'successful_login': False,
            'blocked': False
        }
        
        # REDUCED: Only 3 attempts instead of 5
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
                        timeout=2,  # REDUCED: 2 instead of 5
                        look_for_keys=False, allow_agent=False
                    )
                    
                    result['successful_login'] = True
                    result['credentials'] = f"{username}:{password}"
                    result['severity'] = 'CRITICAL'
                    result['verdict'] = f"❌ Weak credentials: {username}:{password}"
                    ssh.close()
                    break
                    
                except paramiko.AuthenticationException:
                    time.sleep(0.5)  # REDUCED: 0.5 instead of 1
                    
                except Exception as e:
                    if 'refused' in str(e).lower():
                        result['blocked'] = True
                        result['verdict'] = "✅ SSH service not accessible or blocked"
                        break
            
            if result['successful_login']:
                result['recommendation'] = "CRITICAL: Weak SSH credentials!"
            elif result['blocked']:
                result['recommendation'] = "Good: Service protected"
            else:
                result['verdict'] = "✅ No weak credentials found"
            
        except ImportError:
            result['error'] = "paramiko not installed"
        except Exception as e:
            result['error'] = str(e)
        
        return result

    def directory_bruteforce(self, target: str, port: int = 80) -> Dict:
        """Directory bruteforce - FASTER VERSION"""
        self.logger.info(f"Testing directory bruteforce on {target}")
        
        result = {
            'attack_type': 'Directory Bruteforce',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'found_directories': [],
            'tested_count': 0
        }
        
        # REDUCED: Only 10 directories instead of 18
        common_dirs = [
            'admin', 'login', 'wp-admin', 'phpmyadmin', 'backup',
            'config', 'api', 'uploads', 'dashboard', 'panel'
        ]
        
        try:
            base_url = f"http://{target}:{port}"
            
            for directory in common_dirs:
                result['tested_count'] += 1
                test_url = f"{base_url}/{directory}"
                
                try:
                    response = requests.get(test_url, timeout=1, allow_redirects=False)  # REDUCED: 1 instead of 3
                    if response.status_code in [200, 301, 302, 403]:
                        result['found_directories'].append({
                            'path': directory,
                            'status': response.status_code
                        })
                except:
                    pass
            
            if result['found_directories']:
                result['verdict'] = f"Found {len(result['found_directories'])} directories"
            else:
                result['verdict'] = "✅ No common directories found"
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def simulate_xss_attack(self, url: str) -> Dict:
        """
        Test Cross-Site Scripting vulnerabilities
        Attempts to inject JavaScript
        """
        self.logger.info(f"Testing XSS on {url}")
        
        result = {
            'attack_type': 'Cross-Site Scripting (XSS) Test',
            'target': url,
            'timestamp': datetime.now().isoformat(),
            'vulnerable': False,
            'payloads_tested': [],
            'successful_payloads': []
        }
        
        # XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "';alert('XSS');//",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<input onfocus=alert('XSS') autofocus>",
        ]
        
        try:
            for payload in payloads:
                result['payloads_tested'].append(payload)
                
                # Test in URL parameter
                test_url = f"{url}?q={payload}"
                
                try:
                    response = requests.get(test_url, timeout=5)
                    
                    # Check if payload is reflected unescaped
                    if payload in response.text:
                        result['vulnerable'] = True
                        result['successful_payloads'].append(payload)
                        result['evidence'] = "Payload reflected in response without encoding"
                    
                    # Check for partial reflection
                    elif 'alert' in response.text and 'XSS' in response.text:
                        result['vulnerable'] = True
                        result['successful_payloads'].append(payload)
                        result['evidence'] = "Partial payload reflection detected"
                
                except requests.RequestException:
                    pass
            
            if result['vulnerable']:
                result['severity'] = 'HIGH'
                result['recommendation'] = (
                    "HIGH: XSS vulnerability detected! "
                    "Implement output encoding, Content Security Policy (CSP), "
                    "and input validation to prevent XSS attacks."
                )
            else:
                result['verdict'] = "✅ No XSS vulnerabilities detected"
                result['recommendation'] = "Good: Input is being sanitized properly"
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def simulate_directory_traversal(self, url: str) -> Dict:
        """
        Test path traversal vulnerabilities
        Attempts to access files outside web root
        """
        self.logger.info(f"Testing directory traversal on {url}")
        
        result = {
            'attack_type': 'Directory Traversal Test',
            'target': url,
            'timestamp': datetime.now().isoformat(),
            'vulnerable': False,
            'payloads_tested': [],
            'files_accessed': []
        }
        
        # Path traversal payloads
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system.ini",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "../../../../../../../etc/passwd",
            "..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ]
        
        try:
            for payload in payloads:
                result['payloads_tested'].append(payload)
                
                test_url = f"{url}?file={payload}"
                
                try:
                    response = requests.get(test_url, timeout=5)
                    
                    # Check for sensitive file content
                    sensitive_patterns = [
                        'root:',           # Linux /etc/passwd
                        '[extensions]',    # Windows system.ini
                        'daemon:',         # Unix system files
                        'boot loader',     # Windows boot.ini
                        '[fonts]',         # Windows win.ini
                    ]
                    
                    for pattern in sensitive_patterns:
                        if pattern.lower() in response.text.lower():
                            result['vulnerable'] = True
                            result['files_accessed'].append(payload)
                            result['evidence'] = f"Successfully accessed system files - found '{pattern}'"
                            break
                
                except requests.RequestException:
                    pass
            
            if result['vulnerable']:
                result['severity'] = 'CRITICAL'
                result['recommendation'] = (
                    "CRITICAL: Directory traversal vulnerability detected! "
                    "Implement strict input validation, use whitelists for file access, "
                    "and avoid user input in file paths."
                )
            else:
                result['verdict'] = "✅ No directory traversal detected"
                result['recommendation'] = "Good: File access controls are working"
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def test_http_methods(self, url: str) -> Dict:
        """
        Test for dangerous HTTP methods
        """
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
        
        try:
            for method in methods:
                try:
                    response = requests.request(method, url, timeout=5)
                    if response.status_code not in [405, 501]:  # Method not allowed
                        result['all_methods'].append(method)
                        if method in dangerous:
                            result['dangerous_methods'].append(method)
                except:
                    pass
            
            if result['dangerous_methods']:
                result['severity'] = 'MEDIUM'
                result['verdict'] = f"⚠️ Dangerous methods enabled: {', '.join(result['dangerous_methods'])}"
                result['recommendation'] = "Disable unnecessary HTTP methods in web server configuration"
            else:
                result['verdict'] = "✅ No dangerous HTTP methods detected"
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def directory_bruteforce(self, target: str, port: int = 80) -> Dict:
        """
        Brute force common directories
        """
        self.logger.info(f"Testing directory bruteforce on {target}")
        
        result = {
            'attack_type': 'Directory Bruteforce',
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'found_directories': [],
            'tested_count': 0
        }
        
        common_dirs = [
            'admin', 'administrator', 'login', 'wp-admin', 'phpmyadmin',
            'backup', 'config', 'test', 'dev', 'api', 'uploads', 'images',
            'css', 'js', 'includes', 'dashboard', 'panel', 'cpanel'
        ]
        
        try:
            base_url = f"http://{target}:{port}"
            
            for directory in common_dirs:
                result['tested_count'] += 1
                test_url = f"{base_url}/{directory}"
                
                try:
                    response = requests.get(test_url, timeout=3, allow_redirects=False)
                    if response.status_code in [200, 301, 302, 403]:
                        result['found_directories'].append({
                            'path': directory,
                            'status': response.status_code
                        })
                except:
                    pass
            
            if result['found_directories']:
                result['verdict'] = f"Found {len(result['found_directories'])} directories"
                result['recommendation'] = "Review exposed directories and restrict access if needed"
            else:
                result['verdict'] = "✅ No common directories found"
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    # ==================== SERVICE ATTACKS ====================
    
    def simulate_ssh_bruteforce(self, target: str, port: int = 22, max_attempts: int = 5) -> Dict:
        """
        Test SSH bruteforce protection
        """
        self.logger.info(f"Testing SSH bruteforce protection on {target}:{port}")
        
        result = {
            'attack_type': 'SSH Bruteforce Test',
            'target': target,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'attempts': 0,
            'successful_login': False,
            'blocked': False
        }
        
        # Common credentials
        credentials = [
            ('admin', 'admin'),
            ('root', 'root'),
            ('admin', 'password'),
            ('user', 'user'),
            ('test', 'test'),
        ][:max_attempts]
        
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            for username, password in credentials:
                result['attempts'] += 1
                
                try:
                    ssh.connect(
                        target,
                        port=port,
                        username=username,
                        password=password,
                        timeout=5,
                        look_for_keys=False,
                        allow_agent=False
                    )
                    
                    result['successful_login'] = True
                    result['credentials'] = f"{username}:{password}"
                    result['severity'] = 'CRITICAL'
                    result['verdict'] = f"❌ Weak credentials found: {username}:{password}"
                    ssh.close()
                    break
                    
                except paramiko.AuthenticationException:
                    # Failed login (expected)
                    time.sleep(1)
                    
                except Exception as e:
                    if 'refused' in str(e).lower() or 'blocked' in str(e).lower():
                        result['blocked'] = True
                        result['verdict'] = "✅ SSH bruteforce protection active (connection blocked)"
                        break
            
            if result['successful_login']:
                result['recommendation'] = (
                    "CRITICAL: Weak SSH credentials detected! "
                    "Implement strong password policy and consider key-based authentication."
                )
            elif result['blocked']:
                result['recommendation'] = "Good: Bruteforce protection is active (fail2ban or similar)"
            else:
                result['verdict'] = "✅ No weak credentials found in test set"
                result['recommendation'] = "Consider implementing fail2ban or similar protection"
            
        except ImportError:
            result['error'] = "paramiko module not installed. Run: pip install paramiko"
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def simulate_ftp_anonymous_access(self, target: str, port: int = 21) -> Dict:
        """
        Test if FTP allows anonymous access
        """
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
                # Try anonymous login
                ftp.login('anonymous', 'anonymous@example.com')
                result['anonymous_allowed'] = True
                result['severity'] = 'HIGH'
                result['verdict'] = "❌ FTP anonymous access is enabled"
                
                # Try to list files
                try:
                    files = ftp.nlst()
                    result['accessible_files'] = len(files)
                    result['sample_files'] = files[:5]  # First 5 files
                except:
                    result['accessible_files'] = 0
                
                ftp.quit()
                
                result['recommendation'] = (
                    "HIGH: Disable anonymous FTP access unless absolutely required. "
                    "Implement authentication and access controls."
                )
                
            except ftplib.error_perm:
                result['verdict'] = "✅ Anonymous FTP access denied"
                result['recommendation'] = "Good: FTP requires authentication"
        
        except Exception as e:
            result['error'] = str(e)
            result['verdict'] = "⚠️ FTP service not accessible"
        
        return result
    
    # ==================== COMPREHENSIVE ATTACK SIMULATION ====================
    
    def run_full_attack_simulation(self, scan_id: int, target: str, attack_types: List[str]) -> Dict:
        """
        Run comprehensive attack simulation
        
        Args:
            scan_id: Scan ID to attach results to
            target: Target system
            attack_types: List of attack types to simulate
        
        Returns:
            Comprehensive results
        """
        self.logger.info(f"Starting full attack simulation on {target}")
        
        results = {
            'scan_id': scan_id,
            'target': target,
            'started_at': datetime.now().isoformat(),
            'attacks_performed': [],
            'vulnerabilities_confirmed': [],
            'overall_security_score': 0
        }
        
        # Network attacks
        if 'port_scan_detection' in attack_types:
            result = self.simulate_port_scan_detection(target)
            results['attacks_performed'].append(result)
        
        # Determine protocol
        http_url = f"http://{target}"
        
        # Web attacks
        if 'sql_injection' in attack_types:
            result = self.simulate_sql_injection(http_url)
            results['attacks_performed'].append(result)
            if result.get('vulnerable'):
                results['vulnerabilities_confirmed'].append('SQL Injection')
        
        if 'xss' in attack_types:
            result = self.simulate_xss_attack(http_url)
            results['attacks_performed'].append(result)
            if result.get('vulnerable'):
                results['vulnerabilities_confirmed'].append('Cross-Site Scripting')
        
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
        
        # Service attacks
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
        
        # Calculate security score
        total_attacks = len(results['attacks_performed'])
        failed_attacks = len(results['vulnerabilities_confirmed'])
        
        if total_attacks > 0:
            results['overall_security_score'] = int(
                ((total_attacks - failed_attacks) / total_attacks) * 100
            )
        
        results['completed_at'] = datetime.now().isoformat()
        
        # Store in database
        self._save_attack_results(scan_id, results)
        
        return results
    
    def _save_attack_results(self, scan_id: int, results: Dict):
        """Save attack simulation results to database"""
        import json  # ADD THIS IMPORT
        
        try:
            # Create attack_simulations table if doesn't exist
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
            
            # Insert each attack result
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
                    json.dumps(attack),  # ✅ CORRECT! Creates valid JSON
                    1 if attack.get('vulnerable', False) else 0,  # Convert boolean to integer
                    attack.get('severity', 'INFO'),
                    attack['timestamp']
                ))
            
            self.logger.info(f"Saved attack simulation results for scan {scan_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to save attack results: {str(e)}")
    
    def generate_attack_report_pdf(self, scan_id: int) -> str:
        """
        Generate PDF report for attack simulation results
        
        Returns:
            Path to generated PDF file
        """
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
        from datetime import datetime
        import json
        
        try:
            # Get attack results
            query = """
            SELECT * FROM attack_simulations
            WHERE scan_id = ?
            ORDER BY timestamp DESC
            """
            results = db.execute_query(query, (scan_id,))
            
            if not results:
                raise ValueError("No attack simulation results found")
            
            # Get scan info
            from utils.database import get_scan_with_details
            scan = get_scan_with_details(scan_id)
            
            # Create filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"attack_report_{scan_id}_{timestamp}.pdf"
            filepath = config.REPORTS_DIR / filename
            
            # Create PDF
            doc = SimpleDocTemplate(
                str(filepath),
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            story = []
            styles = getSampleStyleSheet()
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#dc3545'),
                spaceAfter=30,
                alignment=1  # Center
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=14,
                textColor=colors.HexColor('#667eea'),
                spaceAfter=12,
                spaceBefore=20
            )
            
            # Title
            story.append(Paragraph("⚔️ Attack Simulation Report", title_style))
            story.append(Spacer(1, 0.3*inch))
            
            # Scan Information
            story.append(Paragraph("Scan Information", heading_style))
            
            scan_info_data = [
                ['Scan ID:', str(scan_id)],
                ['Scan Name:', scan.get('scan_name', 'N/A')],
                ['Target:', scan.get('target', 'N/A')],
                ['Scan Type:', scan.get('scan_type', 'N/A')],
                ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Total Attacks:', str(len(results))],
            ]
            
            scan_table = Table(scan_info_data, colWidths=[2*inch, 4*inch])
            scan_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
            ]))
            
            story.append(scan_table)
            story.append(Spacer(1, 0.5*inch))
            
            # Summary Statistics
            vulnerable_count = sum(1 for r in results if r.get('vulnerable'))
            secure_count = len(results) - vulnerable_count
            
            story.append(Paragraph("Summary", heading_style))
            
            summary_data = [
                ['Total Tests:', str(len(results))],
                ['Vulnerable:', str(vulnerable_count)],
                ['Secure:', str(secure_count)],
                ['Security Score:', f"{int((secure_count/len(results))*100)}%"],
            ]
            
            summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ]))
            
            story.append(summary_table)
            story.append(PageBreak())
            
            # Detailed Results
            story.append(Paragraph("Detailed Attack Results", heading_style))
            
            for idx, result in enumerate(results, 1):
                try:
                    result_data = json.loads(result['result'])
                    
                    # Attack header
                    attack_title = f"{idx}. {result['attack_type']}"
                    story.append(Paragraph(attack_title, heading_style))
                    
                    # Status color
                    if result.get('vulnerable'):
                        status_color = colors.HexColor('#dc3545')
                        status_text = '❌ VULNERABLE'
                    else:
                        status_color = colors.HexColor('#28a745')
                        status_text = '✅ SECURE'
                    
                    # Attack details - use Paragraph for long text
                    attack_details = [
                        ['Status:', Paragraph(status_text, styles['Normal'])],
                        ['Target:', Paragraph(str(result_data.get('target', 'N/A')), styles['Normal'])],
                        ['Timestamp:', Paragraph(str(result_data.get('timestamp', 'N/A')), styles['Normal'])],
                    ]

                    if result.get('severity'):
                        attack_details.append([
                            'Severity:', 
                            Paragraph(str(result['severity']), styles['Normal'])
                        ])

                    if result_data.get('verdict'):
                        attack_details.append([
                            'Verdict:', 
                            Paragraph(str(result_data['verdict']), styles['Normal'])
                        ])

                    if result_data.get('recommendation'):
                        # Wrap long recommendations
                        attack_details.append([
                            'Recommendation:', 
                            Paragraph(str(result_data['recommendation']), styles['Normal'])
                        ])

                    details_table = Table(attack_details, colWidths=[1.5*inch, 4.5*inch])
                    
                    details_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('LEFTPADDING', (0, 0), (-1, -1), 8),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                        ('TOPPADDING', (0, 0), (-1, -1), 6),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ('BACKGROUND', (1, 0), (1, 0), status_color),
                        ('TEXTCOLOR', (1, 0), (1, 0), colors.whitesmoke),
                    ]))
                    
                    story.append(details_table)
                    story.append(Spacer(1, 0.3*inch))
                    
                except json.JSONDecodeError:
                    self.logger.error(f"Failed to parse result data for attack {idx}")
            
            # Build PDF
            doc.build(story)
            
            self.logger.info(f"Attack report PDF generated: {filepath}")
            return str(filepath)
            
        except Exception as e:
            self.logger.error(f"Failed to generate attack report PDF: {str(e)}")
            raise

    

# Create attack simulator instance
attack_simulator = AttackSimulator()