"""
Analyzer Service
Identifies vulnerabilities by matching services against NVD database
"""

import requests
import time
from datetime import datetime
from typing import Dict, List, Optional
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import get_config
from utils.database import (
    db, add_vulnerability, update_scan_status, add_scan_log
)
from utils.logger import setup_logger

config = get_config()
logger = setup_logger('analyzer')

class AnalyzerService:
    """Vulnerability analysis service"""
    
    def __init__(self):
        self.logger = logger
        self.nvd_api_url = config.NVD_API_URL
        self.nvd_api_key = config.NVD_API_KEY
        self.rate_limit_delay = 6 if not self.nvd_api_key else 0.6
        self.last_request_time = 0
    
    def analyze_scan(self, scan_id: int) -> Dict:
        """
        Analyze scan results for vulnerabilities
        
        Args:
            scan_id: Database ID of the scan
        
        Returns:
            Dictionary with vulnerability statistics
        """
        try:
            add_scan_log(scan_id, 'INFO', 'Starting vulnerability analysis', 'analyzer')
            self.logger.info(f"[Scan {scan_id}] Starting vulnerability analysis")
            
            # Get all targets and ports from scan
            targets = self._get_scan_targets(scan_id)
            
            if not targets:
                self.logger.warning(f"[Scan {scan_id}] No targets found for analysis")
                return {'total_vulnerabilities': 0, 'by_severity': {}}
            
            vulnerabilities_found = 0
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            
            # Analyze each target
            for target in targets:
                target_vulns = self._analyze_target(scan_id, target)
                vulnerabilities_found += len(target_vulns)
                
                # Count by severity
                for vuln in target_vulns:
                    severity = vuln.get('severity', 'info')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Update scan with vulnerability counts
            update_scan_status(
                scan_id,
                'completed',
                total_vulnerabilities=vulnerabilities_found,
                critical_count=severity_counts['critical'],
                high_count=severity_counts['high'],
                medium_count=severity_counts['medium'],
                low_count=severity_counts['low']
            )
            
            add_scan_log(
                scan_id,
                'INFO',
                f'Analysis complete: {vulnerabilities_found} vulnerabilities found',
                'analyzer'
            )
            
            self.logger.info(f"[Scan {scan_id}] Analysis complete: {vulnerabilities_found} vulnerabilities")
            
            return {
                'total_vulnerabilities': vulnerabilities_found,
                'by_severity': severity_counts
            }
            
        except Exception as e:
            error_msg = str(e)
            add_scan_log(scan_id, 'ERROR', f'Analysis failed: {error_msg}', 'analyzer')
            self.logger.error(f"[Scan {scan_id}] Analysis failed: {error_msg}")
            raise
    
    def _get_scan_targets(self, scan_id: int) -> List[Dict]:
        """Get all targets with their ports from a scan"""
        query = """
        SELECT 
            t.id as target_id,
            t.ip_address,
            t.hostname,
            p.id as port_id,
            p.port,
            p.protocol,
            p.service,
            p.product,
            p.version
        FROM targets t
        JOIN ports p ON t.id = p.target_id
        WHERE t.scan_id = ? AND p.state = 'open'
        ORDER BY t.ip_address, p.port
        """
        return db.execute_query(query, (scan_id,))
    
    def _analyze_target(self, scan_id: int, target: Dict) -> List[Dict]:
        """Analyze a single target for vulnerabilities"""
        vulnerabilities = []
        
        # Build service signature
        service = target.get('service', '')
        product = target.get('product', '')
        version = target.get('version', '')
        
        if not service or service == 'unknown':
            return vulnerabilities
        
        # Create search keyword
        if product and version:
            keyword = f"{product} {version}"
        elif product:
            keyword = product
        else:
            keyword = service
        
        self.logger.debug(f"[Scan {scan_id}] Searching NVD for: {keyword}")
        
        # Query NVD for vulnerabilities
        nvd_results = self._query_nvd(keyword)
        
        # Process results
        for cve_item in nvd_results:
            vuln_data = self._parse_cve_data(cve_item)
            
            if vuln_data:
                # Add vulnerability to database
                vuln_id = add_vulnerability(
                    target_id=target['target_id'],
                    port_id=target.get('port_id'),
                    title=vuln_data['title'],
                    description=vuln_data['description'],
                    severity=vuln_data['severity'],
                    cve_id=vuln_data['cve_id'],
                    cvss_score=vuln_data.get('cvss_score'),
                    cvss_vector=vuln_data.get('cvss_vector'),
                    service_affected=f"{service} ({product} {version})",
                    references=vuln_data.get('references'),
                    remediation=vuln_data.get('remediation', 'Update to the latest version')
                )
                
                vulnerabilities.append(vuln_data)
                
                self.logger.info(
                    f"[Scan {scan_id}] Found {vuln_data['severity'].upper()} vulnerability: "
                    f"{vuln_data['cve_id']} on {target['ip_address']}:{target['port']}"
                )
        
        return vulnerabilities
    
    def _query_nvd(self, keyword: str, max_results: int = 5) -> List[Dict]:
        """
        Query National Vulnerability Database
        
        Args:
            keyword: Search keyword
            max_results: Maximum results to return
        
        Returns:
            List of CVE items
        """
        # Rate limiting
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - time_since_last)
        
        self.last_request_time = time.time()
        
        # Build request
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': max_results
        }
        
        headers = {}
        if self.nvd_api_key:
            headers['apiKey'] = self.nvd_api_key
        
        try:
            response = requests.get(
                self.nvd_api_url,
                params=params,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('vulnerabilities', [])
            else:
                self.logger.warning(f"NVD API returned status {response.status_code}")
                return []
                
        except requests.RequestException as e:
            self.logger.error(f"Failed to query NVD: {str(e)}")
            return []
    
    def _parse_cve_data(self, cve_item: Dict) -> Optional[Dict]:
        """Parse CVE data from NVD response"""
        try:
            cve = cve_item.get('cve', {})
            cve_id = cve.get('id', '')
            
            # Get description
            descriptions = cve.get('descriptions', [])
            description = descriptions[0].get('value', '') if descriptions else 'No description available'
            
            # Get CVSS metrics
            metrics = cve.get('metrics', {})
            cvss_data = None
            cvss_score = 0
            severity = 'info'
            cvss_vector = ''
            
            # Try CVSS v3.1 first
            if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0)
                severity = cvss_data.get('baseSeverity', 'NONE').lower()
                cvss_vector = cvss_data.get('vectorString', '')
            
            # Fallback to CVSS v3.0
            elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0)
                severity = cvss_data.get('baseSeverity', 'NONE').lower()
                cvss_vector = cvss_data.get('vectorString', '')
            
            # Fallback to CVSS v2
            elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score = cvss_data.get('baseScore', 0)
                # Map v2 score to severity
                if cvss_score >= 7.0:
                    severity = 'high'
                elif cvss_score >= 4.0:
                    severity = 'medium'
                else:
                    severity = 'low'
                cvss_vector = cvss_data.get('vectorString', '')
            
            # Get references
            references = cve.get('references', [])
            reference_urls = [ref.get('url', '') for ref in references[:5]]
            
            return {
                'cve_id': cve_id,
                'title': f"{cve_id}: {description[:100]}...",
                'description': description,
                'severity': severity,
                'cvss_score': cvss_score,
                'cvss_vector': cvss_vector,
                'references': ','.join(reference_urls),
                'remediation': 'Update to the latest patched version'
            }
            
        except Exception as e:
            self.logger.error(f"Failed to parse CVE data: {str(e)}")
            return None

# Create analyzer instance
analyzer_service = AnalyzerService()