"""
Scanner Service
Handles network scanning using Nmap
"""

import nmap
from datetime import datetime
from typing import Dict, List, Optional
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import get_config
from utils.database import (
    update_scan_status, add_target, add_port, add_scan_log
)
from utils.logger import setup_logger

config = get_config()
logger = setup_logger('scanner')

class ScannerService:
    """Network scanner using Nmap"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.logger = logger
    
    def scan(self, scan_id: int, target: str, scan_type: str = 'quick') -> Dict:
        """
        Execute a network scan
        
        Args:
            scan_id: Database ID of the scan
            target: Target IP/network to scan
            scan_type: Type of scan (quick, service, stealth, full)
        
        Returns:
            Dictionary with scan results and statistics
        """
        try:
            # Update scan status to running
            update_scan_status(scan_id, 'running', started_at=datetime.now().isoformat())
            add_scan_log(scan_id, 'INFO', f'Starting {scan_type} scan on {target}', 'scanner')
            
            # Get scan arguments from config
            scan_args = config.SCAN_TYPES.get(scan_type, config.SCAN_TYPES['quick'])
            
            self.logger.info(f"[Scan {scan_id}] Starting Nmap scan: nmap {scan_args} {target}")
            
            # Execute Nmap scan
            self.nm.scan(hosts=target, arguments=scan_args)
            
            # Parse and store results
            results = self._parse_and_store_results(scan_id)
            
            # Update scan status to completed
            update_scan_status(
                scan_id,
                'completed',
                completed_at=datetime.now().isoformat(),
                total_hosts=results['total_hosts'],
                total_ports=results['total_ports']
            )
            
            add_scan_log(
                scan_id, 
                'INFO', 
                f"Scan completed: {results['total_hosts']} hosts, {results['total_ports']} ports", 
                'scanner'
            )
            
            self.logger.info(f"[Scan {scan_id}] Scan completed successfully")
            
            return results
            
        except Exception as e:
            # Update scan status to failed
            error_msg = str(e)
            update_scan_status(
                scan_id,
                'failed',
                error_message=error_msg,
                completed_at=datetime.now().isoformat()
            )
            
            add_scan_log(scan_id, 'ERROR', f'Scan failed: {error_msg}', 'scanner')
            self.logger.error(f"[Scan {scan_id}] Scan failed: {error_msg}")
            
            raise
    
    def _parse_and_store_results(self, scan_id: int) -> Dict:
        """
        Parse Nmap results and store in database
        
        Args:
            scan_id: Database ID of the scan
        
        Returns:
            Dictionary with statistics
        """
        total_hosts = 0
        total_ports = 0
        hosts_data = []
        
        for host in self.nm.all_hosts():
            # Host information
            hostname = self.nm[host].hostname()
            state = self.nm[host].state()
            
            # Get OS information if available
            os_info = {}
            if 'osmatch' in self.nm[host] and self.nm[host]['osmatch']:
                os_match = self.nm[host]['osmatch'][0]
                os_info = {
                    'os_name': os_match.get('name', ''),
                    'os_accuracy': os_match.get('accuracy', 0)
                }
            
            # Add target to database
            target_id = add_target(
                scan_id=scan_id,
                ip_address=host,
                hostname=hostname,
                status=state,
                **os_info
            )
            
            total_hosts += 1
            
            # Parse ports
            ports_data = []
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                
                for port in ports:
                    port_info = self.nm[host][proto][port]
                    
                    # Only store open ports
                    if port_info['state'] == 'open':
                        port_data = {
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'product': port_info.get('product', ''),
                            'version': port_info.get('version', ''),
                            'extra_info': port_info.get('extrainfo', ''),
                            'confidence': port_info.get('conf', 0)
                        }
                        
                        # Add port to database
                        add_port(target_id=target_id, **port_data)
                        
                        ports_data.append(port_data)
                        total_ports += 1
            
            hosts_data.append({
                'ip': host,
                'hostname': hostname,
                'state': state,
                'ports': ports_data,
                **os_info
            })
            
            self.logger.info(f"[Scan {scan_id}] Discovered host {host} with {len(ports_data)} open ports")
        
        return {
            'total_hosts': total_hosts,
            'total_ports': total_ports,
            'hosts': hosts_data
        }
    
    def validate_target(self, target: str) -> tuple:
        """
        Validate if target is a valid IP/network
        
        Args:
            target: Target to validate
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        import ipaddress
        
        try:
            # Try to parse as IP address
            ipaddress.ip_address(target)
            return True, ""
        except ValueError:
            try:
                # Try to parse as network
                ipaddress.ip_network(target, strict=False)
                return True, ""
            except ValueError:
                # Try to resolve as hostname
                import socket
                try:
                    socket.gethostbyname(target)
                    return True, ""
                except socket.gaierror:
                    return False, f"Invalid target: {target}"
    
    
    def is_target_authorized(self, target: str) -> bool:
        import ipaddress
        import socket
        
        try:
            # ✅ Convert domain → IP FIRST
            resolved_ip = socket.gethostbyname(target)
            target_ip = ipaddress.ip_address(resolved_ip)

            for authorized_network in config.AUTHORIZED_NETWORKS:
                network = ipaddress.ip_network(authorized_network.strip(), strict=False)
                if target_ip in network:
                    return True

            return False

        except Exception as e:
            print(f"Authorization error: {e}")
            return False
    # def is_target_authorized(self, target: str) -> bool:
    #     """
    #     Check if target is in authorized networks
        
    #     Args:
    #         target: Target IP/network
        
    #     Returns:
    #         True if authorized, False otherwise
    #     """
    #     import ipaddress
        
    #     try:
    #         target_ip = ipaddress.ip_address(target)
            
    #         for authorized_network in config.AUTHORIZED_NETWORKS:
    #             network = ipaddress.ip_network(authorized_network.strip(), strict=False)
    #             if target_ip in network:
    #                 return True
            
    #         return False
            
    #     except ValueError:
    #         # If target is a network
    #         try:
    #             target_net = ipaddress.ip_network(target, strict=False)
                
    #             for authorized_network in config.AUTHORIZED_NETWORKS:
    #                 auth_net = ipaddress.ip_network(authorized_network.strip(), strict=False)
    #                 if target_net.overlaps(auth_net):
    #                     return True
                
    #             return False
                
    #         except ValueError:
    #             return False

# Create scanner instance
scanner_service = ScannerService()