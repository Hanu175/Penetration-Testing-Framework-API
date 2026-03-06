"""
Reporter Service
Generates professional security reports in multiple formats
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List
import sys

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.platypus import Image as RLImage
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from config import get_config
from utils.database import (
    db, get_scan_with_details, get_vulnerabilities_by_scan
)
from utils.logger import setup_logger

config = get_config()
logger = setup_logger('reporter')

class ReporterService:
    """Generate security reports in various formats"""
    
    def __init__(self):
        self.logger = logger
        self.reports_dir = config.REPORTS_DIR
        
        # Ensure reports directory exists
        self.reports_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_html_report(self, scan_id: int) -> str:
        """
        Generate HTML report for a scan
        
        Args:
            scan_id: Database ID of the scan
        
        Returns:
            Path to generated HTML report file
        """
        try:
            self.logger.info(f"Generating HTML report for scan {scan_id}")
            
            # Get scan data
            scan_data = self._get_report_data(scan_id)
            
            # Generate HTML content
            html_content = self._create_html_content(scan_data)
            
            # Save to file
            filename = f"scan_report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            filepath = self.reports_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report generated: {filepath}")
            
            return str(filepath)
            
        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {str(e)}")
            raise
    
    def generate_csv_report(self, scan_id: int) -> str:
        """
        Generate CSV report for a scan
        
        Args:
            scan_id: Database ID of the scan
        
        Returns:
            Path to generated CSV report file
        """
        try:
            self.logger.info(f"Generating CSV report for scan {scan_id}")
            
            # Get scan data
            scan_data = self._get_report_data(scan_id)
            
            # Generate CSV content
            csv_content = self._create_csv_content(scan_data)
            
            # Save to file
            filename = f"scan_report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            filepath = self.reports_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(csv_content)
            
            self.logger.info(f"CSV report generated: {filepath}")
            
            return str(filepath)
            
        except Exception as e:
            self.logger.error(f"Failed to generate CSV report: {str(e)}")
            raise
    
    def _get_report_data(self, scan_id: int) -> Dict:
        """Gather all data needed for report"""
        
        # Get scan details
        scan = get_scan_with_details(scan_id)
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        
        # Get vulnerabilities
        vulnerabilities = get_vulnerabilities_by_scan(scan_id)
        
        # Get targets and ports
        query_targets = """
        SELECT t.*, 
            COUNT(p.id) as port_count
        FROM targets t
        LEFT JOIN ports p ON t.id = p.target_id
        WHERE t.scan_id = ?
        GROUP BY t.id
        ORDER BY t.ip_address
        """
        targets = db.execute_query(query_targets, (scan_id,))
        
        # Get all ports - ENHANCED with more details
        query_ports = """
        SELECT 
            p.id,
            p.port,
            p.protocol,
            p.state,
            p.service,
            p.product,
            p.version,
            p.extra_info,
            t.ip_address,
            t.hostname
        FROM ports p
        JOIN targets t ON p.target_id = t.id
        WHERE t.scan_id = ?
        ORDER BY t.ip_address, p.port
        """
        ports = db.execute_query(query_ports, (scan_id,))
        
        # Group vulnerabilities by severity
        vuln_by_severity = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'info').lower()
            if severity in vuln_by_severity:
                vuln_by_severity[severity].append(vuln)
        
        return {
            'scan': scan,
            'vulnerabilities': vulnerabilities,
            'vulnerabilities_by_severity': vuln_by_severity,
            'targets': targets,
            'ports': ports,  # Now includes all port details
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
    def _create_html_content(self, data: Dict) -> str:
        """Create HTML report content"""
        
        scan = data['scan']
        vulns_by_severity = data['vulnerabilities_by_severity']
        targets = data['targets']
        ports = data['ports']
        
        # HTML template
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {scan['scan_name']}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        
        .report-container {{
            background: white;
            padding: 40px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        
        .header {{
            border-bottom: 4px solid #667eea;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        
        .header h1 {{
            color: #667eea;
            font-size: 2.5rem;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            color: #666;
            font-size: 1.2rem;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            margin: 30px 0;
            padding: 20px;
            background: #f8f9fa;
            border-radius: 8px;
        }}
        
        .info-item {{
            padding: 10px;
        }}
        
        .info-label {{
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }}
        
        .info-value {{
            color: #333;
        }}
        
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin: 30px 0;
        }}
        
        .summary-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        
        .summary-card.critical {{
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
        }}
        
        .summary-card.high {{
            background: linear-gradient(135deg, #fd7e14 0%, #e8590c 100%);
        }}
        
        .summary-card.medium {{
            background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%);
        }}
        
        .summary-card.low {{
            background: linear-gradient(135deg, #28a745 0%, #218838 100%);
        }}
        
        .summary-number {{
            font-size: 3rem;
            font-weight: bold;
            margin-bottom: 10px;
        }}
        
        .summary-label {{
            font-size: 0.9rem;
            opacity: 0.9;
        }}
        
        .section {{
            margin: 40px 0;
        }}
        
        .section-title {{
            color: #667eea;
            font-size: 1.8rem;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        
        table thead {{
            background: #667eea;
            color: white;
        }}
        
        table th {{
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        
        table td {{
            padding: 12px;
            border-bottom: 1px solid #ddd;
        }}
        
        table tbody tr:hover {{
            background: #f8f9fa;
        }}
        
        .vulnerability-card {{
            background: white;
            border-left: 4px solid #ddd;
            padding: 20px;
            margin: 20px 0;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .vulnerability-card.critical {{
            border-left-color: #dc3545;
        }}
        
        .vulnerability-card.high {{
            border-left-color: #fd7e14;
        }}
        
        .vulnerability-card.medium {{
            border-left-color: #ffc107;
        }}
        
        .vulnerability-card.low {{
            border-left-color: #28a745;
        }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 15px;
        }}
        
        .vuln-title {{
            font-size: 1.2rem;
            font-weight: bold;
            color: #333;
        }}
        
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.9rem;
        }}
        
        .severity-badge.critical {{
            background: #dc3545;
        }}
        
        .severity-badge.high {{
            background: #fd7e14;
        }}
        
        .severity-badge.medium {{
            background: #ffc107;
            color: #333;
        }}
        
        .severity-badge.low {{
            background: #28a745;
        }}
        
        .vuln-details {{
            color: #666;
            margin: 10px 0;
        }}
        
        .remediation-box {{
            background: #d4edda;
            border-left: 4px solid #28a745;
            padding: 15px;
            margin-top: 15px;
            border-radius: 4px;
        }}
        
        .remediation-box strong {{
            color: #155724;
        }}
        
        .footer {{
            margin-top: 50px;
            padding-top: 20px;
            border-top: 2px solid #ddd;
            text-align: center;
            color: #666;
            font-size: 0.9rem;
        }}
        
        @media print {{
            body {{
                background: white;
            }}
            
            .report-container {{
                box-shadow: none;
                padding: 20px;
            }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <!-- Header -->
        <div class="header">
            <h1>🛡️ Security Scan Report</h1>
            <div class="subtitle">{scan['scan_name']}</div>
        </div>
        
        <!-- Scan Information -->
        <div class="info-grid">
            <div class="info-item">
                <div class="info-label">Target</div>
                <div class="info-value">{scan['target']}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Scan Type</div>
                <div class="info-value">{scan['scan_type']}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Started At</div>
                <div class="info-value">{scan.get('started_at', 'N/A')}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Status</div>
                <div class="info-value">{scan['status'].upper()}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Hosts Discovered</div>
                <div class="info-value">{scan.get('total_hosts', 0)}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Open Ports</div>
                <div class="info-value">{scan.get('total_ports', 0)}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Report Generated</div>
                <div class="info-value">{data['generated_at']}</div>
            </div>
            <div class="info-item">
                <div class="info-label">Project</div>
                <div class="info-value">{scan.get('project_name', 'Default Project')}</div>
            </div>
        </div>
        
        <!-- Summary Cards -->
        <div class="summary-cards">
            <div class="summary-card">
                <div class="summary-number">{scan.get('total_vulnerabilities', 0)}</div>
                <div class="summary-label">Total Vulnerabilities</div>
            </div>
            <div class="summary-card critical">
                <div class="summary-number">{scan.get('critical_count', 0)}</div>
                <div class="summary-label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="summary-number">{scan.get('high_count', 0)}</div>
                <div class="summary-label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="summary-number">{scan.get('medium_count', 0)}</div>
                <div class="summary-label">Medium</div>
            </div>
        </div>
        
        
        
        <!-- Discovered Hosts -->
        <div class="section">
            <h2 class="section-title">Discovered Hosts</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>Status</th>
                        <th>OS</th>
                        <th>Open Ports</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        # Add targets
        for target in targets:
            html += f"""
                    <tr>
                        <td>{target['ip_address']}</td>
                        <td>{target.get('hostname') or 'N/A'}</td>
                        <td>{target['status']}</td>
                        <td>{target.get('os_name') or 'Unknown'}</td>
                        <td>{target.get('port_count', 0)}</td>
                    </tr>
"""
        
        html += """
                </tbody>
            </table>
        </div>
"""
        
        # Add vulnerabilities by severity
        for severity in ['critical', 'high', 'medium', 'low']:
            vulns = vulns_by_severity.get(severity, [])
            if vulns:
                severity_label = severity.upper()
                html += f"""
        <!-- {severity_label} Vulnerabilities -->
        <div class="section">
            <h2 class="section-title">🔴 {severity_label} Severity Vulnerabilities ({len(vulns)})</h2>
"""
                
                for vuln in vulns:
                    html += f"""
            <div class="vulnerability-card {severity}">
                <div class="vuln-header">
                    <div class="vuln-title">{vuln.get('cve_id', 'N/A')}</div>
                    <span class="severity-badge {severity}">{severity_label}</span>
                </div>
                <div class="vuln-details">
                    <strong>Host:</strong> {vuln.get('ip_address', 'N/A')} 
                    {f"({vuln.get('hostname')})" if vuln.get('hostname') else ''}
                    {f"| <strong>Port:</strong> {vuln.get('port')}" if vuln.get('port') else ''}
                    {f"| <strong>Service:</strong> {vuln.get('service')}" if vuln.get('service') else ''}
                </div>
                <div class="vuln-details">
                    <strong>Description:</strong><br>
                    {vuln.get('description', 'No description available')}
                </div>
                {f'''<div class="remediation-box">
                    <strong>💡 Remediation:</strong><br>
                    {vuln.get('remediation', 'Update to the latest version')}
                </div>''' if vuln.get('remediation') else ''}
            </div>
"""
                
                html += """
        </div>
"""
        
        # Footer
        html += f"""
        <!-- Footer -->
        <div class="footer">
            <p>Generated by Penetration Testing Framework</p>
            <p>{data['generated_at']}</p>
            <p>⚠️ This report contains sensitive security information. Handle with care.</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    def _create_csv_content(self, data: Dict) -> str:
        """Create CSV report content with multiple sheets worth of data"""
        
        vulnerabilities = data['vulnerabilities']
        ports = data['ports']
        targets = data['targets']
        
        csv = ""
        
        # Section 1: Scan Summary
        csv += "SCAN SUMMARY\n"
        csv += f"Scan Name,{data['scan']['scan_name']}\n"
        csv += f"Target,{data['scan']['target']}\n"
        csv += f"Scan Type,{data['scan']['scan_type']}\n"
        csv += f"Status,{data['scan']['status']}\n"
        csv += f"Started,{data['scan'].get('started_at', 'N/A')}\n"
        csv += f"Completed,{data['scan'].get('completed_at', 'N/A')}\n"
        csv += f"Total Hosts,{data['scan'].get('total_hosts', 0)}\n"
        csv += f"Total Ports,{data['scan'].get('total_ports', 0)}\n"
        csv += f"Total Vulnerabilities,{data['scan'].get('total_vulnerabilities', 0)}\n"
        csv += "\n\n"
        
        # Section 2: Discovered Hosts
        csv += "DISCOVERED HOSTS\n"
        csv += "IP Address,Hostname,Status,OS,Open Ports\n"
        for target in targets:
            csv += f"{target['ip_address']},"
            csv += f"{target.get('hostname', 'N/A')},"
            csv += f"{target['status']},"
            csv += f"{target.get('os_name', 'Unknown')},"
            csv += f"{target.get('port_count', 0)}\n"
        csv += "\n\n"
        
        # Section 3: Open Ports
        csv += "OPEN PORTS\n"
        csv += "IP Address,Hostname,Port,Protocol,State,Service,Product,Version,Extra Info\n"
        
        # Sort ports by IP and port number
        sorted_ports = sorted(ports, key=lambda x: (x['ip_address'], x['port']))
        
        for port in sorted_ports:
            csv += f"{port['ip_address']},"
            csv += f"{port.get('hostname', 'N/A')},"
            csv += f"{port['port']},"
            csv += f"{port.get('protocol', 'tcp')},"
            csv += f"{port.get('state', 'open')},"
            csv += f"{port.get('service', 'unknown')},"
            csv += f"\"{port.get('product', 'N/A')}\"," # Quoted for commas
            csv += f"{port.get('version', 'N/A')},"
            csv += f"\"{port.get('extra_info', 'N/A')}\"\n" # Quoted for commas
        csv += "\n\n"
        
        # Section 4: Vulnerabilities
        csv += "VULNERABILITIES\n"
        csv += "IP Address,Hostname,Port,Service,CVE ID,Severity,CVSS Score,Description,Remediation\n"
        
        for vuln in vulnerabilities:
            # Escape commas and quotes in fields
            fields = [
                vuln.get('ip_address', ''),
                vuln.get('hostname', ''),
                str(vuln.get('port', '')),
                vuln.get('service', ''),
                vuln.get('cve_id', ''),
                vuln.get('severity', ''),
                str(vuln.get('cvss_score', '')),
                f'"{vuln.get("description", "").replace('"', '""')}"',  # Escape quotes
                f'"{vuln.get("remediation", "").replace('"', '""')}"'
            ]
            csv += ','.join(fields) + '\n'
        
        return csv
    
    
    #This was added at 2/03/26  for pdf generation     
    def generate_pdf_report(self, scan_id: int) -> str:
        """
        Generate PDF report for a scan
        
        Args:
            scan_id: Database ID of the scan
        
        Returns:
            Path to generated PDF report file
        """
        try:
            self.logger.info(f"Generating PDF report for scan {scan_id}")
            
            # Get scan data
            scan_data = self._get_report_data(scan_id)
            
            # Create PDF
            filename = f"scan_report_{scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            filepath = self.reports_dir / filename
            
            # Create PDF document
            doc = SimpleDocTemplate(
                str(filepath),
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Container for PDF elements
            story = []
            
            # Styles
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#667eea'),
                spaceAfter=30,
                alignment=TA_CENTER
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                textColor=colors.HexColor('#667eea'),
                spaceAfter=12,
                spaceBefore=12
            )
            
            # Title
            story.append(Paragraph("🛡️ Security Scan Report", title_style))
            story.append(Spacer(1, 0.2*inch))
            
            # Scan Information Table
            scan = scan_data['scan']
            scan_info = [
                ['Scan Name:', scan['scan_name']],
                ['Target:', scan['target']],
                ['Scan Type:', scan['scan_type']],
                ['Status:', scan['status'].upper()],
                ['Started:', scan.get('started_at', 'N/A')],
                ['Completed:', scan.get('completed_at', 'N/A')],
                ['Report Generated:', scan_data['generated_at']]
            ]
            
            info_table = Table(scan_info, colWidths=[2*inch, 4*inch])
            info_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
                ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#667eea')),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('RIGHTPADDING', (0, 0), (-1, -1), 12),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ]))
            
            story.append(info_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Summary Statistics
            story.append(Paragraph("Executive Summary", heading_style))
            
            summary_data = [
                ['Metric', 'Count'],
                ['Hosts Discovered', str(scan.get('total_hosts', 0))],
                ['Open Ports', str(scan.get('total_ports', 0))],
                ['Total Vulnerabilities', str(scan.get('total_vulnerabilities', 0))],
                ['Critical Issues', str(scan.get('critical_count', 0))],
                ['High Severity', str(scan.get('high_count', 0))],
                ['Medium Severity', str(scan.get('medium_count', 0))],
                ['Low Severity', str(scan.get('low_count', 0))]
            ]
            
            summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ALIGN', (1, 1), (1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('RIGHTPADDING', (0, 0), (-1, -1), 12),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ]))
            
            story.append(summary_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Discovered Hosts
            targets = scan_data['targets']
            if targets:
                story.append(Paragraph("Discovered Hosts", heading_style))
                
                hosts_data = [['IP Address', 'Hostname', 'Status', 'OS', 'Ports']]
                for target in targets:
                    hosts_data.append([
                        target['ip_address'],
                        target.get('hostname') or 'N/A',
                        target['status'],
                        target.get('os_name') or 'Unknown',
                        str(target.get('port_count', 0))
                    ])
                
                hosts_table = Table(hosts_data, colWidths=[1.5*inch, 1.5*inch, 1*inch, 1.5*inch, 0.8*inch])
                hosts_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ]))
                
                story.append(hosts_table)
                story.append(Spacer(1, 0.3*inch))

            # ============================================================
            # NEW CODE STARTS HERE - ADD THIS ENTIRE SECTION
            # ============================================================

            # Detailed Ports Section
            ports = scan_data['ports']
            if ports:
                story.append(PageBreak())
                story.append(Paragraph("Open Ports Discovered", heading_style))
                story.append(Spacer(1, 0.2*inch))
                
                # Group ports by IP address
                ports_by_ip = {}
                for port in ports:
                    ip = port['ip_address']
                    if ip not in ports_by_ip:
                        ports_by_ip[ip] = []
                    ports_by_ip[ip].append(port)
                
                # Display ports for each host
                for ip, host_ports in ports_by_ip.items():
                    # Host header
                    host_title = Paragraph(
                        f"<b>Host: {ip}</b>",
                        ParagraphStyle(
                            'HostTitle',
                            parent=styles['Normal'],
                            fontSize=12,
                            textColor=colors.HexColor('#667eea'),
                            spaceAfter=10,
                            spaceBefore=10
                        )
                    )
                    story.append(host_title)
                    
                    # Sort ports by port number
                    sorted_ports = sorted(host_ports, key=lambda x: x['port'])
                    
                    # Create ports table
                    ports_data = [['Port', 'Protocol', 'State', 'Service', 'Version']]
                    
                    for port in sorted_ports:
                        ports_data.append([
                            str(port['port']),
                            port.get('protocol', 'tcp').upper(),
                            port.get('state', 'open').upper(),
                            port.get('service', 'unknown'),
                            f"{port.get('product', '')} {port.get('version', '')}".strip() or 'N/A'
                        ])
                    
                    ports_table = Table(ports_data, colWidths=[0.8*inch, 0.9*inch, 0.8*inch, 1.5*inch, 2.5*inch])
                    
                    # Color code by state
                    table_style = [
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('LEFTPADDING', (0, 0), (-1, -1), 8),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                        ('TOPPADDING', (0, 0), (-1, -1), 6),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ]
                    
                    # Highlight open ports with green background
                    for i, port in enumerate(sorted_ports, start=1):
                        if port.get('state', 'open') == 'open':
                            table_style.append(
                                ('BACKGROUND', (2, i), (2, i), colors.HexColor('#d4edda'))
                            )
                            table_style.append(
                                ('TEXTCOLOR', (2, i), (2, i), colors.HexColor('#155724'))
                            )
                    
                    ports_table.setStyle(TableStyle(table_style))
                    
                    story.append(ports_table)
                    story.append(Spacer(1, 0.2*inch))

            # ============================================================
            # NEW CODE ENDS HERE
            # ============================================================
                        # Vulnerabilities by Severity
            vulns_by_severity = scan_data['vulnerabilities_by_severity']
            
            severity_colors = {
                'critical': colors.HexColor('#dc3545'),
                'high': colors.HexColor('#fd7e14'),
                'medium': colors.HexColor('#ffc107'),
                'low': colors.HexColor('#28a745')
            }
            
            for severity in ['critical', 'high', 'medium', 'low']:
                vulns = vulns_by_severity.get(severity, [])
                if vulns:
                    # Add page break before each severity section (except first)
                    if severity != 'critical' or story:
                        story.append(PageBreak())
                    
                    # Section title
                    title = f"{severity.upper()} Severity Vulnerabilities ({len(vulns)})"
                    story.append(Paragraph(title, heading_style))
                    story.append(Spacer(1, 0.2*inch))
                    
                    # Vulnerability details
                    for vuln in vulns:
                        vuln_data = [
                            ['CVE ID:', vuln.get('cve_id', 'N/A')],
                            ['Host:', f"{vuln.get('ip_address', 'N/A')} ({vuln.get('hostname', 'N/A')})"],
                            ['Port:', f"{vuln.get('port', 'N/A')} - {vuln.get('service', 'N/A')}"],
                            ['CVSS Score:', str(vuln.get('cvss_score', 'N/A'))],
                            ['Description:', vuln.get('description', 'No description')[:200] + '...'],
                            ['Remediation:', vuln.get('remediation', 'Update to latest version')[:150] + '...']
                        ]
                        
                        vuln_table = Table(vuln_data, colWidths=[1.5*inch, 4.5*inch])
                        vuln_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (0, -1), severity_colors[severity]),
                            ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
                            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, -1), 9),
                            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                            ('LEFTPADDING', (0, 0), (-1, -1), 8),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                            ('TOPPADDING', (0, 0), (-1, -1), 6),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                        ]))
                        
                        story.append(vuln_table)
                        story.append(Spacer(1, 0.15*inch))
            
            # Build PDF
            doc.build(story)
            
            self.logger.info(f"PDF report generated: {filepath}")
            
            return str(filepath)
            
        except Exception as e:
            self.logger.error(f"Failed to generate PDF report: {str(e)}")
            raise    

# Create reporter instance
reporter_service = ReporterService()