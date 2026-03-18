
"""
Main Flask Application
API Server for Penetration Testing Framework
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
import sys
from pathlib import Path
from services.reporter_service import reporter_service
from pathlib import Path
from services.attack_service import attack_simulator

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from config import get_config
from utils.logger import setup_logger
from utils.database import (
    db, get_dashboard_stats, get_scan_with_details,
    create_scan, get_vulnerabilities_by_scan, get_scan_logs
)
from services.scanner_service import scanner_service
from services.analyzer_service import analyzer_service
from services.exploiter_service import exploiter_service

# Initialize Flask app
app = Flask(__name__)
config = get_config()
app.config.from_object(config)

# Enable CORS - UPDATED FOR BETTER COMPATIBILITY
CORS(app, resources={
    r"/api/*": {
        "origins": "*",  # Allow all origins for development
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": False
    }
})

# Setup logger
logger = setup_logger('api')

# ==================== API ROUTES ====================

@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'version': config.API_VERSION
    })

@app.route('/api/v1/dashboard', methods=['GET'])
def get_dashboard():
    """Get dashboard statistics"""
    try:
        stats = get_dashboard_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/scans', methods=['GET'])
def get_scans():
    """Get all scans"""
    try:
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 20, type=int)
        
        scans = db.get_all('scans', limit=limit, offset=(page-1)*limit)
        return jsonify({'scans': scans, 'page': page, 'limit': limit})
    except Exception as e:
        logger.error(f"Get scans error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/scans/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    """Get scan details"""
    try:
        scan = get_scan_with_details(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        return jsonify(scan)
    except Exception as e:
        logger.error(f"Get scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/scans', methods=['POST'])
def create_scan_endpoint():
    """Create and start a new scan"""
    try:
        data = request.json
        target = data.get('target')
        scan_type = data.get('scan_type', 'quick')
        scan_name = data.get('scan_name', f'Scan {target}')
        project_id = data.get('project_id', 1)
        
        if not target:
            return jsonify({'error': 'Target is required'}), 400
        
        # Validate target
        is_valid, error = scanner_service.validate_target(target)
        if not is_valid:
            return jsonify({'error': error}), 400
        
        # Check authorization
        if not scanner_service.is_target_authorized(target):
            return jsonify({'error': 'Target not in authorized networks'}), 403
        
        # Create scan record
        scan_id = create_scan(project_id, scan_name, target, scan_type, created_by=1)
        
        # Start scan in background thread
        def run_scan():
            try:
                scanner_service.scan(scan_id, target, scan_type)
                analyzer_service.analyze_scan(scan_id)
            except Exception as e:
                logger.error(f"Scan {scan_id} error: {str(e)}")
        
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'scan_id': scan_id,
            'status': 'started',
            'message': f'Scan started on {target}'
        }), 201
        
    except Exception as e:
        logger.error(f"Create scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/scans/<int:scan_id>/vulnerabilities', methods=['GET'])
def get_vulnerabilities(scan_id):
    """Get vulnerabilities for a scan"""
    try:
        vulnerabilities = get_vulnerabilities_by_scan(scan_id)
        return jsonify({'vulnerabilities': vulnerabilities})
    except Exception as e:
        logger.error(f"Get vulnerabilities error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/scans/<int:scan_id>/logs', methods=['GET'])
def get_logs(scan_id):
    """Get logs for a scan"""
    try:
        logs = get_scan_logs(scan_id)
        return jsonify({'logs': logs})
    except Exception as e:
        logger.error(f"Get logs error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/v1/scans/<int:scan_id>/reports/<report_type>', methods=['POST'])
def generate_report(scan_id, report_type):
    """
    Generate a report for a scan
    
    Args:
        scan_id: Scan ID
        report_type: 'html', 'pdf', or 'csv'
    """
    try:
        if report_type not in ['html', 'pdf', 'csv']:
            return jsonify({'error': 'Invalid report type. Use "html", "pdf", or "csv"'}), 400
        
        # Generate report
        if report_type == 'html':
            filepath = reporter_service.generate_html_report(scan_id)
        elif report_type == 'pdf':
            filepath = reporter_service.generate_pdf_report(scan_id)
        elif report_type == 'csv':
            filepath = reporter_service.generate_csv_report(scan_id)
        
        # Get filename
        filename = Path(filepath).name
        
        return jsonify({
            'success': True,
            'filepath': filepath,
            'filename': filename,
            'message': f'{report_type.upper()} report generated successfully'
        }), 201
        
    except Exception as e:
        logger.error(f"Generate report error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    

@app.route('/api/v1/reports/<filename>', methods=['GET'])
def download_report(filename):
    """Download a generated report"""
    try:
        from flask import send_file
        
        filepath = config.REPORTS_DIR / filename
        
        if not filepath.exists():
            return jsonify({'error': 'Report not found'}), 404
        
        # Determine MIME type
        if filename.endswith('.html'):
            mimetype = 'text/html'
        elif filename.endswith('.pdf'):
            mimetype = 'application/pdf'
        elif filename.endswith('.csv'):
            mimetype = 'text/csv'
        else:
            mimetype = 'application/octet-stream'
        
        return send_file(
            filepath,
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        logger.error(f"Download report error: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/scans/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """
    Delete a scan and all related data
    
    Args:
        scan_id: Scan ID to delete
    """
    try:
        # Check if scan exists
        scan = get_scan_with_details(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Delete scan (CASCADE will delete related data)
        query = "DELETE FROM scans WHERE id = ?"
        deleted = db.execute_update(query, (scan_id,))
        
        if deleted > 0:
            logger.info(f"Deleted scan {scan_id}")
            return jsonify({
                'success': True,
                'message': f'Scan {scan_id} deleted successfully'
            }), 200
        else:
            return jsonify({'error': 'Failed to delete scan'}), 500
            
    except Exception as e:
        logger.error(f"Delete scan error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ==================== METASPLOIT EXPLOITATION ENDPOINTS ====================

@app.route('/api/v1/metasploit/status', methods=['GET'])
def metasploit_status():
    """Check Metasploit connection status"""
    try:
        connected = exploiter_service.connect()
        
        return jsonify({
            'connected': connected,
            'message': 'Metasploit RPC server is ' + ('connected' if connected else 'not connected')
        })
    except Exception as e:
        logger.error(f"Metasploit status error: {str(e)}")
        return jsonify({'connected': False, 'error': str(e)}), 500

@app.route('/api/v1/exploits/search', methods=['GET'])
def search_exploits():
    """Search for exploits"""
    try:
        cve_id = request.args.get('cve')
        keyword = request.args.get('keyword')
        
        if not cve_id and not keyword:
            return jsonify({'error': 'Provide cve or keyword parameter'}), 400
        
        exploits = exploiter_service.search_exploits(cve_id=cve_id, keyword=keyword)
        
        return jsonify({
            'exploits': exploits,
            'count': len(exploits)
        })
    except Exception as e:
        logger.error(f"Search exploits error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/vulnerabilities/<int:vuln_id>/exploit', methods=['POST'])
def exploit_vulnerability(vuln_id):
    """
    Attempt to exploit a vulnerability
    
    DANGER: This actually attempts to compromise the target system!
    Only use on systems you own or have written permission to test.
    """
    try:
        data = request.json or {}
        exploit_path = data.get('exploit_path')
        
        # Attempt exploitation
        result = exploiter_service.exploit_vulnerability(vuln_id, exploit_path)
        
        if result.get('success'):
            return jsonify(result), 200
        else:
            return jsonify(result), 200  # Still 200, just unsuccessful
            
    except Exception as e:
        logger.error(f"Exploit vulnerability error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/v1/sessions', methods=['GET'])
def get_sessions():
    """Get all active Metasploit sessions"""
    try:
        sessions = exploiter_service.get_sessions()
        
        return jsonify({
            'sessions': sessions,
            'count': len(sessions)
        })
    except Exception as e:
        logger.error(f"Get sessions error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/sessions/<session_id>/execute', methods=['POST'])
def execute_command(session_id):
    """Execute command in a session"""
    try:
        data = request.json
        command = data.get('command')
        
        if not command:
            return jsonify({'error': 'Command is required'}), 400
        
        result = exploiter_service.execute_command(session_id, command)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Execute command error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/sessions/<session_id>', methods=['DELETE'])
def close_session(session_id):
    """Close a session"""
    try:
        success = exploiter_service.close_session(session_id)
        
        if success:
            return jsonify({'success': True, 'message': 'Session closed'})
        else:
            return jsonify({'success': False, 'error': 'Failed to close session'}), 500
            
    except Exception as e:
        logger.error(f"Close session error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/scans/<int:scan_id>/ports', methods=['GET'])
def get_ports(scan_id):
    """Get all open ports for a scan"""
    try:
        query = """
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
        
        ports = db.execute_query(query, (scan_id,))
        
        return jsonify({
            'ports': ports,
            'count': len(ports)
        })
        
    except Exception as e:
        logger.error(f"Get ports error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ==================== ATTACK SIMULATION ENDPOINTS ====================

@app.route('/api/v1/scans/<int:scan_id>/simulate-attacks', methods=['POST'])
def simulate_attacks(scan_id):
    """
    Simulate attacks on scanned target
    
    POST body:
    {
        "attack_types": ["sql_injection", "xss", "ssh_bruteforce", "port_scan_detection"]
    }
    """
    try:
        data = request.json
        attack_types = data.get('attack_types', [])
        
        # Get scan details
        from utils.database import get_scan_with_details
        scan = get_scan_with_details(scan_id)
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        target = scan['target']
        
        # Run attack simulation in background
        import threading
        
        def run_attacks():
            try:
                attack_simulator.run_full_attack_simulation(
                    scan_id, target, attack_types
                )
            except Exception as e:
                logger.error(f"Attack simulation error: {str(e)}")
        
        thread = threading.Thread(target=run_attacks)
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'message': f'Attack simulation started on {target}',
            'attack_types': attack_types
        }), 202
        
    except Exception as e:
        logger.error(f"Simulate attacks error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/scans/<int:scan_id>/attack-results', methods=['GET'])
def get_attack_results(scan_id):
    """Get attack simulation results for a scan"""
    try:
        query = """
        SELECT * FROM attack_simulations
        WHERE scan_id = ?
        ORDER BY timestamp DESC
        """
        
        results = db.execute_query(query, (scan_id,))
        
        return jsonify({
            'scan_id': scan_id,
            'results': results,
            'count': len(results)
        })
        
    except Exception as e:
        logger.error(f"Get attack results error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/v1/scans/<int:scan_id>/attack-report/pdf', methods=['POST'])
def generate_attack_pdf_report(scan_id):
    """Generate PDF report for attack simulation results"""
    try:
        from services.attack_service import attack_simulator
        
        # Check if attack results exist
        query = "SELECT COUNT(*) as count FROM attack_simulations WHERE scan_id = ?"
        result = db.execute_query(query, (scan_id,))
        
        if not result or result[0]['count'] == 0:
            return jsonify({'error': 'No attack results found for this scan'}), 404
        
        # Generate PDF
        filepath = attack_simulator.generate_attack_report_pdf(scan_id)
        filename = filepath.split('/')[-1].split('\\')[-1]
        
        return jsonify({
            'success': True,
            'filename': filename,
            'message': 'Attack report PDF generated successfully'
        })
        
    except Exception as e:
        logger.error(f"Generate attack PDF error: {str(e)}")
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    logger.info("=" * 60)
    logger.info("Starting Penetration Testing Framework API")
    logger.info("=" * 60)
    logger.info(f"Authorized networks: {config.AUTHORIZED_NETWORKS}")
    logger.info(f"CORS enabled for all origins (development mode)")
    logger.info(f"API running at: http://localhost:5000")
    logger.info("=" * 60)
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=config.DEBUG,
        threaded=True
    )