# """
# Main Flask Application
# API Server for Penetration Testing Framework
# """

# from flask import Flask, jsonify, request
# from flask_cors import CORS
# import threading
# import sys
# from pathlib import Path

# # Add current directory to path
# sys.path.insert(0, str(Path(__file__).parent))

# from config import get_config
# from utils.logger import setup_logger
# from utils.database import (
#     db, get_dashboard_stats, get_scan_with_details,
#     create_scan, get_vulnerabilities_by_scan, get_scan_logs
# )
# from services.scanner_service import scanner_service
# from services.analyzer_service import analyzer_service

# # Initialize Flask app
# app = Flask(__name__)
# config = get_config()
# app.config.from_object(config)

# # Enable CORS
# CORS(app, origins=config.CORS_ORIGINS)

# # Setup logger
# logger = setup_logger('api')

# # ==================== API ROUTES ====================

# @app.route('/api/v1/health', methods=['GET'])
# def health_check():
#     """Health check endpoint"""
#     return jsonify({
#         'status': 'healthy',
#         'version': config.API_VERSION
#     })

# @app.route('/api/v1/dashboard', methods=['GET'])
# def get_dashboard():
#     """Get dashboard statistics"""
#     try:
#         stats = get_dashboard_stats()
#         return jsonify(stats)
#     except Exception as e:
#         logger.error(f"Dashboard error: {str(e)}")
#         return jsonify({'error': str(e)}), 500

# @app.route('/api/v1/scans', methods=['GET'])
# def get_scans():
#     """Get all scans"""
#     try:
#         page = request.args.get('page', 1, type=int)
#         limit = request.args.get('limit', 20, type=int)
        
#         scans = db.get_all('scans', limit=limit, offset=(page-1)*limit)
#         return jsonify({'scans': scans, 'page': page, 'limit': limit})
#     except Exception as e:
#         logger.error(f"Get scans error: {str(e)}")
#         return jsonify({'error': str(e)}), 500

# @app.route('/api/v1/scans/<int:scan_id>', methods=['GET'])
# def get_scan(scan_id):
#     """Get scan details"""
#     try:
#         scan = get_scan_with_details(scan_id)
#         if not scan:
#             return jsonify({'error': 'Scan not found'}), 404
#         return jsonify(scan)
#     except Exception as e:
#         logger.error(f"Get scan error: {str(e)}")
#         return jsonify({'error': str(e)}), 500

# @app.route('/api/v1/scans', methods=['POST'])
# def create_scan_endpoint():
#     """Create and start a new scan"""
#     try:
#         data = request.json
#         target = data.get('target')
#         scan_type = data.get('scan_type', 'quick')
#         scan_name = data.get('scan_name', f'Scan {target}')
#         project_id = data.get('project_id', 1)
        
#         if not target:
#             return jsonify({'error': 'Target is required'}), 400
        
#         # Validate target
#         is_valid, error = scanner_service.validate_target(target)
#         if not is_valid:
#             return jsonify({'error': error}), 400
        
#         # Check authorization
#         if not scanner_service.is_target_authorized(target):
#             return jsonify({'error': 'Target not in authorized networks'}), 403
        
#         # Create scan record
#         scan_id = create_scan(project_id, scan_name, target, scan_type, created_by=1)
        
#         # Start scan in background thread
#         def run_scan():
#             try:
#                 scanner_service.scan(scan_id, target, scan_type)
#                 analyzer_service.analyze_scan(scan_id)
#             except Exception as e:
#                 logger.error(f"Scan {scan_id} error: {str(e)}")
        
#         thread = threading.Thread(target=run_scan)
#         thread.daemon = True
#         thread.start()
        
#         return jsonify({
#             'scan_id': scan_id,
#             'status': 'started',
#             'message': f'Scan started on {target}'
#         }), 201
        
#     except Exception as e:
#         logger.error(f"Create scan error: {str(e)}")
#         return jsonify({'error': str(e)}), 500

# @app.route('/api/v1/scans/<int:scan_id>/vulnerabilities', methods=['GET'])
# def get_vulnerabilities(scan_id):
#     """Get vulnerabilities for a scan"""
#     try:
#         vulnerabilities = get_vulnerabilities_by_scan(scan_id)
#         return jsonify({'vulnerabilities': vulnerabilities})
#     except Exception as e:
#         logger.error(f"Get vulnerabilities error: {str(e)}")
#         return jsonify({'error': str(e)}), 500

# @app.route('/api/v1/scans/<int:scan_id>/logs', methods=['GET'])
# def get_logs(scan_id):
#     """Get logs for a scan"""
#     try:
#         logs = get_scan_logs(scan_id)
#         return jsonify({'logs': logs})
#     except Exception as e:
#         logger.error(f"Get logs error: {str(e)}")
#         return jsonify({'error': str(e)}), 500

# # Error handlers
# @app.errorhandler(404)
# def not_found(error):
#     return jsonify({'error': 'Not found'}), 404

# @app.errorhandler(500)
# def internal_error(error):
#     return jsonify({'error': 'Internal server error'}), 500

# if __name__ == '__main__':
#     logger.info("Starting Penetration Testing Framework API")
#     logger.info(f"Authorized networks: {config.AUTHORIZED_NETWORKS}")
#     app.run(
#         host='0.0.0.0',
#         port=5000,
#         debug=config.DEBUG              <-------Error Code 
#     )


"""
Main Flask Application
API Server for Penetration Testing Framework
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import threading
import sys
from pathlib import Path

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