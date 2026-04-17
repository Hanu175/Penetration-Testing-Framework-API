"""
Configuration Management
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Base directory
# BASE_DIR = Path(__file__).parent.parent changed dur to its relative nature
BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    """Base configuration"""
    
    # Flask settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    
    # Database
    # DATABASE_PATH = os.getenv('DATABASE_PATH', str(BASE_DIR / 'database' / 'pentest.db'))   changed due to its relative nature
    DATABASE_PATH = os.getenv('DATABASE_PATH', str((BASE_DIR / 'database' / 'pentest.db').resolve()) )
    
    # API settings
    API_VERSION = 'v1'
    API_PREFIX = f'/api/{API_VERSION}'
    
    # CORS settings
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:3000').split(',')
    
    # Scanning settings
    NMAP_TIMEOUT = int(os.getenv('NMAP_TIMEOUT', 300))
    MAX_SCAN_THREADS = int(os.getenv('MAX_SCAN_THREADS', 10))
    SCAN_TYPES = {
        'quick': '-T4 -F',
        'service': '-sV -sC -T4',
        'stealth': '-sS -T2',
        'full': '-sV -sC -A -T4 -p-'
    }
    
    # Metasploit settings
    METASPLOIT_HOST = os.getenv('METASPLOIT_HOST', '127.0.0.1')
    METASPLOIT_PORT = int(os.getenv('METASPLOIT_PORT', 55553))
    METASPLOIT_USER = os.getenv('METASPLOIT_USER', 'msf')
    METASPLOIT_PASS = os.getenv('METASPLOIT_PASS', 'password')
    METASPLOIT_SSL = os.getenv('METASPLOIT_SSL', 'true').lower() == 'true'
    
    # NVD API settings
    NVD_API_KEY = os.getenv('NVD_API_KEY', '')
    NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    
    # Directories
    REPORTS_DIR = BASE_DIR / 'reports'
    LOGS_DIR = BASE_DIR / 'logs'
    
    # Ensure directories exist
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = LOGS_DIR / 'pentest_framework.log'
    
    # Security
    AUTHORIZED_NETWORKS = os.getenv('AUTHORIZED_NETWORKS', '0.0.0.0/0,192.168.0.0/16,10.0.0.0/8,127.0.0.1').split(',')
    
    # Pagination
    DEFAULT_PAGE_SIZE = 20
    MAX_PAGE_SIZE = 100

def get_config():
    """Get configuration"""
    return Config

