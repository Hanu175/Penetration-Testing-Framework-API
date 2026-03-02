#Testing whether all files are imported and working

# print("Testing imports...")

# try:
#     from dotenv import load_dotenv
#     print("✅ dotenv imported successfully")
# except ImportError as e:
#     print(f"❌ dotenv import failed: {e}")

# try:
#     import flask
#     print("✅ Flask imported successfully")
# except ImportError as e:
#     print(f"❌ Flask import failed: {e}")

# try:
#     import nmap
#     print("✅ nmap imported successfully")
# except ImportError as e:
#     print(f"❌ nmap import failed: {e}")

# try:
#     import requests
#     print("✅ requests imported successfully")
# except ImportError as e:
#     print(f"❌ requests import failed: {e}")

# print("\n✅ All imports working!")


#Congifuration testing whether all congifuration are loaded and whether the database is connected 
# from backend.config import get_config

# print("Testing config.py...")

# config = get_config()
# print("Configuration loaded")
# print("Database:", config.DATABASE_PATH)
# print("Debug:", config.DEBUG)
# print("Log Level:", config.LOG_LEVEL)
    
    
#Have done testing the overall setup up until now like checking configuration, database connection, and authorized network 
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / 'backend'))

from backend.config import get_config
from backend.utils.database import db, get_dashboard_stats

config = get_config()

print("✅ Configuration loaded!")
print(f"Database path: {config.DATABASE_PATH}")
print(f"Log level: {config.LOG_LEVEL}")
print(f"Authorized networks: {config.AUTHORIZED_NETWORKS}")

print("\n✅ Testing database connection...")
stats = get_dashboard_stats()
print(f"Total scans in database: {stats['total_scans']}")

print("\n✅ Everything works!")