# import requests
# import time
# import json

# API_URL = "http://localhost:5000/api/v1"

# print("=" * 60)
# print("Testing Penetration Testing Framework")
# print("=" * 60)
# print()

# # Test 1: Health Check
# print("1. Testing health endpoint...")
# response = requests.get(f"{API_URL}/health")
# print(f"   Status: {response.status_code}")
# print(f"   Response: {response.json()}")
# print()

# # Test 2: Create Scan
# print("2. Creating scan...")
# scan_data = {
#     "target": "127.0.0.1",
#     "scan_type": "quick",
#     "scan_name": "Python Test Scan"
# }
# response = requests.post(f"{API_URL}/scans", json=scan_data)
# print(f"   Status: {response.status_code}")
# result = response.json()
# print(f"   Response: {result}")
# scan_id = result.get('scan_id')
# print()

# # Test 3: Monitor Progress
# print("3. Monitoring scan progress...")
# for i in range(10):
#     time.sleep(3)
#     response = requests.get(f"{API_URL}/scans/{scan_id}")
#     scan_info = response.json()
#     status = scan_info.get('status', 'unknown')
#     print(f"   [{i+1}/10] Status: {status}")
    
#     if status == 'completed':
#         print(f"   ✅ Scan completed!")
#         print(f"   Hosts found: {scan_info.get('total_hosts', 0)}")
#         print(f"   Ports found: {scan_info.get('total_ports', 0)}")
#         print(f"   Vulnerabilities: {scan_info.get('total_vulnerabilities', 0)}")
#         break
#     elif status == 'failed':
#         print(f"   ❌ Scan failed: {scan_info.get('error_message')}")
#         break

# print()

# # Test 4: Get Vulnerabilities
# print("4. Getting vulnerabilities...")
# response = requests.get(f"{API_URL}/scans/{scan_id}/vulnerabilities")
# vulns = response.json().get('vulnerabilities', [])
# print(f"   Found {len(vulns)} vulnerabilities")

# if vulns:
#     for v in vulns[:3]:  # Show first 3
#         print(f"   - [{v['severity'].upper()}] {v['cve_id']}: {v['title'][:50]}...")

# print()
# print("=" * 60)
# print("✅ All tests completed!")
# print("=" * 60)

"""
Test if SQLMap and Hashcat are installed correctly
"""
import subprocess
from pathlib import Path

def test_sqlmap():
    """Test SQLMap installation"""
    sqlmap_path = Path('tools/sqlmap/sqlmap.py')
    
    if not sqlmap_path.exists():
        print("❌ SQLMap not found at:", sqlmap_path)
        print("   Install: git clone https://github.com/sqlmapproject/sqlmap.git tools/sqlmap")
        return False
    
    try:
        
        
        result = subprocess.run(
            ['python', 'tools/sqlmap/sqlmap.py', '--version'],
            input="\n",               # 🔥 simulate ENTER
            capture_output=True,
            text=True,
            timeout=15
        )
                
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"✅ SQLMap installed: {version}")
            return True
        else:
            print("❌ SQLMap found but not working")
            return False
    except Exception as e:
        print(f"❌ SQLMap test error: {e}")
        return False

def test_hashcat():
    """Test Hashcat installation"""
    hashcat_path = Path('tools/hashcat/hashcat.exe')
    
    if not hashcat_path.exists():
        print("❌ Hashcat not found at:", hashcat_path)
        print("   Download from: https://hashcat.net/hashcat/")
        return False
    
    try:
        result = subprocess.run(
            [str(hashcat_path), '--version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"✅ Hashcat installed: {version}")
            return True
        else:
            print("❌ Hashcat found but not working")
            return False
    except Exception as e:
        print(f"❌ Hashcat test error: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("Testing Security Tools Installation")
    print("=" * 60)
    
    sqlmap_ok = test_sqlmap()
    hashcat_ok = test_hashcat()
    
    print("=" * 60)
    
    if sqlmap_ok and hashcat_ok:
        print("✅ All tools installed successfully!")
    else:
        print("⚠️ Some tools need to be installed")
        
        if not sqlmap_ok:
            print("\n📝 Install SQLMap:")
            print("   git clone https://github.com/sqlmapproject/sqlmap.git tools/sqlmap")
        
        if not hashcat_ok:
            print("\n📝 Install Hashcat:")
            print("   1. Download: https://hashcat.net/files/hashcat-6.2.6.7z")
            print("   2. Extract to: tools/hashcat/")