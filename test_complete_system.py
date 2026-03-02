import requests
import time
import json

API_URL = "http://localhost:5000/api/v1"

print("=" * 60)
print("Testing Penetration Testing Framework")
print("=" * 60)
print()

# Test 1: Health Check
print("1. Testing health endpoint...")
response = requests.get(f"{API_URL}/health")
print(f"   Status: {response.status_code}")
print(f"   Response: {response.json()}")
print()

# Test 2: Create Scan
print("2. Creating scan...")
scan_data = {
    "target": "127.0.0.1",
    "scan_type": "quick",
    "scan_name": "Python Test Scan"
}
response = requests.post(f"{API_URL}/scans", json=scan_data)
print(f"   Status: {response.status_code}")
result = response.json()
print(f"   Response: {result}")
scan_id = result.get('scan_id')
print()

# Test 3: Monitor Progress
print("3. Monitoring scan progress...")
for i in range(10):
    time.sleep(3)
    response = requests.get(f"{API_URL}/scans/{scan_id}")
    scan_info = response.json()
    status = scan_info.get('status', 'unknown')
    print(f"   [{i+1}/10] Status: {status}")
    
    if status == 'completed':
        print(f"   ✅ Scan completed!")
        print(f"   Hosts found: {scan_info.get('total_hosts', 0)}")
        print(f"   Ports found: {scan_info.get('total_ports', 0)}")
        print(f"   Vulnerabilities: {scan_info.get('total_vulnerabilities', 0)}")
        break
    elif status == 'failed':
        print(f"   ❌ Scan failed: {scan_info.get('error_message')}")
        break

print()

# Test 4: Get Vulnerabilities
print("4. Getting vulnerabilities...")
response = requests.get(f"{API_URL}/scans/{scan_id}/vulnerabilities")
vulns = response.json().get('vulnerabilities', [])
print(f"   Found {len(vulns)} vulnerabilities")

if vulns:
    for v in vulns[:3]:  # Show first 3
        print(f"   - [{v['severity'].upper()}] {v['cve_id']}: {v['title'][:50]}...")

print()
print("=" * 60)
print("✅ All tests completed!")
print("=" * 60)