import sqlite3
from datetime import datetime

# Connect to database
conn = sqlite3.connect('database/pentest.db')
cursor = conn.cursor()

# Get the latest scan
cursor.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1")
scan_result = cursor.fetchone()

if not scan_result:
    print("❌ No scans found. Create a scan first!")
    print("\nSteps:")
    print("1. Go to dashboard")
    print("2. Click 'New Scan'")
    print("3. Scan 127.0.0.1 with Quick Scan")
    print("4. Wait for completion")
    print("5. Run this script again")
    exit()

scan_id = scan_result[0]

# Get first target from this scan
cursor.execute("SELECT id, ip_address FROM targets WHERE scan_id = ? LIMIT 1", (scan_id,))
target_result = cursor.fetchone()

if not target_result:
    print("❌ No targets found in scan.")
    print("The scan might still be running. Wait for it to complete.")
    exit()

target_id = target_result[0]
ip_address = target_result[1]

print(f"📊 Adding test vulnerabilities to:")
print(f"   Scan ID: {scan_id}")
print(f"   Target: {ip_address}")
print()

# Add test vulnerabilities
test_vulnerabilities = [
    {
        'cve_id': 'CVE-2021-41773',
        'title': 'Apache HTTP Server 2.4.49 Path Traversal RCE',
        'description': 'A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased paths, this could allow for remote code execution.',
        'severity': 'critical',
        'cvss_score': 9.8,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'service_affected': 'Apache httpd 2.4.49',
        'remediation': 'Update to Apache HTTP Server 2.4.51 or later. As a workaround, ensure that all directories are protected with "require all denied".'
    },
    {
        'cve_id': 'CVE-2014-0160',
        'title': 'OpenSSL Heartbleed Information Disclosure',
        'description': 'The TLS heartbeat read overrun (CVE-2014-0160) in OpenSSL allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read. This can disclose private keys, usernames, passwords, and other sensitive data.',
        'severity': 'high',
        'cvss_score': 7.5,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
        'service_affected': 'OpenSSL 1.0.1',
        'remediation': 'Update OpenSSL to version 1.0.1g or later. Regenerate all SSL certificates and private keys. Change all passwords that may have been exposed.'
    },
    {
        'cve_id': 'CVE-2017-0144',
        'title': 'Windows SMB Remote Code Execution (EternalBlue)',
        'description': 'The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via crafted packets (MS17-010). This vulnerability was used by the WannaCry and NotPetya ransomware attacks.',
        'severity': 'critical',
        'cvss_score': 9.3,
        'cvss_vector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'service_affected': 'Windows SMB',
        'remediation': 'Install Microsoft Security Bulletin MS17-010. Disable SMBv1 if not required. Block ports 139 and 445 at the network perimeter.'
    },
    {
        'cve_id': 'CVE-2018-15473',
        'title': 'OpenSSH User Enumeration Vulnerability',
        'description': 'OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.',
        'severity': 'medium',
        'cvss_score': 5.3,
        'cvss_vector': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
        'service_affected': 'OpenSSH 7.7',
        'remediation': 'Update to OpenSSH 7.8 or later. Configure fail2ban to limit authentication attempts. Use key-based authentication instead of passwords.'
    }
]

# Insert vulnerabilities
for vuln in test_vulnerabilities:
    cursor.execute("""
        INSERT INTO vulnerabilities (
            target_id, cve_id, title, description, severity,
            cvss_score, cvss_vector, service_affected, remediation, discovered_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        target_id,
        vuln['cve_id'],
        vuln['title'],
        vuln['description'],
        vuln['severity'],
        vuln['cvss_score'],
        vuln['cvss_vector'],
        vuln['service_affected'],
        vuln['remediation'],
        datetime.now().isoformat()
    ))
    print(f"✅ Added: {vuln['cve_id']} ({vuln['severity'].upper()})")

# Update scan statistics
cursor.execute("""
    UPDATE scans SET
        total_vulnerabilities = 4,
        critical_count = 2,
        high_count = 1,
        medium_count = 1,
        low_count = 0
    WHERE id = ?
""", (scan_id,))

conn.commit()
conn.close()

print(f"\n✅ Successfully added 4 test vulnerabilities!")
print(f"\n📊 Summary:")
print(f"   🔴 Critical: 2")
print(f"   🟠 High: 1")
print(f"   🟡 Medium: 1")
print(f"   🟢 Low: 0")
print(f"\n🔄 Refresh your scan details page to see the exploit buttons!")