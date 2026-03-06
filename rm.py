import sqlite3

# Connect to database
conn = sqlite3.connect('database/pentest.db')
cursor = conn.cursor()

print("=" * 60)
print("Removing Test Vulnerabilities")
print("=" * 60)
print()

# List of test CVE IDs we added
test_cve_ids = [
    'CVE-2021-41773',
    'CVE-2014-0160',
    'CVE-2017-0144',
    'CVE-2018-15473'
]

# Show what will be deleted
print("Looking for test vulnerabilities with these CVE IDs:")
for cve in test_cve_ids:
    print(f"  - {cve}")
print()

# Count how many exist
cursor.execute("""
    SELECT COUNT(*) FROM vulnerabilities 
    WHERE cve_id IN (?, ?, ?, ?)
""", tuple(test_cve_ids))

count = cursor.fetchone()[0]

if count == 0:
    print("✅ No test vulnerabilities found in database.")
    print("   Database is already clean!")
    conn.close()
    exit()

print(f"Found {count} test vulnerabilities to remove.")
print()

# Show details of what will be deleted
cursor.execute("""
    SELECT v.id, v.cve_id, v.severity, t.ip_address, s.id as scan_id, s.scan_name
    FROM vulnerabilities v
    JOIN targets t ON v.target_id = t.id
    JOIN scans s ON t.scan_id = s.id
    WHERE v.cve_id IN (?, ?, ?, ?)
""", tuple(test_cve_ids))

vulns = cursor.fetchall()

print("Details of vulnerabilities to be removed:")
print("-" * 60)
for vuln in vulns:
    vuln_id, cve_id, severity, ip, scan_id, scan_name = vuln
    print(f"ID: {vuln_id} | {cve_id} | {severity.upper()} | {ip} | Scan: {scan_name}")
print("-" * 60)
print()

# Confirm deletion
response = input("Do you want to delete these vulnerabilities? (yes/no): ")

if response.lower() != 'yes':
    print("❌ Cancelled. No vulnerabilities were deleted.")
    conn.close()
    exit()

print()
print("Deleting vulnerabilities...")

# Delete the test vulnerabilities
cursor.execute("""
    DELETE FROM vulnerabilities 
    WHERE cve_id IN (?, ?, ?, ?)
""", tuple(test_cve_ids))

deleted_count = cursor.rowcount

# Update scan statistics for affected scans
print("Updating scan statistics...")

cursor.execute("""
    SELECT DISTINCT s.id
    FROM scans s
    JOIN targets t ON s.id = t.scan_id
    JOIN vulnerabilities v ON t.id = v.target_id
""")

scan_ids = [row[0] for row in cursor.fetchall()]

# Recalculate statistics for each affected scan
for scan_id in scan_ids:
    # Count total vulnerabilities
    cursor.execute("""
        SELECT COUNT(*) FROM vulnerabilities v
        JOIN targets t ON v.target_id = t.id
        WHERE t.scan_id = ?
    """, (scan_id,))
    total = cursor.fetchone()[0]
    
    # Count by severity
    cursor.execute("""
        SELECT severity, COUNT(*) FROM vulnerabilities v
        JOIN targets t ON v.target_id = t.id
        WHERE t.scan_id = ?
        GROUP BY severity
    """, (scan_id,))
    
    severity_counts = {row[0]: row[1] for row in cursor.fetchall()}
    
    # Update scan
    cursor.execute("""
        UPDATE scans SET
            total_vulnerabilities = ?,
            critical_count = ?,
            high_count = ?,
            medium_count = ?,
            low_count = ?
        WHERE id = ?
    """, (
        total,
        severity_counts.get('critical', 0),
        severity_counts.get('high', 0),
        severity_counts.get('medium', 0),
        severity_counts.get('low', 0),
        scan_id
    ))

conn.commit()
conn.close()

print()
print("=" * 60)
print(f"✅ Successfully deleted {deleted_count} test vulnerabilities!")
print("=" * 60)
print()
print("Scan statistics have been updated.")
print("Refresh your dashboard to see the changes.")


# #Remove all vulnerabilities from a specific scan

# import sqlite3

# # Connect to database
# conn = sqlite3.connect('database/pentest.db')
# cursor = conn.cursor()

# print("=" * 60)
# print("Remove Vulnerabilities from Scan")
# print("=" * 60)
# print()

# # List all scans
# print("Available scans:")
# print("-" * 60)
# cursor.execute("""
#     SELECT s.id, s.scan_name, s.target, s.total_vulnerabilities, s.status
#     FROM scans s
#     ORDER BY s.id DESC
# """)

# scans = cursor.fetchall()

# if not scans:
#     print("No scans found in database.")
#     conn.close()
#     exit()

# for scan in scans:
#     scan_id, name, target, vuln_count, status = scan
#     print(f"ID: {scan_id} | {name} | Target: {target} | Vulnerabilities: {vuln_count} | Status: {status}")

# print("-" * 60)
# print()

# # Ask which scan
# scan_id = input("Enter scan ID to remove vulnerabilities from (or 'cancel'): ")

# if scan_id.lower() == 'cancel':
#     print("Cancelled.")
#     conn.close()
#     exit()

# try:
#     scan_id = int(scan_id)
# except ValueError:
#     print("Invalid scan ID.")
#     conn.close()
#     exit()

# # Check if scan exists
# cursor.execute("SELECT scan_name, total_vulnerabilities FROM scans WHERE id = ?", (scan_id,))
# result = cursor.fetchone()

# if not result:
#     print(f"Scan ID {scan_id} not found.")
#     conn.close()
#     exit()

# scan_name, vuln_count = result

# print()
# print(f"Scan: {scan_name}")
# print(f"Current vulnerabilities: {vuln_count}")
# print()

# if vuln_count == 0:
#     print("This scan has no vulnerabilities to remove.")
#     conn.close()
#     exit()

# # Confirm
# response = input(f"Delete ALL {vuln_count} vulnerabilities from this scan? (yes/no): ")

# if response.lower() != 'yes':
#     print("Cancelled.")
#     conn.close()
#     exit()

# print()
# print("Deleting vulnerabilities...")

# # Delete vulnerabilities
# cursor.execute("""
#     DELETE FROM vulnerabilities 
#     WHERE target_id IN (
#         SELECT id FROM targets WHERE scan_id = ?
#     )
# """, (scan_id,))

# deleted_count = cursor.rowcount

# # Reset scan statistics
# cursor.execute("""
#     UPDATE scans SET
#         total_vulnerabilities = 0,
#         critical_count = 0,
#         high_count = 0,
#         medium_count = 0,
#         low_count = 0
#     WHERE id = ?
# """, (scan_id,))

# conn.commit()
# conn.close()

# print()
# print(f"✅ Deleted {deleted_count} vulnerabilities from scan #{scan_id}")
# print("Refresh your dashboard to see the changes.")