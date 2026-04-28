-- includes: users, projects, scans, targets, ports, vulnerabilities,
--           exploits, sessions, reports, scan_logs, settings tables
-- Penetration Testing Framework Database Schema

-- Table: users
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Table: projects
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    client_name TEXT,
    user_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'active',
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Table: scans
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    scan_name TEXT NOT NULL,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_by INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, --Newly added
    total_hosts INTEGER DEFAULT 0,
    total_ports INTEGER DEFAULT 0,
    total_vulnerabilities INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    scan_duration INTEGER,
    error_message TEXT,
    FOREIGN KEY (project_id) REFERENCES projects (id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users (id)
);

-- Table: targets
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    hostname TEXT,
    mac_address TEXT,
    status TEXT DEFAULT 'up',
    os_name TEXT,
    os_version TEXT,
    os_accuracy INTEGER,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

-- Table: ports
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT,
    product TEXT,
    version TEXT,
    extra_info TEXT,
    confidence INTEGER,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets (id) ON DELETE CASCADE
);

-- Table: vulnerabilities
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL,
    port_id INTEGER,
    cve_id TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    cvss_score REAL,
    cvss_vector TEXT,
    service_affected TEXT,
    version_affected TEXT,
    exploit_available INTEGER DEFAULT 0,
    exploited INTEGER DEFAULT 0,
    metasploit_module TEXT,
    exploit_notes TEXT,
    reference_links TEXT,
    remediation TEXT,
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    verified_at TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets (id) ON DELETE CASCADE,
    FOREIGN KEY (port_id) REFERENCES ports (id) ON DELETE SET NULL
);

-- Table: scan_logs
CREATE TABLE IF NOT EXISTS scan_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    log_level TEXT NOT NULL,
    message TEXT NOT NULL,
    module TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
);

-- Table: settings
CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE IF NOT EXISTS hash_discoveries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,a
    scan_id INTEGER NOT NULL,
    sqli_result_id INTEGER,
    hash_value TEXT NOT NULL,
    hash_type INTEGER,
    hash_type_name TEXT,
    source TEXT,
    discovered_at TEXT NOT NULL,
    cracked INTEGER DEFAULT 0,
    plaintext TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (sqli_result_id) REFERENCES sqlmap_results(id) ON DELETE CASCADE
)



-- Create indexes
CREATE INDEX IF NOT EXISTS idx_scans_project ON scans (project_id);

CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status);

CREATE INDEX IF NOT EXISTS idx_targets_scan ON targets (scan_id);

CREATE INDEX IF NOT EXISTS idx_targets_ip ON targets (ip_address);

CREATE INDEX IF NOT EXISTS idx_ports_target ON ports (target_id);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_target ON vulnerabilities (target_id);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities (severity);

-- Insert default admin user (password: admin123)
INSERT
    OR IGNORE INTO users (
        username,
        email,
        password_hash,
        role
    )
VALUES (
        'admin',
        'admin@pentest.local',
        'admin123',
        'admin'
    );

-- Insert default project
INSERT
    OR IGNORE INTO projects (
        id,
        name,
        description,
        user_id
    )
VALUES (
        1,
        'Default Project',
        'Default project for all scans',
        1
    );

-- Insert default settings
INSERT
    OR IGNORE INTO settings (key, value, description)
VALUES (
        'nmap_timeout',
        '300',
        'Default Nmap scan timeout in seconds'
    ),
    (
        'max_threads',
        '10',
        'Maximum concurrent scanning threads'
    ),
    (
        'nvd_api_key',
        '',
        'National Vulnerability Database API key'
    ),
    (
        'log_level',
        'INFO',
        'Application logging level'
    );