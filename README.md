# 🔐 Penetration Testing Framework API
A Third-Year CSE Mini Project – A web-based Penetration Testing Framework API that allows users to initiate vulnerability scans from a dashboard interface.

This project automates security assessments using Python and integrates tools like Nmap to perform network scanning and generate structured security reports.

## 📌 Project Overview
The Penetration Testing Framework API is designed to:
* Perform network scanning
* Detect open ports and services
* Generate structured vulnerability reports
* Provide a user-friendly dashboard to initiate scans
* Automate basic penetration testing tasks

## 🛠️ Tech Stack
### Backend
* Python
* Flask
* Flask-CORS

### Frontend
* HTML
* CSS
* JavaScript

### Security Tools
* python-nmap

### Libraries Used
* Flask==3.0.0
* Flask-CORS==4.0.0
* python-dotenv==1.0.0
* python-nmap==0.7.1
* requests==2.31.0
* Jinja2==3.1.2
* fpdf==1.7.2
* colorama==0.4.6
* PyYAML==6.0.1
* bcrypt

## 📂 Project Structure
```text
Penetration Testing Framework API\
│
├── venv\                                   ← Virtual environment (isolated Python)
│   ├── Scripts\
│   │   ├── python.exe                     ← Python interpreter for this project
│   │   └── activate.bat                   ← Activation script
│   └── Lib\                               ← Installed packages
│
├── backend\                                ← All application code
│   ├── services\                          ← Business logic layer
│   │   ├── __init__.py                    ← Makes services a Python package
│   │   ├── scanner_service.py             ← [TO BE CREATED] Nmap integration
│   │   └── analyzer_service.py            ← [TO BE CREATED] NVD integration
│   │
│   ├── utils\                             ← Helper modules
│   │   ├── __init__.py                    ← Makes utils a Python package
│   │   ├── database.py                    ← ✅ Database operations
│   │   └── logger.py                      ← ✅ Logging system
│   │
│   ├── app.py                             ← [TO BE CREATED] Main Flask API
│   ├── config.py                          ← ✅ Configuration management
│   └── requirements.txt                    ← ✅ List of dependencies
│
├── database\                               ← Database directory
│   ├── schema.sql                         ← ✅ Table definitions
│   └── init_db.py                         ← ✅ Database initialization script
│                                           (Note: pentest.db is auto-generated here and hidden via .gitignore)
│
├── logs\                                   ← Application logs (auto-created)
│   └── pentest_framework.log              ← Log file (created on first run)
│
├── reports\                                ← Generated reports (auto-created)
│   └── templates\                         ← Report templates
│
├── .env.example                            ← ✅ Environment template (Safe for GitHub)
└── .gitignore                             ← Git ignore rules (Excludes local .env and pentest.db)
```

## 📂 Database Structure
```text
users ─┬─> projects ─┬─> scans ─┬─> targets ─┬─> ports
       │             │          │            │
       │             │          │            └─> vulnerabilities
       │             │          │
       │             │          └─> scan_logs
       │             │
       │             └─> (future: reports)
       │
       └─> (tracks who created what)

settings (standalone configuration table)
```

## 🚀 How to Run the Project

### ✅ Step 1: Install Python (If Not Installed)
If you don't have Python installed:
* Install Python from the official website.
* While installing, check: **✔ Add Python to Environment Variables**
* Upgrade pip:
  ```bash
  python -m pip install --upgrade pip
  ```

### ✅ Step 2: Create and Activate Virtual Environment
```bash
python -m venv venv
venv\Scripts\activate
```

### ✅ Step 3: Install Dependencies
```bash
python -m pip install -r requirements.txt
pip install bcrypt
```

### ✅ Step 4: Environment Configuration ⚙️
The project relies on localized environment variables that are kept hidden from version control for security.
1. Locate the `.env.example` file in the root directory.
2. Duplicate or copy this file and rename the new copy exactly to `.env`:
   ```bash
   copy .env.example .env
   ```
3. Open your newly created `.env` file and replace the placeholder variables with your configuration data:
   ```text
   PORT=5000
   FLASK_ENV=development
   SECRET_KEY=your_secret_key_here
   ```

### ✅ Step 5: Database Initialization 🗄️
The actual SQLite database file `pentest.db` is strictly excluded from GitHub to keep local tracking clean. You must initialize a fresh database locally before launching the project:
1. Open your terminal and run the database initialization script:
   ```bash
   python database/init_db.py
   ```
2. This creates a clean `pentest.db` file inside the `database/` folder using the structured definitions in `schema.sql`.

### ✅ Step 6: Run the Backend
```bash
python backend/app.py
```

### ✅ Step 7: Run the Frontend
1. Open `frontend/index.html`.
2. Right-click and select **Open with Live Server**.

## 🔎 How to Use
1. Open the dashboard.
2. Register/Login (if authentication is implemented).
3. Enter target IP address or domain.
4. Click **Start Scan**.
5. View scan results.
6. Download report (if PDF generation is enabled).

## 📊 Features
* Network Port Scanning
* Service Detection
* Automated Vulnerability Detection
* PDF Report Generation
* Dashboard Interface
* REST API Architecture

## 🔐 Disclaimer
This project is developed strictly for educational purposes.

**⚠ Do NOT scan:**
* Government websites
* Banking systems
* Production servers
* Any system without proper authorization

**Only test on:**
* Localhost
* Virtual Machines
* Lab environments
* Systems you own or have explicit permission to test

## 👨‍💻 Contributors
* Vedant Paste - Hanu175
* Pranav Sadwelkar - pranav-1205
* Bhavesh Mundye - Bhavesh1412
* Tejas Patil - TEJASPATIL0710

## 📘 Learning Outcomes
* Hands-on experience with Flask API development
* Understanding of vulnerability scanning
* Practical automation of Nmap
* Secure coding practices
* Report generation and automation

## ‼️ Project is Still in progress ‼️
**Tasks remaining:**
* PDF generation and download
* Scan report download
* Delete an entry from dashboard
* Metasploit integration (Requires disabling Windows Defender locally to install Metasploit payload engines)

⭐ *If you found this project useful, consider giving it a star!*
