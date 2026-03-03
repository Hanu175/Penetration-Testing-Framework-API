# 🔐 Penetration Testing Framework API

A Third-Year CSE Mini Project – A web-based **Penetration Testing Framework API** that allows users to initiate vulnerability scans from a dashboard interface.

This project automates security assessments using Python and integrates tools like Nmap to perform network scanning and generate structured security reports.

---

## 📌 Project Overview

The Penetration Testing Framework API is designed to:

- Perform network scanning
- Detect open ports and services
- Generate structured vulnerability reports
- Provide a user-friendly dashboard to initiate scans
- Automate basic penetration testing tasks

---

## 🛠️ Tech Stack

### Backend
- Python
- Flask
- Flask-CORS

### Frontend
- HTML
- CSS
- JavaScript

### Security Tools
- python-nmap

### Libraries Used
- Flask==3.0.0
- Flask-CORS==4.0.0
- python-dotenv==1.0.0
- python-nmap==0.7.1
- requests==2.31.0
- Jinja2==3.1.2
- fpdf==1.7.2
- colorama==0.4.6
- PyYAML==6.0.1
- bcrypt

---

## 📂 Project Structure

```
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
├── database\                               ← Database files
│   ├── schema.sql                         ← ✅ Table definitions
│   ├── init_db.py                         ← ✅ Database initialization script
│   └── pentest.db                         ← ✅ SQLite database file
│
├── logs\                                   ← Application logs (auto-created)
│   └── pentest_framework.log              ← Log file (created on first run)
│
├── reports\                                ← Generated reports (auto-created)
│   └── templates\                         ← Report templates
│
├── .env                                    ← ✅ Environment variables (sensitive)
└── .gitignore                             ← Git ignore rules (recommended)
```

## 📂 Database Structure
```
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

database schema
```

# 🚀 How to Run the Project

---

## ✅ Step 1: Install Python (If Not Installed)

If you don't have Python installed:

1. Install Python from the official website.
2. While installing, make sure to check:
   ✔ Add Python to Environment Variables

### Check if pip is installed

```bash
python -m pip --version
```

### Upgrade pip

```bash
python -m pip install --upgrade pip
```

---

## ✅ Step 2: If Python is Already Installed

```bash
python -m ensurepip --upgrade
python -m pip install --upgrade pip
python -m pip --version
```

---

## ✅ Step 3: Create and Activate Virtual Environment

All further steps must be performed inside a virtual environment (venv).

### Create Virtual Environment

```bash
python -m venv venv
```

### Activate Virtual Environment (Windows)

```bash
venv\Scripts\activate
```

To deactivate:

```bash
deactivate
```

### Check installed packages

```bash
pip list
```

(It should be empty)

---

## ✅ Step 4: Create requirements.txt (If Not Present)

Create a file named:

```
requirements.txt
```

Paste the following inside it:

```
Flask==3.0.0
Flask-CORS==4.0.0
python-dotenv==1.0.0
python-nmap==0.7.1
requests==2.31.0
Jinja2==3.1.2
fpdf==1.7.2
colorama==0.4.6
PyYAML==6.0.1
```

---

## ✅ Step 5: Install Dependencies

```bash
python -m pip install -r requirements.txt
```

Check installation:

```bash
pip list
```

If it doesn't work:

```bash
python -m pip list
```

---

## ✅ Step 6: Install bcrypt (If Missing)

If bcrypt is not listed:

```bash
pip install bcrypt
```

---

## ✅ Step 7: Run the Backend

```bash
py backend\app.py
```

The Flask server should start successfully.

---

## ✅ Step 8: Run the Frontend

1. Go to `index.html`
2. Right-click
3. Open with **Live Server**

---

# 🔎 How to Use

1. Open the dashboard.
2. Register/Login (if authentication is implemented).
3. Enter target IP address or domain.
4. Click **Start Scan**.
5. View scan results.
6. Download report (if PDF generation is enabled).

After login, users can initiate scans directly from the dashboard.

---

# 📊 Features

- Network Port Scanning  
- Service Detection  
- Automated Vulnerability Detection  
- PDF Report Generation  
- Dashboard Interface  
- REST API Architecture  

---

# 🔐 Disclaimer

This project is developed strictly for educational purposes.

⚠ Do NOT scan:
- Government websites
- Banking systems
- Production servers
- Any system without proper authorization

Only test on:
- Localhost
- Virtual Machines
- Lab environments
- Systems you own or have permission to test

---

# 👨‍💻 Contributors

- Vedant Paste - Hanu175
- Pranav Sadwelkar - pranav-1205  
- Bhavesh Mundye - Bhavesh1412
- Tejas Patil - TEJASPATIL0710

---

# 📘 Learning Outcomes

- Hands-on experience with Flask API development
- Understanding of vulnerability scanning
- Practical automation of Nmap
- Secure coding practices
- Report generation and automation

---

# ‼️Project  is Still in progress‼️

⭐ If you found this project useful, consider giving it a star!