# Secure File Transfer Monitoring System

## Description
This project monitors file system activity and detects suspicious actions like:
- File modification
- Bulk file transfer
- Sensitive file movement to USB
- Integrity violations

## Features
- Real-time file monitoring
- SHA-256 integrity checking
- Bulk transfer detection
- USB data exfiltration alert
- Logging system
- Audit report generation

## Technologies Used
Python
Watchdog Library
Hashlib

## Project Structure
SecureFileMonitor/
│
├── monitor.py
├── sensitive_files.txt
├── logs/
│   └── activity_log.txt
├── reports/
│   └── audit_report.txt
└── README.md

## How to Run
1. Install dependencies
pip install watchdog

2. Run program
python monitor.py

## Author
Tejas Dihora
Cyber Security Student
