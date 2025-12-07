# 🛡️ Cyber Infiltration & Defense Monitor

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![Security](https://img.shields.io/badge/Security-Blue%20Team-red?style=flat&logo=hackthebox)
![Platform](https://img.shields.io/badge/Platform-Streamlit-FF4B4B?style=flat&logo=streamlit)
![License](https://img.shields.io/badge/License-MIT-green)

A full-stack **Blue Team** security tool that bridges the gap between offensive reconnaissance and defensive monitoring. It establishes a network baseline, continuously scans for deviations, and alerts on potential "Infiltration" attempts (new devices, rogue ports, or service changes).

---

## 🌐 Live Demo

### [▶️ Click Here to Launch the Dashboard](https://cyber-infiltration-project-gfvncdmhwsfmndxqr3yzbx.streamlit.app)

> **Note:** The cloud demo runs in **Simulation Mode** (using synthetic data) to demonstrate the alert logic without requiring local network access.

---

## ⚡ Quick Start (Local)

### Option 1: One-Click Setup (Windows)
Simply double-click the `setup.bat` file included in this repository.
* ✅ Checks for Python & Nmap
* ✅ Creates a virtual environment
* ✅ Installs dependencies
* ✅ Launches the Dashboard automatically

### Option 2: Manual Setup (Mac/Linux)
```bash
# 1. Clone the repo
git clone [https://github.com/Sanchitt16/Cyber-Infiltration-Project.git](https://github.com/Sanchitt16/Cyber-Infiltration-Project.git)
cd Cyber-Infiltration-Project

# 2. Install dependencies
pip install -r requirements.txt

# 3. Launch the tool
streamlit run app.py

## 🎯 Features

- **Network Scanning**: Scan IP addresses or subnets using Nmap
- **Database Storage**: Store scan results in SQLite database
- **Anomaly Detection**: Detect new devices, open ports, service changes, and security threats
- **Web Dashboard**: Beautiful Streamlit UI with real-time status
- **Continuous Monitoring**: Automated scanning at configurable intervals
- **Security Alerts**: Detect brute force targets, suspicious ports, and aggressive scanning
- **Demo Mode**: Works without Nmap for demonstrations and testing

## 📋 Prerequisites

1. **Python 3.x** - Make sure Python is installed
2. **Nmap** (Optional for Demo Mode) - Required for real network scanning
   - Windows: Download from https://nmap.org/download.html
   - Linux: `sudo apt install nmap`
   - macOS: `brew install nmap`

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/Sanchitt16/Cyber-Infiltration-Project.git
cd Cyber-Infiltration-Project

# Install Python dependencies
pip install -r requirements.txt
```

## 📁 Project Structure

```
Cyber-Infiltration-Project/
├── app.py            # Streamlit Web Dashboard
├── monitor.py        # Continuous monitoring script
├── detector.py       # Anomaly detection engine
├── scanner.py        # Nmap scanning functionality
├── database.py       # SQLite database operations
├── setup.bat         # One-click Windows setup script
├── view_db.py        # Database viewer utility
├── init.py           # Package initialization
├── requirements.txt  # Python dependencies
└── README.md         # This file
```

## 🗄️ Database Schema

### Tables

1. **Scans** - Records of each network scan
   - `id`: Primary key
   - `timestamp`: When the scan was performed

2. **Hosts** - Discovered network hosts
   - `id`: Primary key
   - `scan_id`: Foreign key to Scans
   - `ip_address`: Host IP address
   - `status`: Host status (up/down)
   - `mac_address`: MAC address (if available)

3. **Ports** - Open ports on hosts
   - `id`: Primary key
   - `host_id`: Foreign key to Hosts
   - `port_number`: Port number
   - `protocol`: Protocol (tcp/udp)
   - `state`: Port state (open/closed/filtered)
   - `service_name`: Detected service
   - `version`: Service version info

## 💻 Usage

### Initialize the Database

```bash
python database.py
```

### Run a Network Scan

```bash
# Scan localhost
python scanner.py

# Scan a specific IP
python scanner.py 192.168.1.1

# Scan a subnet
python scanner.py 192.168.1.0/24
```

### Scan Functions

```python
from scanner import run_scan, quick_scan, full_scan

# Standard scan with version detection (-sV -T4)
results = run_scan("192.168.1.0/24")

# Quick scan - faster but less detailed (-T4 -F)
results = quick_scan("192.168.1.1")

# Full scan with OS detection (-sV -sC -O -T4)
results = full_scan("192.168.1.1")
```

## ⚠️ Important Notes

- **Administrator/Root privileges** may be required for certain scan types (OS detection, SYN scans)
- Always ensure you have **permission** to scan the target network
- Scanning networks without authorization is **illegal** in many jurisdictions

## 🛣️ Roadmap

- [x] **Phase 1**: Scanner & Database (Backend)
- [ ] **Phase 2**: Change Detection Engine
- [ ] **Phase 3**: Streamlit Dashboard
- [ ] **Phase 4**: Alerting System (Discord Webhook)

## 📝 License

This project is for educational purposes.
