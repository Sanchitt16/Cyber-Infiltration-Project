# Network Change Detector & Anomaly Monitor

A **Blue Team** monitoring tool that scans a network, saves the state to a database, and detects changes (new devices, new open ports, service changes) over time.

## 🎯 Features

- **Network Scanning**: Scan IP addresses or subnets using Nmap
- **Database Storage**: Store scan results in SQLite database
- **Change Detection**: Track new devices, open ports, and service changes (coming soon)
- **Dashboard**: Visualize network data with Streamlit (coming soon)
- **Alerting**: Discord Webhook notifications (coming soon)

## 📋 Prerequisites

1. **Python 3.x** - Make sure Python is installed
2. **Nmap** - The Nmap port scanner must be installed on your system
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
├── init.py           # Package initialization and entry point
├── database.py       # SQLite database operations
├── scanner.py        # Nmap scanning functionality
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
