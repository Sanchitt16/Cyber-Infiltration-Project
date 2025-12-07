"""
Network Change Detector & Anomaly Monitor
==========================================
A Blue Team monitoring tool that scans networks, detects changes,
and monitors for anomalies.

Author: Sanchitt16
Version: 1.0.0
"""

from database import init_database
from scanner import run_scan, quick_scan, full_scan

__version__ = "1.0.0"
__all__ = ["init_database", "run_scan", "quick_scan", "full_scan"]


if __name__ == "__main__":
    print("Network Change Detector & Anomaly Monitor")
    print("=" * 45)
    print("\nInitializing database...")
    init_database()
    print("\nSystem ready. Use scanner.py to run scans.")
    print("Example: python scanner.py 192.168.1.0/24")