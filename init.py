"""
Network Change Detector & Anomaly Monitor
==========================================
A Blue Team monitoring tool that scans networks, detects changes,
and monitors for anomalies.

Author: Sanchitt16
Version: 1.2.0
"""

from database import init_database
from scanner import run_scan, quick_scan, full_scan
from detector import detect_anomalies, compare_scans, get_two_most_recent_scans
from monitor import NetworkMonitor

__version__ = "1.2.0"
__all__ = [
    "init_database", 
    "run_scan", 
    "quick_scan", 
    "full_scan",
    "detect_anomalies",
    "compare_scans",
    "get_two_most_recent_scans",
    "NetworkMonitor"
]


if __name__ == "__main__":
    print("Network Change Detector & Anomaly Monitor")
    print("=" * 45)
    print("\nInitializing database...")
    init_database()
    print("\nSystem ready.")
    print("\nCommands:")
    print("  python scanner.py <target>      - Run a single network scan")
    print("  python detector.py              - Detect anomalies between scans")
    print("  python monitor.py -t <target>   - Start continuous monitoring")
    print("  python view_db.py               - View database contents")
    print("\nExample:")
    print("  python monitor.py --target 192.168.1.0/24 --interval 5m")