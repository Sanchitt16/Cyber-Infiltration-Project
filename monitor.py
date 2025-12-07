"""
Continuous Network Monitor for Network Change Detector & Anomaly Monitor.
Automatically scans targets at specified intervals and detects anomalies.
"""

import argparse
import time
import sys
import signal
from datetime import datetime
from typing import Optional

from database import init_database, clear_database
from scanner import run_scan, check_nmap_installed
from detector import detect_anomalies, print_anomalies


class NetworkMonitor:
    """Continuous network monitoring with automated scanning and anomaly detection."""
    
    def __init__(self, target: str, interval_minutes: int = 5, scan_args: str = "-sV -T4"):
        """
        Initialize the network monitor.
        
        Args:
            target: Target IP address, subnet, or domain to monitor.
            interval_minutes: Time between scans in minutes.
            scan_args: Nmap scan arguments.
        """
        self.target = target
        self.interval_minutes = interval_minutes
        self.interval_seconds = interval_minutes * 60
        self.scan_args = scan_args
        self.running = False
        self.scan_count = 0
        self.start_time = None
        
    def print_banner(self):
        """Print the monitoring banner."""
        banner = """
╔══════════════════════════════════════════════════════════════════════╗
║           🛡️  NETWORK CHANGE DETECTOR & ANOMALY MONITOR  🛡️          ║
║                      Continuous Monitoring Mode                       ║
╚══════════════════════════════════════════════════════════════════════╝
"""
        print(banner)
        print(f"  🎯 Target:          {self.target}")
        print(f"  ⏱️  Scan Interval:   Every {self.interval_minutes} minute(s)")
        print(f"  📝 Scan Arguments:  {self.scan_args}")
        print(f"  🗑️  Auto-Cleanup:    Yes (clears on stop)")
        print(f"  🕐 Started:         {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n  Press Ctrl+C to stop monitoring\n")
        print("=" * 72)
    
    def run_single_scan(self) -> bool:
        """
        Run a single scan and detect anomalies.
        
        Returns:
            True if scan was successful, False otherwise.
        """
        self.scan_count += 1
        
        print(f"\n{'='*72}")
        print(f"📡 SCAN #{self.scan_count} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 72)
        
        # Run the scan
        result = run_scan(self.target, self.scan_args)
        
        if not result.get('success'):
            print(f"[-] Scan failed: {result.get('error', 'Unknown error')}")
            return False
        
        # Detect anomalies (needs at least 2 scans)
        if self.scan_count >= 2:
            print("\n🔍 Checking for anomalies...")
            anomaly_result = detect_anomalies()
            
            if anomaly_result['success'] and anomaly_result['summary']['total'] > 0:
                print_anomalies(anomaly_result)
                
                # Alert for critical/high severity
                critical_count = anomaly_result['summary']['by_severity'].get('critical', 0)
                high_count = anomaly_result['summary']['by_severity'].get('high', 0)
                
                if critical_count > 0 or high_count > 0:
                    self.trigger_alert(anomaly_result)
            else:
                print("✅ No new anomalies detected.")
        else:
            print("\n📊 First scan complete. Anomaly detection will start after the next scan.")
        
        return True
    
    def trigger_alert(self, anomaly_result: dict):
        """
        Trigger an alert for high-severity anomalies.
        This can be extended to send Discord webhooks, emails, etc.
        
        Args:
            anomaly_result: The anomaly detection result dictionary.
        """
        critical = anomaly_result['summary']['by_severity'].get('critical', 0)
        high = anomaly_result['summary']['by_severity'].get('high', 0)
        
        print("\n" + "!" * 72)
        print("⚠️  SECURITY ALERT ⚠️")
        print("!" * 72)
        print(f"Detected {critical} CRITICAL and {high} HIGH severity anomalies!")
        print("Review the report above for details.")
        print("!" * 72)
        
        # TODO: Add Discord webhook notification here (Phase 4)
        # TODO: Add email notification here
        # TODO: Add logging to file here
    
    def countdown(self, seconds: int):
        """
        Display a countdown timer until next scan.
        
        Args:
            seconds: Number of seconds to countdown.
        """
        print(f"\n⏳ Next scan in {seconds // 60} minute(s)...", end="", flush=True)
        
        try:
            for remaining in range(seconds, 0, -1):
                if not self.running:
                    break
                    
                mins, secs = divmod(remaining, 60)
                timer = f"\r⏳ Next scan in {mins:02d}:{secs:02d}  "
                print(timer, end="", flush=True)
                time.sleep(1)
            
            print("\r" + " " * 40 + "\r", end="", flush=True)  # Clear the line
        except KeyboardInterrupt:
            raise
    
    def start(self):
        """Start continuous monitoring."""
        self.running = True
        self.start_time = datetime.now()
        
        # Set up signal handler for graceful shutdown
        def signal_handler(sig, frame):
            print("\n\n🛑 Stopping monitor...")
            self.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Print banner
        self.print_banner()
        
        # Main monitoring loop
        while self.running:
            try:
                # Run scan
                success = self.run_single_scan()
                
                if not success:
                    print(f"⚠️  Scan failed. Retrying in {self.interval_minutes} minute(s)...")
                
                # Wait for next interval
                if self.running:
                    self.countdown(self.interval_seconds)
                    
            except KeyboardInterrupt:
                print("\n\n🛑 Stopping monitor...")
                self.stop()
                break
            except Exception as e:
                print(f"\n[-] Error during monitoring: {e}")
                print(f"⚠️  Retrying in {self.interval_minutes} minute(s)...")
                time.sleep(self.interval_seconds)
    
    def stop(self):
        """Stop the monitoring and clear the database."""
        self.running = False
        
        # Print summary
        if self.start_time:
            runtime = datetime.now() - self.start_time
            print("\n" + "=" * 72)
            print("📊 MONITORING SESSION SUMMARY")
            print("=" * 72)
            print(f"  🎯 Target:       {self.target}")
            print(f"  📡 Total Scans:  {self.scan_count}")
            print(f"  ⏱️  Runtime:      {runtime}")
            print(f"  🕐 Ended:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("=" * 72)
        
        # Clear database after session ends
        print("\n🗑️  Clearing database...")
        clear_database()
        print("✅ Session data cleared. Ready for next run.")


def parse_interval(interval_str: str) -> int:
    """
    Parse interval string like '5m', '1h', '30s' into minutes.
    
    Args:
        interval_str: Interval string (e.g., '5m', '1h', '30s')
    
    Returns:
        Interval in minutes (minimum 1).
    """
    interval_str = interval_str.strip().lower()
    
    if interval_str.endswith('h'):
        return int(interval_str[:-1]) * 60
    elif interval_str.endswith('m'):
        return max(1, int(interval_str[:-1]))
    elif interval_str.endswith('s'):
        return max(1, int(interval_str[:-1]) // 60) or 1
    else:
        # Assume minutes if no suffix
        return max(1, int(interval_str))


def main():
    """Main entry point for the continuous monitor."""
    parser = argparse.ArgumentParser(
        description="🛡️ Network Change Detector - Continuous Monitoring Mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python monitor.py --target 192.168.1.1
  python monitor.py --target 192.168.1.0/24 --interval 10m
  python monitor.py --target scanme.nmap.org --interval 5m
  python monitor.py --target example.com --interval 1h --quick

Interval formats:
  5m  = 5 minutes
  1h  = 1 hour
  30s = 30 seconds (minimum 1 minute)
        """
    )
    
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target IP address, subnet (CIDR), or domain to monitor"
    )
    
    parser.add_argument(
        "--interval", "-i",
        default="5m",
        help="Scan interval (default: 5m). Examples: 5m, 10m, 1h"
    )
    
    parser.add_argument(
        "--quick", "-q",
        action="store_true",
        help="Use quick scan mode (faster but less detailed)"
    )
    
    parser.add_argument(
        "--full", "-f",
        action="store_true",
        help="Use full scan mode with OS detection (slower, needs admin)"
    )
    
    args = parser.parse_args()
    
    # Check if Nmap is installed
    if not check_nmap_installed():
        print("[-] ERROR: Nmap is not installed or not in PATH!")
        print("    Please install Nmap from https://nmap.org/download.html")
        sys.exit(1)
    
    # Initialize database
    init_database()
    
    # Parse interval
    try:
        interval_minutes = parse_interval(args.interval)
    except ValueError:
        print(f"[-] Invalid interval format: {args.interval}")
        print("    Use formats like: 5m, 10m, 1h")
        sys.exit(1)
    
    # Determine scan arguments
    if args.quick:
        scan_args = "-T4 -F"
    elif args.full:
        scan_args = "-sV -sC -O -T4"
    else:
        scan_args = "-sV -T4"
    
    # Create and start monitor
    monitor = NetworkMonitor(
        target=args.target,
        interval_minutes=interval_minutes,
        scan_args=scan_args
    )
    
    monitor.start()


if __name__ == "__main__":
    main()