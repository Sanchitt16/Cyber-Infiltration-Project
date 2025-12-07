"""
Network Scanner Module for Network Change Detector & Anomaly Monitor.
Uses python-nmap to scan networks and stores results in SQLite database.
"""

import nmap
from datetime import datetime
from typing import Optional, Dict, Any
import shutil
import sys
import os

from database import (
    init_database,
    insert_scan,
    insert_host,
    insert_port
)

# Common Nmap installation paths on Windows
NMAP_PATHS = [
    r"C:\Program Files (x86)\Nmap",
    r"C:\Program Files\Nmap",
]


def check_nmap_installed() -> bool:
    """Check if Nmap is installed and available in PATH or common locations."""
    # First check if it's in PATH
    if shutil.which("nmap") is not None:
        return True
    
    # Check common installation paths on Windows
    for path in NMAP_PATHS:
        nmap_exe = os.path.join(path, "nmap.exe")
        if os.path.exists(nmap_exe):
            # Add to PATH for this session
            os.environ["PATH"] = path + os.pathsep + os.environ.get("PATH", "")
            return True
    
    return False


def run_scan(target: str, arguments: str = "-sV -T4") -> Dict[str, Any]:
    """
    Scan a target IP/Subnet using nmap and save results to database.
    
    Args:
        target: The target IP address or subnet (e.g., "192.168.1.0/24" or "192.168.1.1")
        arguments: Nmap scan arguments (default: "-sV -T4" for service version detection)
    
    Returns:
        A dictionary containing scan summary and results.
    """
    # Check if Nmap is installed
    if not check_nmap_installed():
        error_msg = """
[-] ERROR: Nmap is not installed or not in PATH!

Please install Nmap:
  - Windows: Download from https://nmap.org/download.html
  - Linux:   sudo apt install nmap
  - macOS:   brew install nmap

After installation, restart your terminal/IDE and try again.
"""
        print(error_msg)
        return {"error": "Nmap not installed", "success": False}
    
    print(f"[*] Starting scan on target: {target}")
    print(f"[*] Scan arguments: {arguments}")
    
    # Initialize the nmap scanner
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError as e:
        print(f"[-] Failed to initialize Nmap scanner: {e}")
        return {"error": str(e), "success": False}
    
    try:
        # Execute the scan
        nm.scan(hosts=target, arguments=arguments)
    except nmap.PortScannerError as e:
        print(f"[-] Nmap scan error: {e}")
        return {"error": str(e), "success": False}
    except Exception as e:
        print(f"[-] Unexpected error during scan: {e}")
        return {"error": str(e), "success": False}
    
    # Create a new scan record in the database
    scan_timestamp = datetime.now()
    scan_id = insert_scan(scan_timestamp)
    print(f"[+] Scan record created with ID: {scan_id}")
    
    # Results summary
    results = {
        "success": True,
        "scan_id": scan_id,
        "timestamp": scan_timestamp.isoformat(),
        "hosts_scanned": 0,
        "hosts_up": 0,
        "total_ports_found": 0,
        "hosts": []
    }
    
    # Parse and store scan results
    for host in nm.all_hosts():
        results["hosts_scanned"] += 1
        
        # Get host information
        host_status = nm[host].state()
        
        # Try to get MAC address (may not always be available)
        mac_address = None
        if 'mac' in nm[host]['addresses']:
            mac_address = nm[host]['addresses']['mac']
        
        # Insert host into database
        host_id = insert_host(
            scan_id=scan_id,
            ip_address=host,
            status=host_status,
            mac_address=mac_address
        )
        
        host_data = {
            "ip": host,
            "status": host_status,
            "mac": mac_address,
            "ports": []
        }
        
        if host_status == "up":
            results["hosts_up"] += 1
            print(f"[+] Host {host} is UP (MAC: {mac_address or 'N/A'})")
            
            # Process each protocol (tcp, udp, etc.)
            for protocol in nm[host].all_protocols():
                ports = nm[host][protocol].keys()
                
                for port in ports:
                    port_info = nm[host][protocol][port]
                    
                    port_state = port_info.get('state', 'unknown')
                    service_name = port_info.get('name', '')
                    
                    # Build version string from product, version, and extrainfo
                    version_parts = []
                    if port_info.get('product'):
                        version_parts.append(port_info['product'])
                    if port_info.get('version'):
                        version_parts.append(port_info['version'])
                    if port_info.get('extrainfo'):
                        version_parts.append(f"({port_info['extrainfo']})")
                    version = ' '.join(version_parts) if version_parts else None
                    
                    # Insert port into database
                    insert_port(
                        host_id=host_id,
                        port_number=port,
                        protocol=protocol,
                        state=port_state,
                        service_name=service_name,
                        version=version
                    )
                    
                    results["total_ports_found"] += 1
                    
                    port_data = {
                        "port": port,
                        "protocol": protocol,
                        "state": port_state,
                        "service": service_name,
                        "version": version
                    }
                    host_data["ports"].append(port_data)
                    
                    print(f"    [+] Port {port}/{protocol}: {port_state} - {service_name} {version or ''}")
        
        results["hosts"].append(host_data)
    
    print(f"\n[+] Scan complete!")
    print(f"[+] Summary: {results['hosts_up']}/{results['hosts_scanned']} hosts up, {results['total_ports_found']} open ports found")
    
    return results


def quick_scan(target: str) -> Dict[str, Any]:
    """
    Perform a quick scan without version detection.
    Faster but less detailed than full scan.
    
    Args:
        target: The target IP address or subnet
    
    Returns:
        A dictionary containing scan summary and results.
    """
    return run_scan(target, arguments="-T4 -F")


def full_scan(target: str) -> Dict[str, Any]:
    """
    Perform a comprehensive scan with version detection and OS detection.
    Slower but more detailed.
    
    Args:
        target: The target IP address or subnet
    
    Returns:
        A dictionary containing scan summary and results.
    """
    return run_scan(target, arguments="-sV -sC -O -T4")


if __name__ == "__main__":
    import sys
    
    # Initialize the database
    init_database()
    
    # Default target (localhost) - change this to scan other targets
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "127.0.0.1"
        print(f"[*] No target specified, using default: {target}")
        print(f"[*] Usage: python scanner.py <target>")
        print(f"[*] Example: python scanner.py 192.168.1.0/24")
    
    # Run the scan
    results = run_scan(target)
    
    if results.get("success"):
        print(f"\n[+] Scan data saved to database with Scan ID: {results['scan_id']}")