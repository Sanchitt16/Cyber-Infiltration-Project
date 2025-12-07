"""
Anomaly Detection Engine for Network Change Detector & Anomaly Monitor.
Compares scans to detect security threats like new hosts, new ports, and service changes.
Also detects potential brute force attacks and aggressive scanning patterns.
"""

from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from database import (
    get_connection,
    get_all_scans,
    get_hosts_by_scan,
    get_ports_by_host
)

# =============================================================================
# CONFIGURATION - Thresholds for attack detection
# =============================================================================

# Brute Force Detection Thresholds
BRUTE_FORCE_PORTS = [22, 23, 3389, 5900, 21, 3306, 1433, 5432, 27017]  # SSH, Telnet, RDP, VNC, FTP, MySQL, MSSQL, PostgreSQL, MongoDB
BRUTE_FORCE_TIME_WINDOW_MINUTES = 10  # Time window to check for rapid scans
BRUTE_FORCE_SCAN_THRESHOLD = 5  # Number of scans in time window to trigger alert

# Aggressive Scanning Detection Thresholds
AGGRESSIVE_PORT_THRESHOLD = 20  # Many new ports opened suddenly
AGGRESSIVE_HOST_THRESHOLD = 5   # Many new hosts appearing suddenly
FILTERED_PORT_THRESHOLD = 10    # Many filtered ports (firewall blocking)


def get_two_most_recent_scans() -> Tuple[Optional[int], Optional[int]]:
    """
    Fetch the two most recent scan IDs from the database.
    
    Returns:
        A tuple of (previous_scan_id, current_scan_id).
        Returns (None, None) if no scans exist.
        Returns (None, current_scan_id) if only one scan exists.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM Scans ORDER BY timestamp DESC LIMIT 2")
    scans = cursor.fetchall()
    conn.close()
    
    if len(scans) == 0:
        return (None, None)
    elif len(scans) == 1:
        return (None, scans[0]['id'])
    else:
        # scans[0] is the most recent (current), scans[1] is the previous
        return (scans[1]['id'], scans[0]['id'])


def get_scan_data(scan_id: int) -> Dict[str, Any]:
    """
    Get all hosts and ports for a specific scan in a structured format.
    
    Args:
        scan_id: The ID of the scan to retrieve.
    
    Returns:
        A dictionary with IP addresses as keys, containing host info and ports.
        Example: {
            '192.168.1.1': {
                'status': 'up',
                'mac_address': 'AA:BB:CC:DD:EE:FF',
                'ports': {
                    (80, 'tcp'): {'state': 'open', 'service': 'http', 'version': 'Apache 2.4'},
                    (22, 'tcp'): {'state': 'open', 'service': 'ssh', 'version': 'OpenSSH 8.0'}
                }
            }
        }
    """
    scan_data = {}
    
    hosts = get_hosts_by_scan(scan_id)
    for host in hosts:
        ip = host['ip_address']
        scan_data[ip] = {
            'status': host['status'],
            'mac_address': host['mac_address'],
            'host_id': host['id'],
            'ports': {}
        }
        
        ports = get_ports_by_host(host['id'])
        for port in ports:
            port_key = (port['port_number'], port['protocol'])
            scan_data[ip]['ports'][port_key] = {
                'state': port['state'],
                'service': port['service_name'],
                'version': port['version']
            }
    
    return scan_data


def compare_scans(prev_scan_id: int, curr_scan_id: int) -> List[Dict[str, Any]]:
    """
    Compare two scans to identify security anomalies.
    
    Args:
        prev_scan_id: The ID of the previous (baseline) scan.
        curr_scan_id: The ID of the current scan to compare.
    
    Returns:
        A list of anomaly dictionaries with structure:
        {
            'type': 'new_host' | 'new_port' | 'service_change' | 'host_down' | 'port_closed',
            'severity': 'high' | 'medium' | 'low' | 'info',
            'ip': 'x.x.x.x',
            'details': 'Description of the change',
            'previous': 'Previous value (if applicable)',
            'current': 'Current value (if applicable)'
        }
    """
    anomalies = []
    
    # Get structured data for both scans
    prev_data = get_scan_data(prev_scan_id)
    curr_data = get_scan_data(curr_scan_id)
    
    prev_ips = set(prev_data.keys())
    curr_ips = set(curr_data.keys())
    
    # =========================================================================
    # 1. Detect NEW HOSTS (IPs in current but not in previous)
    # =========================================================================
    new_hosts = curr_ips - prev_ips
    for ip in new_hosts:
        host_info = curr_data[ip]
        port_count = len(host_info['ports'])
        open_ports = [f"{p[0]}/{p[1]}" for p, info in host_info['ports'].items() if info['state'] == 'open']
        
        anomalies.append({
            'type': 'new_host',
            'severity': 'high',
            'ip': ip,
            'details': f"New host detected with {port_count} ports ({len(open_ports)} open)",
            'previous': None,
            'current': f"Status: {host_info['status']}, MAC: {host_info['mac_address'] or 'N/A'}, Open ports: {', '.join(open_ports) if open_ports else 'None'}"
        })
    
    # =========================================================================
    # 2. Detect HOSTS THAT WENT DOWN (IPs in previous but not in current)
    # =========================================================================
    missing_hosts = prev_ips - curr_ips
    for ip in missing_hosts:
        anomalies.append({
            'type': 'host_down',
            'severity': 'medium',
            'ip': ip,
            'details': f"Host no longer detected in scan",
            'previous': f"Status: {prev_data[ip]['status']}",
            'current': None
        })
    
    # =========================================================================
    # 3. For hosts present in BOTH scans, compare ports and services
    # =========================================================================
    common_hosts = prev_ips & curr_ips
    for ip in common_hosts:
        prev_ports = prev_data[ip]['ports']
        curr_ports = curr_data[ip]['ports']
        
        prev_port_keys = set(prev_ports.keys())
        curr_port_keys = set(curr_ports.keys())
        
        # ---------------------------------------------------------------------
        # 3a. Detect NEW PORTS (ports in current but not in previous)
        # ---------------------------------------------------------------------
        new_ports = curr_port_keys - prev_port_keys
        for port_key in new_ports:
            port_num, protocol = port_key
            port_info = curr_ports[port_key]
            
            if port_info['state'] == 'open':
                severity = 'high'
            elif port_info['state'] == 'filtered':
                severity = 'medium'
            else:
                severity = 'low'
            
            anomalies.append({
                'type': 'new_port',
                'severity': severity,
                'ip': ip,
                'details': f"New port {port_num}/{protocol} detected ({port_info['state']})",
                'previous': None,
                'current': f"Service: {port_info['service'] or 'unknown'}, Version: {port_info['version'] or 'N/A'}"
            })
        
        # ---------------------------------------------------------------------
        # 3b. Detect CLOSED PORTS (ports in previous but not in current)
        # ---------------------------------------------------------------------
        closed_ports = prev_port_keys - curr_port_keys
        for port_key in closed_ports:
            port_num, protocol = port_key
            port_info = prev_ports[port_key]
            
            anomalies.append({
                'type': 'port_closed',
                'severity': 'info',
                'ip': ip,
                'details': f"Port {port_num}/{protocol} no longer detected",
                'previous': f"Service: {port_info['service'] or 'unknown'}, Version: {port_info['version'] or 'N/A'}",
                'current': None
            })
        
        # ---------------------------------------------------------------------
        # 3c. Detect SERVICE CHANGES on existing ports
        # ---------------------------------------------------------------------
        common_ports = prev_port_keys & curr_port_keys
        for port_key in common_ports:
            port_num, protocol = port_key
            prev_port = prev_ports[port_key]
            curr_port = curr_ports[port_key]
            
            # Check for state change (e.g., filtered -> open)
            if prev_port['state'] != curr_port['state']:
                if curr_port['state'] == 'open' and prev_port['state'] != 'open':
                    severity = 'high'
                elif curr_port['state'] == 'closed' and prev_port['state'] == 'open':
                    severity = 'medium'
                else:
                    severity = 'low'
                
                anomalies.append({
                    'type': 'state_change',
                    'severity': severity,
                    'ip': ip,
                    'details': f"Port {port_num}/{protocol} state changed: {prev_port['state']} → {curr_port['state']}",
                    'previous': prev_port['state'],
                    'current': curr_port['state']
                })
            
            # Check for service name change
            if prev_port['service'] != curr_port['service']:
                anomalies.append({
                    'type': 'service_change',
                    'severity': 'medium',
                    'ip': ip,
                    'details': f"Port {port_num}/{protocol} service changed",
                    'previous': prev_port['service'] or 'unknown',
                    'current': curr_port['service'] or 'unknown'
                })
            
            # Check for version change
            if prev_port['version'] != curr_port['version']:
                # Only report if both have version info (not just N/A -> something)
                if prev_port['version'] and curr_port['version']:
                    anomalies.append({
                        'type': 'version_change',
                        'severity': 'medium',
                        'ip': ip,
                        'details': f"Port {port_num}/{protocol} ({curr_port['service'] or 'unknown'}) version changed",
                        'previous': prev_port['version'],
                        'current': curr_port['version']
                    })
                elif curr_port['version'] and not prev_port['version']:
                    # Version info now available (likely just more detailed scan)
                    anomalies.append({
                        'type': 'version_change',
                        'severity': 'info',
                        'ip': ip,
                        'details': f"Port {port_num}/{protocol} version info now available",
                        'previous': 'N/A',
                        'current': curr_port['version']
                    })
    
    return anomalies


def detect_brute_force_targets(scan_id: int) -> List[Dict[str, Any]]:
    """
    Detect hosts that may be targets of brute force attacks.
    Looks for open ports commonly targeted by brute force attacks.
    
    Args:
        scan_id: The scan ID to analyze.
    
    Returns:
        List of potential brute force target anomalies.
    """
    anomalies = []
    scan_data = get_scan_data(scan_id)
    
    for ip, host_info in scan_data.items():
        exposed_services = []
        
        for (port_num, protocol), port_info in host_info['ports'].items():
            if port_info['state'] == 'open' and port_num in BRUTE_FORCE_PORTS:
                service_name = port_info['service'] or 'unknown'
                exposed_services.append({
                    'port': port_num,
                    'protocol': protocol,
                    'service': service_name,
                    'version': port_info['version']
                })
        
        if exposed_services:
            # Determine severity based on what's exposed
            high_risk_ports = [22, 3389, 23]  # SSH, RDP, Telnet
            has_high_risk = any(s['port'] in high_risk_ports for s in exposed_services)
            
            service_list = ', '.join([f"{s['port']}/{s['service']}" for s in exposed_services])
            
            anomalies.append({
                'type': 'brute_force_target',
                'severity': 'high' if has_high_risk else 'medium',
                'ip': ip,
                'details': f"Host has {len(exposed_services)} brute-force vulnerable services exposed: {service_list}",
                'previous': None,
                'current': exposed_services
            })
    
    return anomalies


def detect_rapid_scanning(time_window_minutes: int = None) -> List[Dict[str, Any]]:
    """
    Detect if there's been rapid/aggressive scanning activity.
    Multiple scans in a short time window could indicate automated scanning.
    
    Args:
        time_window_minutes: Time window to check (defaults to config value).
    
    Returns:
        List of rapid scanning anomalies.
    """
    if time_window_minutes is None:
        time_window_minutes = BRUTE_FORCE_TIME_WINDOW_MINUTES
    
    anomalies = []
    conn = get_connection()
    cursor = conn.cursor()
    
    # Get scans from the time window
    cursor.execute("""
        SELECT id, timestamp FROM Scans 
        ORDER BY timestamp DESC
    """)
    all_scans = cursor.fetchall()
    conn.close()
    
    if len(all_scans) < 2:
        return anomalies
    
    # Parse timestamps and check for rapid scanning
    recent_scans = []
    now = datetime.now()
    
    for scan in all_scans:
        try:
            # Handle different timestamp formats
            ts = scan['timestamp']
            if isinstance(ts, str):
                # Try parsing the timestamp string
                try:
                    scan_time = datetime.fromisoformat(ts)
                except ValueError:
                    scan_time = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")
            else:
                scan_time = ts
            
            time_diff = now - scan_time
            if time_diff <= timedelta(minutes=time_window_minutes):
                recent_scans.append({
                    'id': scan['id'],
                    'timestamp': scan_time
                })
        except Exception:
            continue
    
    if len(recent_scans) >= BRUTE_FORCE_SCAN_THRESHOLD:
        anomalies.append({
            'type': 'rapid_scanning',
            'severity': 'high',
            'ip': 'N/A',
            'details': f"Detected {len(recent_scans)} scans in the last {time_window_minutes} minutes. Possible automated reconnaissance.",
            'previous': None,
            'current': f"Scan IDs: {', '.join([str(s['id']) for s in recent_scans])}"
        })
    
    return anomalies


def detect_aggressive_port_scanning(prev_scan_id: int, curr_scan_id: int) -> List[Dict[str, Any]]:
    """
    Detect aggressive port scanning patterns.
    A sudden large increase in open/filtered ports could indicate an attack.
    
    Args:
        prev_scan_id: Previous scan ID.
        curr_scan_id: Current scan ID.
    
    Returns:
        List of aggressive scanning anomalies.
    """
    anomalies = []
    
    prev_data = get_scan_data(prev_scan_id)
    curr_data = get_scan_data(curr_scan_id)
    
    # Check for sudden increase in hosts
    new_host_count = len(set(curr_data.keys()) - set(prev_data.keys()))
    if new_host_count >= AGGRESSIVE_HOST_THRESHOLD:
        anomalies.append({
            'type': 'aggressive_host_discovery',
            'severity': 'critical',
            'ip': 'Multiple',
            'details': f"Detected {new_host_count} new hosts suddenly appearing. Possible network intrusion or unauthorized device connection.",
            'previous': f"{len(prev_data)} hosts",
            'current': f"{len(curr_data)} hosts"
        })
    
    # Check each host for aggressive port patterns
    for ip in curr_data:
        curr_ports = curr_data[ip]['ports']
        prev_ports = prev_data.get(ip, {}).get('ports', {})
        
        # Count new open ports
        new_open_ports = []
        new_filtered_ports = []
        
        for port_key, port_info in curr_ports.items():
            if port_key not in prev_ports:
                if port_info['state'] == 'open':
                    new_open_ports.append(port_key[0])
                elif port_info['state'] == 'filtered':
                    new_filtered_ports.append(port_key[0])
        
        # Detect many new open ports (possible backdoor installation)
        if len(new_open_ports) >= AGGRESSIVE_PORT_THRESHOLD:
            anomalies.append({
                'type': 'aggressive_port_opening',
                'severity': 'critical',
                'ip': ip,
                'details': f"Detected {len(new_open_ports)} new open ports. Possible malware or backdoor installation.",
                'previous': f"{len(prev_ports)} ports",
                'current': f"New ports: {', '.join(map(str, sorted(new_open_ports)[:10]))}{'...' if len(new_open_ports) > 10 else ''}"
            })
        
        # Detect many filtered ports (possible firewall/IDS response to scanning)
        if len(new_filtered_ports) >= FILTERED_PORT_THRESHOLD:
            anomalies.append({
                'type': 'firewall_response',
                'severity': 'medium',
                'ip': ip,
                'details': f"Detected {len(new_filtered_ports)} newly filtered ports. Firewall may be responding to scanning activity.",
                'previous': None,
                'current': f"Filtered ports: {', '.join(map(str, sorted(new_filtered_ports)[:10]))}{'...' if len(new_filtered_ports) > 10 else ''}"
            })
    
    return anomalies


def detect_suspicious_services(scan_id: int) -> List[Dict[str, Any]]:
    """
    Detect suspicious or potentially malicious services.
    
    Args:
        scan_id: The scan ID to analyze.
    
    Returns:
        List of suspicious service anomalies.
    """
    anomalies = []
    scan_data = get_scan_data(scan_id)
    
    # Suspicious port numbers often used by malware/hackers
    suspicious_ports = {
        4444: "Metasploit default listener",
        5555: "Android ADB (if unexpected)",
        6666: "IRC backdoor common port",
        6667: "IRC (often used by botnets)",
        31337: "Back Orifice / Elite hacker port",
        12345: "NetBus trojan",
        27374: "SubSeven trojan",
        1234: "Common backdoor port",
        9001: "Tor commonly used port",
        9050: "Tor SOCKS proxy",
        4443: "Common alternate HTTPS/backdoor",
        8080: "Common proxy (check if expected)",
        8443: "Alternate HTTPS",
    }
    
    # Suspicious service names
    suspicious_services = ['bindshell', 'reverse', 'shell', 'backdoor', 'trojan', 'rat', 'meterpreter']
    
    for ip, host_info in scan_data.items():
        for (port_num, protocol), port_info in host_info['ports'].items():
            if port_info['state'] != 'open':
                continue
            
            # Check for suspicious ports
            if port_num in suspicious_ports:
                anomalies.append({
                    'type': 'suspicious_port',
                    'severity': 'critical',
                    'ip': ip,
                    'details': f"Port {port_num}/{protocol} is open - {suspicious_ports[port_num]}",
                    'previous': None,
                    'current': f"Service: {port_info['service'] or 'unknown'}, Version: {port_info['version'] or 'N/A'}"
                })
            
            # Check for suspicious service names
            service = (port_info['service'] or '').lower()
            version = (port_info['version'] or '').lower()
            combined = f"{service} {version}"
            
            for sus in suspicious_services:
                if sus in combined:
                    anomalies.append({
                        'type': 'suspicious_service',
                        'severity': 'critical',
                        'ip': ip,
                        'details': f"Suspicious service detected on port {port_num}: '{sus}' found in service info",
                        'previous': None,
                        'current': f"Service: {port_info['service']}, Version: {port_info['version']}"
                    })
                    break
    
    return anomalies


def build_summary(anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a summary of anomalies by type and severity.
    
    Args:
        anomalies: List of anomaly dictionaries.
    
    Returns:
        Summary dictionary with counts by type and severity.
    """
    summary = {
        'total': len(anomalies),
        'by_type': {},
        'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    }
    
    for anomaly in anomalies:
        # Count by type
        atype = anomaly['type']
        summary['by_type'][atype] = summary['by_type'].get(atype, 0) + 1
        
        # Count by severity
        severity = anomaly['severity']
        if severity in summary['by_severity']:
            summary['by_severity'][severity] += 1
    
    return summary


def detect_anomalies(include_security_scan: bool = True) -> Dict[str, Any]:
    """
    Main function to detect anomalies between the two most recent scans.
    Also runs security checks for brute force targets and suspicious services.
    
    Args:
        include_security_scan: Whether to include brute force and suspicious service detection.
    
    Returns:
        A dictionary containing:
        - 'success': Boolean indicating if comparison was possible
        - 'message': Status message
        - 'prev_scan_id': Previous scan ID
        - 'curr_scan_id': Current scan ID  
        - 'anomalies': List of detected anomalies
        - 'summary': Count of anomalies by type and severity
    """
    prev_scan_id, curr_scan_id = get_two_most_recent_scans()
    
    if curr_scan_id is None:
        return {
            'success': False,
            'message': 'No scans found in database. Run a scan first.',
            'prev_scan_id': None,
            'curr_scan_id': None,
            'anomalies': [],
            'summary': {}
        }
    
    if prev_scan_id is None:
        # Can still run security scans on single scan
        anomalies = []
        
        if include_security_scan:
            # Check for brute force targets in current scan
            anomalies.extend(detect_brute_force_targets(curr_scan_id))
            
            # Check for suspicious services
            anomalies.extend(detect_suspicious_services(curr_scan_id))
            
            # Check for rapid scanning
            anomalies.extend(detect_rapid_scanning())
        
        summary = build_summary(anomalies)
        
        return {
            'success': True,
            'message': f'Only one scan found. Security scan complete. Found {len(anomalies)} potential threats.',
            'prev_scan_id': None,
            'curr_scan_id': curr_scan_id,
            'anomalies': anomalies,
            'summary': summary
        }
    
    # Perform comparison between scans
    anomalies = compare_scans(prev_scan_id, curr_scan_id)
    
    if include_security_scan:
        # Check for brute force targets in current scan
        anomalies.extend(detect_brute_force_targets(curr_scan_id))
        
        # Check for suspicious services
        anomalies.extend(detect_suspicious_services(curr_scan_id))
        
        # Check for rapid scanning patterns
        anomalies.extend(detect_rapid_scanning())
        
        # Check for aggressive port scanning
        anomalies.extend(detect_aggressive_port_scanning(prev_scan_id, curr_scan_id))
    
    # Build summary
    summary = build_summary(anomalies)
    
    return {
        'success': True,
        'message': f'Compared scan {prev_scan_id} with scan {curr_scan_id}. Found {len(anomalies)} anomalies.',
        'prev_scan_id': prev_scan_id,
        'curr_scan_id': curr_scan_id,
        'anomalies': anomalies,
        'summary': summary
    }


def print_anomalies(result: Dict[str, Any]) -> None:
    """Pretty print the anomaly detection results."""
    
    print("\n" + "=" * 70)
    print("🔍 ANOMALY DETECTION REPORT")
    print("=" * 70)
    
    if not result['success']:
        print(f"\n⚠️  {result['message']}")
        return
    
    if result['prev_scan_id']:
        print(f"\n📊 Comparing Scan #{result['prev_scan_id']} → Scan #{result['curr_scan_id']}")
    else:
        print(f"\n� Security Scan of Scan #{result['curr_scan_id']}")
    
    print(f"�📈 Total Anomalies Found: {result['summary']['total']}")
    
    # Print severity summary
    sev = result['summary']['by_severity']
    print(f"\n   ⛔ Critical: {sev.get('critical', 0)}  |  🔴 High: {sev.get('high', 0)}  |  🟠 Medium: {sev.get('medium', 0)}  |  🟡 Low: {sev.get('low', 0)}  |  🔵 Info: {sev.get('info', 0)}")
    
    if result['summary']['total'] == 0:
        print("\n✅ No anomalies detected. Network state unchanged.")
        return
    
    # Print anomalies grouped by severity
    print("\n" + "-" * 70)
    
    severity_icons = {'critical': '⛔', 'high': '🔴', 'medium': '🟠', 'low': '🟡', 'info': '🔵'}
    type_icons = {
        'new_host': '🖥️',
        'host_down': '💀',
        'new_port': '🚪',
        'port_closed': '🔒',
        'state_change': '🔄',
        'service_change': '⚙️',
        'version_change': '📦',
        # New security-related icons
        'brute_force_target': '🎯',
        'rapid_scanning': '⚡',
        'aggressive_host_discovery': '🔍',
        'aggressive_port_opening': '💣',
        'firewall_response': '🛡️',
        'suspicious_port': '⚠️',
        'suspicious_service': '🦠'
    }
    
    # Sort by severity (critical first)
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    sorted_anomalies = sorted(result['anomalies'], key=lambda x: severity_order.get(x['severity'], 5))
    
    for anomaly in sorted_anomalies:
        sev_icon = severity_icons.get(anomaly['severity'], '❓')
        type_icon = type_icons.get(anomaly['type'], '❓')
        
        print(f"\n{sev_icon} [{anomaly['severity'].upper()}] {type_icon} {anomaly['type'].upper()}")
        print(f"   IP: {anomaly['ip']}")
        print(f"   Details: {anomaly['details']}")
        if anomaly['previous']:
            print(f"   Previous: {anomaly['previous']}")
        if anomaly['current']:
            print(f"   Current: {anomaly['current']}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    # Run anomaly detection and print results
    result = detect_anomalies()
    print_anomalies(result)
