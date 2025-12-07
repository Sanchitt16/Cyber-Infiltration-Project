"""Quick script to view database contents."""
from database import get_all_scans, get_hosts_by_scan, get_ports_by_host

print("=" * 60)
print("DATABASE CONTENTS")
print("=" * 60)

scans = get_all_scans()
print(f"\n📊 Total Scans: {len(scans)}\n")

for scan in scans:
    print(f"┌─ SCAN ID: {scan['id']} | Time: {scan['timestamp']}")
    
    hosts = get_hosts_by_scan(scan['id'])
    for host in hosts:
        print(f"│  └─ HOST: {host['ip_address']} ({host['status']}) MAC: {host['mac_address'] or 'N/A'}")
        
        ports = get_ports_by_host(host['id'])
        for port in ports:
            print(f"│      └─ Port {port['port_number']}/{port['protocol']}: {port['state']} - {port['service_name']} {port['version'] or ''}")
    
    print("│")

print("=" * 60)
