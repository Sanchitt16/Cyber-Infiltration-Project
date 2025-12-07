"""
Network Change Detector & Anomaly Monitor - Streamlit Dashboard
================================================================
A Blue Team monitoring tool with a user-friendly web interface.
"""

import streamlit as st
import pandas as pd
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List
import random

# =============================================================================
# Demo Mode Detection - Check if running on Streamlit Cloud
# =============================================================================
import os
IS_STREAMLIT_CLOUD = os.environ.get('STREAMLIT_RUNTIME_ENV') == 'cloud' or not os.path.exists('database.py')

# Only import local modules if not on cloud
if not IS_STREAMLIT_CLOUD:
    try:
        from database import init_database, clear_database, get_all_scans, get_hosts_by_scan, get_ports_by_host
        from scanner import run_scan, quick_scan, check_nmap_installed
        from detector import detect_anomalies, get_two_most_recent_scans, get_scan_data
        LOCAL_MODE_AVAILABLE = True
    except ImportError:
        LOCAL_MODE_AVAILABLE = False
else:
    LOCAL_MODE_AVAILABLE = False

# =============================================================================
# Demo Data Generator
# =============================================================================
def generate_demo_hosts():
    """Generate realistic demo host data."""
    return [
        {'ip_address': '192.168.1.1', 'status': 'up', 'mac_address': '00:1A:2B:3C:4D:5E', 'open_ports': 4, 'filtered_ports': 1},
        {'ip_address': '192.168.1.15', 'status': 'up', 'mac_address': '00:1A:2B:3C:4D:5F', 'open_ports': 2, 'filtered_ports': 0},
        {'ip_address': '192.168.1.42', 'status': 'up', 'mac_address': '00:1A:2B:3C:4D:60', 'open_ports': 3, 'filtered_ports': 2},
        {'ip_address': '192.168.1.100', 'status': 'up', 'mac_address': '00:1A:2B:3C:4D:61', 'open_ports': 1, 'filtered_ports': 0},
        {'ip_address': '192.168.1.105', 'status': 'up', 'mac_address': None, 'open_ports': 5, 'filtered_ports': 1},
    ]

def generate_demo_ports():
    """Generate realistic demo port data with services."""
    return [
        {'ip': '192.168.1.1', 'port': 22, 'protocol': 'tcp', 'state': 'open', 'service': 'ssh', 'version': 'OpenSSH 8.2'},
        {'ip': '192.168.1.1', 'port': 80, 'protocol': 'tcp', 'state': 'open', 'service': 'http', 'version': 'nginx 1.18.0'},
        {'ip': '192.168.1.1', 'port': 443, 'protocol': 'tcp', 'state': 'open', 'service': 'https', 'version': 'nginx 1.18.0'},
        {'ip': '192.168.1.1', 'port': 8080, 'protocol': 'tcp', 'state': 'open', 'service': 'http-proxy', 'version': ''},
        {'ip': '192.168.1.15', 'port': 22, 'protocol': 'tcp', 'state': 'open', 'service': 'ssh', 'version': 'OpenSSH 7.9'},
        {'ip': '192.168.1.15', 'port': 3389, 'protocol': 'tcp', 'state': 'open', 'service': 'ms-wbt-server', 'version': 'Microsoft RDP'},
        {'ip': '192.168.1.42', 'port': 21, 'protocol': 'tcp', 'state': 'open', 'service': 'ftp', 'version': 'vsftpd 3.0.3'},
        {'ip': '192.168.1.42', 'port': 23, 'protocol': 'tcp', 'state': 'open', 'service': 'telnet', 'version': ''},  # Suspicious!
        {'ip': '192.168.1.42', 'port': 3306, 'protocol': 'tcp', 'state': 'open', 'service': 'mysql', 'version': 'MySQL 5.7.32'},
        {'ip': '192.168.1.100', 'port': 80, 'protocol': 'tcp', 'state': 'open', 'service': 'http', 'version': 'Apache 2.4.41'},
        {'ip': '192.168.1.105', 'port': 22, 'protocol': 'tcp', 'state': 'open', 'service': 'ssh', 'version': 'OpenSSH 8.4'},
        {'ip': '192.168.1.105', 'port': 445, 'protocol': 'tcp', 'state': 'open', 'service': 'microsoft-ds', 'version': 'Samba 4.11'},
        {'ip': '192.168.1.105', 'port': 5900, 'protocol': 'tcp', 'state': 'open', 'service': 'vnc', 'version': 'VNC Server 5.3'},
        {'ip': '192.168.1.105', 'port': 6379, 'protocol': 'tcp', 'state': 'open', 'service': 'redis', 'version': 'Redis 6.0.9'},
        {'ip': '192.168.1.105', 'port': 27017, 'protocol': 'tcp', 'state': 'open', 'service': 'mongodb', 'version': 'MongoDB 4.4.2'},
    ]

def generate_demo_anomalies():
    """Generate realistic demo anomalies for impressive display."""
    return {
        'success': True,
        'anomalies': [
            {
                'type': 'new_host',
                'severity': 'high',
                'ip': '192.168.1.105',
                'details': 'New device appeared on network. MAC: Unknown. 5 open ports detected including Redis and MongoDB.'
            },
            {
                'type': 'suspicious_port',
                'severity': 'critical',
                'ip': '192.168.1.42',
                'details': 'TELNET (Port 23) detected! Unencrypted protocol - potential security risk. Recommend immediate investigation.'
            },
            {
                'type': 'new_port',
                'severity': 'medium',
                'ip': '192.168.1.1',
                'details': 'New port 8080 (http-proxy) opened on gateway device since last scan.'
            },
            {
                'type': 'service_change',
                'severity': 'medium',
                'ip': '192.168.1.15',
                'details': 'RDP service (Port 3389) version changed from 10.0 to Microsoft RDP. Possible update or compromise.'
            },
            {
                'type': 'brute_force_target',
                'severity': 'high',
                'ip': '192.168.1.42',
                'details': 'Host has FTP (21), Telnet (23), MySQL (3306) exposed - common brute force targets. High attack surface.'
            },
        ],
        'summary': {
            'total': 5,
            'by_severity': {
                'critical': 1,
                'high': 2,
                'medium': 2,
                'low': 0,
                'info': 0
            },
            'by_type': {
                'new_host': 1,
                'suspicious_port': 1,
                'new_port': 1,
                'service_change': 1,
                'brute_force_target': 1
            }
        }
    }

def generate_demo_scan_history():
    """Generate demo scan history."""
    now = datetime.now()
    return [
        {'id': 5, 'timestamp': (now - timedelta(minutes=2)).strftime('%Y-%m-%d %H:%M:%S'), 'hosts': 5, 'ports': 15},
        {'id': 4, 'timestamp': (now - timedelta(minutes=7)).strftime('%Y-%m-%d %H:%M:%S'), 'hosts': 4, 'ports': 10},
        {'id': 3, 'timestamp': (now - timedelta(minutes=12)).strftime('%Y-%m-%d %H:%M:%S'), 'hosts': 4, 'ports': 9},
        {'id': 2, 'timestamp': (now - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'), 'hosts': 4, 'ports': 8},
        {'id': 1, 'timestamp': (now - timedelta(hours=2)).strftime('%Y-%m-%d %H:%M:%S'), 'hosts': 3, 'ports': 6},
    ]

# =============================================================================
# Page Configuration
# =============================================================================
st.set_page_config(
    page_title="Network Monitor | Blue Team Tool",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =============================================================================
# Custom CSS Styling
# =============================================================================
st.markdown("""
<style>
    /* Main header styling */
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        text-align: center;
        padding: 1rem;
        margin-bottom: 1rem;
    }
    
    /* Status banners */
    .status-secure {
        background: linear-gradient(135deg, #00c853, #69f0ae);
        color: white;
        padding: 2rem;
        border-radius: 15px;
        text-align: center;
        font-size: 2rem;
        font-weight: bold;
        margin: 1rem 0;
        box-shadow: 0 4px 15px rgba(0, 200, 83, 0.4);
    }
    
    .status-alert {
        background: linear-gradient(135deg, #ff1744, #ff5252);
        color: white;
        padding: 2rem;
        border-radius: 15px;
        text-align: center;
        font-size: 2rem;
        font-weight: bold;
        margin: 1rem 0;
        box-shadow: 0 4px 15px rgba(255, 23, 68, 0.4);
        animation: pulse 2s infinite;
    }
    
    .status-warning {
        background: linear-gradient(135deg, #ff9100, #ffab40);
        color: white;
        padding: 2rem;
        border-radius: 15px;
        text-align: center;
        font-size: 2rem;
        font-weight: bold;
        margin: 1rem 0;
        box-shadow: 0 4px 15px rgba(255, 145, 0, 0.4);
    }
    
    .status-neutral {
        background: linear-gradient(135deg, #546e7a, #78909c);
        color: white;
        padding: 2rem;
        border-radius: 15px;
        text-align: center;
        font-size: 1.5rem;
        font-weight: bold;
        margin: 1rem 0;
    }
    
    @keyframes pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.02); }
        100% { transform: scale(1); }
    }
    
    /* Stat cards */
    .stat-card {
        background: #1e1e1e;
        border-radius: 10px;
        padding: 1.5rem;
        text-align: center;
        border: 1px solid #333;
    }
    
    .stat-number {
        font-size: 2.5rem;
        font-weight: bold;
        color: #00bcd4;
    }
    
    .stat-label {
        font-size: 0.9rem;
        color: #888;
        text-transform: uppercase;
    }
    
    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# =============================================================================
# Session State Initialization
# =============================================================================
if 'scan_running' not in st.session_state:
    st.session_state.scan_running = False
if 'last_scan_result' not in st.session_state:
    st.session_state.last_scan_result = None
if 'anomaly_result' not in st.session_state:
    st.session_state.anomaly_result = None
if 'auto_refresh' not in st.session_state:
    st.session_state.auto_refresh = False
if 'scan_count' not in st.session_state:
    st.session_state.scan_count = 0
if 'demo_mode' not in st.session_state:
    # Default to demo mode on Streamlit Cloud or if local modules unavailable
    st.session_state.demo_mode = not LOCAL_MODE_AVAILABLE

# =============================================================================
# Helper Functions
# =============================================================================

def get_hosts_dataframe() -> pd.DataFrame:
    """Get all hosts from the latest scan as a DataFrame."""
    scans = get_all_scans()
    if not scans:
        return pd.DataFrame()
    
    latest_scan = scans[0]
    hosts = get_hosts_by_scan(latest_scan['id'])
    
    data = []
    for host in hosts:
        ports = get_ports_by_host(host['id'])
        open_ports = [p for p in ports if p['state'] == 'open']
        filtered_ports = [p for p in ports if p['state'] == 'filtered']
        
        data.append({
            'IP Address': host['ip_address'],
            'Status': '🟢 Up' if host['status'] == 'up' else '🔴 Down',
            'MAC Address': host['mac_address'] or 'N/A',
            'Open Ports': len(open_ports),
            'Filtered Ports': len(filtered_ports),
            'Total Ports': len(ports)
        })
    
    return pd.DataFrame(data)


def get_ports_dataframe() -> pd.DataFrame:
    """Get all ports from the latest scan as a DataFrame."""
    scans = get_all_scans()
    if not scans:
        return pd.DataFrame()
    
    latest_scan = scans[0]
    hosts = get_hosts_by_scan(latest_scan['id'])
    
    data = []
    for host in hosts:
        ports = get_ports_by_host(host['id'])
        for port in ports:
            state_icon = {
                'open': '🟢',
                'closed': '🔴',
                'filtered': '🟡'
            }.get(port['state'], '⚪')
            
            data.append({
                'IP Address': host['ip_address'],
                'Port': port['port_number'],
                'Protocol': port['protocol'].upper(),
                'State': f"{state_icon} {port['state'].capitalize()}",
                'Service': port['service_name'] or 'Unknown',
                'Version': port['version'] or 'N/A'
            })
    
    return pd.DataFrame(data)


def render_anomaly_box(anomaly: Dict[str, Any]):
    """Render a single anomaly as a styled box."""
    severity = anomaly['severity']
    atype = anomaly['type']
    
    if severity == 'critical':
        st.error(f"⛔ **CRITICAL: {atype.upper().replace('_', ' ')}**\n\n"
                f"**IP:** {anomaly['ip']}\n\n"
                f"**Details:** {anomaly['details']}")
    elif severity == 'high':
        st.error(f"🔴 **HIGH: {atype.upper().replace('_', ' ')}**\n\n"
                f"**IP:** {anomaly['ip']}\n\n"
                f"**Details:** {anomaly['details']}")
    elif severity == 'medium':
        st.warning(f"🟠 **MEDIUM: {atype.upper().replace('_', ' ')}**\n\n"
                  f"**IP:** {anomaly['ip']}\n\n"
                  f"**Details:** {anomaly['details']}")
    elif severity == 'low':
        st.info(f"🟡 **LOW: {atype.upper().replace('_', ' ')}**\n\n"
               f"**IP:** {anomaly['ip']}\n\n"
               f"**Details:** {anomaly['details']}")
    else:
        st.info(f"🔵 **INFO: {atype.upper().replace('_', ' ')}**\n\n"
               f"**IP:** {anomaly['ip']}\n\n"
               f"**Details:** {anomaly['details']}")


# =============================================================================
# Sidebar
# =============================================================================
with st.sidebar:
    st.markdown("## 🛡️ Network Monitor")
    st.markdown("---")
    
    # Demo Mode Toggle - Prominent at top
    st.markdown("### 🎮 Mode")
    demo_mode = st.toggle(
        "Demo Mode",
        value=st.session_state.demo_mode,
        help="Demo Mode shows simulated data. Disable to run real network scans (requires Nmap)."
    )
    st.session_state.demo_mode = demo_mode
    
    if demo_mode:
        st.info("📺 **Demo Mode Active**\nShowing simulated network data with security alerts.")
    else:
        if not LOCAL_MODE_AVAILABLE:
            st.warning("⚠️ Local mode requires Nmap and local installation. Switching to Demo Mode.")
            st.session_state.demo_mode = True
            demo_mode = True
    
    st.markdown("---")
    
    # Target input (only show if not in demo mode)
    if not demo_mode:
        st.markdown("### 🎯 Target Configuration")
        target = st.text_input(
            "Target IP / Subnet / Domain",
            value="127.0.0.1",
            placeholder="e.g., 192.168.1.0/24",
            help="Enter an IP address, subnet (CIDR notation), or domain name"
        )
        
        # Scan type selection
        scan_type = st.selectbox(
            "Scan Type",
            ["Standard (-sV -T4)", "Quick (-T4 -F)", "Full (-sV -sC -O -T4)"],
            help="Quick: Faster but less detailed\nStandard: Service version detection\nFull: Includes OS detection (needs admin)"
        )
        
        st.markdown("---")
        
        # Scan button
        col1, col2 = st.columns(2)
        with col1:
            scan_button = st.button("🔍 Run Scan", use_container_width=True, type="primary")
        with col2:
            clear_button = st.button("🗑️ Clear Data", use_container_width=True)
        
        # Auto-refresh toggle
        st.markdown("---")
        st.markdown("### ⚙️ Settings")
        auto_refresh = st.toggle("Auto-Refresh (30s)", value=st.session_state.auto_refresh)
        st.session_state.auto_refresh = auto_refresh
        
        # Nmap status
        st.markdown("---")
        if LOCAL_MODE_AVAILABLE and check_nmap_installed():
            st.success("✅ Nmap Installed")
        else:
            st.error("❌ Nmap Not Found")
            st.markdown("[Download Nmap](https://nmap.org/download.html)")
    else:
        # Demo mode info
        target = "192.168.1.0/24"
        scan_type = "Standard (-sV -T4)"
        scan_button = False
        clear_button = False
        
        st.markdown("### 📊 Demo Network")
        st.markdown("**Subnet:** `192.168.1.0/24`")
        st.markdown("**Hosts:** 5 devices")
        st.markdown("**Alerts:** 5 detected")
        
        if st.button("🔄 Refresh Demo", use_container_width=True):
            st.rerun()
    
    # Info
    st.markdown("---")
    st.markdown("### 📊 Session Info")
    if demo_mode:
        st.markdown("**Mode:** 🎮 Demo")
        st.markdown("**Scans Simulated:** 5")
    else:
        st.markdown(f"**Scans Run:** {st.session_state.scan_count}")
    st.markdown(f"**Last Updated:** {datetime.now().strftime('%H:%M:%S')}")
    
    # GitHub link
    st.markdown("---")
    st.markdown("### 🔗 Links")
    st.markdown("[📂 View Source Code](https://github.com/Sanchitt16/Cyber-Infiltration-Project)")
    st.markdown("[📥 Download & Run Locally](https://github.com/Sanchitt16/Cyber-Infiltration-Project#-quick-start)")

# =============================================================================
# Handle Button Actions
# =============================================================================

# Initialize database (only if not in demo mode)
if not st.session_state.demo_mode and LOCAL_MODE_AVAILABLE:
    init_database()

# Clear button action
if not st.session_state.demo_mode and clear_button:
    clear_database()
    init_database()
    st.session_state.last_scan_result = None
    st.session_state.anomaly_result = None
    st.session_state.scan_count = 0
    st.success("Database cleared!")
    st.rerun()

# Scan button action
if not st.session_state.demo_mode and scan_button and not st.session_state.scan_running:
    if not LOCAL_MODE_AVAILABLE or not check_nmap_installed():
        st.error("❌ Nmap is not installed. Please install it first.")
    elif not target:
        st.error("❌ Please enter a target IP or domain.")
    else:
        st.session_state.scan_running = True
        
        # Determine scan arguments
        if "Quick" in scan_type:
            scan_args = "-T4 -F"
        elif "Full" in scan_type:
            scan_args = "-sV -sC -O -T4"
        else:
            scan_args = "-sV -T4"
        
        # Show progress
        with st.spinner(f"🔍 Scanning {target}... This may take a few minutes."):
            result = run_scan(target, scan_args)
            st.session_state.last_scan_result = result
            st.session_state.scan_count += 1
            
            # Run anomaly detection
            anomaly_result = detect_anomalies()
            st.session_state.anomaly_result = anomaly_result
        
        st.session_state.scan_running = False
        st.rerun()

# =============================================================================
# Demo Mode Data Setup
# =============================================================================
if st.session_state.demo_mode:
    # Use demo data
    demo_hosts = generate_demo_hosts()
    demo_ports = generate_demo_ports()
    demo_anomalies = generate_demo_anomalies()
    demo_scans = generate_demo_scan_history()
    scans = demo_scans
    anomaly_result = demo_anomalies
else:
    # Use real data
    if LOCAL_MODE_AVAILABLE:
        scans = get_all_scans()
        anomaly_result = st.session_state.anomaly_result
    else:
        scans = []
        anomaly_result = None

# =============================================================================
# Main Content
# =============================================================================

# Header
st.markdown('<h1 class="main-header">🛡️ Network Change Detector & Anomaly Monitor</h1>', unsafe_allow_html=True)

# Demo Mode Banner
if st.session_state.demo_mode:
    st.markdown("""
    <div style="background: linear-gradient(135deg, #667eea, #764ba2); color: white; padding: 1rem; 
    border-radius: 10px; text-align: center; margin-bottom: 1rem;">
        🎮 <strong>DEMO MODE</strong> - Showing simulated network scan with security alerts | 
        <a href="https://github.com/Sanchitt16/Cyber-Infiltration-Project" style="color: #fff; text-decoration: underline;">
        View Source Code →</a>
    </div>
    """, unsafe_allow_html=True)

# Status Banner
if st.session_state.demo_mode:
    # Always show alert in demo mode for impressive display
    st.markdown(f"""
    <div class="status-alert">
        🚨 ALERT: 5 Security Issue(s) Detected!
    </div>
    """, unsafe_allow_html=True)
elif not scans:
    st.markdown("""
    <div class="status-neutral">
        📡 No Scans Yet - Enter a target and click "Run Scan" to begin
    </div>
    """, unsafe_allow_html=True)
elif anomaly_result and anomaly_result.get('success'):
    total_anomalies = anomaly_result['summary'].get('total', 0)
    critical = anomaly_result['summary']['by_severity'].get('critical', 0)
    high = anomaly_result['summary']['by_severity'].get('high', 0)
    
    if critical > 0 or high > 0:
        st.markdown(f"""
        <div class="status-alert">
            🚨 ALERT: {total_anomalies} Security Issue(s) Detected!
        </div>
        """, unsafe_allow_html=True)
    elif total_anomalies > 0:
        st.markdown(f"""
        <div class="status-warning">
            ⚠️ WARNING: {total_anomalies} Change(s) Detected
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="status-secure">
            ✅ SYSTEM SECURE - No Anomalies Detected
        </div>
        """, unsafe_allow_html=True)
else:
    # First scan - no comparison yet
    st.markdown("""
    <div class="status-secure">
        ✅ BASELINE SCAN COMPLETE - Run another scan to detect changes
    </div>
    """, unsafe_allow_html=True)

# Stats Row
if st.session_state.demo_mode:
    # Demo stats
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("📡 Total Scans", 5)
    with col2:
        st.metric("🖥️ Hosts Detected", 5)
    with col3:
        st.metric("🚪 Open Ports", 15)
    with col4:
        st.metric("⚠️ Anomalies", 5)
elif scans:
    latest_scan = scans[0]
    hosts = get_hosts_by_scan(latest_scan['id'])
    total_ports = sum(len(get_ports_by_host(h['id'])) for h in hosts)
    open_ports = sum(len([p for p in get_ports_by_host(h['id']) if p['state'] == 'open']) for h in hosts)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("📡 Total Scans", len(scans))
    with col2:
        st.metric("🖥️ Hosts Detected", len(hosts))
    with col3:
        st.metric("🚪 Open Ports", open_ports)
    with col4:
        if anomaly_result and anomaly_result.get('success'):
            st.metric("⚠️ Anomalies", anomaly_result['summary'].get('total', 0))
        else:
            st.metric("⚠️ Anomalies", "N/A")

st.markdown("---")

# Main content tabs
tab1, tab2, tab3 = st.tabs(["📊 Current Status", "🔍 Anomalies", "📜 Scan History"])

# =============================================================================
# Tab 1: Current Status
# =============================================================================
with tab1:
    if st.session_state.demo_mode:
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🖥️ Discovered Hosts")
            hosts_data = []
            for host in demo_hosts:
                hosts_data.append({
                    'IP Address': host['ip_address'],
                    'Status': '🟢 Up' if host['status'] == 'up' else '🔴 Down',
                    'MAC Address': host['mac_address'] or 'N/A',
                    'Open Ports': host['open_ports'],
                    'Filtered Ports': host['filtered_ports']
                })
            st.dataframe(pd.DataFrame(hosts_data), use_container_width=True, hide_index=True)
        
        with col2:
            st.markdown("### 🚪 Open Ports & Services")
            ports_data = []
            for port in demo_ports:
                state_icon = {'open': '🟢', 'closed': '🔴', 'filtered': '🟡'}.get(port['state'], '⚪')
                ports_data.append({
                    'IP Address': port['ip'],
                    'Port': port['port'],
                    'Protocol': port['protocol'].upper(),
                    'State': f"{state_icon} {port['state'].capitalize()}",
                    'Service': port['service'],
                    'Version': port['version'] or 'N/A'
                })
            ports_df = pd.DataFrame(ports_data)
            open_only = st.checkbox("Show only open ports", value=True)
            if open_only:
                ports_df = ports_df[ports_df['State'].str.contains('open', case=False)]
            st.dataframe(ports_df, use_container_width=True, hide_index=True)
    elif scans:
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### 🖥️ Discovered Hosts")
            hosts_df = get_hosts_dataframe()
            if not hosts_df.empty:
                st.dataframe(hosts_df, use_container_width=True, hide_index=True)
            else:
                st.info("No hosts found in the latest scan.")
        
        with col2:
            st.markdown("### 🚪 Open Ports & Services")
            ports_df = get_ports_dataframe()
            if not ports_df.empty:
                # Filter to show only open ports by default
                open_only = st.checkbox("Show only open ports", value=True)
                if open_only:
                    ports_df = ports_df[ports_df['State'].str.contains('open', case=False)]
                st.dataframe(ports_df, use_container_width=True, hide_index=True)
            else:
                st.info("No ports found in the latest scan.")
    else:
        st.info("👆 Run a scan to see network status")

# =============================================================================
# Tab 2: Anomalies
# =============================================================================
with tab2:
    st.markdown("### 🔍 Detected Anomalies")
    
    if st.session_state.demo_mode:
        # Show demo anomalies
        anomalies = demo_anomalies.get('anomalies', [])
        summary = demo_anomalies['summary']
        
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("⛔ Critical", summary['by_severity'].get('critical', 0))
        col2.metric("🔴 High", summary['by_severity'].get('high', 0))
        col3.metric("🟠 Medium", summary['by_severity'].get('medium', 0))
        col4.metric("🟡 Low", summary['by_severity'].get('low', 0))
        col5.metric("🔵 Info", summary['by_severity'].get('info', 0))
        
        st.markdown("---")
        
        severity_filter = st.multiselect(
            "Filter by Severity",
            ["critical", "high", "medium", "low", "info"],
            default=["critical", "high", "medium"]
        )
        
        filtered = [a for a in anomalies if a['severity'] in severity_filter]
        
        for anomaly in filtered:
            render_anomaly_box(anomaly)
    elif anomaly_result and anomaly_result.get('success'):
        anomalies = anomaly_result.get('anomalies', [])
        
        if anomalies:
            # Summary
            summary = anomaly_result['summary']
            col1, col2, col3, col4, col5 = st.columns(5)
            col1.metric("⛔ Critical", summary['by_severity'].get('critical', 0))
            col2.metric("🔴 High", summary['by_severity'].get('high', 0))
            col3.metric("🟠 Medium", summary['by_severity'].get('medium', 0))
            col4.metric("🟡 Low", summary['by_severity'].get('low', 0))
            col5.metric("🔵 Info", summary['by_severity'].get('info', 0))
            
            st.markdown("---")
            
            # Filter by severity
            severity_filter = st.multiselect(
                "Filter by Severity",
                ["critical", "high", "medium", "low", "info"],
                default=["critical", "high", "medium"]
            )
            
            # Display anomalies
            filtered = [a for a in anomalies if a['severity'] in severity_filter]
            
            if filtered:
                for anomaly in filtered:
                    render_anomaly_box(anomaly)
            else:
                st.info("No anomalies match the selected filters.")
        else:
            st.success("✅ No anomalies detected! Network state is stable.")
    else:
        if len(scans) < 2:
            st.info("📊 Need at least 2 scans to detect anomalies. Run another scan to enable change detection.")
        else:
            st.info("Run a scan to check for anomalies.")

# =============================================================================
# Tab 3: Scan History
# =============================================================================
with tab3:
    st.markdown("### 📜 Scan History")
    
    if st.session_state.demo_mode:
        # Demo scan history
        history_data = []
        for scan in demo_scans:
            history_data.append({
                'Scan ID': scan['id'],
                'Timestamp': scan['timestamp'],
                'Hosts Found': scan['hosts'],
                'Total Ports': scan['ports']
            })
        st.dataframe(pd.DataFrame(history_data), use_container_width=True, hide_index=True)
    elif scans:
        history_data = []
        for scan in scans[:10]:  # Show last 10 scans
            hosts = get_hosts_by_scan(scan['id'])
            total_ports = sum(len(get_ports_by_host(h['id'])) for h in hosts)
            
            history_data.append({
                'Scan ID': scan['id'],
                'Timestamp': scan['timestamp'],
                'Hosts Found': len(hosts),
                'Total Ports': total_ports
            })
        
        history_df = pd.DataFrame(history_data)
        st.dataframe(history_df, use_container_width=True, hide_index=True)
        
        # Option to view specific scan details
        if len(scans) > 1:
            selected_scan = st.selectbox(
                "View details for scan:",
                [s['id'] for s in scans],
                format_func=lambda x: f"Scan #{x}"
            )
            
            if selected_scan:
                with st.expander(f"Details for Scan #{selected_scan}", expanded=False):
                    hosts = get_hosts_by_scan(selected_scan)
                    for host in hosts:
                        st.markdown(f"**Host: {host['ip_address']}** ({host['status']})")
                        ports = get_ports_by_host(host['id'])
                        if ports:
                            port_data = [{
                                'Port': p['port_number'],
                                'Protocol': p['protocol'],
                                'State': p['state'],
                                'Service': p['service_name'] or 'Unknown'
                            } for p in ports]
                            st.dataframe(pd.DataFrame(port_data), hide_index=True)
                        else:
                            st.write("No ports found")
    else:
        st.info("No scan history available yet.")

# =============================================================================
# Auto-refresh
# =============================================================================
if not st.session_state.demo_mode and st.session_state.auto_refresh and scans:
    time.sleep(30)
    st.rerun()

# =============================================================================
# Footer
# =============================================================================
st.markdown("---")
st.markdown(
    """
    <div style="text-align: center; color: #666; font-size: 0.8rem;">
        🛡️ Network Change Detector & Anomaly Monitor | Blue Team Security Tool<br>
        Built with Python, Nmap & Streamlit | 
        <a href="https://github.com/Sanchitt16/Cyber-Infiltration-Project" style="color: #888;">View on GitHub</a>
    </div>
    """,
    unsafe_allow_html=True
)
