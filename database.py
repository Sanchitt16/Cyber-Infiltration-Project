"""
Database module for Network Change Detector & Anomaly Monitor.
Handles SQLite database operations for storing scan results.
"""

import sqlite3
from datetime import datetime
from typing import Optional

DATABASE_NAME = "network_monitor.db"


def get_connection() -> sqlite3.Connection:
    """Create and return a database connection."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row  # Enable column access by name
    return conn


def init_database() -> None:
    """
    Initialize the database with the required schema.
    Creates three tables: Scans, Hosts, and Ports.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Create Scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME NOT NULL
        )
    """)

    # Create Hosts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            status TEXT,
            mac_address TEXT,
            FOREIGN KEY (scan_id) REFERENCES Scans(id) ON DELETE CASCADE
        )
    """)

    # Create Ports table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER NOT NULL,
            port_number INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            state TEXT,
            service_name TEXT,
            version TEXT,
            FOREIGN KEY (host_id) REFERENCES Hosts(id) ON DELETE CASCADE
        )
    """)

    # Create indexes for better query performance
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_hosts_scan_id ON Hosts(scan_id)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_ports_host_id ON Ports(host_id)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_hosts_ip ON Hosts(ip_address)
    """)

    conn.commit()
    conn.close()
    print("[+] Database initialized successfully.")


def insert_scan(timestamp: Optional[datetime] = None) -> int:
    """
    Insert a new scan record.
    
    Args:
        timestamp: The scan timestamp (defaults to current time)
    
    Returns:
        The ID of the newly created scan record.
    """
    if timestamp is None:
        timestamp = datetime.now()
    
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO Scans (timestamp) VALUES (?)",
        (timestamp,)
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id


def insert_host(scan_id: int, ip_address: str, status: str, mac_address: Optional[str] = None) -> int:
    """
    Insert a new host record.
    
    Args:
        scan_id: The ID of the parent scan
        ip_address: The IP address of the host
        status: The host status (up/down)
        mac_address: The MAC address (if available)
    
    Returns:
        The ID of the newly created host record.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO Hosts (scan_id, ip_address, status, mac_address) VALUES (?, ?, ?, ?)",
        (scan_id, ip_address, status, mac_address)
    )
    host_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return host_id


def insert_port(host_id: int, port_number: int, protocol: str, 
                state: str, service_name: Optional[str] = None, 
                version: Optional[str] = None) -> int:
    """
    Insert a new port record.
    
    Args:
        host_id: The ID of the parent host
        port_number: The port number
        protocol: The protocol (tcp/udp)
        state: The port state (open/closed/filtered)
        service_name: The detected service name
        version: The detected service version
    
    Returns:
        The ID of the newly created port record.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO Ports (host_id, port_number, protocol, state, service_name, version) 
           VALUES (?, ?, ?, ?, ?, ?)""",
        (host_id, port_number, protocol, state, service_name, version)
    )
    port_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return port_id


def get_all_scans() -> list:
    """Retrieve all scan records."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Scans ORDER BY timestamp DESC")
    scans = cursor.fetchall()
    conn.close()
    return scans


def get_hosts_by_scan(scan_id: int) -> list:
    """Retrieve all hosts for a specific scan."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Hosts WHERE scan_id = ?", (scan_id,))
    hosts = cursor.fetchall()
    conn.close()
    return hosts


def get_ports_by_host(host_id: int) -> list:
    """Retrieve all ports for a specific host."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Ports WHERE host_id = ?", (host_id,))
    ports = cursor.fetchall()
    conn.close()
    return ports


def get_latest_scan() -> Optional[sqlite3.Row]:
    """Retrieve the most recent scan."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM Scans ORDER BY timestamp DESC LIMIT 1")
    scan = cursor.fetchone()
    conn.close()
    return scan


if __name__ == "__main__":
    # Initialize the database when run directly
    init_database()
