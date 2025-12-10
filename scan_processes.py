import psutil
import time
import socket
import ipaddress
import sqlite3
import os
import sys
import platform

# Platform-specific imports
if platform.system() == 'Windows':
    import ctypes

wait_time = 10
# Parameters for detection
high_cpu_threshold = 80  # Percentage
high_memory_threshold = 70  # Percentage
high_disk_threshold = 50  # MB/s
connection_count = 0

def is_admin():
    """Check if the script is running with administrative/root privileges."""
    try:
        if platform.system() == 'Windows':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # On Unix-like systems, check if effective user ID is 0 (root)
            return os.geteuid() == 0
    except Exception:
        return False

def request_admin_privileges():
    """Request admin privileges or display appropriate message based on platform."""
    current_platform = platform.system()
    
    if current_platform == 'Windows':
        # On Windows, try to re-launch the script with elevated privileges
        try:
            # ShellExecuteW returns > 32 on success (Windows API behavior)
            if ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1) > 32:
                sys.exit(0)
            else:
                print("\n" + "="*70)
                print("ERROR: Administrator privileges are required!")
                print("="*70)
                print("\nThis script needs to run with administrator privileges to access")
                print("detailed process information and network connections.")
                print("\nPlease right-click on the script and select 'Run as administrator'")
                print("or run it from an elevated command prompt/PowerShell.")
                print("="*70)
                sys.exit(1)
        except Exception as e:
            print(f"\nFailed to elevate privileges: {e}")
            print("\nPlease run this script as Administrator.")
            sys.exit(1)
    else:
        # On Linux/macOS, display instructions to run with sudo
        print("\n" + "="*70)
        print("ERROR: Root/sudo privileges are required!")
        print("="*70)
        print("\nThis script needs to run with elevated privileges to access:")
        print("  - Disk I/O statistics (io_counters)")
        print("  - Network connections for all processes")
        print("  - Detailed process information")
        print("\nPlease run the script with sudo:")
        print(f"  sudo {sys.executable} {' '.join(sys.argv)}")
        print("="*70)
        sys.exit(1)

# Build families dictionary dynamically based on available socket families
families = {
    socket.AF_INET: 'IPv4',
    socket.AF_INET6: 'IPv6',
    socket.AF_UNSPEC: 'Unspecified',
}

# Add platform-specific socket families if they exist
if hasattr(socket, 'AF_APPLETALK'):
    families[socket.AF_APPLETALK] = 'AppleTalk'
if hasattr(socket, 'AF_BLUETOOTH'):
    families[socket.AF_BLUETOOTH] = 'Bluetooth'
if hasattr(socket, 'AF_DECnet'):
    families[socket.AF_DECnet] = 'DECnet'
if hasattr(socket, 'AF_HYPERV'):
    families[socket.AF_HYPERV] = 'HyperV'
if hasattr(socket, 'AF_IPX'):
    families[socket.AF_IPX] = 'IPX'
if hasattr(socket, 'AF_IRDA'):
    families[socket.AF_IRDA] = 'IRDA'
if hasattr(socket, 'AF_LINK'):
    families[socket.AF_LINK] = 'Link'
if hasattr(socket, 'AF_SNA'):
    families[socket.AF_SNA] = 'SNA'
if hasattr(socket, 'AF_UNIX'):
    families[socket.AF_UNIX] = 'Unix'
if hasattr(socket, 'AF_PACKET'):
    families[socket.AF_PACKET] = 'Packet'

# Global database connection variables (initialized in main)
# Note: Global state is used here for simplicity as the connection is shared
# across multiple monitoring functions. This is acceptable for a single-threaded
# monitoring script with a single database connection.
conn = None
cursor = None

def init_database():
    """Initialize the SQLite database connection and create tables."""
    global conn, cursor
    conn = sqlite3.connect('process_monitor.db')
    cursor = conn.cursor()
    
    # Create the table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS process_events (
            timestamp TEXT,
            pid INTEGER,
            process_name TEXT,
            event_type TEXT,
            resource_usage REAL,
            open_files TEXT,
            ip_connection_type TEXT,
            ip_connection_status TEXT,
            local_address TEXT,
            local_port TEXT,
            remote_address TEXT,
            remote_port TEXT,
            remote_hostname TEXT,
            ip_address_type TEXT,
            connection_family TEXT
        )
    ''')
    conn.commit()

def monitor_processes():
    process_count = 0
  
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'io_counters']):
        # Check for high resource usage
        if proc.info['cpu_percent'] > high_cpu_threshold:
            insert_event(proc, "High CPU", proc.info['cpu_percent'])
            process_count +=1
            investigate_process(proc, process_count)

        if proc.info['memory_percent'] > high_memory_threshold:
            insert_event(proc, "High Memory", proc.info['memory_percent'])
            process_count +=1
            investigate_process(proc, process_count)

        # Check io_counters (may be None on some platforms without proper permissions)
        if proc.info['io_counters'] is not None:
            write_mb = proc.info['io_counters'].write_bytes / 1024 / 1024
            if write_mb > high_disk_threshold:  # Convert bytes to MB
                insert_event(proc, "High Disk Write", write_mb)
                process_count +=1
                investigate_process(proc, process_count)

def investigate_process(proc, process_count):
    global connection_count
    try:
        open_files = ", ".join([file.path for file in proc.open_files()]) if proc.open_files() else "None"
        # Get network connections
        connections = [conn for conn in psutil.net_connections() if conn.pid == proc.info['pid']]
        for conn in connections:
            connection_count += 1
            try:
                # Extract address information using helper function
                remote_ip, remote_port = get_address_info(conn.raddr)
                local_ip, local_port = get_address_info(conn.laddr)
                
                connection_family = families.get(conn.family, 'Other')
                ip_connection_type = get_connection_type(conn)
                ip_connection_status = conn.status
                
                if len(remote_ip) > 0: 
                    ip_address_type = get_ip_address_type(remote_ip)
                    try:
                        remote_hostname = socket.gethostbyaddr(remote_ip)[0]
                    except socket.herror:
                        remote_hostname = 'Unresolved'
                else:
                    ip_address_type = ''
                    remote_hostname = ''
                
                insert_event(
                    proc,
                    "Network Connection",
                    None,
                    open_files,
                    ip_connection_type,
                    ip_connection_status,
                    local_ip,
                    local_port,
                    remote_ip,
                    remote_port,
                    remote_hostname,
                    ip_address_type,
                    connection_family
                )
                print(f'Processes investigated: {process_count}, {connection_count} connections...', end='\r')                
            
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass

def get_connection_type(conn):
    if conn.type == socket.SOCK_STREAM:
        return "TCP"
    elif conn.type == socket.SOCK_DGRAM:
        return "UDP"
    else:
        return "Unknown"

def get_address_info(addr):
    """Extract IP and port from address object (may be None, namedtuple, or tuple)."""
    if addr is None:
        return '', ''
    
    ip = addr.ip if hasattr(addr, 'ip') else (addr[0] if isinstance(addr, tuple) and len(addr) > 0 else '')
    port = addr.port if hasattr(addr, 'port') else (addr[1] if isinstance(addr, tuple) and len(addr) > 1 else '')
    return ip, port

def get_ip_address_type(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback:
            return "Loopback"
        elif ip.is_private:
            return "Private"
        elif ip.is_link_local:
            return "Link-local"
        elif ip.is_unspecified:
            return "Unspecified"
        else:
            return "Public" 
    except ValueError:
        return "Invalid"

def insert_event(proc, event_type, resource_usage, open_files=None, ip_connection_type=None, ip_connection_status=None, local_address=None, local_port=None, remote_address=None, remote_port=None, remote_hostname=None, ip_address_type=None, connection_family=None):
    cursor.execute('''
        INSERT INTO process_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        time.strftime('%Y-%m-%d %H:%M:%S'),
        proc.info['pid'],
        proc.info['name'],
        event_type,
        resource_usage,
        open_files,
        ip_connection_type,
        ip_connection_status,
        local_address,
        local_port,
        remote_address, 
        remote_port,
        remote_hostname,
        ip_address_type,
        connection_family 
    ))
    conn.commit()

# Main execution
if __name__ == "__main__":
    # Check for administrative/root privileges
    if not is_admin():
        request_admin_privileges()
    
    # Initialize database after privilege check
    init_database()
    
    try:
        print('Process Monitor started with elevated privileges.')
        print('Press ctrl+c to exit.')
        while True:
            monitor_processes()
            time.sleep(wait_time)
    except KeyboardInterrupt:
        print('\nSQLite database "process_monitor.db" has been created.')
        print("Exiting ...")
    finally:
        # Close the database connection when the script ends
        if conn:
            conn.close()