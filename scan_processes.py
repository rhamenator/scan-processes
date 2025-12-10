import psutil
import time
import socket
import ipaddress
import sqlite3
import os
import sys
import platform
import subprocess

# Platform-specific imports
if platform.system() == 'Windows':
    import ctypes

wait_time = 10
# Parameters for detection
high_cpu_threshold = 80  # Percentage
high_memory_threshold = 70  # Percentage
high_disk_write_rate_threshold = 50  # MB/s (rate of writes)
high_disk_read_rate_threshold = 100  # MB/s (rate of reads)
high_disk_cumulative_threshold = 500  # MB (cumulative writes)
connection_count = 0

# Process whitelist - processes that won't trigger disk I/O alerts
# Add process names (case-insensitive) that are known to do heavy I/O
disk_io_whitelist = {
    'onedrive.exe', 'onedrive',
    'googledrivesync.exe', 'googledrivesync',
    'dropbox.exe', 'dropbox',
    'backup', 'backupd',
    'chrome.exe', 'firefox.exe', 'msedge.exe',
    'chrome', 'firefox', 'msedge',
}

# Track previous I/O counters for rate calculation
prev_io_counters = {}

# Track processes that have already triggered cumulative alerts to avoid duplicates
cumulative_alerted_pids = set()

# Cleanup counter to avoid running cleanup on every iteration
cleanup_counter = 0

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
            # Use subprocess.list2cmdline to properly escape arguments with spaces
            # ShellExecuteW returns > 32 on success (Windows API behavior)
            args = subprocess.list2cmdline(sys.argv)
            if ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, args, None, 1) > 32:
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

def check_io_rate(bytes_current, bytes_previous, threshold, wait_time):
    """Helper function to check if I/O rate exceeds threshold.
    
    Args:
        bytes_current: Current byte count
        bytes_previous: Previous byte count
        threshold: Threshold in MB/s
        wait_time: Time interval in seconds
        
    Returns:
        Tuple of (exceeds_threshold, rate_in_mb_per_sec)
    """
    bytes_delta = bytes_current - bytes_previous
    
    # Handle counter resets (negative values) and check for valid wait_time
    if bytes_delta < 0 or wait_time <= 0:
        return False, 0.0
    
    rate_mb_per_sec = (bytes_delta / 1024 / 1024) / wait_time
    return rate_mb_per_sec > threshold, rate_mb_per_sec

def monitor_processes():
    """Monitor all processes for high resource usage and network connections.
    
    Note: CPU measurements via process_iter use non-blocking mode and may not be 
    accurate on first iteration. Subsequent iterations will have accurate measurements.
    """
    global prev_io_counters, cleanup_counter, cumulative_alerted_pids
    process_count = 0
    current_pids = set()
  
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'io_counters']):
        try:
            cpu_usage = proc.info['cpu_percent']
            memory_usage = proc.info['memory_percent']
            pid = proc.info['pid']
            process_name = proc.info['name']
            current_pids.add(pid)
            
            # Track if this process should be investigated
            should_investigate = False
            
            # Check for high resource usage
            if cpu_usage is not None and cpu_usage > high_cpu_threshold:
                insert_event(proc, "High CPU", cpu_usage)
                process_count += 1
                should_investigate = True

            if memory_usage is not None and memory_usage > high_memory_threshold:
                insert_event(proc, "High Memory", memory_usage)
                process_count += 1
                should_investigate = True

            # Check if process is whitelisted for disk I/O monitoring
            is_whitelisted = process_name.lower() in disk_io_whitelist
            
            # Check io_counters (may be None on some platforms without proper permissions)
            if proc.info['io_counters'] is not None and not is_whitelisted:
                io_counters = proc.info['io_counters']
                write_bytes = io_counters.write_bytes
                read_bytes = io_counters.read_bytes
                
                # Rate-based monitoring: Calculate write/read rates between iterations
                if pid in prev_io_counters:
                    prev_write_bytes, prev_read_bytes = prev_io_counters[pid]
                    
                    # Check write rate using helper function
                    exceeds_write, write_rate = check_io_rate(
                        write_bytes, prev_write_bytes, 
                        high_disk_write_rate_threshold, wait_time
                    )
                    if exceeds_write:
                        insert_event(proc, "High Disk Write Rate", write_rate)
                        process_count += 1
                        should_investigate = True
                    
                    # Check read rate using helper function
                    exceeds_read, read_rate = check_io_rate(
                        read_bytes, prev_read_bytes,
                        high_disk_read_rate_threshold, wait_time
                    )
                    if exceeds_read:
                        insert_event(proc, "High Disk Read Rate", read_rate)
                        process_count += 1
                        should_investigate = True
                
                # Cumulative monitoring: Check total writes since process start
                # Only alert once per process to avoid duplicate notifications
                if write_bytes > 0 and pid not in cumulative_alerted_pids:
                    write_mb_cumulative = write_bytes / 1024 / 1024
                    if write_mb_cumulative > high_disk_cumulative_threshold:
                        insert_event(proc, "High Cumulative Disk Writes", write_mb_cumulative)
                        cumulative_alerted_pids.add(pid)  # Mark as alerted
                        process_count += 1
                        should_investigate = True
                
                # Store current counters for next iteration
                prev_io_counters[pid] = (write_bytes, read_bytes)
            
            # Only investigate once per process, even if multiple thresholds exceeded
            if should_investigate:
                investigate_process(proc, process_count)
        
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Process may have terminated or we don't have access
            continue
        except Exception as e:
            # Log unexpected errors but continue monitoring
            print(f"\nError monitoring process: {e}", file=sys.stderr)
            continue
    
    # Clean up terminated processes periodically to prevent memory leak
    # Only run cleanup every 10 iterations to reduce overhead
    cleanup_counter += 1
    if cleanup_counter >= 10:
        terminated_pids = set(prev_io_counters.keys()) - current_pids
        for pid in terminated_pids:
            del prev_io_counters[pid]
            cumulative_alerted_pids.discard(pid)  # Also clean up alert tracking
        cleanup_counter = 0

def investigate_process(proc, process_count):
    global connection_count
    try:
        # Get open files with proper error handling
        try:
            open_files_list = proc.open_files()
            open_files = ", ".join([file.path for file in open_files_list]) if open_files_list else "None"
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            open_files = "Access Denied"
        
        # Get network connections for this specific process
        try:
            # Use net_connections with kind parameter to get process-specific connections
            # This replaces the deprecated proc.connections() method
            pid = proc.info['pid']
            connections = [c for c in psutil.net_connections(kind='inet') if c.pid == pid]
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            # If we can't get connections for this process, skip it
            return
        
        for conn in connections:
            connection_count += 1
            try:
                # Extract address information using helper function
                remote_ip, remote_port = get_address_info(conn.raddr)
                local_ip, local_port = get_address_info(conn.laddr)
                
                connection_family = families.get(conn.family, 'Other')
                ip_connection_type = get_connection_type(conn)
                ip_connection_status = conn.status
                
                if remote_ip and len(remote_ip) > 0: 
                    ip_address_type = get_ip_address_type(remote_ip)
                    # Avoid blocking DNS lookups - set timeout and catch all exceptions
                    try:
                        socket.setdefaulttimeout(1.0)  # 1 second timeout
                        remote_hostname = socket.gethostbyaddr(remote_ip)[0]
                    except (socket.herror, socket.gaierror, socket.timeout, OSError):
                        remote_hostname = 'Unresolved'
                    finally:
                        socket.setdefaulttimeout(None)  # Reset to default
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
                # Connection or process disappeared
                continue
            except Exception as e:
                # Log unexpected errors but continue
                print(f"\nError investigating connection: {e}", file=sys.stderr)
                continue
            
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        # Process disappeared or access denied
        pass
    except Exception as e:
        # Catch any other unexpected errors
        print(f"\nError investigating process: {e}", file=sys.stderr)

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
    
    try:
        ip = addr.ip if hasattr(addr, 'ip') else (addr[0] if isinstance(addr, tuple) and len(addr) > 0 else '')
        port = addr.port if hasattr(addr, 'port') else (addr[1] if isinstance(addr, tuple) and len(addr) > 1 else '')
        return ip, port
    except (IndexError, AttributeError, TypeError):
        # Handle unexpected address formats gracefully
        return '', ''

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
    try:
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
        # Note: We don't commit here for performance reasons.
        # Commits are batched in the main loop to reduce I/O overhead.
    except sqlite3.Error as e:
        print(f"\nDatabase error: {e}", file=sys.stderr)
    except Exception as e:
        print(f"\nUnexpected error inserting event: {e}", file=sys.stderr)

# Main execution
if __name__ == "__main__":
    # Check for administrative/root privileges
    if not is_admin():
        request_admin_privileges()
    
    # Initialize database after privilege check
    try:
        init_database()
    except Exception as e:
        print(f"\nFailed to initialize database: {e}", file=sys.stderr)
        sys.exit(1)
    
    try:
        print('Process Monitor started with elevated privileges.')
        print('Press ctrl+c to exit.')
        iteration_count = 0
        while True:
            monitor_processes()
            iteration_count += 1
            
            # Commit database changes periodically (every iteration) instead of per insert
            # This significantly improves performance
            try:
                if conn:
                    conn.commit()
            except sqlite3.Error as e:
                print(f"\nDatabase commit error: {e}", file=sys.stderr)
            
            time.sleep(wait_time)
    except KeyboardInterrupt:
        print('\n\nSQLite database "process_monitor.db" has been created.')
        print("Exiting ...")
    except Exception as e:
        print(f"\nUnexpected error in main loop: {e}", file=sys.stderr)
    finally:
        # Ensure database is properly closed
        try:
            if conn:
                conn.commit()  # Final commit of any pending data
                conn.close()
                print("Database connection closed successfully.")
        except Exception as e:
            print(f"Error closing database: {e}", file=sys.stderr)