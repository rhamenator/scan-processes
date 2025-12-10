import psutil
import time
import socket
import ipaddress
import sqlite3
import os
import sys
import platform
import subprocess
import argparse
import json
import logging
import csv
from datetime import datetime

# Platform-specific imports
if platform.system() == 'Windows':
    import ctypes

# Default configuration
DEFAULT_CONFIG = {
    'wait_time': 10,
    'high_cpu_threshold': 80,
    'high_memory_threshold': 70,
    'high_disk_write_rate_threshold': 50,
    'high_disk_read_rate_threshold': 100,
    'high_disk_cumulative_threshold': 500,
    'disk_io_whitelist': [
        'onedrive.exe', 'onedrive',
        'googledrivesync.exe', 'googledrivesync',
        'dropbox.exe', 'dropbox',
        'backup', 'backupd',
        'chrome.exe', 'firefox.exe', 'msedge.exe',
        'chrome', 'firefox', 'msedge',
    ],
    'log_level': 'INFO',
    'show_statistics': True,
    'statistics_interval': 60  # Show stats every 60 seconds
}

# Global configuration (will be loaded from file or defaults)
wait_time = DEFAULT_CONFIG['wait_time']
high_cpu_threshold = DEFAULT_CONFIG['high_cpu_threshold']
high_memory_threshold = DEFAULT_CONFIG['high_memory_threshold']
high_disk_write_rate_threshold = DEFAULT_CONFIG['high_disk_write_rate_threshold']
high_disk_read_rate_threshold = DEFAULT_CONFIG['high_disk_read_rate_threshold']
high_disk_cumulative_threshold = DEFAULT_CONFIG['high_disk_cumulative_threshold']
# Normalize whitelist to lowercase for case-insensitive matching
# Convert to string to handle any type gracefully
disk_io_whitelist = set(str(item).lower() for item in DEFAULT_CONFIG['disk_io_whitelist'] if item)
connection_count = 0

# Track previous I/O counters for rate calculation
prev_io_counters = {}

# Track processes that have already triggered cumulative alerts to avoid duplicates
cumulative_alerted_pids = set()

# Cleanup counter to avoid running cleanup on every iteration
cleanup_counter = 0

# Statistics tracking
stats = {
    'high_cpu_events': 0,
    'high_memory_events': 0,
    'high_disk_write_rate_events': 0,
    'high_disk_read_rate_events': 0,
    'high_cumulative_disk_events': 0,
    'network_connections': 0,
    'start_time': None,
    'last_stats_display': None
}

def load_config(config_file):
    """Load configuration from JSON file."""
    global wait_time, high_cpu_threshold, high_memory_threshold
    global high_disk_write_rate_threshold, high_disk_read_rate_threshold
    global high_disk_cumulative_threshold, disk_io_whitelist
    
    try:
        with open(config_file, 'r') as f:
            user_config = json.load(f)
        
        # Merge user config with defaults (user config takes precedence)
        config = {**DEFAULT_CONFIG, **user_config}
        
        # Update global variables from merged config
        wait_time = config['wait_time']
        high_cpu_threshold = config['high_cpu_threshold']
        high_memory_threshold = config['high_memory_threshold']
        high_disk_write_rate_threshold = config['high_disk_write_rate_threshold']
        high_disk_read_rate_threshold = config['high_disk_read_rate_threshold']
        high_disk_cumulative_threshold = config['high_disk_cumulative_threshold']
        
        # Handle whitelist with validation and lowercase normalization
        whitelist_value = config['disk_io_whitelist']
        if isinstance(whitelist_value, list):
            # Normalize all entries to lowercase for case-insensitive matching
            # Convert to string first to handle non-string items gracefully
            disk_io_whitelist = set(str(item).lower() for item in whitelist_value if item)
        else:
            logging.warning("Config value for 'disk_io_whitelist' is not a list; using default whitelist.")
            disk_io_whitelist = set(str(item).lower() for item in DEFAULT_CONFIG['disk_io_whitelist'] if item)
        
        logging.info(f"Configuration loaded from {config_file}")
        return config
    except FileNotFoundError:
        logging.warning(f"Configuration file {config_file} not found, using defaults")
        return DEFAULT_CONFIG
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing configuration file: {e}")
        return DEFAULT_CONFIG

def save_default_config(config_file='config.json'):
    """Save default configuration to a JSON file."""
    try:
        with open(config_file, 'w') as f:
            json.dump(DEFAULT_CONFIG, f, indent=4)
        logging.info(f"Default configuration saved to {config_file}")
        return True
    except Exception as e:
        logging.error(f"Failed to save configuration: {e}")
        return False

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='Process Monitor - Monitor system processes for high resource usage',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--config', '-c', type=str, default='config.json',
                        help='Configuration file path (default: config.json)')
    parser.add_argument('--generate-config', action='store_true',
                        help='Generate a default configuration file and exit')
    parser.add_argument('--db', type=str, default='process_monitor.db',
                        help='Database file path (default: process_monitor.db)')
    parser.add_argument('--wait-time', '-w', type=int,
                        help='Time to wait between scans in seconds (overrides config)')
    parser.add_argument('--cpu-threshold', type=int,
                        help='CPU usage threshold percentage (overrides config)')
    parser.add_argument('--memory-threshold', type=int,
                        help='Memory usage threshold percentage (overrides config)')
    parser.add_argument('--export', '-e', type=str,
                        help='Export database to CSV/JSON file and exit')
    parser.add_argument('--log-level', type=str, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                        help='Logging level (default: INFO)')
    parser.add_argument('--no-stats', action='store_true',
                        help='Disable periodic statistics display')
    
    return parser.parse_args()

def setup_logging(log_level='INFO'):
    """Configure logging system."""
    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def display_statistics():
    """Display monitoring statistics.
    
    Note: Uses print() instead of logging to provide clean, user-facing
    formatted output without log timestamps/levels. Statistics can be
    disabled with --no-stats flag.
    """
    if stats['start_time'] is None:
        return
    
    elapsed = time.time() - stats['start_time']
    hours, remainder = divmod(int(elapsed), 3600)
    minutes, seconds = divmod(remainder, 60)
    
    print("\n" + "="*60)
    print("MONITORING STATISTICS")
    print("="*60)
    print(f"Runtime: {hours:02d}:{minutes:02d}:{seconds:02d}")
    print(f"High CPU events: {stats['high_cpu_events']}")
    print(f"High Memory events: {stats['high_memory_events']}")
    print(f"High Disk Write Rate events: {stats['high_disk_write_rate_events']}")
    print(f"High Disk Read Rate events: {stats['high_disk_read_rate_events']}")
    print(f"High Cumulative Disk events: {stats['high_cumulative_disk_events']}")
    print(f"Network connections tracked: {stats['network_connections']}")
    print("="*60 + "\n")
    
    stats['last_stats_display'] = time.time()

def export_to_csv(db_path, output_file):
    """Export database contents to CSV file."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM process_events")
        rows = cursor.fetchall()
        
        # Get column names
        cursor.execute("PRAGMA table_info(process_events)")
        columns = [col[1] for col in cursor.fetchall()]
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(columns)
            writer.writerows(rows)
        
        conn.close()
        print(f"Exported {len(rows)} records to {output_file}")
        return True
    except Exception as e:
        print(f"Error exporting to CSV: {e}", file=sys.stderr)
        return False

def export_to_json(db_path, output_file):
    """Export database contents to JSON file."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM process_events")
        rows = cursor.fetchall()
        
        # Get column names
        cursor.execute("PRAGMA table_info(process_events)")
        columns = [col[1] for col in cursor.fetchall()]
        
        # Convert to list of dictionaries
        records = [dict(zip(columns, row)) for row in rows]
        
        with open(output_file, 'w') as f:
            json.dump(records, f, indent=2)
        
        conn.close()
        print(f"Exported {len(records)} records to {output_file}")
        return True
    except Exception as e:
        print(f"Error exporting to JSON: {e}", file=sys.stderr)
        return False

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

def init_database(db_path='process_monitor.db'):
    """Initialize the SQLite database connection and create tables."""
    global conn, cursor
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    logging.info(f"Database initialized: {db_path}")
    
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
        Tuple of (exceeds_threshold, rate_in_mb_per_sec), where rate_in_mb_per_sec is in MB/s.
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
                stats['high_cpu_events'] += 1
                process_count += 1
                should_investigate = True

            if memory_usage is not None and memory_usage > high_memory_threshold:
                insert_event(proc, "High Memory", memory_usage)
                stats['high_memory_events'] += 1
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
                        stats['high_disk_write_rate_events'] += 1
                        process_count += 1
                        should_investigate = True
                    
                    # Check read rate using helper function
                    exceeds_read, read_rate = check_io_rate(
                        read_bytes, prev_read_bytes,
                        high_disk_read_rate_threshold, wait_time
                    )
                    if exceeds_read:
                        insert_event(proc, "High Disk Read Rate", read_rate)
                        stats['high_disk_read_rate_events'] += 1
                        process_count += 1
                        should_investigate = True
                
                # Cumulative monitoring: Check total writes since process start
                # Only alert once per process to avoid duplicate notifications
                if write_bytes > 0 and pid not in cumulative_alerted_pids:
                    write_mb_cumulative = write_bytes / 1024 / 1024
                    if write_mb_cumulative > high_disk_cumulative_threshold:
                        insert_event(proc, "High Cumulative Disk Writes", write_mb_cumulative)
                        stats['high_cumulative_disk_events'] += 1
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
            stats['network_connections'] += 1
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

def main():
    """Main entry point for the process monitor."""
    global wait_time, high_cpu_threshold, high_memory_threshold
    
    # Parse command-line arguments
    args = parse_arguments()
    
    # Setup logging
    log_level = args.log_level or DEFAULT_CONFIG.get('log_level', 'INFO')
    setup_logging(log_level)
    
    # Handle generate-config option
    if args.generate_config:
        if save_default_config(args.config):
            print(f"Default configuration saved to {args.config}")
            sys.exit(0)
        else:
            sys.exit(1)
    
    # Handle export option
    if args.export:
        if not os.path.exists(args.db):
            print(f"Database file '{args.db}' not found", file=sys.stderr)
            sys.exit(1)
        
        if args.export.endswith('.csv'):
            success = export_to_csv(args.db, args.export)
        elif args.export.endswith('.json'):
            success = export_to_json(args.db, args.export)
        else:
            print("Export file must have .csv or .json extension (e.g., results.csv or results.json)", file=sys.stderr)
            success = False
        
        sys.exit(0 if success else 1)
    
    # Check for administrative/root privileges
    if not is_admin():
        request_admin_privileges()
    
    # Load configuration (load_config handles missing files)
    config = load_config(args.config)
    
    # Override config with command-line arguments if provided
    if args.wait_time:
        wait_time = args.wait_time
        logging.info(f"Wait time overridden to {wait_time} seconds")
    
    if args.cpu_threshold:
        high_cpu_threshold = args.cpu_threshold
        logging.info(f"CPU threshold overridden to {high_cpu_threshold}%")
    
    if args.memory_threshold:
        high_memory_threshold = args.memory_threshold
        logging.info(f"Memory threshold overridden to {high_memory_threshold}%")
    
    show_stats = config.get('show_statistics', True) and not args.no_stats
    stats_interval = config.get('statistics_interval', 60)
    
    # Initialize database after privilege check
    try:
        init_database(args.db)
    except Exception as e:
        logging.error(f"Failed to initialize database: {e}")
        sys.exit(1)
    
    try:
        logging.info('Process Monitor started with elevated privileges.')
        logging.info(f'Database: {args.db}')
        logging.info(f'Configuration: CPU={high_cpu_threshold}%, Memory={high_memory_threshold}%, '
                    f'Disk Write Rate={high_disk_write_rate_threshold} MB/s, '
                    f'Disk Read Rate={high_disk_read_rate_threshold} MB/s, '
                    f'Cumulative Disk={high_disk_cumulative_threshold} MB')
        logging.info('Press Ctrl+C to exit.')
        
        stats['start_time'] = time.time()
        stats['last_stats_display'] = time.time()
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
                logging.error(f"Database commit error: {e}")
            
            # Display statistics periodically
            if show_stats and (time.time() - stats['last_stats_display']) >= stats_interval:
                display_statistics()
            
            time.sleep(wait_time)
            
    except KeyboardInterrupt:
        logging.info('\nMonitoring stopped by user.')
        if show_stats:
            display_statistics()
    except Exception as e:
        logging.error(f"Unexpected error in main loop: {e}")
    finally:
        # Ensure database is properly closed
        try:
            if conn:
                conn.commit()  # Final commit of any pending data
                conn.close()
                logging.info("Database connection closed successfully.")
        except Exception as e:
            logging.error(f"Error closing database: {e}")

# Main execution
if __name__ == "__main__":
    main()