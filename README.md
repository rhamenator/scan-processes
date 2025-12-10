# Process Monitor

This Python script actively monitors running processes on your system, flagging those that exhibit high resource usage (CPU, memory, or disk) or those establishing network connections. It records these events in an SQLite database for further analysis.

## Platform Support

This script is cross-platform and works on:
- **Windows** (Windows 10/11)
- **Linux** (most distributions)
- **macOS** (10.13 and later)

**Note:** Administrative/root privileges are required for full functionality:
- On **Windows**: Run as Administrator
- On **Linux/macOS**: Run with `sudo`

Without elevated privileges, some features (like disk I/O monitoring and network connections) may have limited functionality.

## Features

- **Resource Monitoring:** Tracks CPU usage, memory consumption, and disk write activity of processes.
- **Network Connection Tracking:** Logs details about network connections established by processes, including remote IP addresses and ports.
- **SQLite Database:** Stores events in a local SQLite database for easy querying and analysis.
- **Real-time Monitoring:** Continuously monitors processes and reports events as they occur.
- **Cross-Platform:** Works seamlessly on Windows, Linux, and macOS.

## Requirements

- Python 3.7 or higher (preferably 3.8+)
- `psutil` library (installed via pip)

## Installation

1. Clone this repository or download the script:

    ```bash
    git clone https://github.com/rhamenator/scan-processes.git
    cd scan-processes
    ```

2. Install the required library using `pip`:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. Run the script:

    **Windows:**
    
    Simply run the script normally. If administrative privileges are required, the script will automatically request elevation:
    ```powershell
    python scan_processes.py
    ```
    
    If automatic elevation fails, you can manually run PowerShell as Administrator and execute the script.

    **Linux/macOS:**
    
    The script will check for root privileges and display a clear message if they're needed:
    ```bash
    python3 scan_processes.py
    ```
    
    If you don't have root privileges, the script will display instructions to run with sudo:
    ```bash
    sudo python3 scan_processes.py
    ```

2. Monitor output: Once running with elevated privileges, the script will display a confirmation message and show a summary of investigated processes and connections in real-time. Press `Ctrl+C` to stop monitoring.

3. Access the database: Events are stored in an SQLite database called `process_monitor.db` in the same directory as the script. You can use tools like:
    - [DB Browser for SQLite](https://sqlitebrowser.org/) (cross-platform GUI)
    - SQLite command-line tool: `sqlite3 process_monitor.db`
    - Python scripts with the `sqlite3` module

## Database Structure

The script creates an SQLite database named `process_monitor.db` with a table `process_events` having the following columns:

- `timestamp`: Timestamp of the event
- `pid`: Process ID
- `process_name`: Process name
- `event_type`: Type of event (High CPU, High Memory, High Disk Write, Network Connection)
- `resource_usage`: Resource usage value (if applicable)
- `open_files`: Comma-separated list of open files (if applicable)
- `ip_connection_type`: Type of IP connection (TCP, UDP, Unknown)
- `ip_connection_status`: Status of IP connection (ESTABLISHED, etc.)
- `local_address`: Local IP address
- `local_port`: Local port
- `remote_address`: Remote IP address
- `remote_port`: Remote port
- `remote_hostname`: Remote hostname (if resolved)
- `ip_address_type`: Type of IP address (Public, Private, Loopback, etc.)
- `connection_family`: Connection family (IPv4, IPv6, etc.)

## Customization

You can modify the following parameters at the top of `scan_processes.py`:

- `wait_time`: Interval in seconds between process scans (default: 10 seconds)
- `high_cpu_threshold`: CPU usage percentage to trigger an alert (default: 80%)
- `high_memory_threshold`: Memory usage percentage to trigger an alert (default: 70%)
- `high_disk_threshold`: Disk write speed in MB/s to trigger an alert (default: 50 MB/s)

## Important Notes

- **Elevated Privileges:** The script automatically checks for and requests administrative/root privileges:
  - **Windows:** Attempts to automatically request elevation; if that fails, displays instructions
  - **Linux/macOS:** Displays clear instructions to run with `sudo` if privileges are insufficient
  - Required for: disk I/O monitoring, network connections, and detailed process information
- **Database Location:** The SQLite database (`process_monitor.db`) is created in the current working directory
- **Continuous Monitoring:** The script runs continuously until interrupted with `Ctrl+C`
- **Monitoring Behavior:** 
  - CPU and memory usage are measured at each scan interval
  - Disk write speed (MB/s) is calculated between consecutive scans, so disk alerts won't appear until the second iteration
- **Performance Impact:** Monitoring can consume system resources; adjust `wait_time` if needed

## Troubleshooting

### Privilege Check Failed
- **Windows:** If automatic elevation doesn't work, manually run PowerShell or Command Prompt as Administrator
- **Linux/macOS:** Run the script with `sudo` as instructed by the error message

### "Access Denied" Errors During Monitoring
- **Solution:** Ensure the script is running with elevated privileges (the script checks this at startup)

### No Disk I/O Data on Linux/macOS
- **Cause:** Requires root privileges
- **Solution:** The script will prompt you to use `sudo` if not running as root

### Empty Network Connection Data
- **Cause:** Insufficient privileges or no active connections
- **Solution:** Ensure elevated privileges (checked automatically) and that monitored processes have network activity

## Disclaimer

- This script is intended for educational and system monitoring purposes only
- Use responsibly and in compliance with your organization's policies
- Respect privacy and security considerations when monitoring processes
- Be cautious when acting on the script's output—understand the implications before terminating any processes

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License.
