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

- Python 3.6 or higher
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

1. Run the script with elevated privileges:

    **Windows (PowerShell as Administrator):**
    ```powershell
    python scan_processes.py
    ```

    **Linux/macOS:**
    ```bash
    sudo python3 scan_processes.py
    ```

2. Monitor output: The script will display a summary of investigated processes and connections to the console in real-time. Press `Ctrl+C` to stop monitoring.

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

- **Elevated Privileges Required:** The script requires administrative/root privileges to access detailed process information and network connections.
  - Without elevated privileges, disk I/O monitoring may not work on Linux/macOS
  - Network connection monitoring requires elevated privileges on all platforms
- **Database Location:** The SQLite database (`process_monitor.db`) is created in the current working directory
- **Continuous Monitoring:** The script runs continuously until interrupted with `Ctrl+C`
- **Performance Impact:** Monitoring can consume system resources; adjust `wait_time` if needed

## Troubleshooting

### "Access Denied" Errors
- **Solution:** Run the script with elevated privileges (Administrator on Windows, sudo on Linux/macOS)

### No Disk I/O Data on Linux/macOS
- **Cause:** Requires root privileges
- **Solution:** Run with `sudo python3 scan_processes.py`

### Empty Network Connection Data
- **Cause:** Insufficient privileges or no active connections
- **Solution:** Ensure elevated privileges and that monitored processes have network activity

## Disclaimer

- This script is intended for educational and system monitoring purposes only
- Use responsibly and in compliance with your organization's policies
- Respect privacy and security considerations when monitoring processes
- Be cautious when acting on the script's output—understand the implications before terminating any processes

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License.
