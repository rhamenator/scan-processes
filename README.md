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

- **Resource Monitoring:** Tracks CPU usage, memory consumption, and disk I/O (read/write rates and cumulative writes) of processes.
- **Network Connection Tracking:** Logs details about network connections established by processes, including remote IP addresses and ports.
- **SQLite Database:** Stores events in a local SQLite database for easy querying and analysis.
- **Real-time Monitoring:** Continuously monitors processes and reports events as they occur.
- **Cross-Platform:** Works seamlessly on Windows, Linux, and macOS.
- **Configuration File Support:** Use JSON configuration files for easy customization without editing code.
- **Command-Line Interface:** Flexible CLI with options to override settings, export data, and more.
- **Statistics Display:** View real-time monitoring statistics showing event counts and runtime.
- **Data Export:** Export monitoring data to CSV or JSON format for analysis in other tools.
- **Structured Logging:** Configurable logging levels (DEBUG, INFO, WARNING, ERROR) for better diagnostics.

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

## Command-Line Options

The script now supports flexible command-line options for easy customization:

```bash
python3 scan_processes.py [options]
```

**Available Options:**

- `--config, -c <file>`: Specify a configuration file (default: `config.json`)
- `--generate-config`: Generate a default configuration file and exit
- `--db <file>`: Specify database file path (default: `process_monitor.db`)
- `--wait-time, -w <seconds>`: Override scan interval
- `--cpu-threshold <percentage>`: Override CPU threshold
- `--memory-threshold <percentage>`: Override memory threshold
- `--export, -e <file>`: Export database to CSV or JSON file
- `--log-level <level>`: Set logging level (DEBUG, INFO, WARNING, ERROR)
- `--no-stats`: Disable periodic statistics display
- `--help, -h`: Show help message

**Examples:**

```bash
# Generate a default configuration file
python3 scan_processes.py --generate-config

# Run with custom configuration file
python3 scan_processes.py --config my_config.json

# Override specific settings via command line
python3 scan_processes.py --wait-time 5 --cpu-threshold 90

# Export database to CSV
python3 scan_processes.py --export results.csv

# Run with debug logging and custom database
python3 scan_processes.py --db my_monitor.db --log-level DEBUG
```

## Configuration File

You can customize all monitoring parameters using a JSON configuration file. Generate a default configuration:

```bash
python3 scan_processes.py --generate-config
```

This creates a `config.json` file that you can edit with the following parameters:

- `wait_time`: Interval in seconds between process scans (default: 10 seconds)
- `high_cpu_threshold`: CPU usage percentage to trigger an alert (default: 80%)
- `high_memory_threshold`: Memory usage percentage to trigger an alert (default: 70%)
- `high_disk_write_rate_threshold`: Disk write speed in MB/s to trigger an alert (default: 50 MB/s)
- `high_disk_read_rate_threshold`: Disk read speed in MB/s to trigger an alert (default: 100 MB/s)
- `high_disk_cumulative_threshold`: Cumulative disk writes in MB to trigger an alert (default: 500 MB)
- `disk_io_whitelist`: Array of process names to exclude from disk I/O monitoring
- `log_level`: Logging verbosity - DEBUG, INFO, WARNING, or ERROR (default: "INFO")
- `show_statistics`: Enable/disable periodic statistics display (default: true)
- `statistics_interval`: Seconds between statistics displays (default: 60)

### Disk I/O Whitelist

The `disk_io_whitelist` allows you to exclude known legitimate processes from disk I/O alerts. This is useful for processes like:
- Cloud storage sync clients (OneDrive, Google Drive, Dropbox)
- Web browsers performing downloads
- Backup software
- Other applications with expected heavy disk activity

Edit the `disk_io_whitelist` array in your `config.json`:

```json
{
    "disk_io_whitelist": [
        "onedrive.exe", "onedrive",
        "googledrivesync.exe", "googledrivesync",
        "dropbox.exe", "dropbox",
        "mybackup.exe"
    ]
}
```

Process names are case-insensitive and should match the process name as shown by the system.

## Data Export

You can export the monitoring data from the database to CSV or JSON format:

```bash
# Export to CSV
python3 scan_processes.py --export results.csv

# Export to JSON
python3 scan_processes.py --export results.json
```

This allows you to analyze the data in spreadsheet applications, create visualizations, or process it with other tools.

## Statistics Display

By default, the monitor displays periodic statistics showing:
- Runtime duration
- Count of high CPU events
- Count of high memory events
- Count of high disk write/read rate events
- Count of cumulative disk events
- Number of network connections tracked

Statistics are displayed every 60 seconds (configurable via `statistics_interval` in config.json). Disable with `--no-stats` flag.

## Important Notes

- **Elevated Privileges:** The script automatically checks for and requests administrative/root privileges:
  - **Windows:** Attempts to automatically request elevation; if that fails, displays instructions
  - **Linux/macOS:** Displays clear instructions to run with `sudo` if privileges are insufficient
  - Required for: disk I/O monitoring, network connections, and detailed process information
- **Database Location:** The SQLite database (`process_monitor.db`) is created in the current working directory
- **Continuous Monitoring:** The script runs continuously until interrupted with `Ctrl+C`
- **Monitoring Behavior:** 
  - CPU and memory usage are measured at each scan interval
  - Disk monitoring uses both rate-based and cumulative tracking:
    - **Rate-based**: Detects processes suddenly consuming high disk I/O (MB/s for reads and writes)
    - **Cumulative**: Detects processes with excessive total disk writes since they started
  - Disk rate alerts (MB/s) appear starting from the second monitoring cycle
  - Whitelisted processes (OneDrive, Google Drive, browsers, etc.) are excluded from disk I/O alerts
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
