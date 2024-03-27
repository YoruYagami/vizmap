# VizMap

VizMap is a Python script designed for parsing and filtering Nmap scan results in XML format. It enhances the usability and readability of Nmap's output by allowing users to easily filter hosts based on operating system type, open ports, and specific protocols. Additionally, VizMap introduces an auto-detection feature for SQL servers, improving the process of identifying database services across scanned networks.

## Features

- **OS Filtering**: Allows filtering hosts based on their operating system (Windows or Linux).
- **Protocol Auto-Detector**: Automatically detects SQL servers (MSSQL, MySQL, PostgreSQL, Oracle, MongoDB, etc.) across the network.
- **Protocol Filters**: Filters hosts based on the presence of open ports for common services like FTP, SSH, HTTP(S), DNS, Kerberos, SMB, LDAP, MSSQL, MySQL, RDP, VNC, and WinRM.
- **Port State Highlighting**: Highlights open ports in green and filtered ports in yellow, for a clear and concise presentation of the scan results.
- **Include Filtered Ports Option**: Optionally includes filtered ports in the output for a more comprehensive overview of network security posture.

## Installation

1. Clone the repository or download the script directly.
2. Ensure Python 3 is installed on your system.
3. Install the required Python packages:

```
pip install prettytable colorama
```

## Usage

Run VizMap by passing an Nmap XML output file as an argument:

```
python vizmap.py <nmap-output.xml>
```

## Optional Arguments

```
--windows: Filter for Windows hosts.
--linux: Filter for Linux hosts.
--SQL-Servers: Detect SQL Servers.
--ftp, --ssh, --http, etc.: Filter for hosts with specified open ports.
--filtered: Include filtered ports in the output.
```

## Example

```
python3 vizmap.py nmap-results.xml --windows --SQL-Servers
```

This command filters the scan results to show only SQL Servers with by filtering for windows hosts.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request with your suggested improvements.

## License
Distributed under the MIT License. See LICENSE for more information.