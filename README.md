⚠️ Vizmap is in an early state of release. Many more features will be added as the script matures.

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
pip3 install -r requirements.txt
```

## Usage

Run VizMap by passing an Nmap XML output file as an argument:

```
# List all Windows Host with smb enabled
python3 vizmap.py nmap-results.xml --windows --smb

# List all Host with winrm enabled in matrix mode
python3 vizmap.py nmap-results.xml --windows --winrm --matrix

# List all hosts with SQL service enabled
python3 vizmap.py nmap-results.xml --windows --sql-server

# Filter for specific port
python3 vizmap.py nmap-results.xml --port 2375
```

## Optional Arguments

```
usage: vizmap.py [-h] [--windows] [--linux] [--sql-server] [--ftp] [--ssh] [--http] [--https] [--dns] [--kerberos] [--smb] [--ldap] [--mssql] [--mysql] [--rdp] [--vnc] [--winrm] [--matrix-mode] [--filtered] file

Parse and visualize Nmap XML output in matrix mode.

positional arguments:
  file           Nmap XML output file

options:
  -h, --help     show this help message and exit

OS Filters:
  --windows      Filter for Windows hosts
  --linux        Filter for Linux hosts

Protocol Auto-Detector:
  --sql-server   Detect SQL Servers (MSSQL, MySQL, PostgreSQL, Oracle, MongoDB, HSQLDB ecc..)

Protocol Filters:
  --ftp          Filter for hosts with an open FTP port
  --ssh          Filter for hosts with an open SSH port
  --http         Filter for hosts with an open HTTP port
  --https        Filter for hosts with an open HTTPS port
  --dns          Filter for hosts with an open DNS port
  --kerberos     Filter for hosts with an open Kerberos port
  --smb          Filter for hosts with an open SMB port
  --ldap         Filter for hosts with an open LDAP port
  --mssql        Filter for hosts with an open MSSQL port
  --mysql        Filter for hosts with an open MySQL port
  --rdp          Filter for hosts with an open RDP port
  --vnc          Filter for hosts with an open VNC port
  --winrm        Filter for hosts with an open WinRM port

Visualization:
  --matrix-mode  Enable matrix mode visualization

Other:
  --filtered     Include filtered ports
```

This command filters the scan results to show only SQL Servers with by filtering for windows hosts.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request with your suggested improvements.

## License
Distributed under the MIT License. See LICENSE for more information.
