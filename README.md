# VizMap
This project is a cli tool designed to parse and visualize Nmap XML output files in a matrix format. It supports filtering hosts based on various criteria such as operating system, specific protocols, and open ports.

## Features
- **Parse Nmap XML Output:** Extracts detailed information from Nmap XML files.
- **OS and Protocol Filters:** Filters hosts based on operating system and specific protocols.
- **Protocol Auto-Detection:** Automatically detects SQL servers and other common services.
- **Color-Coded Output:** Utilizes color coding to distinguish open and filtered ports.

## Requirements
- Python 3.x
- Required Python packages: `xml.etree.ElementTree`, `argparse`, `prettytable`, `colorama`

## Installation
To install the required Python packages, run:
```bash
pip install -r requirements.txt
```

## Usage
```bash
python vizmap.py <nmap_xml_file> [options]
```

## Example
```bash
python vizmap.py scan.xml --windows --http
```

## --help
```bash
usage: vizmap.py [-h] [--windows] [--sql] [--ftp] [--ssh] [--http] [--https] [--dns] [--kerberos] [--smb] [--ldap] [--mssql] [--mysql] [--rdp] [--vnc] [--winrm]
                 [--port PORT] [--filtered]
                 file

Parse and visualize Nmap XML output in matrix mode.

positional arguments:
  file         Nmap XML output file

options:
  -h, --help   show this help message and exit

OS Filters:
  --windows    Filter for Windows hosts

Protocol Auto-Detector:
  --sql        Detect SQL Servers (MSSQL, MySQL, PostgreSQL, Oracle, MongoDB, HSQLDB ecc..)

Protocol Filters:
  --ftp        Filter for hosts with an open FTP port
  --ssh        Filter for hosts with an open SSH port
  --http       Filter for hosts with an open HTTP port
  --https      Filter for hosts with an open HTTPS port
  --dns        Filter for hosts with an open DNS port
  --kerberos   Filter for hosts with an open Kerberos port
  --smb        Filter for hosts with an open SMB port
  --ldap       Filter for hosts with an open LDAP port
  --mssql      Filter for hosts with an open MSSQL port
  --mysql      Filter for hosts with an open MySQL port
  --rdp        Filter for hosts with an open RDP port
  --vnc        Filter for hosts with an open VNC port
  --winrm      Filter for hosts with an open WinRM port

Other:
  --port PORT  Filter for hosts with a specific open port
  --filtered   Include filtered ports
```
