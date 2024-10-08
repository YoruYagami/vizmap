import xml.etree.ElementTree as ElementTree
import argparse
from prettytable import PrettyTable
from colorama import Fore, Style
import sys
import re

def initialize_colorama():
    """Initializes colorama for color support on Windows."""
    if sys.platform.startswith('win'):
        import colorama
        colorama.init()

def parse_arguments():
    """Simplified argument parsing."""
    parser = argparse.ArgumentParser(description='Parse and visualize Nmap XML output in matrix mode.')
    parser.add_argument('file', help='Nmap XML output file')
    
    os_group = parser.add_argument_group('OS Filters')
    os_group.add_argument('--windows', action='store_true', help='Filter for Windows hosts')

    protocol_group = parser.add_argument_group('Protocol Auto-Detector')
    protocol_group.add_argument('--sql', action='store_true', help='Detect SQL Servers (MSSQL, MySQL, PostgreSQL, Oracle, MongoDB, HSQLDB ecc..)')

    protocol_group = parser.add_argument_group('Protocol Filters')
    protocol_group.add_argument('--ftp', action='store_true', help='Filter for hosts with an open FTP port')
    protocol_group.add_argument('--ssh', action='store_true', help='Filter for hosts with an open SSH port')
    protocol_group.add_argument('--http', action='store_true', help='Filter for hosts with an open HTTP port')
    protocol_group.add_argument('--https', action='store_true', help='Filter for hosts with an open HTTPS port')
    protocol_group.add_argument('--dns', action='store_true', help='Filter for hosts with an open DNS port')
    protocol_group.add_argument('--kerberos', action='store_true', help='Filter for hosts with an open Kerberos port')
    protocol_group.add_argument('--smb', action='store_true', help='Filter for hosts with an open SMB port')
    protocol_group.add_argument('--ldap', action='store_true', help='Filter for hosts with an open LDAP port')
    protocol_group.add_argument('--mssql', action='store_true', help='Filter for hosts with an open MSSQL port')
    protocol_group.add_argument('--mysql', action='store_true', help='Filter for hosts with an open MySQL port')
    protocol_group.add_argument('--rdp', action='store_true', help='Filter for hosts with an open RDP port')
    protocol_group.add_argument('--vnc', action='store_true', help='Filter for hosts with an open VNC port')
    protocol_group.add_argument('--winrm', action='store_true', help='Filter for hosts with an open WinRM port')

    other_group = parser.add_argument_group('Other')
    other_group.add_argument('--port', type=int, help='Filter for hosts with a specific open port')
    other_group.add_argument('--filtered', action='store_true', help='Include filtered ports')
    
    return parser.parse_args()

def parse_nmap_xml(file_path):
    tree = ElementTree.parse(file_path)
    root = tree.getroot()
    hosts_data = []

    for host in root.findall('host'):
        if host.find('status').get('state') == 'up':
            host_data = {
                'ip_address': host.find('address').get('addr'),
                'hostname': host.find('hostnames/hostname').get('name') if host.find('hostnames/hostname') is not None else '',
                'os_name': "Unknown",
                'ports': [],
                'sql_service': ''
            }

            highest_confidence = 0
            for osmatch in host.findall('os/osmatch'):
                current_confidence = int(osmatch.get('accuracy', 0))
                if current_confidence > highest_confidence:
                    highest_confidence = current_confidence
                    host_data['os_name'] = osmatch.get('name')

            for port in host.findall('ports/port'):
                port_id = port.get('portid')
                state = port.find('state').get('state')
                host_data['ports'].append((port_id, state))
            
            hosts_data.append(host_data)
    
    return hosts_data

def filter_hosts(hosts_data, args):
    sql_port_service_mapping = {
        '1433': 'MSSQL',
        '1434': 'MSSQL Browser',
        '1521': 'Oracle',
        '2483': 'Oracle SSL',
        '2484': 'Oracle SSL Alternative',
        '3306': 'MySQL',
        '5432': 'PostgreSQL',
        '5433': 'PostgreSQL',
        '5984': 'CouchDB',
        '6379': 'Redis',
        '7474': 'Neo4j',
        '8086': 'InfluxDB',
        '8087': 'Riak',
        '9001': 'HSQLDB',
        '9042': 'Cassandra',
        '9200': 'Elasticsearch',
        '27017': 'MongoDB',
        '27018': 'MongoDB Replica Set',
        '26257': 'CockroachDB'
    }

    protocol_port_mapping = {
        'ftp': '21',
        'ssh': '22',
        'http': '80',
        'https': '443',
        'dns': '53',
        'kerberos': '88',
        'smb': {'139', '445'},
        'ldap': {'389', '636', '3268', '3269'},
        'mssql': '1433',
        'mysql': '3306',
        'rdp': '3389',
        'vnc': '5900',
        'winrm': '5985'
    }

    def is_protocol_open(host, protocol):
        ports = protocol_port_mapping.get(protocol)
        if isinstance(ports, set):
            return bool(ports.intersection([pid for pid, state in host['ports'] if state == 'open' or (state == 'filtered' and args.filtered)]))
        else:
            return ports in [pid for pid, state in host['ports'] if state == 'open' or (state == 'filtered' and args.filtered)]

    filtered_hosts = []
    for host in hosts_data:
        if args.windows and 'windows' not in host['os_name'].lower():
            continue

        ports = [
            f'{Fore.GREEN}{pid}{Style.RESET_ALL}' if state == 'open' else f'{Fore.YELLOW}{pid}{Style.RESET_ALL}' 
            for pid, state in host['ports'] if state == 'open' or (state == 'filtered' and args.filtered)
        ]

        if args.port and not any(pid == str(args.port) and state == 'open' for pid, state in host['ports']):
            continue

        if args.sql:
            sql_ports = set(sql_port_service_mapping.keys())
            open_sql_ports = sql_ports.intersection([pid for pid, state in host['ports'] if state == 'open'])
            if open_sql_ports:
                host['sql_service'] = ', '.join([sql_port_service_mapping[port] for port in open_sql_ports])
            else:
                continue

        for protocol in protocol_port_mapping.keys():
            if getattr(args, protocol, False) and not is_protocol_open(host, protocol):
                break
        else:
            if ports:
                host['ports'] = ports
                filtered_hosts.append(host)

    return filtered_hosts

def strip_ansi(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def create_grid(hosts_data, include_sql_service=False):
    all_ports = set(strip_ansi(port) for host in hosts_data for port in host['ports'])
    ports = sorted(all_ports, key=lambda x: int(x))
    hosts = sorted(set(host['ip_address'] for host in hosts_data))
    grid = PrettyTable()

    grid.border = True  
    grid.horizontal_char = '-'
    grid.junction_char = '+'
    grid.header = False

    field_names = ['IP Address', 'Hostname', 'OS'] + ports
    if include_sql_service:
        field_names.append('SQL Service')
    grid.field_names = field_names

    for host in hosts:
        host_data = next(h for h in hosts_data if h['ip_address'] == host)
        host_ports = {strip_ansi(port): port for port in host_data['ports']}
        row = [host, host_data['hostname'], host_data['os_name']]
        for port in ports:
            if port in host_ports:
                row.append(host_ports[port])
            else:
                row.append('')
        if include_sql_service:
            row.append(host_data.get('sql_service', ''))
        grid.add_row(row)

    return grid

def get_arguments():
    try:
        return parse_arguments()
    except argparse.ArgumentError as e:
        raise Exception(f"Error parsing arguments: {e}")

def get_hosts_data(file):
    try:
        return parse_nmap_xml(file)
    except FileNotFoundError:
        raise Exception(f"Error: File {file} not found.")
    except ElementTree.ParseError as e:
        raise Exception(f"Error parsing XML: {e}")

def get_filtered_hosts(hosts_data, args):
    try:
        return filter_hosts(hosts_data, args)
    except Exception as e:
        raise Exception(f"Error filtering hosts: {e}")

def main():
    initialize_colorama()
    args = parse_arguments()
    hosts_data = parse_nmap_xml(args.file)
    filtered_hosts = filter_hosts(hosts_data, args)

    if not filtered_hosts:
        print("No hosts found matching the given criteria.")
        return

    grid = create_grid(filtered_hosts, args.sql)
    print(grid)

if __name__ == "__main__":
    main()