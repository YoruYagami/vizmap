import xml.etree.ElementTree as ET
import argparse
from prettytable import PrettyTable
from colorama import Fore, Style
import sys

def initialize_colorama():
    """Initializes colorama for color support on Windows."""
    if sys.platform.startswith('win'):
        import colorama
        colorama.init()

def parse_arguments():
    """Parses and returns command-line arguments, organized into groups."""
    parser = argparse.ArgumentParser(description='Parse Nmap XML output easily.')
    parser.add_argument('file', help='Nmap XML output file')
    
    # OS Filters
    os_group = parser.add_argument_group('OS Filters')
    os_group.add_argument('--windows', action='store_true', help='Filter for Windows hosts')
    os_group.add_argument('--linux', action='store_true', help='Filter for Linux hosts')

    # Protocol Auto-Detector
    protocol_group = parser.add_argument_group('Protocol Auto-Detector')
    protocol_group.add_argument('--sql-server', action='store_true', help='Detect all SQL Servers (MSSQL, MySQL, PostgreSQL, Oracle, MongoDB, HSQLDB ecc..)')
    
    # Protocol Filters
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

    # Other
    other_group = parser.add_argument_group('Other')
    other_group.add_argument('--filtered', action='store_true', help='Include filtered ports')
    
    return parser.parse_args()

def parse_nmap_xml(file_path):
    """Parses the Nmap XML file and returns a list of host data, with improved OS detection."""
    tree = ET.parse(file_path)
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


            # Enhanced OS detection
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
    """Filters hosts based on the command-line arguments and returns the filtered list."""
    sql_port_service_mapping = {
        '1433': 'MSSQL',
        '3306': 'MySQL',
        '5432': 'PostgreSQL',
        '1521': 'Oracle',
        '27017': 'MongoDB',
        '9001': 'HSQLDB',
        '6379': 'Redis',
        '5984': 'CouchDB',
        '7474': 'Neo4j',
        '9200': 'Elasticsearch',
        '26257': 'CockroachDB',
        '8087': 'Riak',
        '9042': 'Cassandra'
    }

    filtered_hosts = []
    for host in hosts_data:
        ports = [
            f'{Fore.GREEN}{pid}{Style.RESET_ALL}' if state == 'open' else f'{Fore.YELLOW}{pid}{Style.RESET_ALL}' 
            for pid, state in host['ports'] if state == 'open' or (state == 'filtered' and args.filtered)
        ]

        # Protocol Auto-Detector part
        if args.sql_server:
            sql_ports = set(sql_port_service_mapping.keys())
            open_sql_ports = sql_ports.intersection([pid for pid, state in host['ports'] if state == 'open'])
            if open_sql_ports:
                host['sql_service'] = ', '.join([sql_port_service_mapping[port] for port in open_sql_ports])
            else:
                continue

        # Protocol only part
        if args.ftp:
            if '21' not in [pid for pid, state in host['ports'] if state == 'open']:
                continue

        if args.ssh:
            if '22' not in [pid for pid, state in host['ports'] if state == 'open']:
                continue
        
        if args.http:
            if '80' not in [pid for pid, state in host['ports'] if state == 'open']:
                continue
        
        if args.https:
            if '443' not in [pid for pid, state in host['ports'] if state == 'open']:
                continue
                
        if args.dns:
            if '53' not in [pid for pid, state in host['ports'] if state == 'open']:
                continue

        if args.kerberos:
            if '88' not in [pid for pid, state in host['ports'] if state == 'open']:
                continue

        if args.smb:
            smb_ports = {'139', '445'}
            if not smb_ports.intersection([pid for pid, state in host['ports'] if state == 'open']):
                continue
        
        if args.ldap:
            ldap_ports= {'139', '636', '3268', '3269'}
            if not ldap_ports.intersection([pid for pid, state in host['ports'] if state == 'open']):
                continue

        if args.mssql:
            if '1433' not in [pid for pid, state in host['ports'] if state == 'open']:
                continue

        if args.mysql:
            if '3306' not in [pid for pid, state in host['ports'] if state == 'open']:
                continue

        if args.rdp:
            if '3389' not in [pid for pid, state in host['ports'] if state == 'open']:
                continue

        if args.vnc:
            if '5900' not in [pid for pid, state in host['ports'] if state == 'open']:
                continue

        if args.winrm:
            if '5985' not in [pid for pid, state in host['ports'] if state == 'open']:
                continue
        
        if ports and (
            (args.windows and 'windows' in host['os_name'].lower()) or 
            (args.linux and 'linux' in host['os_name'].lower()) or 
            (not args.windows and not args.linux)
        ):
            host['ports'] = ports
            filtered_hosts.append(host)

    return filtered_hosts

def create_table(hosts_data, include_sql_service):
    """Creates and returns a table with the parsed data, optionally including SQL Service type."""
    if include_sql_service:
        table = PrettyTable(['IP Address', 'Hostname', 'OS', 'Ports', 'SQL Service'])
    else:
        table = PrettyTable(['IP Address', 'Hostname', 'OS', 'Ports'])
    
    for host in hosts_data:
        if include_sql_service:
            table.add_row([
                host['ip_address'], 
                host['hostname'], 
                host['os_name'], 
                ','.join(host['ports']), 
                host.get('sql_service', '')
            ])
        else:
            table.add_row([
                host['ip_address'], 
                host['hostname'], 
                host['os_name'], 
                ','.join(host['ports'])
            ])
    return table

def main():
    """The entry point for the script."""
    initialize_colorama()
    args = parse_arguments()
    hosts_data = parse_nmap_xml(args.file)
    filtered_hosts = filter_hosts(hosts_data, args)
    table = create_table(filtered_hosts, args.sql_server)
    print(table)

if __name__ == "__main__":
    main()