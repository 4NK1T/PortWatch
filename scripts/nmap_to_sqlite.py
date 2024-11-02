#!/usr/bin/python3
import xml.etree.ElementTree as ET
import sqlite3
from datetime import datetime
import sys
import os

def create_database(db_name):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    
    # Drop existing tables if they exist
    c.execute('DROP TABLE IF EXISTS ports')
    c.execute('DROP TABLE IF EXISTS hosts')
    c.execute('DROP TABLE IF EXISTS scans')
    
    # Create tables with correct schema
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                nmap_version TEXT,
                command_line TEXT,
                start_time INTEGER,
                elapsed_time TEXT,
                total_hosts INTEGER,
                total_open_ports INTEGER)''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS hosts
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                ip TEXT,
                hostname TEXT,
                os TEXT,
                ports_tested INTEGER,
                ports_open INTEGER,
                ports_closed INTEGER,
                ports_filtered INTEGER,
                start_time INTEGER,
                end_time INTEGER,
                FOREIGN KEY (scan_id) REFERENCES scans(id))''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS ports
                (id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                host_id INTEGER,
                port TEXT,
                protocol TEXT,
                state TEXT,
                service_name TEXT,
                service_info TEXT,
                http_title TEXT,
                ssl_common_name TEXT,
                ssl_issuer TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id),
                FOREIGN KEY (host_id) REFERENCES hosts(id))''')
    
    # Create indexes for better performance
    c.execute('CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scans(start_time)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_host_ip ON hosts(ip)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_port_number ON ports(port)')
    
    conn.commit()
    return conn

def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    scan = {
        'nmap_version': root.get('version', ''),
        'command_line': root.get('args', ''),
        'start_time': int(root.get('start', '0')),
        'elapsed_time': root.find('.//finished').get('elapsed', '0') if root.find('.//finished') is not None else '0',
        'total_hosts': 0,
        'total_open_ports': 0
    }
    
    hosts = []
    for host in root.findall('host'):
        host_data = {
            'ip': host.find('address').get('addr', ''),
            'hostname': '',
            'os': 'Unknown',
            'ports_tested': 0,
            'ports_open': 0,
            'ports_closed': 0,
            'ports_filtered': 0,
            'start_time': int(host.get('starttime', '0')) * 1000,
            'end_time': int(host.get('endtime', '0')) * 1000,
            'ports': []
        }
        
        hostname_elem = host.find('.//hostname')
        if hostname_elem is not None:
            host_data['hostname'] = hostname_elem.get('name', '')
        
        os_elem = host.find('.//osclass')
        if os_elem is not None:
            host_data['os'] = os_elem.get('osfamily', 'Unknown')
        
        for port in host.findall('.//port'):
            port_data = {
                'port': port.get('portid', ''),
                'protocol': port.get('protocol', ''),
                'state': port.find('state').get('state', ''),
                'service_name': '',
                'service_info': '',
                'http_title': '',
                'ssl_common_name': '',
                'ssl_issuer': ''
            }
            
            service = port.find('service')
            if service is not None:
                port_data['service_name'] = service.get('name', '')
                product = service.get('product', '')
                version = service.get('version', '')
                port_data['service_info'] = f"{product} {version}".strip()
            
            # Parse script output for http-title and ssl info
            for script in port.findall('script'):
                if script.get('id') == 'http-title':
                    port_data['http_title'] = script.get('output', '')
                elif script.get('id') == 'ssl-cert':
                    for table in script.findall('table'):
                        if table.get('key') == 'subject':
                            cn = table.find("elem[@key='commonName']")
                            if cn is not None:
                                port_data['ssl_common_name'] = cn.text
                        elif table.get('key') == 'issuer':
                            cn = table.find("elem[@key='commonName']")
                            if cn is not None:
                                port_data['ssl_issuer'] = cn.text
            
            if port_data['state'] == 'open':
                host_data['ports_open'] += 1
                scan['total_open_ports'] += 1
            elif port_data['state'] == 'closed':
                host_data['ports_closed'] += 1
            elif port_data['state'] == 'filtered':
                host_data['ports_filtered'] += 1
            
            host_data['ports'].append(port_data)
            host_data['ports_tested'] += 1
        
        hosts.append(host_data)
        scan['total_hosts'] += 1
    
    return scan, hosts

def insert_data(conn, scan, hosts):
    c = conn.cursor()
    
    c.execute('''INSERT INTO scans 
                (nmap_version, command_line, start_time, elapsed_time, total_hosts, total_open_ports)
                VALUES (?, ?, ?, ?, ?, ?)''',
                (scan['nmap_version'], scan['command_line'], scan['start_time'],
                 scan['elapsed_time'], scan['total_hosts'], scan['total_open_ports']))
    scan_id = c.lastrowid
    
    for host in hosts:
        c.execute('''INSERT INTO hosts
                    (scan_id, ip, hostname, os, ports_tested, ports_open, 
                    ports_closed, ports_filtered, start_time, end_time)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (scan_id, host['ip'], host['hostname'], host['os'],
                     host['ports_tested'], host['ports_open'], host['ports_closed'],
                     host['ports_filtered'], host['start_time'], host['end_time']))
        host_id = c.lastrowid
        
        for port in host['ports']:
            c.execute('''INSERT INTO ports
                        (scan_id, host_id, port, protocol, state, service_name,
                        service_info, http_title, ssl_common_name, ssl_issuer)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                        (scan_id, host_id, port['port'], port['protocol'],
                         port['state'], port['service_name'], port['service_info'],
                         port['http_title'], port['ssl_common_name'], port['ssl_issuer']))
    
    conn.commit()

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 nmap_to_sqlite.py <xml_file>")
        sys.exit(1)
    
    xml_file = sys.argv[1]
    db_file = os.path.join(os.path.dirname(xml_file), 'nmap_results.db')
    
    if not os.path.exists(xml_file):
        print(f"Error: XML file {xml_file} not found")
        sys.exit(1)
    
    try:
        conn = create_database(db_file)
        scan, hosts = parse_nmap_xml(xml_file)
        insert_data(conn, scan, hosts)
        conn.close()
        print(f"Successfully processed {xml_file} to {db_file}")
    except Exception as e:
        print(f"Error processing file: {e}")
        sys.exit(1)
    
    conn = create_database(db_file)
    scan, hosts = parse_nmap_xml(xml_file)
    insert_data(conn, scan, hosts)
    conn.close()

if __name__ == '__main__':
    main()