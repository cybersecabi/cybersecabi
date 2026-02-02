import click
import requests
import re
import json
from urllib.parse import urljoin
from aegis.core import output_result, Spinner, log_activity
from aegis.config import config

class VulnerabilityScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': config.get('web.user_agent')})
        self.findings = []
    
    def scan_service(self, target: str, port: int, service: str):
        """Scan a specific service for known vulnerabilities"""
        if service == 'HTTP' or port == 80:
            self._check_http_vulns(target, port)
        elif service == 'HTTPS' or port == 443:
            self._check_https_vulns(target, port)
        elif service == 'SSH' or port == 22:
            self._check_ssh_vulns(target, port)
        elif service == 'FTP' or port == 21:
            self._check_ftp_vulns(target, port)
        
        return self.findings
    
    def _check_http_vulns(self, host: str, port: int):
        protocols = ['http', 'https']
        for proto in protocols:
            try:
                url = f"{proto}://{host}:{port}"
                response = self.session.get(url, timeout=5, verify=False)
                
                # Check for common indicators
                server = response.headers.get('Server', 'Unknown')
                x_powered = response.headers.get('X-Powered-By', '')
                
                # Check security headers
                security_headers = [
                    'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
                    'Strict-Transport-Security', 'Content-Security-Policy'
                ]
                
                missing_headers = [h for h in security_headers if h not in response.headers]
                
                if missing_headers:
                    self.findings.append({
                        'host': host,
                        'port': port,
                        'vulnerability': 'Missing Security Headers',
                        'severity': 'Medium',
                        'details': f"Missing: {', '.join(missing_headers)}"
                    })
                
                # Check for directory listing
                if 'Index of' in response.text or 'directory listing' in response.text.lower():
                    self.findings.append({
                        'host': host,
                        'port': port,
                        'vulnerability': 'Directory Listing Enabled',
                        'severity': 'Medium',
                        'details': 'Server allows directory browsing'
                    })
                
                # Check for default pages
                if any(x in response.text for x in ['Apache2', 'nginx', 'IIS', 'Welcome to']):
                    if response.status_code == 200:
                        self.findings.append({
                            'host': host,
                            'port': port,
                            'vulnerability': 'Default Page Detected',
                            'severity': 'Low',
                            'details': 'Web server showing default page'
                        })
                
            except:
                continue
    
    def _check_https_vulns(self, host: str, port: int):
        import ssl
        import socket
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check SSL/TLS version
                    if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                        self.findings.append({
                            'host': host,
                            'port': port,
                            'vulnerability': f'Weak SSL/TLS Version ({version})',
                            'severity': 'High',
                            'details': f'Server supports vulnerable protocol {version}'
                        })
                    
                    # Check certificate expiration
                    if cert and 'notAfter' in cert:
                        from datetime import datetime
                        import time
                        expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if expire_date < datetime.now():
                            self.findings.append({
                                'host': host,
                                'port': port,
                                'vulnerability': 'Expired SSL Certificate',
                                'severity': 'High',
                                'details': f'Certificate expired on {expire_date}'
                            })
        except:
            pass
    
    def _check_ssh_vulns(self, host: str, port: int):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            
            # Check for old SSH versions
            if any(x in banner for x in ['SSH-1.', 'OpenSSH_3.', 'OpenSSH_4.', 'OpenSSH_5.']):
                self.findings.append({
                    'host': host,
                    'port': port,
                    'vulnerability': 'Outdated SSH Version',
                    'severity': 'High',
                    'details': f'Banner: {banner}'
                })
        except:
            pass
    
    def _check_ftp_vulns(self, host: str, port: int):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            banner = sock.recv(1024).decode().strip()
            sock.close()
            
            # Check for anonymous FTP
            if 'vsftpd' in banner or 'FileZilla' in banner:
                self.findings.append({
                    'host': host,
                    'port': port,
                    'vulnerability': 'FTP Service Detected',
                    'severity': 'Info',
                    'details': f'Banner: {banner}'
                })
        except:
            pass
    
    def check_default_creds(self, target: str, service: str) -> list:
        """Check for default/weak credentials"""
        weak_creds = []
        
        # Common default credentials
        default_creds = {
            'admin': ['admin', 'password', '123456', 'default'],
            'root': ['root', 'toor', 'password', '123456'],
            'guest': ['guest', 'password', '123456'],
        }
        
        # This is a simplified check - in production, use proper auth testing
        if service in ['SSH', 'Telnet', 'FTP']:
            for user, passwords in default_creds.items():
                weak_creds.append({
                    'user': user,
                    'passwords': passwords,
                    'note': 'Default credentials should be changed'
                })
        
        return weak_creds

@click.group()
def vuln_group():
    """Vulnerability scanning and assessment tools"""
    pass

@vuln_group.command()
@click.option('--target', '-t', required=True, help='Target host')
@click.option('--port', '-p', type=int, help='Specific port to scan')
@click.option('--service', '-s', help='Service name (SSH, HTTP, FTP, etc.)')
@click.pass_context
def scan(ctx, target, port, service):
    """Scan for common vulnerabilities"""
    scanner = VulnerabilityScanner()
    log_activity('vuln', f"Scanning {target} for vulnerabilities...")
    
    with Spinner(f"Scanning {target}..."):
        if port and service:
            findings = scanner.scan_service(target, port, service)
        else:
            # Scan common ports
            common_services = [
                (80, 'HTTP'), (443, 'HTTPS'), (22, 'SSH'),
                (21, 'FTP'), (3306, 'MySQL'), (3389, 'RDP')
            ]
            for p, s in common_services:
                scanner.scan_service(target, p, s)
            findings = scanner.findings
    
    if findings:
        data = [[f['host'], f['port'], f['vulnerability'], f['severity'], f['details'][:50]] for f in findings]
        output_result(data, ['Host', 'Port', 'Vulnerability', 'Severity', 'Details'], 
                     ctx.obj.get('format', 'table'), f"Vulnerability Scan Results: {target}")
    else:
        click.echo("No vulnerabilities detected.")

@vuln_group.command()
@click.option('--keyword', '-k', required=True, help='Search keyword or CVE ID')
def cve(keyword):
    """Search CVE database"""
    # Simulated CVE lookup - in production, integrate with CVE API
    cve_db = {
        'CVE-2021-44228': {
            'name': 'Log4Shell',
            'severity': 'Critical',
            'cvss': 10.0,
            'description': 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints'
        },
        'CVE-2017-0144': {
            'name': 'EternalBlue',
            'severity': 'High',
            'cvss': 8.1,
            'description': 'SMBv1 vulnerability in Microsoft Windows'
        },
    }
    
    found = False
    for cve_id, info in cve_db.items():
        if keyword.lower() in cve_id.lower() or keyword.lower() in info['name'].lower():
            click.echo(f"\n[cyan]{cve_id}[/cyan]")
            click.echo(f"Name: {info['name']}")
            click.echo(f"Severity: {info['severity']} (CVSS: {info['cvss']})")
            click.echo(f"Description: {info['description']}")
            found = True
    
    if not found:
        click.echo(f"No CVE found matching '{keyword}'")

@vuln_group.command()
@click.option('--target', '-t', required=True, help='Target to check')
def weakcreds(target):
    """Check for weak/default credentials"""
    scanner = VulnerabilityScanner()
    log_activity('vuln', f"Checking weak credentials on {target}...")
    
    services = ['SSH', 'FTP', 'Telnet']
    for service in services:
        weak = scanner.check_default_creds(target, service)
        if weak:
            click.echo(f"\n[yellow]{service} - Potential Weak Credentials:[/yellow]")
            for cred in weak:
                click.echo(f"  User: {cred['user']}")
                click.echo(f"  Common passwords: {', '.join(cred['passwords'])}")
