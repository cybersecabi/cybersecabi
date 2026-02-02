import click
import requests
import urllib3
from urllib.parse import urlparse, urljoin
import ssl
import socket
from datetime import datetime
from aegis.core import output_result, Spinner, log_activity
from aegis.config import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config.get('web.user_agent', 'Aegis-Security-Scanner/1.0')
        })
        self.session.verify = config.get('web.ssl_verify', False)
        self.session.timeout = config.get('timeout', 30)
        self.findings = []
    
    def analyze_url(self, url: str):
        """Comprehensive web security analysis"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        parsed = urlparse(url)
        
        # Check SSL/TLS if HTTPS
        if parsed.scheme == 'https':
            self._analyze_ssl(parsed.hostname, parsed.port or 443)
        
        # Check HTTP security
        self._analyze_http(url)
        
        # Check for common files
        self._check_common_files(url)
        
        # Check security headers
        self._check_headers(url)
        
        return self.findings
    
    def _analyze_ssl(self, hostname: str, port: int):
        """Analyze SSL/TLS configuration"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # SSL Version check
                    if version in ['TLSv1', 'TLSv1.1']:
                        self.findings.append({
                            'type': 'SSL/TLS',
                            'issue': f'Weak protocol: {version}',
                            'severity': 'High',
                            'details': 'Upgrade to TLS 1.2 or higher'
                        })
                    elif version == 'TLSv1.2':
                        self.findings.append({
                            'type': 'SSL/TLS',
                            'issue': f'Protocol: {version}',
                            'severity': 'Info',
                            'details': 'TLS 1.2 is acceptable but 1.3 is recommended'
                        })
                    else:
                        self.findings.append({
                            'type': 'SSL/TLS',
                            'issue': f'Protocol: {version}',
                            'severity': 'Good',
                            'details': 'Using latest TLS version'
                        })
                    
                    # Certificate check
                    if cert:
                        not_after = cert.get('notAfter')
                        if not_after:
                            expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            days_left = (expire_date - datetime.now()).days
                            
                            if days_left < 0:
                                self.findings.append({
                                    'type': 'SSL/TLS',
                                    'issue': 'Expired Certificate',
                                    'severity': 'Critical',
                                    'details': f'Expired {abs(days_left)} days ago'
                                })
                            elif days_left < 30:
                                self.findings.append({
                                    'type': 'SSL/TLS',
                                    'issue': 'Certificate Expiring Soon',
                                    'severity': 'Warning',
                                    'details': f'Expires in {days_left} days'
                                })
                        
                        # Check certificate subject
                        subject = cert.get('subject')
                        issuer = cert.get('issuer')
                        
                        self.findings.append({
                            'type': 'SSL/TLS',
                            'issue': 'Certificate Info',
                            'severity': 'Info',
                            'details': f'Subject: {subject}, Issuer: {issuer}'
                        })
                    
                    # Cipher check
                    self.findings.append({
                        'type': 'SSL/TLS',
                        'issue': 'Cipher Suite',
                        'severity': 'Info',
                        'details': f'{cipher[0]} ({cipher[2]} bits)'
                    })
                    
        except ssl.SSLError as e:
            self.findings.append({
                'type': 'SSL/TLS',
                'issue': 'SSL Error',
                'severity': 'High',
                'details': str(e)
            })
        except Exception as e:
            self.findings.append({
                'type': 'SSL/TLS',
                'issue': 'Connection Failed',
                'severity': 'Error',
                'details': str(e)
            })
    
    def _analyze_http(self, url: str):
        """Analyze HTTP response and configuration"""
        try:
            response = self.session.get(url, allow_redirects=True)
            
            # Check response status
            self.findings.append({
                'type': 'HTTP',
                'issue': 'Response Status',
                'severity': 'Info',
                'details': f'{response.status_code}'
            })
            
            # Check server header
            server = response.headers.get('Server', 'Not disclosed')
            self.findings.append({
                'type': 'HTTP',
                'issue': 'Server Software',
                'severity': 'Info',
                'details': server
            })
            
            # Check for exposed information
            powered_by = response.headers.get('X-Powered-By')
            if powered_by:
                self.findings.append({
                    'type': 'HTTP',
                    'issue': 'Technology Disclosure',
                    'severity': 'Low',
                    'details': f'X-Powered-By: {powered_by}'
                })
            
            # Check for redirects
            if len(response.history) > 0:
                redirect_chain = ' -> '.join([str(r.status_code) for r in response.history])
                self.findings.append({
                    'type': 'HTTP',
                    'issue': 'Redirect Chain',
                    'severity': 'Info',
                    'details': f'{redirect_chain} -> {response.status_code}'
                })
            
        except requests.exceptions.RequestException as e:
            self.findings.append({
                'type': 'HTTP',
                'issue': 'Request Failed',
                'severity': 'Error',
                'details': str(e)
            })
    
    def _check_common_files(self, base_url: str):
        """Check for common sensitive files"""
        common_files = [
            'robots.txt', '.git/config', '.env', 'config.php',
            '.htaccess', 'phpinfo.php', 'admin/', 'backup/',
            'wp-admin/', 'wp-config.php', 'phpmyadmin/',
            'admin.php', 'login.php', 'api/', '.svn/entries'
        ]
        
        found_files = []
        for file_path in common_files:
            try:
                url = urljoin(base_url, file_path)
                response = self.session.get(url, timeout=5)
                
                if response.status_code == 200:
                    found_files.append(file_path)
                    self.findings.append({
                        'type': 'Discovery',
                        'issue': f'Exposed: {file_path}',
                        'severity': 'Medium',
                        'details': f'Found at {url}'
                    })
            except:
                pass
    
    def _check_headers(self, url: str):
        """Check security headers"""
        try:
            response = self.session.get(url, timeout=10)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': 'HSTS - Forces HTTPS',
                'Content-Security-Policy': 'CSP - Prevents XSS and injection',
                'X-Frame-Options': 'Clickjacking protection',
                'X-Content-Type-Options': 'MIME-sniffing protection',
                'X-XSS-Protection': 'XSS filter (legacy)',
                'Referrer-Policy': 'Controls referrer information',
                'Permissions-Policy': 'Controls browser features'
            }
            
            for header, description in security_headers.items():
                if header in headers:
                    self.findings.append({
                        'type': 'Headers',
                        'issue': f'{header} Present',
                        'severity': 'Good',
                        'details': f'{description}: {headers[header]}'
                    })
                else:
                    self.findings.append({
                        'type': 'Headers',
                        'issue': f'{header} Missing',
                        'severity': 'Medium',
                        'details': description
                    })
        except:
            pass

@click.group()
def web_group():
    """Web security analysis and testing tools"""
    pass

@web_group.command()
@click.option('--url', '-u', required=True, help='Target URL to analyze')
@click.pass_context
def analyze(ctx, url):
    """Comprehensive web security analysis"""
    scanner = WebScanner()
    log_activity('web', f"Analyzing {url}...")
    
    with Spinner(f"Analyzing {url}..."):
        findings = scanner.analyze_url(url)
    
    if findings:
        data = [[f['type'], f['issue'], f['severity'], f['details'][:40]] for f in findings]
        output_result(data, ['Type', 'Issue', 'Severity', 'Details'], 
                     ctx.obj.get('format', 'table'), f"Web Security Analysis: {url}")
    else:
        click.echo("No findings.")

@web_group.command()
@click.option('--url', '-u', required=True, help='Target URL')
def headers(url):
    """Analyze HTTP security headers"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        
        click.echo(f"\n[cyan]Security Headers for {url}:[/cyan]\n")
        
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy',
            'Cache-Control',
            'Pragma'
        ]
        
        for header in security_headers:
            value = response.headers.get(header)
            if value:
                click.echo(f"[green]✓ {header}:[/green] {value}")
            else:
                click.echo(f"[red]✗ {header}:[/red] Not present")
        
        click.echo(f"\n[yellow]Server:[/yellow] {response.headers.get('Server', 'Not disclosed')}")
        
    except Exception as e:
        click.echo(f"Error: {e}")

@web_group.command()
@click.option('--url', '-u', required=True, help='Target URL')
def ssl(url):
    """Detailed SSL/TLS analysis"""
    if not url.startswith('https://'):
        click.echo("Error: URL must use HTTPS for SSL analysis")
        return
    
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 443
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                click.echo(f"\n[cyan]SSL/TLS Analysis for {hostname}:{port}[/cyan]\n")
                click.echo(f"Protocol Version: {version}")
                click.echo(f"Cipher Suite: {cipher[0]}")
                click.echo(f"Key Size: {cipher[2]} bits")
                
                if cert:
                    click.echo(f"\nCertificate Details:")
                    for key, value in cert.items():
                        click.echo(f"  {key}: {value}")
    except Exception as e:
        click.echo(f"SSL Error: {e}")

@web_group.command()
@click.option('--url', '-u', required=True, help='Target URL')
def crawl(url):
    """Crawl website and discover links"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        from bs4 import BeautifulSoup
        
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        
        # Filter and deduplicate
        internal = []
        external = []
        
        for link in links:
            if link.startswith('/'):
                internal.append(link)
            elif link.startswith('http'):
                if url in link:
                    internal.append(link)
                else:
                    external.append(link)
        
        click.echo(f"\n[cyan]Discovered Links on {url}:[/cyan]")
        click.echo(f"\nInternal ({len(set(internal))}):")
        for link in sorted(set(internal))[:10]:
            click.echo(f"  {link}")
        
        click.echo(f"\nExternal ({len(set(external))}):")
        for link in sorted(set(external))[:10]:
            click.echo(f"  {link}")
            
    except Exception as e:
        click.echo(f"Error: {e}")
