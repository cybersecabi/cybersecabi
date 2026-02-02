import click
import re
import json
import gzip
from pathlib import Path
from datetime import datetime
from collections import Counter
from aegis.core import output_result, Spinner, log_activity

class LogAnalyzer:
    COMMON_PATTERNS = {
        'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'url': r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        'error': r'(ERROR|FATAL|CRITICAL|EXCEPTION)',
        'warning': r'(WARNING|WARN)',
    }
    
    def __init__(self):
        self.iocs = {
            'suspicious_ips': [],
            'failed_logins': [],
            'sql_injection': [],
            'xss_attempts': [],
            'directory_traversal': []
        }
    
    def analyze_log(self, filepath: str, log_type: str = 'auto'):
        """Analyze log file for security events"""
        findings = []
        
        # Read log file
        content = self._read_log_file(filepath)
        lines = content.split('\n')
        
        # Auto-detect log type if not specified
        if log_type == 'auto':
            log_type = self._detect_log_type(lines[:10])
        
        # Analyze based on log type
        if log_type == 'apache' or log_type == 'nginx':
            findings.extend(self._analyze_web_log(lines))
        elif log_type == 'auth' or log_type == 'syslog':
            findings.extend(self._analyze_auth_log(lines))
        elif log_type == 'application':
            findings.extend(self._analyze_application_log(lines))
        else:
            findings.extend(self._analyze_generic_log(lines))
        
        return findings, log_type
    
    def _read_log_file(self, filepath: str) -> str:
        """Read log file (handles gzip)"""
        path = Path(filepath)
        
        if path.suffix == '.gz':
            with gzip.open(path, 'rt', encoding='utf-8', errors='ignore') as f:
                return f.read()
        else:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
    
    def _detect_log_type(self, sample_lines: list) -> str:
        """Auto-detect log type from sample lines"""
        sample = ' '.join(sample_lines).lower()
        
        if any(x in sample for x in ['apache', 'nginx', 'get /', 'post /']):
            return 'apache'
        elif any(x in sample for x in ['sshd', 'authentication', 'login', 'pam']):
            return 'auth'
        elif any(x in sample for x in ['error', 'exception', 'debug', 'info']):
            return 'application'
        else:
            return 'generic'
    
    def _analyze_web_log(self, lines: list) -> list:
        """Analyze web server logs"""
        findings = []
        
        suspicious_patterns = [
            (r'(union|select|insert|update|delete|drop|create).*from', 'SQL Injection Attempt'),
            (r'<script.*>', 'XSS Attempt'),
            (r'\.\./\.\./', 'Directory Traversal'),
            (r'etc/passwd', 'File Access Attempt'),
            (r'cmd\.exe', 'Windows Command Execution'),
            (r'phpinfo', 'Information Disclosure'),
            (r'admin|administrator|login|wp-admin', 'Admin Panel Access'),
        ]
        
        for line_num, line in enumerate(lines, 1):
            for pattern, description in suspicious_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        'line': line_num,
                        'type': 'Suspicious Activity',
                        'description': description,
                        'details': line[:100]
                    })
        
        # Count status codes
        status_codes = re.findall(r'\s(\d{3})\s', ' '.join(lines))
        error_codes = [c for c in status_codes if c.startswith('4') or c.startswith('5')]
        
        if error_codes:
            counter = Counter(error_codes)
            for code, count in counter.most_common(5):
                findings.append({
                    'line': '-',
                    'type': 'Status Code Analysis',
                    'description': f'HTTP {code}',
                    'details': f'{count} occurrences'
                })
        
        return findings
    
    def _analyze_auth_log(self, lines: list) -> list:
        """Analyze authentication logs"""
        findings = []
        failed_attempts = {}
        
        for line_num, line in enumerate(lines, 1):
            # Failed login attempts
            if 'failed' in line.lower() or 'authentication failure' in line.lower():
                ip_match = re.search(self.COMMON_PATTERNS['ip'], line)
                if ip_match:
                    ip = ip_match.group()
                    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
                
                findings.append({
                    'line': line_num,
                    'type': 'Failed Login',
                    'description': 'Authentication failure',
                    'details': line[:100]
                })
            
            # Successful logins
            if 'accepted' in line.lower() or 'session opened' in line.lower():
                findings.append({
                    'line': line_num,
                    'type': 'Successful Login',
                    'description': 'Authentication success',
                    'details': line[:100]
                })
            
            # Privilege escalation
            if 'sudo' in line.lower() and 'command' in line.lower():
                findings.append({
                    'line': line_num,
                    'type': 'Sudo Usage',
                    'description': 'Privilege escalation',
                    'details': line[:100]
                })
        
        # Report brute force attempts
        for ip, count in failed_attempts.items():
            if count > 5:
                findings.append({
                    'line': '-',
                    'type': 'Brute Force',
                    'description': f'Multiple failed logins from {ip}',
                    'details': f'{count} attempts'
                })
        
        return findings
    
    def _analyze_application_log(self, lines: list) -> list:
        """Analyze application logs"""
        findings = []
        
        for line_num, line in enumerate(lines, 1):
            # Errors
            if re.search(self.COMMON_PATTERNS['error'], line, re.IGNORECASE):
                findings.append({
                    'line': line_num,
                    'type': 'Error',
                    'description': 'Application error',
                    'details': line[:100]
                })
            
            # Warnings
            elif re.search(self.COMMON_PATTERNS['warning'], line, re.IGNORECASE):
                findings.append({
                    'line': line_num,
                    'type': 'Warning',
                    'description': 'Application warning',
                    'details': line[:100]
                })
            
            # Stack traces
            if 'at ' in line and ('Exception' in line or 'Error' in line):
                findings.append({
                    'line': line_num,
                    'type': 'Stack Trace',
                    'description': 'Exception details',
                    'details': line[:100]
                })
        
        return findings
    
    def _analyze_generic_log(self, lines: list) -> list:
        """Generic log analysis"""
        findings = []
        
        # Extract all IPs
        all_ips = []
        for line_num, line in enumerate(lines, 1):
            ips = re.findall(self.COMMON_PATTERNS['ip'], line)
            all_ips.extend(ips)
            
            # Look for suspicious keywords
            suspicious = ['error', 'fail', 'denied', 'unauthorized', 'attack', 'intrusion']
            for word in suspicious:
                if word in line.lower():
                    findings.append({
                        'line': line_num,
                        'type': 'Suspicious',
                        'description': f'Contains: {word}',
                        'details': line[:100]
                    })
        
        # Report top IPs
        if all_ips:
            ip_counter = Counter(all_ips)
            for ip, count in ip_counter.most_common(5):
                findings.append({
                    'line': '-',
                    'type': 'IP Analysis',
                    'description': f'Frequent IP: {ip}',
                    'details': f'{count} occurrences'
                })
        
        return findings

@click.group()
def analyze_group():
    """Log analysis and IOC detection tools"""
    pass

@analyze_group.command()
@click.option('--file', '-f', required=True, help='Log file to analyze', type=click.Path(exists=True))
@click.option('--type', '-t', 'log_type', default='auto', 
              type=click.Choice(['auto', 'apache', 'nginx', 'auth', 'syslog', 'application']),
              help='Log type')
@click.pass_context
def log(ctx, file, log_type):
    """Analyze log files for security events"""
    analyzer = LogAnalyzer()
    log_activity('analyze', f"Analyzing log file: {file}")
    
    with Spinner(f"Analyzing {file}..."):
        findings, detected_type = analyzer.analyze_log(file, log_type)
    
    if findings:
        data = [[f['line'], f['type'], f['description'], f['details']] for f in findings]
        output_result(data, ['Line', 'Type', 'Description', 'Details'],
                     ctx.obj.get('format', 'table'), 
                     f"Log Analysis Results ({detected_type})")
    else:
        click.echo("No security events found in log.")

@analyze_group.command()
@click.option('--file', '-f', required=True, help='Log file', type=click.Path(exists=True))
def stats(file):
    """Show log statistics"""
    analyzer = LogAnalyzer()
    
    with Spinner("Analyzing..."):
        content = analyzer._read_log_file(file)
        lines = content.split('\n')
        
        # Calculate stats
        total_lines = len(lines)
        total_size = len(content)
        
        # Extract IPs
        ips = re.findall(analyzer.COMMON_PATTERNS['ip'], content)
        unique_ips = len(set(ips))
        
        # Extract emails
        emails = re.findall(analyzer.COMMON_PATTERNS['email'], content)
        
        # Count errors
        errors = len(re.findall(r'ERROR|FATAL|CRITICAL', content, re.IGNORECASE))
        warnings = len(re.findall(r'WARNING|WARN', content, re.IGNORECASE))
    
    click.echo(f"\n[cyan]Log Statistics for {file}:[/cyan]")
    click.echo(f"  Total lines: {total_lines}")
    click.echo(f"  File size: {total_size:,} bytes")
    click.echo(f"  Unique IPs: {unique_ips}")
    click.echo(f"  Email addresses found: {len(emails)}")
    click.echo(f"  Error entries: {errors}")
    click.echo(f"  Warning entries: {warnings}")
    
    if ips:
        click.echo(f"\n[yellow]Top 5 IP Addresses:[/yellow]")
        counter = Counter(ips)
        for ip, count in counter.most_common(5):
            click.echo(f"  {ip}: {count} occurrences")

@analyze_group.command()
@click.option('--file', '-f', required=True, help='Log file', type=click.Path(exists=True))
def extract(file):
    """Extract IOCs (Indicators of Compromise) from logs"""
    analyzer = LogAnalyzer()
    
    with Spinner("Extracting IOCs..."):
        content = analyzer._read_log_file(file)
        
        ips = list(set(re.findall(analyzer.COMMON_PATTERNS['ip'], content)))
        emails = list(set(re.findall(analyzer.COMMON_PATTERNS['email'], content)))
        urls = list(set(re.findall(analyzer.COMMON_PATTERNS['url'], content)))
    
    click.echo(f"\n[cyan]Extracted IOCs:[/cyan]")
    
    if ips:
        click.echo(f"\nIP Addresses ({len(ips)}):")
        for ip in ips[:20]:
            click.echo(f"  {ip}")
    
    if emails:
        click.echo(f"\nEmail Addresses ({len(emails)}):")
        for email in emails[:10]:
            click.echo(f"  {email}")
    
    if urls:
        click.echo(f"\nURLs ({len(urls)}):")
        for url in urls[:10]:
            click.echo(f"  {url}")
