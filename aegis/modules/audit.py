import click
import os
import platform
import subprocess
import json
from pathlib import Path
from aegis.core import output_result, Spinner, log_activity
from aegis.config import config

class SystemAuditor:
    def __init__(self):
        self.os_type = platform.system().lower()
        self.findings = []
    
    def audit_system(self):
        """Run full system audit"""
        self.check_ssh_config()
        self.check_password_policy()
        self.check_firewall()
        self.check_updates()
        self.check_sudo_config()
        self.check_file_permissions()
        self.check_services()
        return self.findings
    
    def check_ssh_config(self):
        """Check SSH configuration security"""
        ssh_config_paths = ['/etc/ssh/sshd_config', '/etc/sshd_config']
        
        for config_path in ssh_config_paths:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    content = f.read()
                
                # Check for root login
                if 'PermitRootLogin yes' in content or 'PermitRootLogin without-password' in content:
                    self.findings.append({
                        'category': 'SSH',
                        'check': 'Root Login',
                        'status': 'Warning',
                        'recommendation': 'Set PermitRootLogin to no'
                    })
                
                # Check for password authentication
                if 'PasswordAuthentication yes' in content:
                    self.findings.append({
                        'category': 'SSH',
                        'check': 'Password Auth',
                        'status': 'Warning',
                        'recommendation': 'Use key-based authentication'
                    })
                
                # Check for protocol version
                if 'Protocol 1' in content:
                    self.findings.append({
                        'category': 'SSH',
                        'check': 'Protocol Version',
                        'status': 'Critical',
                        'recommendation': 'Use Protocol 2 only'
                    })
    
    def check_password_policy(self):
        """Check password policy configuration"""
        if self.os_type == 'linux':
            # Check /etc/login.defs
            if os.path.exists('/etc/login.defs'):
                with open('/etc/login.defs', 'r') as f:
                    content = f.read()
                
                if 'PASS_MAX_DAYS' in content:
                    lines = [l for l in content.split('\n') if 'PASS_MAX_DAYS' in l and not l.startswith('#')]
                    if lines:
                        days = lines[0].split()[-1]
                        if days == '99999':
                            self.findings.append({
                                'category': 'Password Policy',
                                'check': 'Max Password Age',
                                'status': 'Warning',
                                'recommendation': 'Set PASS_MAX_DAYS to 90 or less'
                            })
            
            # Check PAM configuration
            if os.path.exists('/etc/pam.d/common-password'):
                with open('/etc/pam.d/common-password', 'r') as f:
                    content = f.read()
                
                if 'pam_cracklib.so' not in content and 'pam_pwquality.so' not in content:
                    self.findings.append({
                        'category': 'Password Policy',
                        'check': 'Password Complexity',
                        'status': 'Warning',
                        'recommendation': 'Enable password complexity requirements'
                    })
    
    def check_firewall(self):
        """Check firewall status"""
        if self.os_type == 'linux':
            # Check ufw
            try:
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=5)
                if 'inactive' in result.stdout.lower():
                    self.findings.append({
                        'category': 'Firewall',
                        'check': 'UFW Status',
                        'status': 'Warning',
                        'recommendation': 'Enable UFW firewall'
                    })
            except:
                pass
            
            # Check iptables
            try:
                result = subprocess.run(['iptables', '-L'], capture_output=True, text=True, timeout=5)
                if 'Chain INPUT' in result.stdout and len(result.stdout.split('\n')) < 10:
                    self.findings.append({
                        'category': 'Firewall',
                        'check': 'IPTables Rules',
                        'status': 'Warning',
                        'recommendation': 'Configure iptables rules'
                    })
            except:
                pass
    
    def check_updates(self):
        """Check for available updates"""
        if self.os_type == 'linux':
            try:
                # Check apt
                if os.path.exists('/usr/bin/apt'):
                    result = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True, timeout=10)
                    updates = [l for l in result.stdout.split('\n') if 'upgradable' in l]
                    if len(updates) > 0:
                        self.findings.append({
                            'category': 'Updates',
                            'check': 'Pending Updates',
                            'status': 'Info',
                            'recommendation': f'{len(updates)} packages need updating'
                        })
            except:
                pass
    
    def check_sudo_config(self):
        """Check sudo configuration"""
        if os.path.exists('/etc/sudoers'):
            with open('/etc/sudoers', 'r') as f:
                content = f.read()
            
            # Check for NOPASSWD
            if 'NOPASSWD' in content:
                self.findings.append({
                    'category': 'Sudo',
                    'check': 'NOPASSWD',
                    'status': 'Warning',
                    'recommendation': 'Avoid NOPASSWD in sudoers'
                })
    
    def check_file_permissions(self):
        """Check critical file permissions"""
        critical_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
        ]
        
        for file_path in critical_files:
            if os.path.exists(file_path):
                stat = os.stat(file_path)
                mode = oct(stat.st_mode)[-3:]
                
                if file_path == '/etc/shadow' and mode != '000':
                    self.findings.append({
                        'category': 'Permissions',
                        'check': f'{file_path}',
                        'status': 'Warning',
                        'recommendation': f'Current: {mode}, Should be: 000'
                    })
    
    def check_services(self):
        """Check for unnecessary services"""
        unnecessary = ['telnet', 'ftp', 'rsh', 'rlogin', 'rexec']
        
        for service in unnecessary:
            try:
                result = subprocess.run(['systemctl', 'is-active', service], 
                                      capture_output=True, text=True, timeout=5)
                if 'active' in result.stdout:
                    self.findings.append({
                        'category': 'Services',
                        'check': service,
                        'status': 'Critical',
                        'recommendation': f'Disable {service} service'
                    })
            except:
                pass

@click.group()
def audit_group():
    """System security auditing and hardening checks"""
    pass

@audit_group.command()
@click.pass_context
def system(ctx):
    """Perform comprehensive system audit"""
    auditor = SystemAuditor()
    log_activity('audit', "Starting system security audit...")
    
    with Spinner("Auditing system..."):
        findings = auditor.audit_system()
    
    if findings:
        data = [[f['category'], f['check'], f['status'], f['recommendation']] for f in findings]
        output_result(data, ['Category', 'Check', 'Status', 'Recommendation'], 
                     ctx.obj.get('format', 'table'), "System Security Audit Results")
    else:
        click.echo("No issues found. System appears secure.")

@audit_group.command()
def compliance():
    """Check compliance with security standards (CIS)"""
    log_activity('audit', "Checking CIS compliance...")
    
    cis_checks = [
        {'id': '1.1.1', 'description': 'Ensure mounting of cramfs is disabled', 'status': 'Check manually'},
        {'id': '1.1.2', 'description': 'Ensure mounting of freevxfs is disabled', 'status': 'Check manually'},
        {'id': '1.3.1', 'description': 'Ensure AIDE is installed', 'status': 'Check manually'},
        {'id': '1.4.1', 'description': 'Ensure permissions on bootloader config', 'status': 'Check manually'},
        {'id': '2.1.1', 'description': 'Ensure xinetd is not installed', 'status': 'Check manually'},
    ]
    
    click.echo("\n[cyan]CIS Benchmark Compliance Checklist:[/cyan]")
    for check in cis_checks:
        click.echo(f"  {check['id']}: {check['description']} - {check['status']}")

@audit_group.command()
@click.option('--service', '-s', required=True, help='Service to harden (ssh, nginx, apache)')
def harden(service):
    """Generate hardening recommendations for services"""
    recommendations = {
        'ssh': [
            'Set PermitRootLogin no',
            'Set PasswordAuthentication no',
            'Use key-based authentication',
            'Change default port (22)',
            'Enable fail2ban',
            'Use Protocol 2',
            'Set MaxAuthTries 3',
        ],
        'nginx': [
            'Hide server_tokens',
            'Enable SSL/TLS',
            'Use strong SSL configuration',
            'Enable HSTS',
            'Set client timeouts',
            'Limit request size',
        ],
        'apache': [
            'Hide ServerSignature',
            'Hide ServerTokens',
            'Disable directory listing',
            'Enable mod_security',
            'Use SSL/TLS',
            'Set proper file permissions',
        ]
    }
    
    if service.lower() in recommendations:
        click.echo(f"\n[cyan]{service.upper()} Hardening Recommendations:[/cyan]")
        for i, rec in enumerate(recommendations[service.lower()], 1):
            click.echo(f"  {i}. {rec}")
    else:
        click.echo(f"No recommendations available for {service}")
