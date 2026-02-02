import click
import time
import hashlib
from pathlib import Path
from datetime import datetime
from aegis.core import Spinner, log_activity
from aegis.config import config

class FileWatcher:
    def __init__(self, watch_path: str, recursive: bool = False):
        self.watch_path = Path(watch_path)
        self.recursive = recursive
        self.file_states = {}
        self.running = False
    
    def _calculate_hash(self, filepath: Path) -> str:
        """Calculate MD5 hash of file"""
        try:
            hash_obj = hashlib.md5()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except:
            return ""
    
    def _get_file_info(self, filepath: Path) -> dict:
        """Get file information"""
        stat = filepath.stat()
        return {
            'path': str(filepath),
            'size': stat.st_size,
            'mtime': stat.st_mtime,
            'hash': self._calculate_hash(filepath)
        }
    
    def _scan_files(self) -> dict:
        """Scan files in watch directory"""
        files = {}
        
        if self.recursive:
            for filepath in self.watch_path.rglob('*'):
                if filepath.is_file():
                    files[str(filepath)] = self._get_file_info(filepath)
        else:
            for filepath in self.watch_path.iterdir():
                if filepath.is_file():
                    files[str(filepath)] = self._get_file_info(filepath)
        
        return files
    
    def start(self, interval: int = 5, alert_threshold: int = 3):
        """Start watching files"""
        click.echo(f"[cyan]Starting file watcher on: {self.watch_path}[/cyan]")
        click.echo(f"[dim]Monitoring {'recursively ' if self.recursive else ''}every {interval} seconds...[/dim]")
        click.echo("[yellow]Press Ctrl+C to stop[/yellow]\n")
        
        # Initial scan
        self.file_states = self._scan_files()
        click.echo(f"Initial scan complete. Monitoring {len(self.file_states)} files.")
        
        self.running = True
        try:
            while self.running:
                time.sleep(interval)
                current_states = self._scan_files()
                
                # Check for changes
                self._detect_changes(current_states)
                
                # Update state
                self.file_states = current_states
                
        except KeyboardInterrupt:
            self.running = False
            click.echo("\n[green]File watcher stopped.[/green]")
    
    def _detect_changes(self, current_states: dict):
        """Detect file changes"""
        # Check for new files
        for path, info in current_states.items():
            if path not in self.file_states:
                click.echo(f"[green]+ New file: {Path(path).name} ({info['size']} bytes)[/green]")
        
        # Check for deleted files
        for path in self.file_states:
            if path not in current_states:
                click.echo(f"[red]- Deleted: {Path(path).name}[/red]")
        
        # Check for modified files
        for path, info in current_states.items():
            if path in self.file_states:
                old_info = self.file_states[path]
                if info['mtime'] != old_info['mtime']:
                    if info['hash'] != old_info['hash']:
                        click.echo(f"[yellow]~ Modified: {Path(path).name} ({info['size']} bytes)[/yellow]")

class SystemMonitor:
    def __init__(self):
        self.running = False
    
    def monitor_resources(self, interval: int = 5):
        """Monitor system resources"""
        try:
            import psutil
        except ImportError:
            click.echo("[red]psutil not installed. Install with: pip install psutil[/red]")
            return
        
        click.echo(f"[cyan]System Resource Monitor[/cyan]")
        click.echo(f"[dim]Updating every {interval} seconds...[/dim]")
        click.echo("[yellow]Press Ctrl+C to stop[/yellow]\n")
        
        self.running = True
        try:
            while self.running:
                # CPU
                cpu_percent = psutil.cpu_percent(interval=1)
                
                # Memory
                memory = psutil.virtual_memory()
                
                # Disk
                disk = psutil.disk_usage('/')
                
                # Network
                net_io = psutil.net_io_counters()
                
                # Display
                click.echo(f"CPU: {cpu_percent:5.1f}% | "
                          f"RAM: {memory.percent:5.1f}% | "
                          f"Disk: {disk.percent:5.1f}% | "
                          f"Net: ↑{self._format_bytes(net_io.bytes_sent)} ↓{self._format_bytes(net_io.bytes_recv)}")
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.running = False
            click.echo("\n[green]Monitor stopped.[/green]")
    
    def _format_bytes(self, bytes_val: int) -> str:
        """Format bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f}{unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f}TB"

@click.group()
def watch_group():
    """Real-time file and system monitoring"""
    pass

@watch_group.command()
@click.option('--path', '-p', required=True, help='Directory to watch')
@click.option('--recursive', '-r', is_flag=True, help='Watch recursively')
@click.option('--interval', '-i', default=5, help='Check interval in seconds')
def files(path, recursive, interval):
    """Monitor files for changes"""
    watcher = FileWatcher(path, recursive)
    watcher.start(interval)

@watch_group.command()
@click.option('--interval', '-i', default=5, help='Update interval in seconds')
def system(interval):
    """Monitor system resources (CPU, RAM, Disk, Network)"""
    monitor = SystemMonitor()
    monitor.monitor_resources(interval)

@watch_group.command()
@click.option('--command', '-c', required=True, help='Command to execute')
@click.option('--interval', '-i', default=60, help='Execution interval in seconds')
def command(command, interval):
    """Watch a command and alert on output changes"""
    import subprocess
    
    click.echo(f"[cyan]Watching command: {command}[/cyan]")
    click.echo(f"[dim]Checking every {interval} seconds...[/dim]")
    
    previous_output = ""
    
    try:
        while True:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            current_output = result.stdout.strip()
            
            if previous_output and current_output != previous_output:
                click.echo(f"[yellow]Output changed at {datetime.now()}[/yellow]")
                click.echo(current_output[:200])
            
            previous_output = current_output
            time.sleep(interval)
            
    except KeyboardInterrupt:
        click.echo("\n[green]Watcher stopped.[/green]")

@watch_group.command()
@click.option('--logfile', '-l', required=True, help='Log file to monitor')
@click.option('--pattern', '-p', help='Pattern to watch for')
def logs(logfile, pattern):
    """Monitor log files in real-time"""
    import os
    
    click.echo(f"[cyan]Monitoring log: {logfile}[/cyan]")
    if pattern:
        click.echo(f"[dim]Filtering for: {pattern}[/dim]")
    
    try:
        with open(logfile, 'r') as f:
            # Go to end of file
            f.seek(0, os.SEEK_END)
            
            while True:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue
                
                line = line.strip()
                
                if pattern:
                    if pattern.lower() in line.lower():
                        click.echo(f"[yellow]{datetime.now().strftime('%H:%M:%S')} - {line}[/yellow]")
                else:
                    # Color based on log level
                    if 'error' in line.lower() or 'fatal' in line.lower():
                        click.echo(f"[red]{line}[/red]")
                    elif 'warning' in line.lower() or 'warn' in line.lower():
                        click.echo(f"[yellow]{line}[/yellow]")
                    else:
                        click.echo(line)
                        
    except KeyboardInterrupt:
        click.echo("\n[green]Log monitor stopped.[/green]")
    except FileNotFoundError:
        click.echo(f"[red]Log file not found: {logfile}[/red]")
