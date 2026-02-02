"""
Aegis CLI - Core utilities and decorators
"""
import time
import functools
from typing import Callable, Any
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.text import Text
import json
import csv
from datetime import datetime

console = Console()

def timer(func: Callable) -> Callable:
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        console.print(f"[dim]⏱️  Completed in {elapsed:.2f}s[/dim]")
        return result
    return wrapper

def output_result(data: list, headers: list, format_type: str = "table", title: str = ""):
    if format_type == "json":
        console.print(json.dumps([dict(zip(headers, row)) for row in data], indent=2))
    elif format_type == "csv":
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(headers)
        writer.writerows(data)
        console.print(output.getvalue())
    else:
        table = Table(title=title, show_header=True, header_style="bold magenta")
        for header in headers:
            table.add_column(header)
        for row in data:
            table.add_row(*[str(cell) for cell in row])
        console.print(table)

def print_banner():
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║    █████╗ ███████╗ ██████╗ ██╗███████╗    ║
    ║   ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝    ║
    ║   ███████║█████╗  ██║  ███╗██║███████╗    ║
    ║   ██╔══██║██╔══╝  ██║   ██║██║╚════██║    ║
    ║   ██║  ██║███████╗╚██████╔╝██║███████║    ║
    ║   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝    ║
    ║                                                           ║
    ║              Advanced Security Toolkit v1.0               ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(Panel(Text(banner, style="bold cyan"), border_style="blue"))

def log_activity(module: str, action: str, status: str = "info"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    color = {"info": "blue", "success": "green", "warning": "yellow", "error": "red"}.get(status, "white")
    console.print(f"[{color}][{timestamp}] [{module.upper()}] {action}[/{color}]")

class Spinner:
    def __init__(self, message: str = "Processing..."):
        self.message = message
        self.progress = None
    
    def __enter__(self):
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        )
        self.progress.start()
        self.task = self.progress.add_task(description=self.message, total=None)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.progress.stop()
        return False
