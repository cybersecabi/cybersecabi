import click
from aegis.core import print_banner, console
from aegis.modules.recon import recon_group
from aegis.modules.vuln import vuln_group
from aegis.modules.audit import audit_group
from aegis.modules.web import web_group
from aegis.modules.crypto import crypto_group
from aegis.modules.analyze import analyze_group
from aegis.modules.watch import watch_group
from aegis.modules.report import report_group
from aegis.config import config

@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--format', '-f', 'output_format', type=click.Choice(['table', 'json', 'csv']), 
              default='table', help='Output format')
@click.option('--threads', '-t', type=int, help='Number of threads')
@click.pass_context
def cli(ctx, verbose, output_format, threads):
    """Aegis CLI - Advanced Cybersecurity Toolkit"""
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    ctx.obj['format'] = output_format
    
    if threads:
        config.set('threads', threads)
    
    if verbose:
        print_banner()

cli.add_command(recon_group, name='recon')
cli.add_command(vuln_group, name='vuln')
cli.add_command(audit_group, name='audit')
cli.add_command(web_group, name='web')
cli.add_command(crypto_group, name='crypto')
cli.add_command(analyze_group, name='analyze')
cli.add_command(watch_group, name='watch')
cli.add_command(report_group, name='report')

def main():
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

if __name__ == '__main__':
    main()
