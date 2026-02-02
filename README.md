# Aegis CLI

A comprehensive, modular cybersecurity toolkit designed for security professionals, penetration testers, and system administrators.

## Features

- **recon** - Network discovery, port scanning, OSINT gathering
- **vuln** - CVE lookup, vulnerability scanning, misconfiguration detection
- **audit** - System hardening checks, compliance validation
- **web** - HTTP security analysis, SSL/TLS testing, endpoint probing
- **crypto** - Hash operations, encoding/decoding, cipher tools
- **analyze** - Log parsing, traffic analysis, IOC detection
- **watch** - Real-time file and system monitoring
- **report** - Professional PDF/HTML report generation

## Installation

### From Source
```bash
git clone <repository>
cd aegis-cli
pip install -e .
```

### Using Docker
```bash
docker build -t aegis-cli .
docker run --rm aegis-cli --help
```

## Quick Start

```bash
# Show help
aegis --help

# Network reconnaissance
aegis recon scan -t 192.168.1.1
aegis recon ping -n 192.168.1.0/24

# Vulnerability scan
aegis vuln scan -t target.com

# System audit
aegis audit system

# Web security check
aegis web analyze -u https://target.com
aegis web headers -u https://target.com

# Cryptographic tools
aegis crypto hash -t "password" -a sha256
aegis crypto encode -t "hello" -f base64

# Log analysis
aegis analyze log -f /var/log/apache2/access.log

# File monitoring
aegis watch files -p /path/to/watch -r

# Generate report
aegis report generate -f html -o report.html
```

## Module Details

### Recon Module
Network reconnaissance and discovery:
- Port scanning (TCP SYN, Connect)
- Ping sweep for host discovery
- DNS resolution
- Common service detection

### Vuln Module
Vulnerability assessment:
- CVE database lookup
- Common vulnerability checks
- SSL/TLS configuration issues
- Weak credential detection

### Audit Module
System security auditing:
- SSH configuration checks
- Password policy validation
- Firewall status
- Service hardening recommendations
- CIS compliance checklist

### Web Module
Web application security:
- Security headers analysis
- SSL/TLS certificate inspection
- Common file/directory discovery
- Redirect chain analysis
- Web crawler

### Crypto Module
Cryptographic utilities:
- Multiple hash algorithms (MD5, SHA1, SHA256, SHA512, etc.)
- Base64/Base32/Hex encoding
- Caesar cipher
- XOR encryption
- Simple hash cracking

### Analyze Module
Log file analysis:
- Apache/Nginx access logs
- Authentication logs
- Application logs
- IOC extraction (IPs, emails, URLs)
- Brute force detection
- Suspicious activity identification

### Watch Module
Real-time monitoring:
- File system changes
- System resource monitoring (CPU, RAM, Disk, Network)
- Log file tailing with filtering
- Command output monitoring

### Report Module
Report generation:
- HTML reports with styling
- JSON output for automation
- Markdown reports
- Report management and listing

## Configuration

Configuration is stored in `~/.aegis/config.yaml`:

```yaml
threads: 50
timeout: 30
output_format: table
verbose: false
recon:
  ports: top1000
  scan_type: syn
vuln:
  check_cves: true
web:
  follow_redirects: true
  ssl_verify: false
  user_agent: Aegis-Security-Scanner/1.0
api_keys:
  shodan: null
  virustotal: null
```

## Architecture

- **Modular Design**: Each tool is a separate, self-contained module
- **Plugin System**: Easy to extend with custom modules
- **Concurrent Execution**: Multi-threaded for performance
- **Structured Output**: JSON/CSV/Table formats for automation
- **Unified Config**: Single configuration across all modules
- **Rich CLI**: Beautiful terminal output with colors and progress indicators

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run linting
make lint

# Clean build artifacts
make clean
```

## Project Structure

```
aegis-cli/
├── aegis/
│   ├── __init__.py
│   ├── cli.py          # Main CLI entry point
│   ├── config.py       # Configuration management
│   ├── core.py         # Core utilities
│   └── modules/
│       ├── recon.py    # Network reconnaissance
│       ├── vuln.py     # Vulnerability scanning
│       ├── audit.py    # System auditing
│       ├── web.py      # Web security
│       ├── crypto.py   # Cryptographic tools
│       ├── analyze.py  # Log analysis
│       ├── watch.py    # Monitoring
│       └── report.py   # Report generation
├── tests/
├── README.md
├── setup.py
├── requirements.txt
├── Dockerfile
└── Makefile
```

## License

MIT License - See LICENSE file for details

## Security Note

This tool is intended for authorized security testing and research only. Always obtain proper authorization before scanning systems you do not own.

## Contributing

Contributions are welcome! Please follow the existing code style and add tests for new features.

## Roadmap

- [ ] Integration with external APIs (Shodan, VirusTotal)
- [ ] Exploit database integration
- [ ] Network packet capture and analysis
- [ ] Wireless network scanning
- [ ] Password cracking with GPU acceleration
- [ ] Automated report scheduling
- [ ] Web dashboard for results visualization
# AegisSec
