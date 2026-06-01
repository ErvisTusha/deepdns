# DeepDNS

[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)](https://github.com/ErvisTusha/deepdns/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-5.0%2B-orange.svg)](https://www.gnu.org/software/bash/)

**DeepDNS** is an advanced DNS enumeration tool designed for security professionals and enthusiasts. It offers a comprehensive set of features for discovering subdomains and analyzing DNS records efficiently.

## Features

- **Advanced DNS Enumeration**: Multiple scanning modes including passive data sources and active probing techniques
- **Recursive Scanning**: Discover subdomains recursively with configurable depth
- **Pattern Recognition**: Intelligent subdomain discovery using pattern analysis
- **Virtual Host Scanning**: Identify virtual hosts with customizable ports and response filtering
- **Multithreading**: High-performance concurrent processing with adjustable thread counts
- **Smart Resolver Management**: Automatic resolver health monitoring and rotation
- **API Integration**: Seamless integration with SecurityTrails, VirusTotal, and Censys
- **Expanded Passive Sources**: Certificate Transparency, AlienVault OTX, HackerTarget, URLScan, and Wayback CDX
- **DNS Security Checks**: Optional zone transfer and DNSSEC posture checks
- **Pentest Findings**: Optional takeover, DNS, mail, HTTP, TLS, and cloud/CDN checks with evidence files
- **Robust Error Handling**: Graceful interrupt handling and comprehensive error recovery
- **Protocol Detection**: Automatic HTTP/HTTPS protocol detection for virtual host scanning
- **Advanced Logging**: Multiple log levels with detailed diagnostics capabilities
- **Progress Tracking**: Real-time progress visualization with detailed status updates
- **Resource Management**: Efficient cleanup and memory management
- **Flexible Output**: Configurable output formats with filtering options

## Installation

To install DeepDNS globally, run:

```bash
sudo deepdns install
```

## Usage

Basic usage:

```bash
deepdns -d example.com
```

### Core Options

- `-h, --help`               : Show help message.
- `-v, --version`            : Show version information.
- `-D, --debug [file]`       : Enable debug mode (default log file: `~/.deepdns/logs/debug.log`).
- `-V, --verbose`            : Enable verbose output.

### Scan Options

- `-d, --domain <domain>`         : Target domain to scan
- `-w, --wordlist <file>`         : Custom wordlist file
- `-o, --output <file>`           : Output file location
- `--format <txt|json|csv>`       : Output format
- `-R, --resolver <file>`         : Custom DNS resolver file
- `-t, --threads <number>`        : Thread count (1-100, default: 10)
- `-p, --passive`                 : Enable passive scanning
- `-a, --active`                  : Enable active scanning
- `-r, --recursive [depth]`       : Enable recursive scanning
- `--pattern`                     : Enable pattern recognition
- `--zone-transfer`               : Attempt DNS zone transfer checks
- `--dnssec`                      : Run DNSSEC posture checks
- `--pentest`                     : Run penetration-testing checks
- `--profile <safe|balanced|aggressive>` : Pentest profile
- `--checks <list>`               : Comma-separated pentest checks
- `--evidence-dir <dir>`          : Raw evidence output directory
- `--vhost`                       : Enable virtual host scanning
- `--vhost-port <ports>`          : Custom virtual host ports
- `--vhost-filter <filter>`       : Response filtering options
- `--vhost-filter-type <type>`    : Filter type (`status`, `size`, `words`, or `lines`)
- `--raw`                         : Enable raw output format

### Update Verification

DeepDNS supports signed release verification for `update`. Set `RELEASE_SIGNING_FINGERPRINT` in `dev/config/settings.sh` or the generated script, publish `${REPO_URL}.asc`, and optionally publish the public key at `RELEASE_SIGNING_KEY_URL`. Set `RELEASE_SIGNATURE_REQUIRED=true` to fail closed when the signature cannot be verified.

### Management Commands

- `install`     : Install DeepDNS globally.
- `update`      : Update DeepDNS to the latest version.
- **Basic scan**:

  ```bash
  deepdns example.com
  ```

- **Passive scan**:

  ```bash
  deepdns -d example.com -p
  ```

- **Recursive active scan with pattern recognition**:

  ```bash
  deepdns -d example.com -a --pattern -r 2
  ```

- **Full scan with custom settings**:

  ```bash
  deepdns -d example.com -a -t 20 \
    -w wordlist.txt -o output.txt \
    -R resolvers.txt -p -r 3 \
    --vhost --vhost-port 80,443,8000,8443 \
    --vhost-filter 200 --vhost-filter-type status \
    --zone-transfer --dnssec --pentest --profile safe --format json
  ```

## Updates and Uninstallation

- **Update DeepDNS**:

  ```bash
  sudo deepdns update
  ```

- **Uninstall DeepDNS**:

  ```bash
  sudo deepdns uninstall
  ```

## Testing

Run the unit tests with:

```bash
bash dev/test/test.sh
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on [GitHub](https://github.com/ErvisTusha/deepdns).

## License

DeepDNS is released under the [MIT License](LICENSE).

## Contact

- **Author**: Ervis Tusha
- **GitHub**: [https://github.com/ErvisTusha/deepdns](https://github.com/ErvisTusha/deepdns)
- **X**: [https://x.com/ET](https://x.com/ET)
- **Email**: [ ervistusha@gmail.com]
