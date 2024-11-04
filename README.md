# DeepDNS

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/ErvisTusha/deepdns)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-5.0%2B-orange.svg)](https://www.gnu.org/software/bash/)

An advanced DNS enumeration tool for comprehensive DNS reconnaissance and security assessments.

## Overview

DeepDNS is a powerful Bash script designed for in-depth DNS enumeration and reconnaissance. It combines both passive and active scanning techniques to discover subdomains, DNS records, and potential misconfigurations, aiding security professionals in penetration testing and vulnerability assessments.

## Key Features

- **Passive Scanning**: Leverage APIs like SecurityTrails and VirusTotal for silent subdomain enumeration.
- **Active Scanning**: Perform DNS record enumeration and wordlist-based brute-force attacks.
- **Recursive Scanning**: Scan discovered subdomains up to a specified depth.
- **Customization**: Support custom wordlists and DNS resolver files.
- **Detailed Output**: Provide options for verbose and debug modes, outputting results to specified files.
- **User-Friendly Interface**: Feature ANSI color-coded output for enhanced readability.

## Installation

To install DeepDNS, clone the repository and run the install command:

```shell
sudo ./deepdns.sh install
```

## Usage

DeepDNS offers a variety of scanning options to suit different needs. Below are the available commands and options:

```shell
# Basic command:
./deepdns.sh <domain>

# Example:
./deepdns.sh example.com
```

### Options

- `-d <domain>`: Specify the target domain.
- `-p`: Perform a passive scan using APIs.
- `-a`: Perform an active scan.
- `-w <wordlist>`: Use a custom wordlist for brute-force attacks.
- `-o <output file>`: Output results to a specified file.
- `-R <resolvers file>`: Use a custom DNS resolvers file.
- `-r <depth>`: Set the recursion depth for scanning subdomains.
- `-v`: Enable verbose mode.
- `-h`: Display help message.

## Examples

### Basic Scan

```shell
./deepdns.sh example.com
```

### Passive Scan

```shell
./deepdns.sh -d example.com -p
```

### Active Scan

```shell
./deepdns.sh -d example.com -a
```

### Full Scan with Custom Options

```shell
./deepdns.sh -d example.com -a -p -w wordlist.txt -o output.txt -R resolvers.txt -r 3
```

## API Configuration

To utilize APIs like SecurityTrails,VirusTotal and Censys, set your API keys in the script or export them as environment variables:

- **SecurityTrails API key:** `SECURITYTRAILS_API_KEY`
- **VirusTotal API key:** `VIRUSTOTAL_API_KEY`
- **Censys API ID:** `CENSYS_API_ID`
- **Censys API Secret:** `CENSYS_API`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Author

Ervis Tusha

- **GitHub:** [https://github.com/ErvisTusha/deepdns](https://github.com/ErvisTusha/deepdns)
- **Twitter:** [@ET](https://www.x.com/ET)
- **LinkedIn:** [Ervis Tusha](https://www.linkedin.com/in/ervis-tusha)
- **Website:** [https://www.ervistusha.com](https://www.ervistusha.com)
- **Email:** [ErvisTusha@gmail.com](mailto:ErvisTusha@gmail.com)