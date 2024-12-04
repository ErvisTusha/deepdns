# DeepDNS Docker Implementation

[![Version](https://img.shields.io/badge/version-1.0-blue.svg)](https://github.com/your-repo/deepdns)
[![Docker Pulls](https://img.shields.io/docker/pulls/deepdns/deepdns.svg)](https://hub.docker.com/r/deepdns/deepdns)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Overview

DeepDNS is an advanced DNS enumeration tool containerized for easy deployment and scalability. This Docker implementation ensures consistent execution across different environments while maintaining security and performance.

## Quick Start

### Option 1: Using Docker Hub (Quickest Method)

Pull and run directly from Docker Hub:

### Prerequisites

- Docker Engine 20.10+
- Docker Compose v2.0+ (optional)
- 2GB RAM minimum
- Host network access

### Building the Image

```bash
./build.sh build
```

### Running DeepDNS

```bash
./build.sh run [options]
```

### Cleaning Up

```bash
./build.sh clean
```

## Configuration

### Volume Mounts

- `/app/config`: Configuration files (read-only)
- `/app/output`: Output directory (read-write)

### Environment Variables

- `DEEPDNS_CONFIG`: Configuration directory path (default: `/app/config`)
- `PATH`: Application path (automatically configured)

## Security Features

- Non-root user execution
- No new privileges flag
- Resource limitations
- Read-only file system where possible

## Resource Management

- CPU Shares: 1024
- Memory Limit: 2GB
- Memory Swap: 2GB

## Docker Compose Usage

```yaml
docker compose up -d
```

## Contributing

Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- Documentation: [docs/](docs/)
- Issues: GitHub Issues
- Maintainer: Ervis Tusha <x.com/ET>

## Security

For security concerns, please report them via private channels listed in our security policy.