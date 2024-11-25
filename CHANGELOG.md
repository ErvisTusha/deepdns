# Changelog

All notable changes to DeepDNS will be documented in this file.

## [2.0.0] - 2024-11-25

### Added
- Improved directory structure with dedicated folders for logs and files
- Virtual host scanning capability with customizable ports
- Pattern recognition for intelligent subdomain discovery
- Advanced threading system for improved performance
- Resolver health monitoring and rotation
- Protocol detection (HTTP/HTTPS) for virtual host scanning
- Progress bars for all scanning operations
- Global pattern tracking for recursive scans
- Improved wildcard detection with user interaction
- Customizable thread count (1-100 threads)

### Changed
- Complete code restructuring for better maintainability
- Enhanced recursive scanning with visual depth indicators
- Improved API validation for SecurityTrails and VirusTotal
- Better error handling and logging system
- More detailed scan progress feedback
- Cleaner output formatting with color-coded results
- Resolver validation now runs in parallel
- Wordlist validation with duplicate removal
- Improved handling of temporary files

### Fixed
- Resolver cleanup issues from v1.0.0
- Wildcard detection false positives
- Progress bar display issues
- Memory usage in recursive scans
- API rate limiting issues

### Removed
- Legacy code paths for outdated features

### Security
- Improved input sanitization
- Better handling of sensitive data

### Performance
- Optimized DNS query handling
- Reduced unnecessary API calls
- Improved parallel processing
- Better resource management
- Enhanced cleanup procedures

## [1.0.0] - 2024-11-4


### Initial Release
- Basic DNS enumeration functionality
- Passive and active scanning modes
- Simple recursive scanning
- Basic API integration (SecurityTrails, VirusTotal)
- Command-line interface
- Basic logging system
