# Changelog

All notable changes to DeepDNS will be documented in this file.

## [2.0.0dev] - 2024-11-25

### Added
- **Advanced DNS Enumeration Features**: Introduced virtual host scanning with customizable ports and pattern recognition for intelligent subdomain discovery.
- **Enhanced Threading System**: Implemented multithreading support for improved performance and resource utilization.
- **Resolver Management**: Added resolver health monitoring and automatic rotation to maintain optimal scanning efficiency.
- **Protocol Detection**: Integrated HTTP/HTTPS protocol detection for virtual host scanning.
- **User Interface Improvements**: Enhanced progress tracking with progress bars and visual depth indicators for recursive scans.
- **Wildcard Detection**: Improved wildcard detection with interactive prompts to handle false positives effectively.
- **Interrupt Handling and Cleanup**: Implemented interrupt handling with graceful exit procedures to ensure resource cleanup.
- **Logging System**: Integrated advanced logging with multiple log levels for better diagnostics and debugging.
- **API Key Validation**: Enabled validation for API keys (SecurityTrails, VirusTotal, Censys) to enhance security.
- **Recursive Scanning Enhancements**: Improved recursive scanning capabilities with global pattern tracking.
- **Customizable Thread Counts**: Added support for specifying thread counts between 1 and 100.
- **Command-Line Interface Updates**: Expanded CLI options with updated help and version information displays.
- **Interrupt Handling in Main Scan Loop**: Included interrupt checks in the main scanning section to improve responsiveness and ensure proper cleanup upon user interruption.
- **Port Checking in VHOST_SCAN**: Implemented `CHECK_PORT` within `VHOST_SCAN` to identify open ports before scanning, improving efficiency and reducing unnecessary requests.

### Changed
- **Code Refactoring**: Restructured the codebase into modular functions to improve maintainability and readability.
- **Global Variable Standardization**: Updated global variable naming conventions for consistency.
- **Output Formatting**: Enhanced output with color-coded messages and structured summaries for better user experience.
- **Error Handling**: Improved error handling to provide more informative and user-friendly feedback.
- **Installer Updates**: Updated installation scripts for more reliable installation, updating, and uninstallation processes.
- **Performance Optimizations**: Optimized DNS query handling and reduced unnecessary API calls for better performance.
- **Wordlist and Resolver Processing**: Implemented multithreaded validation and cleaning of wordlists and resolvers.

### Fixed
- **Resolver Health Checks**: Resolved issues with resolver cleanup and health monitoring from version 1.0.0.
- **Wildcard Detection**: Corrected wildcard detection mechanisms to prevent false positives.
- **Progress Bar Display**: Fixed glitches in progress bar displays during multithreaded operations.
- **Memory Management**: Addressed memory usage issues during recursive scans to prevent leaks.
- **API Rate Limiting**: Optimized API interactions to handle rate limiting and reduce unnecessary requests.

### Removed
- **Deprecated Code**: Removed legacy code paths and unused functions to streamline the codebase.

### Security
- **Input Validation**: Strengthened input validation and sanitization across all user inputs.
- **Sensitive Data Handling**: Secured the handling and storage of API keys and configuration data.

### Performance
- **Multithreading Enhancements**: Improved multithreading support for better utilization of system resources.
- **Resource Management**: Optimized resource allocation and cleanup procedures to enhance efficiency.
- **DNS Query Efficiency**: Enhanced the efficiency of DNS query operations and data processing.
- **API Usage Optimization**: Reduced unnecessary calls to external APIs for improved performance.

### Breaking Changes
- **Configuration Updates**: The configuration file format has changed. Users need to update their existing configurations to match the new format.
- **Command-Line Options**: Some command-line options have been renamed or removed. Refer to the updated help (`--help`) for the new options.

### Migration Notes
- **Updating from 1.0.0 to 2.0.0**: Users should back up their current configuration files and refer to the updated documentation for migration steps.

### Known Issues
- **Censys API Integration**: Limited testing has been conducted on the Censys API integration. Users may experience unexpected behavior.
- **IPv6 Support**: Full IPv6 support is not yet implemented and will be added in a future release.

### Acknowledgments
- **Contributors**: Special thanks to all contributors who provided feedback and code improvements for this release.

## [1.0.0] - 2024-11-04

### Initial Release
- **Basic DNS Enumeration**: Introduced passive and active scanning modes with simple recursive scanning.
- **API Integration**: Included basic integration with SecurityTrails and VirusTotal APIs.
- **Command-Line Interface**: Provided a CLI for user interaction and configuration.
- **Logging System**: Implemented a basic logging mechanism for tracking operations.
