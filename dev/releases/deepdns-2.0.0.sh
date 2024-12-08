#!/bin/bash
#
######################################################################
#         DeepDNS - Advanced DNS Enumeration Script                  #
#  Author: Ervis Tusha               X: htts://x.com/ET              #
#  License: MIT        GitHub: https://github.com/ErvisTusha/deepdns #
######################################################################
#

# Directory settings
declare -g SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
declare -g HOME_DIR="$HOME/.deepdns"
declare -g LOG_DIR="$HOME_DIR/logs"
declare -g FILES_DIR="$HOME_DIR/files"
# Create required directories if they don't exist
[[ ! -d "$HOME_DIR" ]] && mkdir -p "$HOME_DIR"
[[ ! -d "$LOG_DIR" ]] && mkdir -p "$LOG_DIR"
[[ ! -d "$FILES_DIR" ]] && mkdir -p "$FILES_DIR"
# Debug settings
declare -g DEBUG_LOG="$LOG_DIR/debug.log"
# Global variables
declare -g START_TIME=$(date +%s)
declare -g TEMP_DIR=""
declare -g VERBOSE=false
declare -g DEBUG=false
declare -g VERSION="2.0.0"
declare -g AUTHOR="Ervis Tusha"
# Default settings
declare -g DEFAULT_RECURSIVE_DEPTH=3
declare -g DEFAULT_OUTPUT_DIR="$PWD"
declare -g OUTPUT_FORMAT="txt"
declare -g WORDLIST_PATH="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
# API Keys
declare -g SECURITYTRAILS_API_KEY=""
declare -g VIRUSTOTAL_API_KEY=""
declare -g CENSYS_API_ID=""
declare -g CENSYS_API_SECRET=""
# Feature flags
declare -g ACTIVE_SCAN_ENABLED=false
declare -g RECURSIVE_SCAN_ENABLED=false
declare -g VHOST_SCAN_ENABLED=false
declare -g PATTERN_RECOGNITION_ENABLED=false
declare -g API_VALIDATION_ENABLED=true
declare -g VHOST_PORTS=(80 443)
# Colors
declare -r RED='\033[0;31m'
declare -r GREEN='\033[0;32m'
declare -r YELLOW='\033[1;33m'
declare -r BLUE='\033[0;34m'
declare -r CYAN='\033[0;36m'
declare -r NC='\033[0m'
declare -r BOLD='\033[1m'
declare -r GRAY='\033[0;90m'
declare -r PURPLE='\033[0;35m'
declare -r DIM='\033[2m'
declare -r UNDERLINE='\033[4m'
declare -r WHITE='\033[1;37m'
# Add these variables near the top with other declarations
declare -g CLEANUP_DONE=false
declare -g INTERRUPT_RECEIVED=false
# Response filtering
declare -g VHOST_FILTER=""
declare -g VHOST_FILTER_TYPE="status" # status, size, words, lines
# Thread count
declare -g THREAD_COUNT=10
# GitHub repository URL
declare -g REPO_URL="https://raw.githubusercontent.com/ErvisTusha/deepdns/main/deepdns.sh"
# Raw output flag
declare -g RAW_OUTPUT=false
declare -g CLEANUP_DONE="false"
declare -g INTERRUPT_RECEIVED="false"
declare -g PATTERN_SCAN_CLEANED="false"


# From core.sh
CREATE_TEMP_DIR() {
    if [[ -z "$TEMP_DIR" ]]; then
        TEMP_DIR=$(mktemp -d)
        [[ ! -d "$TEMP_DIR" ]] && mkdir -p "$TEMP_DIR"
        trap 'rm -rf "$TEMP_DIR"' EXIT
    fi
}
# Add trap for SIGINT/SIGTERM
#trap 'CLEANUP; exit 130' SIGINT SIGTERM
CLEANUP() {
    local EXIT_CODE=$?
    if [[ "$CLEANUP_DONE" == "true" ]]; then
        return $EXIT_CODE
    fi
    CLEANUP_DONE="true"
    INTERRUPT_RECEIVED="true"
    echo -e "\n${YELLOW}${BOLD}[!]${NC} Cleaning up..."
    LOG "INFO" "Cleaning up temporary files"
    # Kill all background processes
    pkill -P $$
    if [ $EXIT_CODE -ne 0 ]; then
        echo -e "${RED}${BOLD}[!]${NC} Scan interrupted. Partial results may have been saved."
        LOG "WARNING" "Scan interrupted with exit code $EXIT_CODE"
    fi
    # Clean up temporary files
    rm -rf "$THREAD_DIR" "$LOCK_DIR" 2>/dev/null
    [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && rm -f "$GLOBAL_PATTERNS_FILE" 2>/dev/null
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "${TEMP_DIR}"/* 2>/dev/null
        rmdir "$TEMP_DIR" 2>/dev/null
    fi
    exit $EXIT_CODE
}
LOG() {
    # Ensure DEBUG_LOG is set
    [[ -z "$DEBUG_LOG" ]] && DEBUG_LOG="$LOG_DIR/debug.log"
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: LOG() no status provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: LOG() no message provided"
        return 1
    fi
    local STATUS
    local MESSAGE="$2"
    if ! [[ "$1" =~ ^(INFO|WARNING|ERROR|DEBUG)$ ]]; then
        STATUS="INFO"
        MESSAGE="$1"
    else
        STATUS="$1"
    fi
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') [$STATUS] : $MESSAGE" >>"$DEBUG_LOG"
    [[ "$VERBOSE" == "true" ]] && echo "[$STATUS] : $MESSAGE"
    return 0
}
SHOW_HELP() {
    echo -e ""
    echo -e "${BOLD}Basic Commands:${NC}"
    echo -e "  ${CYAN}${BOLD}$SCRIPT${NC} <domain>                     ${BLUE}${BOLD}# Run full scan on domain${NC}"
    echo -e "  ${CYAN}${BOLD}$SCRIPT${NC} install                      ${BLUE}${BOLD}# Install the script (${YELLOW}${BOLD}requires root${BLUE}${BOLD})${NC}"
    echo -e ""
    echo -e "${BOLD}Core Options:${NC}"
    echo -e "  ${GREEN}${BOLD}-h, --help${NC}                    ${BLUE}${BOLD}# Show this help message${NC}"
    echo -e "  ${GREEN}${BOLD}-v, --version${NC}                 ${BLUE}${BOLD}# Show version information${NC}"
    echo -e "  ${GREEN}${BOLD}-D, --debug${NC} [file]            ${BLUE}${BOLD}# Enable debug mode (default: ${YELLOW}${BOLD}${LOG_DIR}/debug_output.log${NC}${BLUE}${BOLD})${NC}"
    echo -e "  ${GREEN}${BOLD}-V, --verbose${NC}                 ${BLUE}${BOLD}# Enable verbose mode${NC}"
    echo -e ""
    echo -e "${BOLD}Scan Options:${NC}"
    echo -e "  ${GREEN}${BOLD}-d, --domain${NC} <domain>         ${BLUE}${BOLD}# Domain to scan${NC}"
    echo -e "  ${GREEN}${BOLD}-w, --wordlist${NC} <file>         ${BLUE}${BOLD}# Custom wordlist (default: ${YELLOW}${BOLD}${WORDLIST_PATH}${NC}${BLUE}${BOLD})${NC}"
    echo -e "  ${GREEN}${BOLD}-o, --output${NC} <file>           ${BLUE}${BOLD}# Output file (default: ${YELLOW}${BOLD}pwd/<domain>.txt${NC}${BLUE}${BOLD})${NC}"
    echo -e "  ${GREEN}${BOLD}-R, --resolver${NC} <file>         ${BLUE}${BOLD}# Custom resolver file${NC}"
    echo -e "  ${GREEN}${BOLD}-t, --threads${NC} <number>        ${BLUE}${BOLD}# Number of threads (default: ${YELLOW}${BOLD}10${NC}${BLUE}${BOLD}, max: 100)${NC}"
    echo -e "  ${GREEN}${BOLD}-p, --passive${NC}                 ${BLUE}${BOLD}# Enable passive scanning${NC}"
    echo -e "  ${GREEN}${BOLD}-a, --active${NC}                  ${BLUE}${BOLD}# Enable active scanning${NC}"
    echo -e "  ${GREEN}${BOLD}-r, --recursive${NC} [depth]       ${BLUE}${BOLD}# Enable recursive scanning (default: ${YELLOW}${BOLD}${DEFAULT_RECURSIVE_DEPTH}${NC}${BLUE}${BOLD})${NC}"
    echo -e "  ${GREEN}${BOLD}--pattern${NC}                     ${BLUE}${BOLD}# Enable pattern recognition${NC}"
    echo -e "  ${GREEN}${BOLD}--vhost${NC}                       ${BLUE}${BOLD}# Enable virtual host scanning${NC}"
    echo -e "  ${GREEN}${BOLD}--vhost-port${NC} <ports>          ${BLUE}${BOLD}# Custom vhost ports (comma-separated, default: 80,443,8080,8443)${NC}"
    echo -e "  ${GREEN}${BOLD}--vhost-filter${NC} <filter>       ${BLUE}${BOLD}# Filter vhost responses (status, size, words, lines)${NC}"
    echo -e "  ${GREEN}${BOLD}--vhost-filter-value${NC} <value>  ${BLUE}${BOLD}# Filter value for vhost responses${NC}"
    echo -e ""
    echo -e "${BOLD}Management Commands:${NC}"
    echo -e "  ${GREEN}${BOLD}install${NC}                       ${BLUE}${BOLD}# Install DeepDNS globally${NC}"
    echo -e "  ${GREEN}${BOLD}update${NC}                        ${BLUE}${BOLD}# Update to latest version${NC}"
    echo -e "  ${GREEN}${BOLD}uninstall${NC}                     ${BLUE}${BOLD}# Remove DeepDNS from system${NC}"
    echo -e ""
    echo -e "${BOLD}API Configuration:${NC}"
    echo -e "  ${GREEN}${BOLD}--st-key${NC} <key>                ${BLUE}${BOLD}# SecurityTrails API key${NC}"
    echo -e "  ${GREEN}${BOLD}--vt-key${NC} <key>                ${BLUE}${BOLD}# VirusTotal API key${NC}"
    echo -e "  ${GREEN}${BOLD}--censys-id${NC} <id>              ${BLUE}${BOLD}# Censys API ID${NC}"
    echo -e "  ${GREEN}${BOLD}--censys-secret${NC} <secret>      ${BLUE}${BOLD}# Censys API secret${NC}"
    echo -e ""
    echo -e "${BOLD}Examples:${NC}"
    echo -e "  ${CYAN}${BOLD}$SCRIPT${NC} example.com                   ${BLUE}${BOLD}# Basic scan${NC}"
    echo -e "  ${CYAN}${BOLD}$SCRIPT${NC} -d example.com -p             ${BLUE}${BOLD}# Passive scan${NC}"
    echo -e "  ${CYAN}${BOLD}$SCRIPT${NC} -d example.com -r 2           ${BLUE}${BOLD}# Recursive scan (depth 2)${NC}"
    echo -e "  ${CYAN}${BOLD}$SCRIPT${NC} -d example.com -a -t 20 \\     ${BLUE}${BOLD}# Full scan with custom settings${NC}"
    echo -e "      -w wordlist.txt -o output.txt \\"
    echo -e "      -R resolvers.txt -p -r 3 \\"
    echo -e "      --vhost --vhost-port 80,443,8000,8443"
    echo -e "      --vh-filter status --vh-filter-value 200"
}
SHOW_VERSION() {
    echo -e "${BLUE}
    ██████╗  ███████╗ ███████╗ ██████╗     ██████╗  ███╗   ██╗ ███████╗
    ██╔══██╗ ██╔════╝ ██╔════╝ ██╔══██╗    ██╔══██╗ ████╗  ██║ ██╔════╝
    ██║  ██║ █████╗   █████╗   ██████╔╝    ██║  ██║ ██╔██╗ ██║ ███████╗
    ██║  ██║ ██╔══╝   ██╔══╝   ██╔═══╝     ██║  ██║ ██║╚██╗██║ ╚════██║
    ██████╔╝ ███████╗ ███████╗ ██║         ██████╔╝ ██║ ╚████║ ███████║
    ╚═════╝  ╚══════╝ ╚══════╝ ╚═╝         ╚═════╝  ╚═╝  ╚═══╝ ╚══════╝${NC}"
    echo -e "\n\n${GREEN}${BOLD}    DeepDNS${NC} v${YELLOW}${VERSION}${NC} - ${CYAN}${BOLD}Advanced DNS Enumeration Tool${NC}    ${GREEN}${BOLD}From:${NC} ${RED}${BOLD}${AUTHOR}${NC}
    ${GREEN}${BOLD}GITHUB${NC}:${YELLOW}${BOLD}https://github.com/ErvisTusha/deepdns${NC}   ${GREEN}${BOLD}X:${NC} ${YELLOW}${BOLD}https://www.x.com/ET${NC}
                                ${GREEN}${BOLD}LICENSE:${NC} ${YELLOW}${BOLD}MIT${NC}"
}


# From utils.sh
FILE_EMPTY() {
    if [[ -z "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No file provided"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No file provided" >>"$DEBUG_LOG"
        return 1
    fi
    if [[ -s "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File $1 is not empty"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File $1 is not empty" >>"$DEBUG_LOG"
        return 1
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File $1 is empty"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File $1 is empty" >>"$DEBUG_LOG"
        return 0
    fi
}
IS_INSTALLED() {
    if [[ -z "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No package name provided"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%S') ERROR: No package name provided" >>"$DEBUG_LOG"
        return 1
    fi
    if command -v "$1" &>/dev/null; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: Package $1 is installed"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Package $1 is installed" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: Package $1 is not installed"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Package $1 is not installed" >>"$DEBUG_LOG"
        return 1
    fi
}
INSTALL_SCRIPT() {
    LOG "INFO" "Starting DeepDNS installation"
    if ! sudo -v &>/dev/null; then
        echo -e "${RED}${BOLD}[ERROR]${NC} Sudo access required for installation"
        LOG "ERROR" "Installation failed - no sudo access"
        return 1
    fi
    echo -e "\n${CYAN}${BOLD}[*]${NC} Installing DeepDNS..."
    # Create required directories with correct permissions
    local HOME_DIR="$HOME/.deepdns"
    local LOG_DIR="$HOME_DIR/logs"
    local FILES_DIR="$HOME_DIR/files"
    
    mkdir -p "$HOME_DIR" "$LOG_DIR" "$FILES_DIR"
    chmod 755 "$HOME_DIR"
    chmod 755 "$LOG_DIR"
    chmod 755 "$FILES_DIR"
    if [ -f "/usr/local/bin/deepdns" ]; then
        echo -e "${YELLOW}${BOLD}[!]${NC} DeepDNS is already installed. Use 'update' to upgrade."
        LOG "INFO" "Installation skipped - already installed"
        return 0
    fi
    if sudo install -m 0755 -o root -g root "$0" /usr/local/bin/deepdns; then
        echo -e "${GREEN}${BOLD}[✓]${NC} Successfully installed DeepDNS:"
        echo -e "   ${CYAN}${BOLD}→${NC} Binary: /usr/local/bin/deepdns"
        echo -e "   ${CYAN}${BOLD}→${NC} Config: $HOME_DIR"
        echo -e "\nYou can now use 'deepdns' from anywhere"
        LOG "INFO" "Installation successful"
        return 0
    else
        echo -e "${RED}${BOLD}[✗]${NC} Failed to install DeepDNS"
        LOG "ERROR" "Installation failed - copy error"
        return 1
    fi
}
UPDATE_SCRIPT() {
    LOG "INFO" "Starting DeepDNS update"
    local CURRENT_VERSION="$VERSION"
    local NEW_VERSION
    echo -e "\n${CYAN}${BOLD}[*]${NC} Updating DeepDNS..."
    echo -e "   ${CYAN}${BOLD}→${NC} Current version: ${YELLOW}${BOLD}${CURRENT_VERSION}${NC}"
    # Check if installed
    if [ ! -f "/usr/local/bin/deepdns" ]; then
        echo -e "${YELLOW}${BOLD}[!]${NC} DeepDNS is not installed. Use 'install' first."
        LOG "ERROR" "Update failed - not installed"
        return 1
    fi
    # Verify sudo access
    if ! sudo -v &>/dev/null; then
        echo -e "${RED}${BOLD}[ERROR]${NC} Sudo access required for update"
        LOG "ERROR" "Update failed - no sudo access"
        return 1
    fi
    # Check for curl
    if ! command -v curl &>/dev/null; then
        echo -e "${RED}${BOLD}[ERROR]${NC} curl is required but not installed"
        LOG "ERROR" "Update failed - curl not found"
        return 1
    fi
    # Download and update
    local TEMP_FILE=$(mktemp)
    if curl -sL "$REPO_URL" -o "$TEMP_FILE"; then
        # Extract version from downloaded file
        NEW_VERSION=$(grep "declare -g VERSION=" "$TEMP_FILE" | cut -d'"' -f2)
        if sudo cp "$TEMP_FILE" /usr/local/bin/deepdns && sudo chmod +x /usr/local/bin/deepdns; then
            rm -f "$TEMP_FILE"
            echo -e "${GREEN}${BOLD}[✓]${NC} Successfully updated DeepDNS:"
            echo -e "   ${CYAN}${BOLD}→${NC} Binary: /usr/local/bin/deepdns"
            echo -e "   ${CYAN}${BOLD}→${NC} Updated: ${YELLOW}${BOLD}v${CURRENT_VERSION}${NC} ${GREEN}${BOLD}→${NC} ${YELLOW}${BOLD}v${NEW_VERSION}${NC}"
            echo -e "\nYou can now use 'deepdns' from anywhere"
            LOG "INFO" "Update successful from v${CURRENT_VERSION} to v${NEW_VERSION}"
            return 0
        fi
    fi
    rm -f "$TEMP_FILE"
    echo -e "${RED}${BOLD}[✗]${NC} Failed to update DeepDNS"
    LOG "ERROR" "Update failed - download/copy error"
    return 1
}
UNINSTALL_SCRIPT() {
    LOG "INFO" "Starting DeepDNS uninstallation"
    echo -e "\n${CYAN}${BOLD}[*]${NC} Uninstalling DeepDNS..."
    if [ ! -f "/usr/local/bin/deepdns" ]; then
        echo -e "${YELLOW}${BOLD}[!]${NC} DeepDNS is not installed"
        LOG "INFO" "Uninstall skipped - not installed"
        return 0
    fi
    if ! sudo -v &>/dev/null; then
        echo -e "${RED}${BOLD}[ERROR]${NC} Sudo access required for uninstallation"
        LOG "ERROR" "Uninstall failed - no sudo access"
        return 1
    fi
    if sudo rm -f /usr/local/bin/deepdns; then
        echo -e "${GREEN}${BOLD}[✓]${NC} Successfully uninstalled DeepDNS:"
        echo -e "   ${CYAN}${BOLD}→${NC} Removed: /usr/local/bin/deepdns"
        echo -e "\nDeepDNS has been completely removed from your system"
        LOG "INFO" "Uninstall successful"
        return 0
    else
        echo -e "${RED}${BOLD}[✗]${NC} Failed to uninstall DeepDNS"
        LOG "ERROR" "Uninstall failed - removal error"
        return 1
    fi
}
FILE_READABLE() {
    if [ -r "$1" ]; then
        return 0
    else
        return 1
    fi
}
FILE_WRITABLE() {
    if [ -w "$1" ]; then
        return 0
    else
        return 1
    fi
}
IS_EMPTY() {
    if [[ -z "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: Variable is empty"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Variable is empty" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: Variable is not empty"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Variable is not empty" >>"$DEBUG_LOG"
        return 1
    fi
}
IS_NUMBER() {
    if [[ -z "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No variable provided"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No variable provided" >>"$DEBUG_LOG"
        return 1
    fi
    if [[ "$1" =~ ^[0-9]+$ ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: $1 is numeric"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: $1 is numeric" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: $1 is not numeric"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: $1 is not numeric" >>"$DEBUG_LOG"
        return 1
    fi
}
FILE_EXISTS() {
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No file provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No file provided"
        return 1
    fi
    if [[ -f "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File $1 exists"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File $1 exists" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File $1 does not exist"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File $1 does not exist" >>"$DEBUG_LOG"
        return 1
    fi
}
DETECT_PROTOCOL() {
    local DOMAIN="$1"
    local PORT="$2"
    # Try HTTPS first
    if curl -s -k --head \
        --connect-timeout 2 \
        --max-time 3 \
        "https://${DOMAIN}:${PORT}" >/dev/null 2>&1; then
        echo "https"
        return 0
    fi
    # Try HTTP if HTTPS failed
    if curl -s --head \
        --connect-timeout 2 \
        --max-time 3 \
        "http://${DOMAIN}:${PORT}" >/dev/null 2>&1; then
        echo "http"
        return 0
    fi
    # Default to http if both fail
    echo "http"
    return 1
}


# From validation.sh
VALIDATE_IP() {
    local IP="$1"
    if [[ ! "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 1
    fi
    # Check each octet
    local IFS='.'
    read -ra OCTETS <<<"$IP"
    for OCTET in "${OCTETS[@]}"; do
        if [[ "$OCTET" -lt 0 || "$OCTET" -gt 255 ]]; then
            return 1
        fi
    done
    return 0
}
VALIDATE_DOMAIN() {
    LOG "DEBUG" "Starting VALIDATE_DOMAIN with input: $1"
    if ! [[ "$1" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        LOG "ERROR" "VALIDATE_DOMAIN $1 - Invalid domain"
        return 1
    fi
    LOG "INFO" "VALIDATE_DOMAIN $1 - OK"
    return 0
}
VALIDATE_API_KEY() {
    local KEY="$1"
    local TYPE="$2"
    [[ "$API_VALIDATION_ENABLED" == false ]] && return 0
    case "$TYPE" in
    "ST") [[ ${#KEY} -eq 32 && $KEY =~ ^[A-Za-z0-9]+$ ]] ;;
    "VT") [[ ${#KEY} -eq 64 && $KEY =~ ^[A-Za-z0-9]+$ ]] ;;
    "CENSYS") [[ ${#KEY} -ge 32 && $KEY =~ ^[A-Za-z0-9_-]+$ ]] ;;
    *) return 1 ;;
    esac
    LOG "DEBUG" "Validated $TYPE API key"
    return $?
}
VALIDATE_WORDLIST_CHUNK() {
    local CHUNK="$1"
    local CHUNK_RESULTS="$THREAD_DIR/results_$(basename "$CHUNK")"
    local PROCESSED=0
    local CHUNK_SIZE=$(wc -l <"$CHUNK")
    while read -r WORD; do
        if [[ "$WORD" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] && [[ ${#WORD} -le 63 ]]; then
            echo "$WORD" >>"$CHUNK_RESULTS"
            ((PROCESSED++))
        else
            LOG "DEBUG" "Invalid word removed: $WORD"
        fi
        (
            flock 200
            local CURRENT=$(cat "$PROGRESS_FILE")
            echo $((CURRENT + 1)) >"$PROGRESS_FILE"
        ) 200>"$PROGRESS_FILE.lock"
    done < <(tr '[:upper:]' '[:lower:]' <"$CHUNK")
}
CLEAN_WORDLIST() {
    local INPUT_FILE="$1"
    #local THREAD_COUNT="${2:-10}"
    local TOTAL_COUNT=0
    local WORKING_COUNT=0
    local THREAD_DIR="$TEMP_DIR/wordlist_threads"
    local PROGRESS_FILE="$THREAD_DIR/progress"
    local CLEAN_FILE="$TEMP_DIR/clean_wordlist.txt"
    #if ACTIVE_SCAN_ENABLED and VHOST_SCAN_ENABLED are false, skip wordlist validation
    if [[ "$ACTIVE_SCAN_ENABLED" == false ]] && [[ "$VHOST_SCAN_ENABLED" == false ]]; then
        LOG "INFO" "Skipping wordlist validation"
        return 0
    fi
    # if WORDLIST is empty, check if os is kali linux use seclists /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
    if [ -z "$INPUT_FILE" ]; then
        INPUT_FILE=$WORDLIST_PATH
    fi
    if [[ ! -f "$INPUT_FILE" ]]; then
        LOG "ERROR" "Wordlist file not found: $INPUT_FILE"
        echo -e "${RED}${BOLD}[ERROR]${NC} Wordlist file not found: $INPUT_FILE"
        exit 1
    fi
    echo -e "\n"
    echo -e "${CYAN}${BOLD}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}${BOLD}│${NC}                           ${UNDERLINE}${BOLD}Wordlist Validation${NC}                            ${CYAN}${BOLD}│${NC}"
    echo -e "${CYAN}${BOLD}└──────────────────────────────────────────────────────────────────────────┘${NC}"
    echo -e "\n${YELLOW}${BOLD}[*]${NC} Cleaning and validating wordlist..."
    LOG "INFO" "Starting wordlist validation from: $INPUT_FILE"
    mkdir -p "$THREAD_DIR"
    echo "0" >"$PROGRESS_FILE"
    TOTAL_COUNT=$(grep -Ec '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$' "$INPUT_FILE")
    if [[ $TOTAL_COUNT -eq 0 ]]; then
        echo -e "${RED}${BOLD}[!]${NC} No valid entries found in wordlist"
        LOG "ERROR" "No valid entries found in $INPUT_FILE"
        rm -rf "$THREAD_DIR"
        exit 1 # Changed from return 1 to exit 1
    fi
    echo -e "${YELLOW}${BOLD}[*]${NC} Processing $TOTAL_COUNT unique entries..."
    local CHUNK_SIZE=$(((TOTAL_COUNT + THREAD_COUNT - 1) / THREAD_COUNT))
    LOG "DEBUG" "Splitting wordlist into chunks of size: $CHUNK_SIZE"
    tr -d '\000' <"$INPUT_FILE" | tr -d '\0' | grep -E '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$' | split -l "$CHUNK_SIZE" - "$THREAD_DIR/chunk_"
    local PIDS=()
    for CHUNK in "$THREAD_DIR"/chunk_*; do
        LOG "DEBUG" "Launching validation thread for chunk: $CHUNK"
        VALIDATE_WORDLIST_CHUNK "$CHUNK" &
        PIDS+=($!)
        LOG "DEBUG" "Started wordlist validation thread PID: ${PIDS[-1]}"
    done
    while true; do
        local RUNNING=0
        for PID in "${PIDS[@]}"; do
            if kill -0 "$PID" 2>/dev/null; then
                ((RUNNING++))
            fi
        done
        local CURRENT_PROGRESS=$(cat "$PROGRESS_FILE")
        local PROGRESS=$((CURRENT_PROGRESS * 100 / TOTAL_COUNT))
        printf "\r${YELLOW}${BOLD}[*]${NC} Progress: [${GREEN}${BOLD}%-50s${NC}] %3d%% (%d threads active) " \
            "$(printf '#%.0s' $(seq 1 $((PROGRESS / 2))))" \
            "$PROGRESS" \
            "$RUNNING"
        if [[ $RUNNING -eq 0 ]]; then
            echo
            break
        fi
        sleep 1
    done
    if find "$THREAD_DIR" -name "results_chunk_*" -type f | grep -q .; then
        cat "$THREAD_DIR"/results_chunk_* | sort -u >"$CLEAN_FILE"
        WORKING_COUNT=$(wc -l <"$CLEAN_FILE")
    fi
    if [[ $WORKING_COUNT -eq 0 ]]; then
        echo -e "${RED}${BOLD}[!]${NC} No valid words found!"
        LOG "ERROR" "No valid words found in $INPUT_FILE"
        rm -rf "$THREAD_DIR"
        return 1
    fi
    WORDLIST_PATH="$CLEAN_FILE"
    echo -e -n "\033[1A\033[2K\r"
    echo -e "${GREEN}${BOLD}[✓]${NC} Found $WORKING_COUNT valid entries out of $TOTAL_COUNT tested"
    LOG "INFO" "Wordlist validation complete. Using $WORKING_COUNT valid entries"
    rm -rf "$THREAD_DIR"
    return 0
}
VALIDATE_RESOLVER_CHUNK() {
    local CHUNK="$1"
    local CHUNK_RESULTS="$THREAD_DIR/results_$(basename "$CHUNK")"
    local PROCESSED=0
    local CHUNK_SIZE=$(wc -l <"$CHUNK")
    while read -r RESOLVER; do
        if timeout $TIMEOUT dig @"$RESOLVER" "$TEST_DOMAIN" A +time=1 +tries=1 &>/dev/null &&
            timeout $TIMEOUT dig @"$RESOLVER" "$TEST_DOMAIN" NS +time=1 +tries=1 &>/dev/null; then
            echo "$RESOLVER" >>"$CHUNK_RESULTS"
            LOG "DEBUG" "Working resolver found: $RESOLVER"
        else
            LOG "DEBUG" "Failed resolver: $RESOLVER"
        fi
        ((PROCESSED++))
        local CURRENT=$(cat "$PROGRESS_FILE")
        echo $((CURRENT + 1)) >"$PROGRESS_FILE"
    done <"$CHUNK"
}
CLEAN_RESOLVERS() {
    local INPUT_FILE="$1"
    local TEMP_FILE="$TEMP_DIR/temp_resolvers.txt"
    local VALID_FILE="$TEMP_DIR/valid_resolvers.txt"
    local CLEAN_FILE="$TEMP_DIR/clean_resolvers.txt"
    local TEST_DOMAIN="google.com"
    local TIMEOUT=2
    local WORKING_COUNT=0
    local TOTAL_COUNT=0
    #local THREAD_COUNT=50
    #if ACTIVE_SCAN_ENABLED and PATTERN_RECOGNITION_ENABLED are false, skip resolver validation
    if [[ "$ACTIVE_SCAN_ENABLED" == false ]] && [[ "$PATTERN_RECOGNITION_ENABLED" == false ]]; then
        LOG "INFO" "Skipping resolver validation"
        return 0
    fi
    if [[ -z "$INPUT_FILE" ]]; then
        LOG "DEBUG" "No resolver file provided, skipping validation"
        return 0
    fi
    if [[ ! -f "$INPUT_FILE" ]]; then
        LOG "ERROR" "Resolver file not found: $INPUT_FILE"
        return 1
    fi
    echo -e "\n"
    echo -e "${CYAN}${BOLD}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}${BOLD}│${NC}                           ${UNDERLINE}${BOLD}Resolver Validation${NC}                            ${CYAN}${BOLD}│${NC}"
    echo -e "${CYAN}${BOLD}└──────────────────────────────────────────────────────────────────────────┘${NC}"
    echo -e "\n${YELLOW}${BOLD}[*]${NC} Cleaning and validating resolvers..."
    LOG "INFO" "Starting resolver validation from: $INPUT_FILE"
    grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' "$INPUT_FILE" |
        while read -r IP; do
            if [[ $(echo "$IP" | tr '.' '\n' | awk '$1 >= 0 && $1 <= 255' | wc -l) -eq 4 ]]; then
                echo "$IP"
            else
                LOG "DEBUG" "Invalid IP removed: $IP"
            fi
        done | sort -u >"$TEMP_FILE"
    TOTAL_COUNT=$(wc -l <"$TEMP_FILE")
    if [[ $TOTAL_COUNT -eq 0 ]]; then
        echo -e "${RED}${BOLD}[!]${NC} No valid resolver IPs found in input file"
        LOG "ERROR" "No valid resolver IPs found in $INPUT_FILE"
        exit 1
    fi
    echo -e "${YELLOW}${BOLD}[*]${NC} Testing $TOTAL_COUNT unique resolvers..."
    local THREAD_DIR="$TEMP_DIR/resolver_threads"
    mkdir -p "$THREAD_DIR"
    local PROGRESS_FILE="$THREAD_DIR/progress"
    echo "0" >"$PROGRESS_FILE"
    local CHUNK_SIZE=$(((TOTAL_COUNT + THREAD_COUNT - 1) / THREAD_COUNT))
    split -l "$CHUNK_SIZE" "$TEMP_FILE" "$THREAD_DIR/chunk_"
    local PIDS=()
    for CHUNK in "$THREAD_DIR"/chunk_*; do
        LOG "DEBUG" "Launching validation thread for chunk: $CHUNK"
        VALIDATE_RESOLVER_CHUNK "$CHUNK" &
        PIDS+=($!)
        LOG "DEBUG" "Started resolver validation thread PID: ${PIDS[-1]}"
    done
    while true; do
        local RUNNING=0
        for PID in "${PIDS[@]}"; do
            if kill -0 "$PID" 2>/dev/null; then
                ((RUNNING++))
            fi
        done
        local CURRENT_PROGRESS=$(cat "$PROGRESS_FILE")
        local PROGRESS=$((CURRENT_PROGRESS * 100 / TOTAL_COUNT))
        printf "\r${YELLOW}${BOLD}[*]${NC} Progress: [${GREEN}${BOLD}%-50s${NC}] %3d%% (%d threads active) " \
            "$(printf '#%.0s' $(seq 1 $((PROGRESS / 2))))" \
            "$PROGRESS" \
            "$RUNNING"
        if [[ $RUNNING -eq 0 ]]; then
            echo
            break
        fi
        sleep 1
    done
    if find "$THREAD_DIR" -name "results_chunk_*" -type f | grep -q .; then
        cat "$THREAD_DIR"/results_chunk_* | sort -u >"$CLEAN_FILE"
        WORKING_COUNT=$(wc -l <"$CLEAN_FILE")
    fi
    if [[ $WORKING_COUNT -eq 0 ]]; then
        echo -e "${RED}${BOLD}[!]${NC} No working resolvers found!"
        LOG "ERROR" "No working resolvers found in $INPUT_FILE"
        rm -rf "$THREAD_DIR"
        return 1
    fi
    RESOLVER_FILE="$CLEAN_FILE"
    echo -e -n "\033[1A\033[2K\r"
    echo -e "${GREEN}${BOLD}[✓]${NC} Found $WORKING_COUNT working resolvers out of $TOTAL_COUNT tested"
    LOG "INFO" "Resolver validation complete. Using $WORKING_COUNT working resolvers"
    rm -rf "$THREAD_DIR"
    return 0
}


# From dns.sh
CHECK_DNS_TOOLS() {
    local MISSING_TOOLS=()
    local REQUIRED_TOOLS=("dig" "host" "nslookup")
    for TOOL in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$TOOL" >/dev/null 2>&1; then
            MISSING_TOOLS+=("$TOOL")
        fi
    done
    if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
        LOG "ERROR" "Missing required tools: ${MISSING_TOOLS[*]}"
        echo -e "${RED}${BOLD}[ERROR]${NC} Missing required tools: ${MISSING_TOOLS[*]}"
        echo -e "Please install: ${YELLOW}${BOLD}dnsutils${NC}"
        return 1
    fi
    return 0
}
declare -A RESOLVER_HEALTH
declare -A RESOLVER_LAST_USED
SELECT_RESOLVER() {
    local best_resolver=""
    local min_time=$(($(date +%s) - 2)) # 2 second cooldown
    # Find least recently used healthy resolver
    for resolver in "${RESOLVERS[@]}"; do
        local last_used=${RESOLVER_LAST_USED[$resolver]:-0}
        local health=${RESOLVER_HEALTH[$resolver]:-100}
        if [[ $last_used -lt $min_time && $health -gt 20 ]]; then
            best_resolver=$resolver
            min_time=$last_used
        fi
    done
    # If no resolver found, take any with health > 20
    if [[ -z "$best_resolver" ]]; then
        for resolver in "${RESOLVERS[@]}"; do
            if [[ ${RESOLVER_HEALTH[$resolver]:-100} -gt 20 ]]; then
                best_resolver=$resolver
                break
            fi
        done
    fi
    # Last resort - take first resolver and reset its health
    if [[ -z "$best_resolver" ]]; then
        best_resolver=${RESOLVERS[0]}
        RESOLVER_HEALTH[$best_resolver]=100
    fi
    RESOLVER_LAST_USED[$best_resolver]=$(date +%s)
    echo "$best_resolver"
}
UPDATE_RESOLVER_HEALTH() {
    local resolver="$1"
    local success="$2"
    if [[ $success -eq 0 ]]; then
        RESOLVER_HEALTH[$resolver]=$((${RESOLVER_HEALTH[$resolver]:-100} + 5))
        [[ ${RESOLVER_HEALTH[$resolver]} -gt 100 ]] && RESOLVER_HEALTH[$resolver]=100
    else
        RESOLVER_HEALTH[$resolver]=$((${RESOLVER_HEALTH[$resolver]:-100} - 20))
        [[ ${RESOLVER_HEALTH[$resolver]} -lt 0 ]] && RESOLVER_HEALTH[$resolver]=0
    fi
}
CHECK_SUBDOMAIN() {
    local DOMAIN="$1"
    local TIMEOUT=2
    local MAX_RETRIES=2
    local RETRY_COUNT=0
    if [[ -z "$RESOLVERS" ]]; then
        if [[ -f "$RESOLVER_FILE" ]]; then
            mapfile -t RESOLVERS <"$RESOLVER_FILE"
        else
            RESOLVERS=("1.1.1.1" "8.8.8.8" "9.9.9.9")
        fi
    fi
    local RESOLVER=$(SELECT_RESOLVER)
    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
        # Check with dig
        local DIG_RESULT
        DIG_RESULT=$(dig +short "@$RESOLVER" "$DOMAIN" A +time=$TIMEOUT 2>/dev/null)
        if [[ -n "$DIG_RESULT" ]]; then
            # Validate each IP in result
            while read -r IP; do
                if VALIDATE_IP "$IP"; then
                    # Double check with host command
                    if host "$DOMAIN" "$RESOLVER" &>/dev/null; then
                        LOG "DEBUG" "Subdomain $DOMAIN verified (A: $IP) using resolver $RESOLVER"
                        UPDATE_RESOLVER_HEALTH "$RESOLVER" 0
                        return 0
                    fi
                fi
            done <<<"$DIG_RESULT"
        fi
        # Check CNAME as fallback
        local CNAME_RESULT
        CNAME_RESULT=$(dig +short "@$RESOLVER" "$DOMAIN" CNAME +time=$TIMEOUT 2>/dev/null)
        if [[ -n "$CNAME_RESULT" ]] && [[ "$CNAME_RESULT" =~ \.$DOMAIN$ ]]; then
            if host "$DOMAIN" "$RESOLVER" &>/dev/null; then
                LOG "DEBUG" "Subdomain $DOMAIN verified (CNAME: $CNAME_RESULT) using resolver $RESOLVER"
                UPDATE_RESOLVER_HEALTH "$RESOLVER" 0
                return 0
            fi
        fi
        ((RETRY_COUNT++))
        [ $RETRY_COUNT -lt $MAX_RETRIES ] && sleep 1
    done
    LOG "DEBUG" "Subdomain $DOMAIN not verified using resolver $RESOLVER"
    UPDATE_RESOLVER_HEALTH "$RESOLVER" 1
    return 1
}
DNS_PATTERN_RECOGNITION() {
    local DOMAIN="$1"
    local OUTPUT_FILE="$2"
    local FOUND_COUNT=0
    local RESULTS_FILE="$TEMP_DIR/pattern_results.txt"
    local THREAD_DIR="$TEMP_DIR/pattern_threads"
    local LOCK_DIR="$THREAD_DIR/locks"
    local PROGRESS_FILE="$THREAD_DIR/progress"
    local LOCK_FILE="$LOCK_DIR/progress.lock"
    
    # Create required directories first
    for dir in "$THREAD_DIR" "$LOCK_DIR"; do
        if ! mkdir -p "$dir"; then
            LOG "ERROR" "Failed to create directory: $dir"
            return 1
        fi
    done
    # Create and initialize required files with proper permissions
    for file in "$PROGRESS_FILE" "$LOCK_FILE"; do
        if ! touch "$file" 2>/dev/null || ! chmod 644 "$file" 2>/dev/null; then
            LOG "ERROR" "Failed to create/set permissions for file: $file"
            return 1
        fi
    done
    # Ensure progress file exists
    touch "$PROGRESS_FILE" || {
        LOG "ERROR" "Failed to create progress file"
        return 1
    }
    # Create lock file if it doesn't exist
    touch "$PROGRESS_FILE.lock" || {
        LOG "ERROR" "Failed to create progress lock file"
        return 1
    }
    # Add tracking file for already found patterns
    local GLOBAL_PATTERNS_FILE="$TEMP_DIR/global_patterns.txt"
    [[ ! -f "$GLOBAL_PATTERNS_FILE" ]] && touch "$GLOBAL_PATTERNS_FILE"
    declare -A PATTERNS=(
        ["development"]="dev test stage staging uat qa beta demo poc sandbox alpha preview review canary"
        ["infrastructure"]="api ws rest graphql grpc soap rpc gateway proxy cdn edge cache redis"
        ["admin"]="admin administrator manage portal dashboard console control panel cpanel whm webmin"
        ["services"]="app web mobile m api auth login sso oauth service app-service microservice"
        ["storage"]="storage cdn static assets img images media files docs documents s3 backup archive"
        ["mail"]="mail smtp pop3 imap webmail exchange postfix mx mailer newsletter"
        ["internal"]="internal intranet corp private local dev-internal stg-internal prod-internal"
        ["monitoring"]="monitor status health metrics grafana prometheus uptimerobot uptime ping nagios zabbix kibana observability"
        ["security"]="vpn remote gateway ssl secure auth security waf firewall scan antivirus"
        ["environments"]="prod production staging dev development test testing hotfix release rc qa"
        ["databases"]="db database mysql mongodb postgres postgresql redis elastic elastic-search solr"
        ["networking"]="ns dns mx router gateway proxy lb loadbalancer traffic nat vpn"
        ["collaboration"]="git gitlab github bitbucket svn jira confluence wiki docs team chat slack"
        ["analytics"]="analytics tracking stats statistics metric grafana kibana elk splunk graylog"
        ["regions"]="us eu asia af sa na oc aus nz uk fr de us-east us-west eu-west eu-east ap-south ap-northeast ap-southeast al it es az ca"
        ["cloud"]="aws gcp azure cloud k8s kubernetes docker container pod swarm"
        ["ci"]="ci cd jenkins travis circleci gitlab-ci github-actions"
        ["cdn"]="cdn cloudflare akamai fastly cloudfront"
        ["proxy"]="proxy forward reverse nginx haproxy squid varnish"
        ["gateway"]="gateway api ingress egress"
        ["registry"]="registry docker-registry container-registry"
        ["queue"]="queue kafka rabbitmq zeromq redis"
        ["search"]="search elasticsearch solr lucene"
        ["auth"]="auth oauth sso openid ldap identity"
        ["web"]="web app frontend ui mobile api"
        ["api"]="api rest graphql grpc rpc soap ws"
        ["control"]="control panel dashboard admin portal console management"
        #["debug"]="www m api debug trace tracepoint breakpoint"
    )
    mkdir -p "$THREAD_DIR"
    echo "0" >"$PROGRESS_FILE"
    # Setup pattern header
    if [[ "$RECURSIVE_SCAN_ENABLED" == false ]]; then
        echo -e "\n${CYAN}${BOLD}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}${BOLD}│${NC}                       ${UNDERLINE}Pattern Recognition Results${NC}                        ${CYAN}${BOLD}│${NC}"
        echo -e "${CYAN}${BOLD}└──────────────────────────────────────────────────────────────────────────┘${NC}\n"
    fi
    LOG "INFO" "Starting pattern recognition for $DOMAIN"
    echo -e "${INDENT}${CYAN}${BOLD}[*]${NC} ${WHITE}${BOLD}Pattern Recognition${NC} for ${YELLOW}${BOLD}$DOMAIN${NC}"
    #WILDCARD_DETECTION "$DOMAIN" "$INDENT"
    COMMAND_STATUS=$?
    LOG "DEBUG" "Wildcard detection returned status: $COMMAND_STATUS"
    if [ $COMMAND_STATUS == 2 ]; then
        LOG "INFO" "Aborting scan due to wildcard detection user choice"
        return 0
    fi
    # Calculate total patterns
    for category in "${!PATTERNS[@]}"; do
        for pattern in ${PATTERNS[$category]}; do
            ((TOTAL_PATTERNS++))
        done
    done
    if [ $TOTAL_PATTERNS -eq 0 ]; then
        LOG "ERROR" "No patterns found to scan"
        echo -e "${RED}${BOLD}[!]${NC} No patterns found to scan"
        return 1
    fi
    LOG "DEBUG" "Found $TOTAL_PATTERNS patterns to scan"
    # Create pattern chunks
    local chunk_size=$(((TOTAL_PATTERNS + THREAD_COUNT - 1) / THREAD_COUNT))
    local current_chunk=0
    local current_chunk_file="$THREAD_DIR/chunk_$current_chunk"
    local pattern_count=0
    # Create directory for chunks
    mkdir -p "$THREAD_DIR"
    echo -e "${INDENT}${YELLOW}${BOLD}[*]${NC} Scanning $TOTAL_PATTERNS patterns for $DOMAIN"
    # Prepare pattern chunks
    for category in "${!PATTERNS[@]}"; do
        for pattern in ${PATTERNS[$category]}; do
            echo "$category:$pattern" >>"$THREAD_DIR/chunk_$current_chunk"
            ((pattern_count++))
            if [ $pattern_count -eq $chunk_size ]; then
                ((current_chunk++))
                pattern_count=0
            fi
        done
    done
    scan_pattern_chunk() {
        local chunk="$1"
        local chunk_results="$THREAD_DIR/results_$(basename "$chunk")"
        while IFS=: read -r category pattern; do
            # Check for interrupt before processing each pattern
            if [[ "$INTERRUPT_RECEIVED" == "true" ]]; then
                LOG "DEBUG" "Pattern scan interrupted in chunk processing"
                return 1
            fi
            local variations=(
                "$pattern"
                "${pattern}-${DOMAIN%%.*}"
                "${DOMAIN%%.*}-${pattern}"
                "v1-$pattern"
                "v2-$pattern"
                "$pattern-v1"
                "$pattern-v2"
                "$pattern-api"
                "api-$pattern"
            )
            for variant in "${variations[@]}"; do
                if [[ "$INTERRUPT_RECEIVED" == "true" ]]; then
                    return 1
                fi
                local subdomain="${variant}.$DOMAIN"
                if CHECK_SUBDOMAIN "$subdomain"; then
                    {
                        flock -x 200
                        printf "\033[2K\r" 
                        echo -e "${INDENT}     ${GREEN}${BOLD}[+]${NC} Found ${WHITE}${BOLD}$category${NC} pattern: ${YELLOW}${BOLD}$subdomain${NC}"
                        echo "${category}:${pattern}:${subdomain}" >>"$chunk_results"
                    } 200>"$LOCK_FILE"
                fi
            done
            # Update progress with improved lock handling
            (
                if flock -n 200; then
                    local current=$(cat "$PROGRESS_FILE" 2>/dev/null || echo "0")
                    echo $((current + 1)) >"$PROGRESS_FILE"
                    local progress=$((current * 100 / TOTAL_PATTERNS))
                    printf "\r${INDENT}${YELLOW}${BOLD}[*]${NC} Progress: [${GREEN}${BOLD}%-50s${NC}] %3d%% " \
                        "$(printf '#%.0s' $(seq 1 $((progress / 2))))" \
                        "$progress"
                fi
            ) 200>"$LOCK_FILE"
        done < <(cat "$chunk" 2>/dev/null || true)
    }
    # Launch threads
    local pids=()
    for chunk in "$THREAD_DIR"/chunk_*; do
        scan_pattern_chunk "$chunk" &
        pids+=($!)
    done
    # Monitor progress with interrupt handling
    while true; do
        if [[ "$INTERRUPT_RECEIVED" == "true" ]]; then
            LOG "DEBUG" "Pattern scan interrupted in progress monitoring"
            break
        fi
        local running=0
        for pid in "${pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                ((running++))
            fi
        done
        [[ $running -eq 0 ]] && break
        sleep 1
    done
    echo # New line after progress complete
    # Collect and process results
    if find "$THREAD_DIR" -name "results_chunk_*" -type f | grep -q .; then
        cat "$THREAD_DIR"/results_chunk_* | sort -u >"$RESULTS_FILE"
        FOUND_COUNT=$(wc -l <"$RESULTS_FILE")
    fi
    # Add result display vars
    local CATEGORY_COUNTS=()
    local TOTAL_FOUND=0
    echo -e -n "\033[1A\033[2K\r"
    echo -e "${INDENT}${GREEN}${BOLD}[✓]${NC} Pattern scan complete. Processing results..."
    if [[ -f "$RESULTS_FILE" ]]; then
        echo -e "${INDENT}     ${CYAN}${BOLD}[*]${NC} Pattern scan summary by category:"
        local CURRENT_CATEGORY=""
        local CATEGORY_COUNT=0
        local NEW_FINDINGS=0
        while IFS=: read -r category pattern subdomain; do
            # Skip if this pattern:subdomain was already found
            if grep -q "^${category}:${pattern}:${subdomain}$" "$GLOBAL_PATTERNS_FILE"; then
                continue
            fi
            # Add to global patterns file
            echo "${category}:${pattern}:${subdomain}" >>"$GLOBAL_PATTERNS_FILE"
            if [[ "$CURRENT_CATEGORY" != "$category" ]]; then
                [[ -n "$CURRENT_CATEGORY" ]] && [[ $CATEGORY_COUNT -gt 0 ]] &&
                    echo -e "${INDENT}           ${GRAY}${BOLD}Total:${NC} ${WHITE}${BOLD}$CATEGORY_COUNT${NC}"
                [[ $CATEGORY_COUNT -gt 0 ]] && echo
                echo -e "${INDENT}           ${CYAN}${BOLD}[*]${NC} ${WHITE}${BOLD}${category}${NC}:"
                CURRENT_CATEGORY="$category"
                CATEGORY_COUNT=0
            fi
            ((CATEGORY_COUNT++))
            ((TOTAL_FOUND++))
            ((NEW_FINDINGS++))
            echo -e "${INDENT}           ${GREEN}${BOLD}├─${NC} ${subdomain}"
            echo "$subdomain" >>"$OUTPUT_FILE"
        done <"$RESULTS_FILE"
        # Only show category total if we found anything
        [[ $CATEGORY_COUNT -gt 0 ]] &&
            echo -e "${INDENT}           ${GRAY}${BOLD}Total:${NC} ${WHITE}${BOLD}$CATEGORY_COUNT${NC}"
        if [[ $NEW_FINDINGS -gt 0 ]]; then
            echo -e "\n${INDENT}${GREEN}${BOLD}[✓]${NC} Found ${WHITE}${BOLD}${NEW_FINDINGS}${NC} new subdomains across all patterns for ${YELLOW}${BOLD}${DOMAIN}${NC}"
        else
            echo -e "\n${INDENT}${YELLOW}${BOLD}[!]${NC} No new patterns found"
        fi
    fi
    # Cleanup temporary files but preserve global patterns file
    rm -rf "$THREAD_DIR"
    rm -f "$RESULTS_FILE"
    # If this is not a recursive scan, cleanup the global patterns file
    [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && rm -f "$GLOBAL_PATTERNS_FILE"
    # Add cleanup trap for pattern recognition
    trap 'rm -rf "$THREAD_DIR" "$LOCK_DIR" 2>/dev/null' EXIT
    return 0
}


# From passive.sh
PASSIVE_SCAN() {
    local DOMAIN="$1"
    local RESULTS_FILE="${2:-${OUTPUT:-$PWD/${DOMAIN}_passive.txt}}"
    local TEMP_DIR="${TEMP_DIR:-/tmp/deepdns}"
    LOG "DEBUG" "Starting PASSIVE_SCAN for domain: $DOMAIN"
    mkdir -p "$TEMP_DIR" || {
        LOG "ERROR" "Failed to create temp directory: $TEMP_DIR"
        echo -e "${RED}${BOLD}[ERROR]${NC} Failed to create temp directory"
        return 1
    }
    touch "$RESULTS_FILE" || {
        LOG "ERROR" "Failed to create results file: $RESULTS_FILE"
        echo -e "${RED}${BOLD}[ERROR]${NC} Failed to create results file"
        return 1
    }
    local ST_RESULTS="$TEMP_DIR/${DOMAIN}_st.txt"
    local CRT_RESULTS="$TEMP_DIR/${DOMAIN}_crt.txt"
    local VT_RESULTS="$TEMP_DIR/${DOMAIN}_vt.txt"
    touch "$ST_RESULTS" "$CRT_RESULTS" "$VT_RESULTS" || {
        LOG "ERROR" "Failed to create temporary files"
        echo -e "${RED}${BOLD}[ERROR]${NC} Failed to create temporary files"
        return 1
    }
    if [[ "$RECURSIVE_SCAN_ENABLED" == false ]]; then
        echo -e "\n${CYAN}${BOLD}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}${BOLD}│${NC}                           ${UNDERLINE}Passive Scan Results${NC}                           ${CYAN}${BOLD}│${NC}"
        echo -e "${CYAN}${BOLD}└──────────────────────────────────────────────────────────────────────────┘${NC}\n"
        echo -e "\n${CYAN}${BOLD}[PASSIVE SCAN]${NC} Starting passive enumeration for $DOMAIN"
    fi
    echo -e "${YELLOW}${BOLD}[*]${NC} Querying SecurityTrails API..."
    LOG "DEBUG" "Querying SecurityTrails API"
    if [[ -n "$SECURITYTRAILS_API_KEY" ]]; then
        QUERY_SECURITYTRAILS "$DOMAIN" >"$ST_RESULTS"
        local ST_COUNT=$(wc -l <"$ST_RESULTS")
        [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && echo -e "${GREEN}${BOLD}[✓]${NC} SecurityTrails: Found $ST_COUNT subdomains"
    else
        [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && echo -e "${RED}${BOLD}[!]${NC} SecurityTrails: Skipped (no API key)"
    fi
    echo -e "${YELLOW}${BOLD}[*]${NC} Querying Certificate Transparency logs..."
    LOG "DEBUG" "Querying Certificate Transparency logs"
    QUERY_CRTSH "$DOMAIN" >"$CRT_RESULTS"
    echo -e "${YELLOW}${BOLD}[*]${NC} Querying VirusTotal API..."
    LOG "DEBUG" "Querying VirusTotal API"
    if [[ -n "$VIRUSTOTAL_API_KEY" ]]; then
        QUERY_VIRUSTOTAL "$DOMAIN" >"$VT_RESULTS"
        local VT_COUNT=$(wc -l <"$VT_RESULTS")
        echo -e "${GREEN}${BOLD}[✓]${NC} VirusTotal: Found $VT_COUNT subdomains"
    else
        echo -e "${RED}${BOLD}[!]${NC} VirusTotal: Skipped (no API key)"
    fi
    cat "$ST_RESULTS" "$CRT_RESULTS" "$VT_RESULTS" 2>/dev/null | grep -E "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" | sort -u | while read -r TARGET; do
        echo -e "${INDENT}     ${GREEN}${BOLD}[+]${NC} Found: $TARGET"
        echo "$TARGET" >>"$RESULTS_FILE"
    done
    local TOTAL=$(wc -l <"$RESULTS_FILE")
    [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && echo -e "\n${GREEN}${BOLD}[✓]${NC} Passive scan complete: $TOTAL unique results found"
    LOG "INFO" "Passive scan complete: Found $TOTAL unique subdomains"
    rm -f "$ST_RESULTS" "$CRT_RESULTS" "$VT_RESULTS"
    return 0
}
QUERY_SECURITYTRAILS() {
    local DOMAIN="$1"
    LOG "DEBUG" "Querying SecurityTrails for $DOMAIN"
    local API_URL="https://api.securitytrails.com/v1/domain/$DOMAIN/subdomains"
    if [[ -z "$SECURITYTRAILS_API_KEY" ]]; then
        LOG "WARNING" "SecurityTrails API key not configured"
        return 1
    fi
    local RESULT
    RESULT=$(curl -s -H "APIKEY: $SECURITYTRAILS_API_KEY" "$API_URL")
    echo "$RESULT" | jq -r '.subdomains[]' 2>/dev/null
    LOG "DEBUG" "SecurityTrails query completed for $DOMAIN"
}
QUERY_CRTSH() {
    local DOMAIN="$1"
    local API_URL="https://crt.sh/?q=%.${DOMAIN}&output=json"
    local RESULT
    RESULT=$(curl -s "$API_URL")
    echo "$RESULT" | jq -r '.[].name_value' 2>/dev/null | sort -u
}
QUERY_VIRUSTOTAL() {
    local DOMAIN="$1"
    local API_URL="https://www.virustotal.com/vtapi/v2/domain/report"
    if [[ -z "$VIRUSTOTAL_API_KEY" ]]; then
        LOG "WARNING" "VirusTotal API key not configured"
        return 1
    fi
    local RESULT
    RESULT=$(curl -s -G --data-urlencode "apikey=$VIRUSTOTAL_API_KEY" --data-urlencode "domain=$DOMAIN" "$API_URL")
    echo "$RESULT" | jq -r '.subdomains[]' 2>/dev/null
}


# From active.sh
WILDCARD_DETECTION() {
    local DOMAIN="$1"
    local ATTEMPTS=3
    local WILDCARD_DETECTED=false
    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}[ERROR] DOMAIN PARAMETER IS REQUIRED${NC}"
        return 1
    fi
    for ATTEMPT in $(seq 1 $ATTEMPTS); do
        local RANDOM_SUBDOMAIN="WILDCARD-$(openssl rand -hex 10)"
        local DNS_RESULT
        if ! DNS_RESULT=$(dig +short "$RANDOM_SUBDOMAIN.$DOMAIN" 2>/dev/null); then
            echo -e "${RED}[ERROR] DNS QUERY FAILED FOR $RANDOM_SUBDOMAIN.$DOMAIN${NC}"
            LOG "ERROR" "DNS QUERY FAILED FOR $RANDOM_SUBDOMAIN.$DOMAIN"
            continue
        fi
        if echo "$DNS_RESULT" | grep -q '[0-9]\|CNAME'; then
            WILDCARD_DETECTED=true
            break
        fi
        sleep 1
    done
    if [ "$WILDCARD_DETECTED" = true ]; then
        LOG "WARNING" "WILDCARD DNS DETECTED FOR $DOMAIN"
        if [[ "$RECURSIVE_SCAN_ENABLED" == false ]]; then
            echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} Wildcard DNS detected for $DOMAIN${NC}"
            echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} This may generate false positives${NC}"
            read -p "$(echo -e "${INDENT}${YELLOW}${BOLD}[?]${NC} Do you want to continue scanning? [y/N]: ")" CONTINUE
        else
            read -p "$(echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} Wildcard DNS detected, do you want to continue scanning? [y/N]: ")" CONTINUE
        fi
        if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
            echo -e "${INDENT}${RED}${BOLD}[!]${NC} SCAN ABORTED BY USER${NC}"
            return 2
        fi
        return 0
    else
        [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && echo -e "${INDENT}${GREEN}${BOLD}[✓]${NC} No wildcard DNS detected for $DOMAIN${NC}"
        LOG "INFO" "No wildcard DNS detected for $DOMAIN"
        return 0
    fi
}
CHECK_PORT() {
    local IP="$1"
    local PORT="$2"
    local TIMEOUT=2
    # Try nc with shorter timeout first
    if command -v nc >/dev/null 2>&1; then
        if timeout $TIMEOUT nc -z -w1 "$IP" "$PORT" 2>/dev/null; then
            return 0
        fi
        return 1
    fi
    # Fallback to bash TCP test with timeout
    # This ensures we don't hang on closed ports
    if timeout $TIMEOUT bash -c "</dev/tcp/$IP/$PORT" 2>/dev/null; then
        return 0
    fi
    return 1
}
VHOST_WILDCARD_DETECTION() {
    local DOMAIN="$1"
    local DOMAIN_IP="$2"
    local PORT="$3"
    local INDENT="$4"
    local ATTEMPTS=3
    local WILDCARD_DETECTED=false
    local PROTOCOL=$(DETECT_PROTOCOL "${DOMAIN_IP}" "${PORT}")
    LOG "DEBUG" "Starting VHOST wildcard detection for $DOMAIN on $PROTOCOL://$DOMAIN_IP:$PORT"
    for ATTEMPT in $(seq 1 $ATTEMPTS); do
        local RANDOM_VHOST="wildcard-$(openssl rand -hex 10).${DOMAIN}"
        # Get baseline response with random vhost
        local RESPONSE=$(curl -s -I \
            --connect-timeout 3 \
            --max-time 5 \
            -k \
            -H "Host: ${RANDOM_VHOST}" \
            "${PROTOCOL}://${DOMAIN_IP}:${PORT}" 2>/dev/null)
        local STATUS=$(echo "$RESPONSE" | grep -E "^HTTP" | cut -d' ' -f2)
        # If we get a successful response (200 or 300s) for a random hostname, it's likely a wildcard
        if [[ "$STATUS" =~ ^(200|30[0-9])$ ]]; then
            WILDCARD_DETECTED=true
            break
        fi
        sleep 1
    done
    if [ "$WILDCARD_DETECTED" = true ]; then
        LOG "WARNING" "VHOST WILDCARD DETECTED FOR $DOMAIN on port $PORT"
        if [[ "$RECURSIVE_SCAN_ENABLED" == false ]]; then
            echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} Virtual host wildcard detected for $DOMAIN on port $PORT"
            echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} Server responds to non-existent vhosts - results may be unreliable"
            read -p "$(echo -e "${INDENT}${YELLOW}${BOLD}[?]${NC} Do you want to continue scanning? [y/N]: ")" CONTINUE
        else
            read -p "$(echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} Virtual host wildcard detected, continue scanning? [y/N]: ")" CONTINUE
        fi
        if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
            echo -e "${INDENT}${RED}${BOLD}[!]${NC} VHOST SCAN ABORTED BY USER"
            return 2
        fi
        return 0
    else
        [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && echo -e "${INDENT}${GREEN}${BOLD}[✓]${NC} No virtual host wildcard detected for $DOMAIN on port $PORT"
        LOG "INFO" "No VHOST wildcard detected for $DOMAIN on port $PORT"
        return 0
    fi
}
PROCESS_ACTIVE_CHUNK() {
    local CHUNK="$1"
    local CHUNK_RESULTS="$THREAD_DIR/results_$(basename "$CHUNK")"
    local PROCESSED=0
    local CHUNK_SIZE=$(wc -l <"$CHUNK")
    LOG "DEBUG" "Processing chunk: $CHUNK with $CHUNK_SIZE entries"
    # Define per-chunk progress file
    local PROGRESS_FILE="$THREAD_DIR/progress_$(basename "$CHUNK")"
    echo "0" >"$PROGRESS_FILE"
    while read -r SUBDOMAIN; do
        local TARGET="${SUBDOMAIN}.${DOMAIN}"
        local RESOLVER=${RESOLVERS[$((RANDOM % ${#RESOLVERS[@]}))]}
        LOG "DEBUG" "Testing subdomain: $TARGET using resolver: $RESOLVER"
        if dig +short "$TARGET" "@$RESOLVER" | grep -q '^[0-9]'; then
            LOG "INFO" "Found valid subdomain: $TARGET"
            echo -e "${INDENT}     ${GREEN}${BOLD}[+]${NC} Found: $TARGET"
            echo "$TARGET" >> "$CHUNK_RESULTS"
        fi
        ((PROCESSED++))
        echo "$PROCESSED" >"$PROGRESS_FILE"
        LOG "DEBUG" "Processed $PROCESSED/$CHUNK_SIZE in current chunk"
    done <"$CHUNK"
    LOG "DEBUG" "Completed processing chunk: $CHUNK"
}
ACTIVE_SCAN() {
    local DOMAIN="$1"
    local RESULTS_FILE="${2:-${OUTPUT:-$PWD/${DOMAIN}_ACTIVE.TXT}}"
    local INDENT="$3"
    LOG "DEBUG" "Starting ACTIVE_SCAN for domain: $DOMAIN with $THREAD_COUNT threads"
    LOG "DEBUG" "Results will be written to: $RESULTS_FILE"
    LOG "DEBUG" "Using indent level: $INDENT"
    if [[ "$RECURSIVE_SCAN_ENABLED" == false ]]; then
        echo
        echo -e "${CYAN}${BOLD}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}${BOLD}│${NC}                           ${UNDERLINE}Active Scan Results${NC}                            ${CYAN}${BOLD}│${NC}"
        echo -e "${CYAN}${BOLD}└──────────────────────────────────────────────────────────────────────────┘${NC}\n"
        echo -e "\n${CYAN}${BOLD}[ACTIVE SCAN]${NC} Starting active enumeration for $DOMAIN using $THREAD_COUNT threads"
        LOG "INFO" "Starting non-recursive active scan for $DOMAIN"
    fi
    WILDCARD_DETECTION "$DOMAIN" "$INDENT"
    COMMAND_STATUS=$?
    LOG "DEBUG" "Wildcard detection returned status: $COMMAND_STATUS"
    if [ $COMMAND_STATUS == 2 ]; then
        LOG "INFO" "Aborting scan due to wildcard detection user choice"
        return 0
    fi
    if [[ -n "$WORDLIST_PATH" ]]; then
        [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && echo -e "${INDENT}${YELLOW}${BOLD}[*]${NC} Starting parallel wordlist bruteforce..."
        local TOTAL_WORDS=$(wc -l <"$WORDLIST_PATH")
        LOG "DEBUG" "Using wordlist: $WORDLIST_PATH with $TOTAL_WORDS entries"
        # Create thread directory with proper permissions and cleanup handler
        local THREAD_DIR="$TEMP_DIR/threads"
        local PROGRESS_DIR="$THREAD_DIR/progress"
        # Ensure directories exist with proper permissions
        mkdir -p "$THREAD_DIR" "$PROGRESS_DIR" || {
            LOG "ERROR" "Failed to create thread directories"
            echo -e "${RED}${BOLD}[ERROR]${NC} Failed to create thread directories"
            return 1
        }
        # Ensure directories are writable
        chmod 755 "$THREAD_DIR" "$PROGRESS_DIR" || {
            LOG "ERROR" "Failed to set directory permissions"
            return 1
        }
        # Create and initialize progress file with proper permissions
        local STATUS_FILE="$THREAD_DIR/progress_status"
        echo "0" >"$STATUS_FILE" || {
            LOG "ERROR" "Failed to create progress status file"
            return 1
        }
        chmod 644 "$STATUS_FILE" || {
            LOG "ERROR" "Failed to set progress file permissions"
            return 1
        }
        LOG "DEBUG" "Thread directories created successfully"
        local CHUNK_SIZE=$(((TOTAL_WORDS + THREAD_COUNT - 1) / THREAD_COUNT))
        LOG "DEBUG" "Splitting wordlist into chunks of size: $CHUNK_SIZE"
        # Create chunks with proper error handling
        split -l "$CHUNK_SIZE" "$WORDLIST_PATH" "$THREAD_DIR/chunk_" || {
            LOG "ERROR" "Failed to split wordlist into chunks"
            return 1
        }
        if [[ -z "$RESOLVER_FILE" ]]; then
            RESOLVERS=("1.1.1.1" "8.8.8.8" "9.9.9.9")
            LOG "DEBUG" "Using default resolvers: ${RESOLVERS[*]}"
        else
            mapfile -t RESOLVERS <"$RESOLVER_FILE"
            LOG "DEBUG" "Loaded ${#RESOLVERS[@]} resolvers from $RESOLVER_FILE"
        fi
        local PIDS=()
        for CHUNK in "$THREAD_DIR"/chunk_*; do
            LOG "DEBUG" "Launching thread for chunk: $CHUNK"
            PROCESS_ACTIVE_CHUNK "$CHUNK" &
            PIDS+=($!)
            LOG "DEBUG" "Started thread PID: ${PIDS[-1]}"
        done
        while true; do
            local RUNNING=0
            for PID in "${PIDS[@]}"; do
                if kill -0 "$PID" 2>/dev/null; then
                    ((RUNNING++))
                fi
            done
            # Sum up progress with error handling
            local CURRENT_PROGRESS=0
            local PROGRESS_FILES=("$THREAD_DIR"/progress_*)
            if [ -e "${PROGRESS_FILES[0]}" ]; then
                while read -r val; do
                    ((CURRENT_PROGRESS += val))
                done < <(cat "$THREAD_DIR"/progress_* 2>/dev/null || echo 0)
            fi
            local PROGRESS=$((CURRENT_PROGRESS * 100 / TOTAL_WORDS))
            LOG "DEBUG" "Progress: $PROGRESS% complete, $RUNNING threads active"
            printf "\r${INDENT}${YELLOW}${BOLD}[*]${NC} Progress: [${GREEN}${BOLD}%-50s${NC}] %3d%% (%d threads active) " \
                "$(printf '#%.0s' $(seq 1 $((PROGRESS / 2))))" \
                "$PROGRESS" \
                "$RUNNING"
            if [[ $RUNNING -eq 0 ]]; then
                echo
                LOG "DEBUG" "All threads completed"
                break
            fi
            sleep 1
        done
        wait
        LOG "DEBUG" "All threads finished execution"
        # Merge results from all chunks
        cat "$THREAD_DIR"/results_* >"$RESULTS_FILE" 2>/dev/null
        # Count total unique results
        local TOTAL=$(sort -u "$RESULTS_FILE" | wc -l)
        echo -e "${INDENT}${GREEN}${BOLD}[✓]${NC} Active scan complete: $TOTAL unique results found"
        LOG "DEBUG" "Cleaning up temporary thread directory: $THREAD_DIR"
        rm -rf "$THREAD_DIR" 2>/dev/null || {
            CLEANUP
        }
    fi
    LOG "DEBUG" "ACTIVE_SCAN completed for domain: $DOMAIN"
    return 0
}
# Add helper function for status colors
GET_STATUS_COLOR() {
    local STATUS=$1
    case $STATUS in
    200) echo "${GREEN}" ;;                     # Success
    301 | 302 | 307 | 308) echo "${BLUE}" ;;    # Redirects
    401 | 403) echo "${YELLOW}" ;;              # Auth required/Forbidden
    404) echo "${RED}" ;;                       # Not Found
    500 | 502 | 503 | 504) echo "${MAGENTA}" ;; # Server Errors
    *) echo "${WHITE}" ;;                       # Other codes
    esac
}
PROCESS_VHOST_CHUNK() {
    local CHUNK="$1"
    local PORT="$2"
    local CHUNK_RESULTS="$THREAD_DIR/results_$(basename "$CHUNK")_${PORT}"
    local PROCESSED=0
    local CHUNK_SIZE=$(wc -l <"$CHUNK")
    local PROGRESS_FILE="$THREAD_DIR/progress_$(basename "$CHUNK")_${PORT}"
    echo "0" >"$PROGRESS_FILE"
    # Determine protocol based on port
    local PROTOCOL="http"
    local PROTOCOL=$(DETECT_PROTOCOL "${DOMAIN_IP}" "${PORT}")
    while IFS= read -r SUBDOMAIN; do
        local VHOST="${SUBDOMAIN}.${DOMAIN}"
        # Get random User-Agent
        local RANDOM_UA=${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}
        # Start timing
        local START_TIME=$(date +%s%N)
        # Use curl with connection timeout, max time and SSL options
        local RESPONSE=$(curl -s -I \
            --connect-timeout 3 \
            --max-time 5 \
            -k \
            -A "$RANDOM_UA" \
            -H "Host: ${VHOST}" \
            "${PROTOCOL}://${DOMAIN_IP}:${PORT}" 2>/dev/null)
        # Calculate duration in milliseconds
        local END_TIME=$(date +%s%N)
        local STATUS=$(echo "$RESPONSE" | grep -E "^HTTP" | cut -d' ' -f2)
        local SIZE=$(echo "$RESPONSE" | grep -E "^Content-Length" | cut -d' ' -f2 | awk '{print int($1)}')
        local WORDS=$(echo "$RESPONSE" | wc -w)
        local LINES=$(echo "$RESPONSE" | wc -l)
        local DURATION=$(((END_TIME - START_TIME) / 1000000))
        if [[ "$STATUS" =~ ^(200|30[0-9])$ ]]; then
            # Apply filters if specified
            local SHOW_RESULT=true
            if [[ -n "$VHOST_FILTER" ]]; then
                case "$VHOST_FILTER_TYPE" in
                "status")
                    # Split comma-separated filters into array
                    IFS=',' read -ra FILTERS <<<"$VHOST_FILTER"
                    for FILTER in "${FILTERS[@]}"; do
                        # If any filter matches, hide the result
                        [[ "$STATUS" =~ ^($FILTER)$ ]] && SHOW_RESULT=false && break
                    done
                    ;;
                "size")
                    IFS=',' read -ra FILTERS <<<"$VHOST_FILTER"
                    for FILTER in "${FILTERS[@]}"; do
                        if [[ "$FILTER" =~ ^[0-9]+$ ]]; then
                            [[ "$SIZE" -eq "$FILTER" ]] && SHOW_RESULT=false && break
                        elif [[ "$FILTER" =~ ^\<[0-9]+$ ]]; then
                            local VAL=${FILTER#<}
                            [[ "$SIZE" -lt "$VAL" ]] && SHOW_RESULT=false && break
                        elif [[ "$FILTER" =~ ^\>[0-9]+$ ]]; then
                            local VAL=${FILTER#>}
                            [[ "$SIZE" -gt "$VAL" ]] && SHOW_RESULT=false && break
                        fi
                    done
                    ;;
                "words")
                    IFS=',' read -ra FILTERS <<<"$VHOST_FILTER"
                    for FILTER in "${FILTERS[@]}"; do
                        if [[ "$FILTER" =~ ^[0-9]+$ ]]; then
                            [[ "$WORDS" -eq "$FILTER" ]] && SHOW_RESULT=false && break
                        elif [[ "$FILTER" =~ ^\<[0-9]+$ ]]; then
                            local VAL=${FILTER#<}
                            [[ "$WORDS" -lt "$VAL" ]] && SHOW_RESULT=false && break
                        elif [[ "$FILTER" =~ ^\>[0-9]+$ ]]; then
                            local VAL=${FILTER#>}
                            [[ "$WORDS" -gt "$VAL" ]] && SHOW_RESULT=false && break
                        fi
                    done
                    ;;
                "lines")
                    IFS=',' read -ra FILTERS <<<"$VHOST_FILTER"
                    for FILTER in "${FILTERS[@]}"; do
                        if [[ "$FILTER" =~ ^[0-9]+$ ]]; then
                            [[ "$LINES" -eq "$FILTER" ]] && SHOW_RESULT=false && break
                        elif [[ "$FILTER" =~ ^\<[0-9]+$ ]]; then
                            local VAL=${FILTER#<}
                            [[ "$LINES" -lt "$VAL" ]] && SHOW_RESULT=false && break
                        elif [[ "$FILTER" =~ ^\>[0-9]+$ ]]; then
                            local VAL=${FILTER#>}
                            [[ "$LINES" -gt "$VAL" ]] && SHOW_RESULT=false && break
                        fi
                    done
                    ;;
                esac
            fi
            if [[ "$SHOW_RESULT" == true ]]; then
                {
                    flock 200
                    printf "\033[2K\r" # Clear current line
                    local STATUS_COLOR=$(GET_STATUS_COLOR "$STATUS")
                    echo -e "${INDENT}   ${GREEN}${BOLD}[+]${NC} Found: ${PROTOCOL}://${VHOST}"
                    echo -e "${INDENT}      └─▶ IP: ${DOMAIN_IP} ${PROTOCOL}://${DOMAIN}:${PORT}"
                    echo -e "${INDENT}      [${BOLD}Status: ${STATUS_COLOR}${STATUS}${NC}, ${BOLD}Size: ${BLUE}${SIZE}${NC}, ${BOLD}Words: ${YELLOW}${WORDS}${NC}, ${BOLD}Lines: ${MAGENTA}${LINES}${NC}, ${BOLD}Duration: ${CYAN}${DURATION}ms${NC}]"
                    if [[ "$RAW_OUTPUT" == true ]]; then
                        echo "${DOMAIN_IP}    ${VHOST}" >>"$CHUNK_RESULTS"
                    else
                        echo "${VHOST}:${PORT} ${PROTOCOL}://${DOMAIN}:${PORT} (Status: ${STATUS})" >>"$CHUNK_RESULTS"
                    fi
                } 200>"$STATUS_FILE.lock"
            fi
        fi
        ((PROCESSED++))
        echo "$PROCESSED" >"$PROGRESS_FILE"
    done <"$CHUNK"
}
VHOST_SCAN() {
    local DOMAIN="$1"
    local OUTPUT_FILE="$2"
    local FOUND_COUNT=0
    local INDENT="$3"
    # Array of common browser User-Agents
    local USER_AGENTS=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
    )
    if [[ "$RECURSIVE_SCAN_ENABLED" == false ]]; then
        echo -e "\n${CYAN}${BOLD}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}${BOLD}│${NC}                         ${UNDERLINE}${BOLD}Virtual Host Scan Results${NC}                        ${CYAN}${BOLD}│${NC}"
        echo -e "${CYAN}${BOLD}└──────────────────────────────────────────────────────────────────────────┘${NC}\n"
    fi
    LOG "INFO" "Starting VHOST scan for $DOMAIN"
    local TOTAL_WORDS=$(wc -l <"$WORDLIST_PATH")
    local THREAD_DIR="$TEMP_DIR/vhost_threads"
    mkdir -p "$THREAD_DIR"
    local STATUS_FILE="$THREAD_DIR/progress"
    echo "0" >"$STATUS_FILE"
    local CHUNK_SIZE=$(((TOTAL_WORDS + THREAD_COUNT - 1) / THREAD_COUNT))
    LOG "DEBUG" "Splitting wordlist into chunks of size: $CHUNK_SIZE"
    split -l "$CHUNK_SIZE" "$WORDLIST_PATH" "$THREAD_DIR/chunk_"
    # Get IP address of domain from hosts file
    local DOMAIN_IP=$(grep -E "^([0-9]{1,3}\.){3}[0-9]{1,3}[[:space:]]+$DOMAIN" /etc/hosts | awk '{print $1}')
    #if domain is not found in hosts file, use dig to resolve it
    if [ -z "$DOMAIN_IP" ]; then
        DOMAIN_IP=$(dig +short "$DOMAIN" | head -n1)
    fi
    #if domain is still not resolved, skip the chunk
    if [ -z "$DOMAIN_IP" ]; then
        LOG "ERROR" "Failed to resolve domain: $DOMAIN"
        echo -e "${INDENT}${RED}[ERROR]${NC} Failed to resolve domain: $DOMAIN"
        return 1
    fi
    # Make sure VHOST_PORTS is reset to original ports for each new domain
    if [[ "$RECURSIVE_SCAN_ENABLED" == true ]]; then
        # Store original ports array
        if [[ -z "${ORIGINAL_VHOST_PORTS[*]}" ]]; then
            ORIGINAL_VHOST_PORTS=("${VHOST_PORTS[@]}")
        else
            # Reset to original ports for new subdomain
            VHOST_PORTS=("${ORIGINAL_VHOST_PORTS[@]}")
        fi
    fi
    # Check which ports are open before starting the scan
    local OPEN_PORTS=()
    echo -e "${INDENT}${YELLOW}${BOLD}[*]${NC} Checking for open ports..."
    for PORT in "${VHOST_PORTS[@]}"; do
        echo -n -e "${INDENT}   ${YELLOW}${BOLD}[*]${NC} Testing port ${WHITE}${BOLD}$PORT${NC}... "
        if CHECK_PORT "$DOMAIN_IP" "$PORT"; then
            OPEN_PORTS+=("$PORT")
            echo -e "${GREEN}${BOLD}OPEN${NC}"
        else
            echo -e "${RED}${BOLD}CLOSED${NC}"
            LOG "INFO" "Port $PORT is closed on $DOMAIN_IP"
        fi
    done
    if [ ${#OPEN_PORTS[@]} -eq 0 ]; then
        echo -e "${INDENT}${RED}${BOLD}[!]${NC} No open ports found, skipping VHOST scan"
        LOG "WARNING" "No open ports found for VHOST scan on $DOMAIN"
        return 0
    fi
    echo -e "${INDENT}${GREEN}${BOLD}[✓]${NC} Found ${#OPEN_PORTS[@]} open ports: ${WHITE}${BOLD}${OPEN_PORTS[*]}${NC}"
    # Replace original VHOST_PORTS with only open ports
    VHOST_PORTS=("${OPEN_PORTS[@]}")
    # Continue with existing VHOST scan code for open ports
    for PORT in "${VHOST_PORTS[@]}"; do
        echo -e "${INDENT}${YELLOW}${BOLD}[*]${NC} Starting scan on port ${WHITE}${BOLD}$PORT${NC}"
        VHOST_WILDCARD_DETECTION "$DOMAIN" "$DOMAIN_IP" "$PORT" "$INDENT"
        COMMAND_STATUS=$?
        if [ $COMMAND_STATUS == 2 ]; then
            LOG "INFO" "Aborting VHOST scan on port $PORT due to wildcard detection"
            continue
        fi
        local PIDS=()
        # Launch parallel threads for current port
        for CHUNK in "$THREAD_DIR"/chunk_*; do
            PROCESS_VHOST_CHUNK "$CHUNK" "$PORT" &
            PIDS+=($!)
            LOG "DEBUG" "Started VHOST thread PID: ${PIDS[-1]} for port $PORT"
        done
        # Monitor progress for current port
        while true; do
            local RUNNING=0
            for PID in "${PIDS[@]}"; do
                if kill -0 "$PID" 2>/dev/null; then
                    ((RUNNING++))
                fi
            done
            # Calculate progress for current port
            local CURRENT_PROGRESS=0
            for PF in "$THREAD_DIR"/progress_*_${PORT}; do
                if [[ -f "$PF" ]]; then
                    local VAL=$(cat "$PF")
                    ((CURRENT_PROGRESS += VAL))
                fi
            done
            local PROGRESS=$((CURRENT_PROGRESS * 100 / TOTAL_WORDS))
            printf "\r${INDENT}${YELLOW}${BOLD}[*]${NC} Progress: [${GREEN}${BOLD}%-50s${NC}] %3d%% (%d threads active) " \
                "$(printf '#%.0s' $(seq 1 $((PROGRESS / 2))))" \
                "$PROGRESS" \
                "$RUNNING"
            if [[ $RUNNING -eq 0 ]]; then
                echo
                break
            fi
            sleep 1
        done
        # Combine results for current port
        if find "$THREAD_DIR" -name "results_chunk_*_${PORT}" -type f | grep -q .; then
            cat "$THREAD_DIR"/results_chunk_*_${PORT} | sort -u >"$THREAD_DIR/port_${PORT}_results"
            PORT_COUNT=$(wc -l <"$THREAD_DIR/port_${PORT}_results")
        else
            PORT_COUNT=0
        fi
        #clear last line of progress bar and print on same line
        echo -e -n "\033[1A\033[2K\r"
        echo -e "${INDENT}${GREEN}${BOLD}[✓]${NC} Port ${WHITE}${BOLD}$PORT${NC} scan complete (Found: ${WHITE}${BOLD}${PORT_COUNT}${NC} hosts)"
        # Cleanup temporary files for current port
        rm -f "$THREAD_DIR"/progress_*_${PORT}
        rm -f "$THREAD_DIR"/results_chunk_*_${PORT}
    done
    # Combine all port results at the end
    if find "$THREAD_DIR" -name "port_*_results" -type f | grep -q .; then
        cat "$THREAD_DIR"/port_*_results | sort -u >"$OUTPUT_FILE"
        FOUND_COUNT=$(wc -l <"$OUTPUT_FILE")
        [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && echo -e "${GREEN}${BOLD}[✓]${NC} VHOST scan complete: Found ${WHITE}${BOLD}${FOUND_COUNT}${NC} hosts"
    fi
    # Final cleanup
    rm -rf "$THREAD_DIR"
    return 0
}


# From scan.sh
SCAN_DOMAIN() {
    local TARGET_DOMAIN="$1"
    LOG "DEBUG" "Starting SCAN_DOMAIN for target: $TARGET_DOMAIN"
    if [[ -z "$OUTPUT" ]]; then
        mkdir -p "$DEFAULT_OUTPUT_DIR"
        OUTPUT="${DEFAULT_OUTPUT_DIR}/${TARGET_DOMAIN}.${OUTPUT_FORMAT:-txt}"
    else
        mkdir -p "$(dirname "$OUTPUT")"
    fi
    if ! touch "$OUTPUT" 2>/dev/null; then
        LOG "ERROR" "Cannot write to output file: $OUTPUT"
        echo -e "${RED}${BOLD}[ERROR]${NC} Cannot write to output file: $OUTPUT"
        exit 1
    fi
    echo -e "${BLUE}${BOLD}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}${BOLD}│${NC}                           ${UNDERLINE}${BOLD}Scan Configuration${NC}                             ${BLUE}${BOLD}│${NC}"
    echo -e "${BLUE}${BOLD}└──────────────────────────────────────────────────────────────────────────┘${NC}\n"
    echo -e " ${PURPLE}${BOLD}Target Domain${NC}    │ ${YELLOW}${BOLD}$TARGET_DOMAIN${NC} | ${GRAY}${DIM}$(date '+%Y-%m-%d %H:%M:%S')${NC}\n"
    local SCAN_MODES=""
    [[ "$PASSIVE_SCAN_ENABLED" == true ]] && SCAN_MODES+="${GREEN}${BOLD}Passive${NC} "
    [[ "$ACTIVE_SCAN_ENABLED" == true ]] && SCAN_MODES+="${GREEN}${BOLD}Active${NC} "
    [[ "$RECURSIVE_SCAN" == true ]] && SCAN_MODES+="${GREEN}${BOLD}Recursive(${RECURSIVE_DEPTH})${NC} "
    [[ "$VHOST_SCAN_ENABLED" == true ]] && SCAN_MODES+="${GREEN}${BOLD}VHost(${VHOST_PORTS[@]})${NC} "
    [[ "$PATTERN_RECOGNITION_ENABLED" == true ]] && SCAN_MODES+="${GREEN}${BOLD}Pattern${NC} "
    echo -e " ${PURPLE}${BOLD}Scan Modes${NC}       │ ${SCAN_MODES:-${RED}${BOLD}None${NC}}"
    
    # Add filter information if VHOST scan is enabled
    if [[ "$VHOST_SCAN_ENABLED" == true && -n "$VHOST_FILTER" ]]; then
        echo -e " ${PURPLE}${BOLD}VHOST filter${NC}     │ ${CYAN}${BOLD}${VHOST_FILTER_TYPE}${NC}: ${YELLOW}${BOLD}${VHOST_FILTER}${NC}"
    fi
    
    echo -e " ${PURPLE}${BOLD}Wordlist${NC}         │ ${CYAN}${BOLD}${WORDLIST_PATH}${NC}"
    [[ "$RESOLVER_SCAN" == true ]] && echo -e " ${PURPLE}${BOLD}Resolver File${NC}    │ ${CYAN}${BOLD}$RESOLVER_FILE${NC}"
    echo -e " ${PURPLE}${BOLD}Thread Count${NC}     │ ${CYAN}${BOLD}${THREAD_COUNT}${NC}"
    echo -e " ${PURPLE}${BOLD}Output File${NC}      │ ${CYAN}${BOLD}${OUTPUT:-Not specified}${NC}"
    [[ "$DEBUG" == true ]] && echo -e " ${PURPLE}${BOLD}Debug Mode${NC}       │ ${GREEN}${BOLD}Enabled${NC}"
    [[ "$DEBUG" == true ]] && echo -e " ${PURPLE}${BOLD}Log File${NC}         │ ${CYAN}${BOLD}${DEBUG_LOG}${NC}"
    [[ "$VERBOSE" == true ]] && echo -e " ${PURPLE}${BOLD}Verbose Mode${NC}     │ ${GREEN}${BOLD}Enabled${NC}"
    CHECK_DNS_TOOLS || return 1
    CLEAN_RESOLVERS "$RESOLVER_FILE"
    CLEAN_WORDLIST "$WORDLIST_PATH"
    echo -e "\n${BLUE}${BOLD}============================================================================${NC}"
    echo -e "\n${BLUE}${BOLD}[»]${NC} ${UNDERLINE}Scan Status${NC}\n"
    if [[ -n "$OUTPUT" ]]; then
        mkdir -p "$(dirname "$OUTPUT")"
    else
        OUTPUT="$PWD/${TARGET_DOMAIN}_scan.txt"
    fi
    local PASSIVE_OUT="$TEMP_DIR/${TARGET_DOMAIN}_passive_tmp.txt"
    local ACTIVE_OUT="$TEMP_DIR/${TARGET_DOMAIN}_active_tmp.txt"
    local VHOST_OUT="$TEMP_DIR/${TARGET_DOMAIN}_vhost_tmp.txt"
    local PATTERN_OUT="$TEMP_DIR/${TARGET_DOMAIN}_pattern_tmp.txt"
    local FINAL_TMP="$TEMP_DIR/${TARGET_DOMAIN}_final_tmp.txt"
    if [[ "$RECURSIVE_SCAN" == true ]]; then
        echo -e "\n${CYAN}${BOLD}[RECURSIVE SCAN]${NC} Starting recursive enumeration (depth: $RECURSIVE_DEPTH)"
        RECURSIVE_SCAN "$TARGET_DOMAIN" "$RECURSIVE_DEPTH" "$FINAL_TMP"
    else
        [[ "$PASSIVE_SCAN_ENABLED" == true ]] && PASSIVE_SCAN "$TARGET_DOMAIN" "$PASSIVE_OUT"
        [[ "$ACTIVE_SCAN_ENABLED" == true ]] && ACTIVE_SCAN "$TARGET_DOMAIN" "$ACTIVE_OUT"
        [[ "$VHOST_SCAN_ENABLED" == true ]] && VHOST_SCAN "$TARGET_DOMAIN" "$VHOST_OUT"
        [[ "$PATTERN_RECOGNITION_ENABLED" == true ]] && DNS_PATTERN_RECOGNITION "$TARGET_DOMAIN" "$PATTERN_OUT"
        cat "$TEMP_DIR/${TARGET_DOMAIN}"_*_tmp.txt 2>/dev/null | sort -u >"$FINAL_TMP"
    fi
    # Check if output file exists and prompt for overwrite
    if [[ -f "$OUTPUT" ]]; then
        echo -e "${YELLOW}${BOLD}[!]${NC} Output file exists: ${CYAN}${BOLD}$OUTPUT${NC}"
        while true; do
            echo -n -e "${YELLOW}${BOLD}[?]${NC} Overwrite? [${GREEN}${BOLD}y${NC}/${RED}${BOLD}N${NC}] "
            read -r REPLY
            if [[ "$REPLY" =~ ^[Yy]$ ]]; then
                echo -e "${GREEN}${BOLD}[✓]${NC} Overwriting existing file"
                mv "$FINAL_TMP" "$OUTPUT"
                break
            elif [[ "$REPLY" =~ ^[Nn]$ ]] || [[ -z "$REPLY" ]]; then
                echo -e "${RED}${BOLD}[!]${NC} Keeping existing file"
                rm -f "$FINAL_TMP"
                break
            fi
        done
    else
        mv "$FINAL_TMP" "$OUTPUT"
    fi
    rm -f "$TEMP_DIR/${TARGET_DOMAIN}"_*_tmp.txt
    echo -e "\n${BLUE}${BOLD}[»]${NC} ${UNDERLINE}Scan Completed${NC}"
    LOG "DEBUG" "SCAN_DOMAIN completed for target: $TARGET_DOMAIN"
    return 0
}
FORMAT_RESULTS() {
    local DOMAIN="$1"
    local OUTPUT_FILE="$2"
    local TEMP_FILE="$TEMP_DIR/format_temp.txt"
    local TEMP_MERGED="$TEMP_DIR/format_merged.txt"
    LOG "INFO" "Formatting results for $DOMAIN"
    if [[ "$RAW_OUTPUT" == true ]]; then
        # For raw output, directly use collected results without extra processing
        if [[ -s "$OUTPUT_FILE" ]]; then
            sort -u "$OUTPUT_FILE" > "$TEMP_FILE"
            mv "$TEMP_FILE" "$OUTPUT_FILE"
            local TOTAL=$(wc -l < "$OUTPUT_FILE")
            LOG "INFO" "Saved $TOTAL raw entries to $OUTPUT_FILE"
        else
            LOG "WARNING" "No results found for $DOMAIN"
            TOTAL=0
        fi
    else
        find "${DEFAULT_OUTPUT_DIR}" -type f -name "${DOMAIN}_*.txt" -exec cat {} + >"$TEMP_MERGED"
        if [[ -s "$TEMP_MERGED" ]] || [[ -s "$OUTPUT_FILE" ]]; then
            cat "$TEMP_MERGED" "$OUTPUT_FILE" 2>/dev/null |
                grep -Eh "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" |
                sort -u |
                grep -v "^$DOMAIN$" >"$TEMP_FILE"
            mv "$TEMP_FILE" "$OUTPUT_FILE"
            local TOTAL=$(wc -l <"$OUTPUT_FILE")
            LOG "INFO" "Saved $TOTAL unique domains to $OUTPUT_FILE"
        else
            LOG "WARNING" "No results found for $DOMAIN"
            TOTAL=0
        fi
    fi
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    DURATION_FORMATTED=$(printf '%02dh:%02dm:%02ds' $((DURATION / 3600)) $(((DURATION % 3600) / 60)) $((DURATION % 60)))
    echo -e "\n"
    echo -e "${BLUE}${BOLD}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}${BOLD}│${NC}                           ${UNDERLINE}Final Scan Summary${NC}                             ${BLUE}${BOLD}│${NC}"
    echo -e "${BLUE}${BOLD}└──────────────────────────────────────────────────────────────────────────┘${NC}\n"
    echo -e " ${PURPLE}${BOLD}Target Domain${NC}    │ ${YELLOW}${BOLD}$DOMAIN${NC}"
    echo -e " ${PURPLE}${BOLD}Total Subdomains${NC} | ${GREEN}${BOLD}$TOTAL${NC} unique results"
    echo -e " ${PURPLE}${BOLD}Scan Duration${NC}    │ ${WHITE}${BOLD}$DURATION_FORMATTED${NC}"
    echo -e " ${PURPLE}${BOLD}Finished${NC}         │ ${WHITE}${BOLD}$(date '+%Y-%m-%d %H:%M:%S')${NC}"
    echo -e " ${PURPLE}${BOLD}Output Location${NC}  | ${CYAN}${BOLD}$OUTPUT_FILE${NC}\n"
    rm -f "$TEMP_FILE" "$TEMP_MERGED"
    return 0
}
RECURSIVE_SCAN() {
    local DOMAIN="$1"
    local DEPTH="$2"
    local RESULTS_FILE="${3:-${OUTPUT:-$PWD/${DOMAIN}_recursive.txt}}"
    local INDENT=""
    RECURSIVE_SCAN_ENABLED=true
    for ((i = 0; i < (4 - DEPTH); i++)); do
        INDENT+="    "
    done
    local DEPTH_MARKER=""
    for ((i = 0; i < (4 - DEPTH); i++)); do
        DEPTH_MARKER+="→"
    done
    echo -e "${INDENT}${CYAN}${BOLD}[${DEPTH_MARKER}]${NC} Scanning ${YELLOW}${BOLD}${DOMAIN}${NC}"
    LOG "INFO" "Starting recursive scan for $DOMAIN (depth: $DEPTH)"
    if [[ " ${GLOBAL_SEEN_DOMAINS[@]} " =~ " ${DOMAIN} " ]]; then
        echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} Domain already scanned, skipping"
        return 0
    fi
    GLOBAL_SEEN_DOMAINS+=("$DOMAIN")
    local CURRENT_RESULTS="$TEMP_DIR/${DOMAIN}_subdomains.txt"
    touch "$CURRENT_RESULTS"
    if [[ "$PASSIVE_SCAN_ENABLED" == true ]]; then
        echo -e "${INDENT}${BLUE}${BOLD}[+]${NC} Running passive scan"
        PASSIVE_SCAN "$DOMAIN" "$CURRENT_RESULTS.passive" >/dev/null
        if [[ -f "$CURRENT_RESULTS.passive" ]]; then
            local COUNT=$(wc -l <"$CURRENT_RESULTS.passive")
            echo -e "${INDENT}${GREEN}${BOLD}[✓]${NC} Found $COUNT subdomains via passive scan"
            cat "$CURRENT_RESULTS.passive" >>"$CURRENT_RESULTS"
        fi
    fi
    if [[ "$ACTIVE_SCAN_ENABLED" == true ]]; then
        echo -e "${INDENT}${BLUE}${BOLD}[+]${NC} Running active scan"
        ACTIVE_SCAN "$DOMAIN" "$CURRENT_RESULTS.active" "$INDENT"
        if [[ -f "$CURRENT_RESULTS.active" ]]; then
            local COUNT=$(wc -l <"$CURRENT_RESULTS.active")
            cat "$CURRENT_RESULTS.active" >>"$CURRENT_RESULTS"
        fi
    fi
    if [[ "$VHOST_SCAN_ENABLED" == true ]]; then
        echo -e "${INDENT}${BLUE}${BOLD}[+]${NC} Running virtual host scan"
        VHOST_SCAN "$DOMAIN" "$CURRENT_RESULTS.vhost" "$INDENT"
        if [[ -f "$CURRENT_RESULTS.vhost" ]]; then
            local COUNT=$(wc -l <"$CURRENT_RESULTS.vhost")
            cat "$CURRENT_RESULTS.vhost" >>"$CURRENT_RESULTS"
        fi
    fi
    if [[ "$PATTERN_RECOGNITION_ENABLED" == true ]]; then
        echo -e "${INDENT}${BLUE}${BOLD}[+]${NC} Running pattern recognition scan"
        DNS_PATTERN_RECOGNITION "$DOMAIN" "$CURRENT_RESULTS.pattern" "$INDENT"
        if [[ -f "$CURRENT_RESULTS.pattern" ]]; then
            local COUNT=$(wc -l <"$CURRENT_RESULTS.pattern")
            cat "$CURRENT_RESULTS.pattern" >>"$CURRENT_RESULTS"
        fi
    fi
    if [[ -s "$CURRENT_RESULTS" ]]; then
        cat "$CURRENT_RESULTS" >>"$RESULTS_FILE"
        local TOTAL=$(wc -l <"$CURRENT_RESULTS")
        echo -e "${INDENT}${GREEN}${BOLD}[✓]${NC} Total unique subdomains for ${YELLOW}${BOLD}${DOMAIN}${NC}: ${GREEN}${BOLD}${TOTAL}${NC}"
    else
        echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} No subdomains found for ${DOMAIN}"
    fi
    if [[ "$DEPTH" -gt 1 ]] && [[ -s "$CURRENT_RESULTS" ]]; then
        local SUBDOMAIN_COUNT=0
        local UNIQUE_SUBDOMAINS=($(sort -u "$CURRENT_RESULTS"))
        for SUBDOMAIN in "${UNIQUE_SUBDOMAINS[@]}"; do
            if ! VALIDATE_DOMAIN "$SUBDOMAIN" || [[ " ${GLOBAL_SEEN_DOMAINS[@]} " =~ " ${SUBDOMAIN} " ]]; then
                continue
            fi
            RECURSIVE_SCAN "$SUBDOMAIN" "$((DEPTH - 1))" "$RESULTS_FILE"
            SUBDOMAIN_COUNT=$((SUBDOMAIN_COUNT + 1))
        done
    fi
    return 0
}




# Add trap for SIGINT and SIGTERM
trap 'CLEANUP' SIGINT SIGTERM

# Setup initial state
CREATE_TEMP_DIR

# Main execution flow
SHOW_VERSION

if [ $# -eq 0 ]; then
    SHOW_HELP
    exit 1
fi

# Command line argument parsing
if [ $# -eq 1 ]; then
    case "${1,,}" in
        "install")
            INSTALL_SCRIPT
            exit $?
            ;;
        "update")
            UPDATE_SCRIPT
            exit $?
            ;;
        "uninstall")
            UNINSTALL_SCRIPT
            exit $?
            ;;
        "-h" | "--help")
            LOG "INFO" "SHOW_HELP"
            SHOW_HELP
            exit 0
            ;;
        "-v" | "--version")
            LOG "INFO" "SHOW VERSION"
            exit 0
            ;;
        *)
            if VALIDATE_DOMAIN "$1"; then
                DOMAIN="$1"
                PASSIVE_SCAN_ENABLED=true
                ACTIVE_SCAN_ENABLED=true
                PATTERN_RECOGNITION_ENABLED=true
                VHOST_SCAN_ENABLED=true
                RECURSIVE_SCAN_ENABLED=false
            else
                LOG "INFO" "SHOW_HELP - INVALID argument"
                SHOW_HELP
                exit 1
            fi
            ;;
    esac
fi

while [[ "$#" -gt 0 ]]; do
    case $1 in
    -D | --debug)
        DEBUG=true
        if [[ "$2" != "" ]] && [[ ! "$2" =~ ^- ]]; then
            DEBUG_LOG="$2"
            shift
        fi
        ;;
    -V | --verbose)
        VERBOSE=true
        ;;
    -d | --domain)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Domain argument missing${NC}\n" && LOG "ERROR" "Domain argument missing" && exit 1
        DOMAIN="$2"
        shift
        ;;
    -w | --wordlist)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Wordlist argument missing${NC}\n" && LOG "ERROR" "Wordlist argument missing" && exit 1
        ! FILE_EXISTS "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Wordlist file not found: $2${NC}\n" && LOG "ERROR" "Wordlist file not found: $2" && exit 1
        ! FILE_READABLE "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}File is not readable : $2${NC}\n" && LOG "ERROR" "Wordlist file not readable: $2" && exit 1
        WORDLIST_PATH="$2"
        shift
        ;;
    -o | --output)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Output file argument missing${NC}\n" && LOG "ERROR" "Output file argument missing" && exit 1
        OUTPUT="$2"
        shift
        ;;
    -r | --recursive)
        RECURSIVE_SCAN=true
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Recursive depth argument missing${NC}\n" && LOG "ERROR" "Recursive depth argument missing" && exit 1
        ! IS_NUMBER "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid recursive depth: $2${NC}\n" && LOG "ERROR" "Invalid recursive depth: $2" && exit 1
        if [ "$2" -gt 0 ] && [ "$2" -lt 11 ]; then
            RECURSIVE_DEPTH="$2"
        else
            LOG "ERROR" "Recursive depth must be between 1 and 10"
            echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Recursive depth must be between 1 and 10${NC}\n"
            exit 1
        fi
        shift
        ;;
    -p | --passive)
        PASSIVE_SCAN_ENABLED=true
        ;;

    -a | --active)
        ACTIVE_SCAN_ENABLED=true
        ;;
    -R | --resolver)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Resolver file argument missing${NC}\n" && LOG "ERROR" "Resolver file argument missing" && exit 1
        ! FILE_EXISTS "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Resolver file not found: $2${NC}\n" && LOG "ERROR" "Resolver file not found: $2" && exit 1
        ! FILE_READABLE "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}File is not readable : $2${NC}\n" && LOG "ERROR" "Resolver file not readable: $2" && exit 1
        FILE_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Resolver file is empty : $2${NC}\n" && LOG "ERROR" "Resolver file is empty: $2" && exit 1

        RESOLVER_SCAN=true
        RESOLVER_FILE="$2"
        shift
        ;;
    --st-key)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}SecurityTrails API key missing${NC}\n" && LOG "ERROR" "SecurityTrails API key missing" && exit 1
        ! VALIDATE_API_KEY "$2" "ST" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid SecurityTrails API key format${NC}\n" && LOG "ERROR" "Invalid SecurityTrails API key format" && exit 1
        SECURITYTRAILS_API_KEY="$2"
        PASSIVE_SCAN_ENABLED=true
        shift
        ;;
    --vt-key)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}VirusTotal API key missing${NC}\n" && LOG "ERROR" "VirusTotal API key missing" && exit 1
        VIRUSTOTAL_API_KEY="$2"
        PASSIVE_SCAN_ENABLED=true
        shift
        ;;
    --censys-id)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Censys API ID missing${NC}\n" && LOG "ERROR" "Censys API ID missing" && exit 1
        CENSYS_API_ID="$2"
        PASSIVE_SCAN_ENABLED=true
        shift
        ;;
    --censys-secret)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Censys API secret missing${NC}\n" && LOG "ERROR" "Censys API secret missing" && exit 1
        CENSYS_API_SECRET="$2"
        PASSIVE_SCAN_ENABLED=true
        shift
        ;;
    --vhost)
        VHOST_SCAN_ENABLED=true
        ;;
    --pattern)
        PATTERN_RECOGNITION_ENABLED=true
        ;;
    --vhost-port)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Port list missing${NC}\n" && LOG "ERROR" "Port list missing" && exit 1
        # Remove duplicate ports using sort -u
        VHOST_PORTS=($(echo "$2" | tr ',' '\n' | sort -un | tr '\n' ' '))
        # Validate ports
        for port in "${VHOST_PORTS[@]}"; do
            if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
                echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid port number: $port${NC}\n"
                LOG "ERROR" "Invalid port number: $port"
                exit 1
            fi
        done
        LOG "DEBUG" "Using unique ports: ${VHOST_PORTS[*]}"
        shift
        ;;
    --vhost-filter)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Filter argument missing${NC}\n" && LOG "ERROR" "Filter argument missing" && exit 1
        # Remove duplicate filters
        VHOST_FILTER=$(echo "$2" | tr ',' '\n' | sort -u | tr '\n' ',' | sed 's/,$//')
        LOG "DEBUG" "Using unique filters: $VHOST_FILTER"
        shift
        ;;
    --vhost-filter-type)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Filter type argument missing${NC}\n" && LOG "ERROR" "Filter type argument missing" && exit 1
        case "${2,,}" in
            "status"|"size"|"words"|"lines")
                VHOST_FILTER_TYPE="$2"
                ;;
            *)
                echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid filter type. Use: status, size, words, or lines${NC}\n"
                LOG "ERROR" "Invalid filter type: $2"
                exit 1
                ;;
        esac
        shift
        ;;
    -t | --threads)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Thread count missing${NC}\n" && LOG "ERROR" "Thread count missing" && exit 1
        ! IS_NUMBER "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid thread count: $2${NC}\n" && LOG "ERROR" "Invalid thread count: $2" && exit 1
        if [ "$2" -gt 0 ] && [ "$2" -le 100 ]; then
            THREAD_COUNT="$2"
        else
            LOG "ERROR" "Thread count must be between 1 and 50"
            echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Thread count must be between 1 and 50${NC}\n"
            exit 1
        fi
        shift
        ;;
    --raw)
        RAW_OUTPUT=true
        ;;
    *)
        ! VALIDATE_DOMAIN "$1" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid domain: $1${NC}\n" && LOG "ERROR" "Invalid domain: $1" && exit 1
        DOMAIN="$1"
        ;;
    esac
    shift
done

# Main execution
if [ "$DEBUG" = true ]; then
    # Override debug log if provided
    if [[ -n "$2" ]]; then
        DEBUG_LOG="$2"
    fi

    # Ensure log directory exists
    mkdir -p "$(dirname "$DEBUG_LOG")"

    if [[ -f "$DEBUG_LOG" ]]; then
        rm -f "$DEBUG_LOG" || {
            echo -e "\n${RED}${BOLD}[ERROR]${NC} Unable to remove log file: $DEBUG_LOG"
            exit 1
            CLEANUP
        }
    fi

    touch "$DEBUG_LOG" || {
        echo -e "\n${RED}${BOLD}[ERROR]${NC} Unable to create log file: $DEBUG_LOG"
        exit 1
    }
fi

# Modify the main scanning section to include interrupt checks:
if [[ -n "$DOMAIN" ]]; then
    SCAN_DOMAIN "$DOMAIN" || {
        echo -e "\n${RED}${BOLD}[ERROR]${NC} Scan failed for domain: $DOMAIN"
        exit 1
    }
fi

FORMAT_RESULTS "$DOMAIN" "$OUTPUT"
exit $?

