#!/bin/bash
######################################################################
#         DeepDNS - Advanced DNS Enumeration Script                  #
######################################################################

#FIXME CLEAN_RESOLVER DONT USE WHEN PASSIVE_SCAN
#FIXME Capture the flag 
#TODO Improved wildcard detection
#TODO Add more API's
#TODO VHOST scan
#TODO DNSSEC validation scan
#TODO DNS pattern recognition
#TODO JSON/XML export
#TODO Certificate monitoring
#TODO Certificate Transparency monitoring
#TODO Domain takeover detection
#TODO  Pattern analysis


START_TIME=$(date +%s)


# Global configuration
declare -g VERBOSE=false
declare -g DEBUG=false 
declare -g LOG_DIR="/tmp/log/deepdns"
declare -g SCRIPT=$(basename $0)
declare -g DEBUG_LOG=$SCRIPT"_debug.log"
declare -g VERSION="1.0.0"
declare -g AUTHOR="Ervis Tusha"

# Default configuration 
declare -g DEFAULT_WORDLIST="/usr/share/wordlists/amass/subdomains-top1mil-5000.txt"
#declare -g DEFAULT_THREADS=10
declare -g DEFAULT_RECURSIVE_DEPTH=3

# Initialize variables
declare -g DOMAIN=""
#declare -g THREADS=$DEFAULT_THREADS
declare -g OUTPUT=""
declare -g RECURSIVE_SCAN=false
declare -g RECURSIVE_DEPTH=$DEFAULT_RECURSIVE_DEPTH
declare -g PASSIVE_SCAN=false
declare -g ACTIVE_SCAN=false
declare -g RESOLVER_SCAN=false
declare -g RESOLVER_FILE=""
declare -g WORDLIST_PATH=$DEFAULT_WORDLIST

# API Configuration
declare -g SECURITYTRAILS_API_KEY=""
declare -g VIRUSTOTAL_API_KEY=""
declare -g CENSYS_API_ID=""
declare -g CENSYS_API_SECRET=""

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'
readonly GRAY='\033[0;90m'
readonly PURPLE='\033[0;35m'
readonly DIM='\033[2m'
readonly UNDERLINE='\033[4m'
readonly BLINK='\033[5m'
readonly ITALIC='\033[3m'
readonly REVERSE='\033[7m'
readonly WHITE='\033[1;37m'

# Add this to global variables section
declare -g GLOBAL_SEEN_DOMAINS=()

# Function: LOG
# Log messages to /tmp/log/$SCRIPT.log
LOG() {
    # $1 = STATUS
    # $2 = MESSAGE
    # $3 = DEBUG_LOG
    # if $1 is empty, return 1
    # if $2 is empty, return 1
    # if $1 is not valid, set to INFO

    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: LOG() no status provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: LOG() no message provided"
        return 1
    fi
    #check if $1 is INFO, WARNING, ERROR, DEBUG else add INFO to $1
    if ! [[ "$1" =~ ^(INFO|WARNING|ERROR|DEBUG)$ ]]; then
        STATUS="[INFO] : $1"
    else
        STATUS="$1"
        #if $2 provided then DEBUG_LOG=$2
        if [[ -z "$2" ]]; then
            DEBUG_LOG=$2
        fi
    fi
    

    MESSAGE="$2"
    #check if $3 is set then DEBUG_LOG=$3
    if [[ -n "$3" ]]; then
        DEBUG_LOG="$3"
    fi

    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') [$STATUS] : $MESSAGE" >>"$DEBUG_LOG"
    [[ "$VERBOSE" == "true" ]] && echo "[$STATUS] : $MESSAGE"

    return 0
}

# Function: IS_INSTALLED
# Checks if a package is installed
IS_INSTALLED() {
    if [[ -z "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No package name provided"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No package name provided" >>"$DEBUG_LOG"
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

# Function: INSTALL
# Installs a package
# Function to install the script
INSTALL_SCRIPT() {
    local SCRIPT=""
    SCRIPT="$(basename "$0")"
    # Check if $1 is empty
    if [[ -z "$1" ]]; then
        INSTALL_DIR="/usr/local/bin"
    else
        # Check if $1 is a valid directory
        if ! [[ -d "$1" ]]; then
            [[ "$VERBOSE" == "true" ]] && echo "ERROR:INSTALL_SCRIPT Invalid directory provided"
            [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:INSTALL_SCRIPT Invalid directory provided" >>"$DEBUG_LOG"
            return 1
        fi
        INSTALL_DIR="$1"
    fi

    # Check if user has sudo privileges if now return 1
    if [[ "$EUID" -ne 0 ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO:INSTALL_SCRIPT User does not have root privileges"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:INSTALL_SCRIPT User does not have root privileges" >>"$DEBUG_LOG"
        return 1
    fi

    # Check if the script is already installed
    if command -v "$SCRIPT" >/dev/null 2>&1; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO:INSTALL_SCRIPT $SCRIPT is already installed"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:INSTALL_SCRIPT $SCRIPT is already installed" >>"$DEBUG_LOG"
        return 0
    fi

    # Remove .sh extension if present
    NEW_NAME=$(echo "$SCRIPT" | sed 's/\.sh$//')

    # Install the script
    cp "$0" "$INSTALL_DIR/$NEW_NAME"
    chmod +x "$INSTALL_DIR/$NEW_NAME"

    # check if the script was installed successfully
    if ! command -v "$NEW_NAME" >/dev/null 2>&1; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR:INSTALL_SCRIPT Failed to install $NEW_NAME"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:INSTALL_SCRIPT Failed to install $NEW_NAME" >>"$DEBUG_LOG"
        return 1
    fi
    [[ "$VERBOSE" == "true" ]] && echo "INFO:INSTALL_SCRIPT $NEW_NAME installed successfully"
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:INSTALL_SCRIPT $NEW_NAME installed successfully" >>"$DEBUG_LOG"
    return 0
}

## Function: UNINSTALL
#UNINSTALL_SCRIPT() {
#    local SCRIPT="$1"
#    local INSTALL_DIR="/usr/local/bin"
#    echo "$SCRIPT"
#    # check if user has sudo privileges if now return 1
#    if [[ "$EUID" -ne 0 ]]; then
#        [[ "$VERBOSE" == "true" ]] && echo "INFO:UNINSTALL_SCRIPT User does not have root privileges"
#        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:UNINSTALL_SCRIPT User does not have root privileges" >>"$DEBUG_LOG"
#        return 1
#    fi
#
#    #check if the script is installed
#    if ! command -v "$SCRIPT" >/dev/null 2>&1; then
#        [[ "$VERBOSE" == "true" ]] && echo "INFO:UNINSTALL_SCRIPT $SCRIPT is not installed"
#        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:UNINSTALL_SCRIPT $SCRIPT is not installed" >>"$DEBUG_LOG"
#        return 1
#    fi
#
#    # uninstall the script
#    rm -r "$INSTALL_DIR/$SCRIPT"
#    
#    # check if the script was uninstalled successfully
#    if command -v "$SCRIPT" >/dev/null 2>&1; then
#        [[ "$VERBOSE" == "true" ]] && echo "ERROR:UNINSTALL_SCRIPT Failed to uninstall $SCRIPT"
#        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:UNINSTALL_SCRIPT Failed to uninstall $SCRIPT" >>"$DEBUG_LOG"
#        return 1
#    fi
#    [[ "$VERBOSE" == "true" ]] && echo "INFO:UNINSTALL_SCRIPT $SCRIPT uninstalled successfully"
#    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:UNINSTALL_SCRIPT $SCRIPT uninstalled successfully" >>"$DEBUG_LOG"
#    return 0
#
#}
#
## Function: UPDATE
## Updates
#UPDATE() {
#
#    #check if user has sudo privileges if now return 1
#    if [[ "$EUID" -ne 0 ]]; then
#        [[ "$VERBOSE" == "true" ]] && echo "INFO:UPDATE User does not have root privileges"
#        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:UPDATE User does not have root privileges" >>"$DEBUG_LOG"
#        return 1
#    fi
#
#    #check if script is installed
#    if ! command -v "$SCRIPT" >/dev/null 2>&1; then
#        [[ "$VERBOSE" == "true" ]] && echo "INFO:UPDATE $SCRIPT is not installed"
#        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:UPDATE $SCRIPT is not installed" >>"$DEBUG_LOG"
#        return 1
#    fi
#
#    # update the script
#    [[ "$VERBOSE" == "true" ]] && echo "INFO:UPDATE Updating $SCRIPT"
#    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:UPDATE Updating $SCRIPT" >>"$DEBUG_LOG"
#    #download the latest version with curl or wget to /tmp/$SCRIPT
#    if command -v curl >/dev/null 2>&1; then
#        curl -L "$SCRIPT_URL" -o "/tmp/$SCRIPT"
#    elif command -v wget >/dev/null 2>&1; then
#        wget "$SCRIPT_URL" -O "/tmp/$SCRIPT"
#    else
#        [[ "$VERBOSE" == "true" ]] && echo "ERROR:UPDATE curl or wget not found"
#        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:UPDATE curl or wget not found" >>"$DEBUG_LOG"
#        return 1
#    fi
#
#    # check if the downloaded file is empty
#    if [ ! -s "/tmp/$SCRIPT" ]; then
#        [[ "$VERBOSE" == "true" ]] && echo "ERROR:UPDATE Downloaded file is empty"
#        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:UPDATE Downloaded file is empty" >>"$DEBUG_LOG"
#        return 1
#    fi
#
#    # move the downloaded file to /usr/local/bin
#    cp "/tmp/$SCRIPT" "/usr/local/bin/$SCRIPT"
#    chmod +x "/usr/local/bin/$SCRIPT"
#    [[ "$VERBOSE" == "true" ]] && echo "INFO:UPDATE $SCRIPT updated successfully"
#    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:UPDATE $SCRIPT updated successfully" >>"$DEBUG_LOG"
#    return 0
#}


# FUNCTION: FILE_READABLE
# Description: Check if a file is readable returns 0 if true, 1 if false
# Usage: FILE_READABLE file
# Arguments: 
#   $1 - File to check
# Returns:
#   0 - File is readable
#   1 - File is not readable
FILE_READABLE() {
    if [ -r "$1" ]; then
        return 0
    else
        return 1
    fi
}

# FUNCTION: FILE_WRITABLE
# Description: Check if a file is writable returns 0 if true, 1 if false
# Usage: FILE_WRITABLE file
# Arguments:
#   $1 - File to check
# Returns:
#   0 - File is writable
#   1 - File is not writable
FILE_WRITABLE() {
    if [ -w "$1" ]; then
        return 0
    else
        return 1
    fi
}


# Function: IS_EMPTY
# Checks if a variable is empty
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

# Function: IS_NUMERIC
# Checks if a variable is numeric
IS_NUMBER() {
    # check if is empty
    if [[ -z "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No variable provided"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No variable provided" >>"$DEBUG_LOG"
        return 1
    fi
    # Check if the variable is numeric
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


# Function: FILE_EXISTS
# Checks if a file exists
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

# Function: SHOW_HELP
# Description: Display usage information and help text
# Usage: SHOW_HELP
# Returns: None
SHOW_HELP() {
    echo -e ""
    echo -e "${BOLD}Basic Commands:${NC}"
    echo -e "  ${CYAN}${BOLD}$SCRIPT${NC} <domain>              ${BLUE}${BOLD}# Run full scan on domain${NC}"
    echo -e "  ${CYAN}${BOLD}$SCRIPT${NC} install               ${BLUE}${BOLD}# Install the script (${YELLOW}${BOLD}requires root${BLUE}${BOLD})${NC}"
    #echo -e "  ${CYAN}${BOLD}$SCRIPT${NC} uninstall             ${BLUE}${BOLD}# Uninstall the script (${YELLOW}${BOLD}requires root${BLUE}${BOLD})${NC}"
    #echo -e "  ${CYAN}${BOLD}$SCRIPT${NC} update                ${BLUE}${BOLD}# Update the script (${YELLOW}${BOLD}requires root${BLUE}${BOLD})${NC}"
    echo -e ""
    echo -e "${BOLD}Core Options:${NC}"
    echo -e "  ${GREEN}${BOLD}-h, --help${NC}                    ${BLUE}${BOLD}# Show this help message${NC}"
    echo -e "  ${GREEN}${BOLD}-v, --version${NC}                 ${BLUE}${BOLD}# Show version information${NC}" 
    echo -e "  ${GREEN}${BOLD}-D${NC} [file]                     ${BLUE}${BOLD}# Enable debug mode (default: ${YELLOW}${BOLD}${LOG_DIR}/debug_output.log${NC}${BLUE}${BOLD})${NC}"
    echo -e "  ${GREEN}${BOLD}-V, --verbose${NC}                 ${BLUE}${BOLD}# Enable verbose mode${NC}"
    echo -e ""
    echo -e "${BOLD}Scan Options:${NC}"
    echo -e "  ${GREEN}${BOLD}-d, --domain${NC} <domain>         ${BLUE}${BOLD}# Domain to scan${NC}"
    echo -e "  ${GREEN}${BOLD}-w, --wordlist${NC} <file>         ${BLUE}${BOLD}# Custom wordlist (default: ${YELLOW}${BOLD}${DEFAULT_WORDLIST}${NC}${BLUE}${BOLD})${NC}"
    echo -e "  ${GREEN}${BOLD}-o, --output${NC} <file>           ${BLUE}${BOLD}# Output file (default: ${YELLOW}${BOLD}pwd/<domain>.txt${NC}${BLUE}${BOLD})${NC}"
    #echo -e "  ${GREEN}${BOLD}-t, --threads${NC} <number>        ${BLUE}${BOLD}# Number of threads (default: ${YELLOW}${BOLD}${DEFAULT_THREADS}${NC}${BLUE}${BOLD})${NC}"
    echo -e "  ${GREEN}${BOLD}-R, --resolver${NC} <file>         ${BLUE}${BOLD}# Custom resolver file${NC}"
    echo -e "  ${GREEN}${BOLD}-p, --passive${NC}                 ${BLUE}${BOLD}# Enable passive scanning${NC}"
    echo -e "  ${GREEN}${BOLD}-a, --active${NC}                  ${BLUE}${BOLD}# Enable active scanning${NC}"
    echo -e "  ${GREEN}${BOLD}-r, --recursive${NC} [depth]       ${BLUE}${BOLD}# Enable recursive scanning (default: ${YELLOW}${BOLD}${DEFAULT_RECURSIVE_DEPTH}${NC}${BLUE}${BOLD})${NC}"
    echo -e ""
    echo -e "${BOLD}API Configuration:${NC}"
    echo -e "  ${GREEN}${BOLD}--st-key${NC} <key>              ${BLUE}${BOLD}# SecurityTrails API key${NC}"
    echo -e "  ${GREEN}${BOLD}--vt-key${NC} <key>              ${BLUE}${BOLD}# VirusTotal API key${NC}"
    echo -e "  ${GREEN}${BOLD}--censys-id${NC} <id>            ${BLUE}${BOLD}# Censys API ID${NC}"
    echo -e "  ${GREEN}${BOLD}--censys-secret${NC} <secret>    ${BLUE}${BOLD}# Censys API secret${NC}"
    echo -e ""
    echo -e "${BOLD}Examples:${NC}"
    echo -e "  ${CYAN}${BOLD}$SCRIPT${NC} example.com                   ${BLUE}${BOLD}# Basic scan${NC}"
    echo -e "  ${CYAN}${BOLD}$SCRIPT${NC} -d example.com -p             ${BLUE}${BOLD}# Passive scan${NC}"
    echo -e "  ${CYAN}${BOLD}$SCRIPT${NC} -d example.com -r 2           ${BLUE}${BOLD}# Recursive scan (depth 2)${NC}"
    echo -e "  ${CYAN}${BOLD}$SCRIPT${NC} -d example.com -a    \\        ${BLUE}${BOLD}# Full scan${NC}"
    echo -e "      -w wordlist.txt -o output.txt \\"
    echo -e "      -R resolvers.txt -p -r 3 \\"
}

# Function: SHOW_VERSION
# Description: Display version information
# Usage: SHOW_VERSION
# Returns: None
SHOW_VERSION() {
    echo -e "${BLUE}
    
    ██████╗  ███████╗ ███████╗ ██████╗      ██████╗  ███╗   ██╗ ███████╗
    ██╔══██╗ ██╔════╝ ██╔════╝ ██╔══██╗     ██╔══██╗ ████╗  ██║ ██╔════╝
    ██║  ██║ █████╗   ██████╗  ██████╔╝     ██║  ██║ ██╔██╗ ██║ ███████╗
    ██║  ██║ ██╔══╝   ██╔═══╝  ██╔═══╝      ██║  ██║ ██║╚██╗██║ ╚════██║
    ██████╔╝ ███████╗ ███████╗ ██║          ██████╔╝ ██║ ╚████║ ███████║
    ╚═════╝  ╚══════╝ ╚══════╝ ╚═╝          ╚═════╝  ╚═╝  ╚═══╝ ╚══════╝${NC}
    
    ${GREEN}${BOLD}DeepDNS${NC} v${YELLOW}${VERSION}${NC} - ${CYAN}${BOLD}Advanced DNS Enumeration Tool${NC}    ${GREEN}${BOLD}From:${NC} ${RED}${BOLD}${AUTHOR}${NC}
    ${GREEN}${BOLD}GITHUB${NC}:${YELLOW}${BOLD}https://github.com/ErvisTusha/deepdns${NC}   ${GREEN}${BOLD}X:${NC} ${YELLOW}${BOLD}https://www.x.com/ET${NC}
                                ${GREEN}${BOLD}LICENSE:${NC} ${YELLOW}${BOLD}MIT${NC}"
    
}
# Function: VALIDATE_DOMAIN
# Description: Validate if a string is a valid domain name
# Usage: VALIDATE_DOMAIN domain.com
# Arguments:
#   $1 - Domain name to validate
# Returns:
#   0 - Valid domain
#   1 - Invalid domain
VALIDATE_DOMAIN() {
    LOG "DEBUG" "Starting VALIDATE_DOMAIN with input: $1"
    if ! [[ "$1" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        LOG "ERROR" "VALIDATE_DOMAIN $1 - Invalid domain"
        return 1
    fi
    LOG "INFO" "VALIDATE_DOMAIN $1 - OK" 
    return 0
}

# Modify PASSIVE_SCAN to accept an output file parameter and output only subdomain names
PASSIVE_SCAN() {
    local DOMAIN="$1"
    local RESULTS_FILE="${2:-${OUTPUT:-$PWD/${DOMAIN}_passive.txt}}"
    LOG "DEBUG" "Starting PASSIVE_SCAN for domain: $DOMAIN"
    
    echo -e "\n${CYAN}${BOLD}┌──────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}${BOLD}│${NC}               ${UNDERLINE}Passive Scan Results${NC}               ${CYAN}${BOLD}│${NC}"
    echo -e "${CYAN}${BOLD}└──────────────────────────────────────────────────┘${NC}\n"
   
    echo -e "\n${CYAN}${BOLD}[PASSIVE SCAN]${NC} Starting passive enumeration for $DOMAIN"
    
    # SecurityTrails scan
    echo -e "${YELLOW}${BOLD}[*]${NC} Querying SecurityTrails API..."
    LOG "DEBUG" "Querying SecurityTrails API"
    if [[ -n "$SECURITYTRAILS_API_KEY" ]]; then
        QUERY_SECURITYTRAILS "$DOMAIN" > "$RESULTS_FILE.st"
        local ST_COUNT=$(wc -l < "$RESULTS_FILE.st")
        echo -e "${GREEN}${BOLD}[✓]${NC} SecurityTrails: Found $ST_COUNT subdomains"
    else
        echo -e "${RED}${BOLD}[!]${NC} SecurityTrails: Skipped (no API key)"
    fi
    
    # Certificate Transparency scan
    echo -e "${YELLOW}${BOLD}[*]${NC} Querying Certificate Transparency logs..."
    LOG "DEBUG" "Querying Certificate Transparency logs"
    QUERY_CRTSH "$DOMAIN" > "$RESULTS_FILE.crt"

    # VirusTotal scan
    echo -e "${YELLOW}${BOLD}[*]${NC} Querying VirusTotal API..."
    LOG "DEBUG" "Querying VirusTotal API"
    if [[ -n "$VIRUSTOTAL_API_KEY" ]]; then
        QUERY_VIRUSTOTAL "$DOMAIN" > "$RESULTS_FILE.vt"
        local VT_COUNT=$(wc -l < "$RESULTS_FILE.vt")
        echo -e "${GREEN}${BOLD}[✓]${NC} VirusTotal: Found $VT_COUNT subdomains"
    else
        echo -e "${RED}${BOLD}[!]${NC} VirusTotal: Skipped (no API key)"
    fi
    
    # Combine all results
    cat "$RESULTS_FILE".* 2>/dev/null | grep -E "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" | sort -u > "$RESULTS_FILE"
    local TOTAL=$(wc -l < "$RESULTS_FILE")
    echo -e "${GREEN}${BOLD}[✓]${NC} Passive scan complete: $TOTAL unique subdomains found"
    LOG "INFO" "Passive scan complete: Found $TOTAL unique subdomains"
    
    # Cleanup temporary files
    rm -f "$RESULTS_FILE".*
    return 0
}

# Modify ACTIVE_SCAN to accept an output file parameter and output only subdomain names
ACTIVE_SCAN() {
    local DOMAIN="$1"
    local RESULTS_FILE="${2:-${OUTPUT:-$PWD/${DOMAIN}_active.txt}}"
    LOG "DEBUG" "Starting ACTIVE_SCAN for domain: $DOMAIN"
    
    echo -e "\n${CYAN}${BOLD}┌──────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}${BOLD}│${NC}               ${UNDERLINE}Active Scan Results${NC}                ${CYAN}${BOLD}│${NC}"
    echo -e "${CYAN}${BOLD}└──────────────────────────────────────────────────┘${NC}\n"
    echo -e "\n${CYAN}${BOLD}[ACTIVE SCAN]${NC} Starting active enumeration for $DOMAIN"
    
    # Check DNS tools
    echo -e "${YELLOW}${BOLD}[*]${NC} Checking required DNS tools..."
    CHECK_DNS_TOOLS || return 1
    
    # Try zone transfer
    echo -e "${YELLOW}${BOLD}[*]${NC} Attempting zone transfer..."
    LOG "DEBUG" "Attempting zone transfer for $DOMAIN"
    if ZONE_TRANSFER "$DOMAIN" > "$RESULTS_FILE.zone"; then
        local ZONE_COUNT=$(wc -l < "$RESULTS_FILE.zone")
        echo -e "${GREEN}${BOLD}[✓]${NC} Zone transfer successful: Found $ZONE_COUNT records"
    else
        echo -e "${RED}${BOLD}[!]${NC} Zone transfer failed"
    fi
    
    # DNS record enumeration
    echo -e "${YELLOW}${BOLD}[*]${NC} Enumerating DNS records..."
    LOG "DEBUG" "Enumerating DNS records for $DOMAIN"
    local RECORD_COUNT=0
    local RESOLVER_INDEX=0
    local RESOLVER_COUNT=0
    
    # Get total resolver count if using resolver file
    [[ "$RESOLVER_SCAN" == true ]] && [[ -n "$RESOLVER_FILE" ]] && \
        RESOLVER_COUNT=$(wc -l < "$RESOLVER_FILE")
    
    for RECORD in "${DNS_RECORDS[@]}"; do
        printf "\r${YELLOW}${BOLD}[*]${NC} Checking %s records..." "$RECORD"
        if [[ "$RESOLVER_SCAN" == true ]] && [[ -n "$RESOLVER_FILE" ]]; then
            # Read resolvers into array for rotation
            mapfile -t RESOLVERS < "$RESOLVER_FILE"
            
            # Use resolver rotation
            RESOLVER=${RESOLVERS[$RESOLVER_INDEX]}
            RESOLVER_INDEX=$(( (RESOLVER_INDEX + 1) % RESOLVER_COUNT ))
            
            #RATE_LIMIT
            GET_DNS_RECORD "$DOMAIN" "$RECORD" "$RESOLVER" >> "$RESULTS_FILE.dns"
        else
            #RATE_LIMIT
            GET_DNS_RECORD "$DOMAIN" "$RECORD" >> "$RESULTS_FILE.dns"
        fi
        local THIS_COUNT=$(grep -c "^$RECORD" "$RESULTS_FILE.dns" 2>/dev/null)
        RECORD_COUNT=$((RECORD_COUNT + THIS_COUNT))
    done
    
    echo -e "\r${GREEN}${BOLD}[✓]${NC} DNS enumeration complete: Found $RECORD_COUNT records"
    
    # Wordlist bruteforce
    if [[ -n "$WORDLIST_PATH" ]]; then
        echo -e "${YELLOW}${BOLD}[*]${NC} Starting wordlist bruteforce..."
        local TOTAL_WORDS=$(wc -l < "$WORDLIST_PATH")
        local FOUND=0
        local COUNT=0
        local PROGRESS_INTERVAL=$((TOTAL_WORDS / 20))  # Show progress every 5%
        [[ $PROGRESS_INTERVAL -lt 1 ]] && PROGRESS_INTERVAL=1
        
        while read -r SUBDOMAIN; do
            COUNT=$((COUNT + 1))
            local TARGET="${SUBDOMAIN}.${DOMAIN}"
            #RATE_LIMIT
            
            if ((COUNT % PROGRESS_INTERVAL == 0)); then
                local PERCENT=$((COUNT * 100 / TOTAL_WORDS))
                printf "\r${YELLOW}${BOLD}[*]${NC} Testing subdomains... %d%% (%d/%d found: %d)" "$PERCENT" "$COUNT" "$TOTAL_WORDS" "$FOUND"
            fi
            
            if dig +short "$TARGET" | grep -q '^[0-9]'; then
                echo "$TARGET" >> "$RESULTS_FILE.brute"
                FOUND=$((FOUND + 1))
            fi
        done < "$WORDLIST_PATH"
        echo -e "\n${GREEN}${BOLD}[✓]${NC} Bruteforce complete: Found $FOUND subdomains from $TOTAL_WORDS attempts"
    fi
    
    # Combine all results
    cat "$RESULTS_FILE".* 2>/dev/null | grep -E "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" | sort -u > "$RESULTS_FILE"
    local TOTAL=$(wc -l < "$RESULTS_FILE")
    echo -e "${GREEN}${BOLD}[✓]${NC} Active scan complete: $TOTAL unique results found"
    LOG "INFO" "Active scan complete: $TOTAL unique results found"
    
    # Cleanup temporary files
    rm -f "$RESULTS_FILE".*
    return 0
}

# Function: QUERY_SECURITYTRAILS
# Description: Query SecurityTrails API for subdomains
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

# Function: QUERY_CRTSH
# Description: Query crt.sh for SSL certificates
QUERY_CRTSH() {
    local DOMAIN="$1"
    local API_URL="https://crt.sh/?q=%.${DOMAIN}&output=json"
    
    local RESULT
    RESULT=$(curl -s "$API_URL")
    echo "$RESULT" | jq -r '.[].name_value' 2>/dev/null | sort -u
}

# Function: QUERY_VIRUSTOTAL
# Description: Query VirusTotal API for subdomains
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

# Adjust RECURSIVE_SCAN to properly process subdomains
RECURSIVE_SCAN() {
    local DOMAIN="$1"
    local DEPTH="$2"
    local RESULTS_FILE="${3:-${OUTPUT:-$PWD/${DOMAIN}_recursive.txt}}"
    local TEMP_DIR=$(mktemp -d)
    local INDENT=""
    
    # Create indent based on depth
    for ((i=0; i<(4-DEPTH); i++)); do
        INDENT+="    "
    done
    
    # Create prettier depth indicator
    local DEPTH_MARKER=""
    for ((i=0; i<(4-DEPTH); i++)); do
        DEPTH_MARKER+="→"
    done
    
    # Show depth indicator
    echo -e "\n${INDENT}${CYAN}${BOLD}[${DEPTH_MARKER}]${NC} Scanning ${YELLOW}${BOLD}${DOMAIN}${NC}"
    LOG "INFO" "Starting recursive scan for $DOMAIN (depth: $DEPTH)"
    
    # Check if domain was already scanned
    if [[ " ${GLOBAL_SEEN_DOMAINS[@]} " =~ " ${DOMAIN} " ]]; then
        echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} Domain already scanned, skipping"
        return 0
    fi
    
    # Add domain to global seen list
    GLOBAL_SEEN_DOMAINS+=("$DOMAIN")
    
    local CURRENT_RESULTS="$TEMP_DIR/${DOMAIN}_subdomains.txt"
    touch "$CURRENT_RESULTS"
    
    # Perform scans with indented output
    if [[ "$PASSIVE_SCAN" == true ]]; then
        echo -e "${INDENT}${BLUE}${BOLD}[+]${NC} Running passive scan"
        PASSIVE_SCAN "$DOMAIN" "$CURRENT_RESULTS.passive" >/dev/null
        if [[ -f "$CURRENT_RESULTS.passive" ]]; then
            local COUNT=$(wc -l < "$CURRENT_RESULTS.passive")
            echo -e "${INDENT}    ${GREEN}${BOLD}[✓]${NC} Found $COUNT subdomains via passive scan"
            cat "$CURRENT_RESULTS.passive" >> "$CURRENT_RESULTS"
        fi
    fi
    
    if [[ "$ACTIVE_SCAN" == true ]]; then
        echo -e "${INDENT}${BLUE}${BOLD}[+]${NC} Running active scan"
        ACTIVE_SCAN "$DOMAIN" "$CURRENT_RESULTS.active" >/dev/null
        if [[ -f "$CURRENT_RESULTS.active" ]]; then
            local COUNT=$(wc -l < "$CURRENT_RESULTS.active")
            echo -e "${INDENT}    ${GREEN}${BOLD}[✓]${NC} Found $COUNT subdomains via active scan"
            cat "$CURRENT_RESULTS.active" >> "$CURRENT_RESULTS"
        fi
    fi
    
    # Append unique results to main output file
    if [[ -s "$CURRENT_RESULTS" ]]; then
        cat "$CURRENT_RESULTS" >> "$RESULTS_FILE"
        local TOTAL=$(wc -l < "$CURRENT_RESULTS")
        echo -e "${INDENT}${GREEN}${BOLD}[✓]${NC} Total unique subdomains for ${YELLOW}${BOLD}${DOMAIN}${NC}: ${GREEN}${BOLD}${TOTAL}${NC}"
    else
        echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} No subdomains found for ${DOMAIN}"
    fi
    
    # Only recurse if depth > 1 and we have results
    if [[ "$DEPTH" -gt 1 ]] && [[ -s "$CURRENT_RESULTS" ]]; then
        local SUBDOMAIN_COUNT=0
        local UNIQUE_SUBDOMAINS=($(sort -u "$CURRENT_RESULTS"))
        
        for SUBDOMAIN in "${UNIQUE_SUBDOMAINS[@]}"; do
            
            # Skip if already seen or invalid
            if ! VALIDATE_DOMAIN "$SUBDOMAIN" || [[ " ${GLOBAL_SEEN_DOMAINS[@]} " =~ " ${SUBDOMAIN} " ]]; then
                continue
            fi
            
            RECURSIVE_SCAN "$SUBDOMAIN" "$((DEPTH-1))" "$RESULTS_FILE"
            SUBDOMAIN_COUNT=$((SUBDOMAIN_COUNT + 1))
        done
    fi
    
    # Cleanup
    rm -rf "$TEMP_DIR"
    return 0
}

# Function: SCAN_DOMAIN
# Description: Main scanning function that coordinates different scan types
SCAN_DOMAIN() {
    local TARGET_DOMAIN="$1"
    LOG "DEBUG" "Starting SCAN_DOMAIN for target: $TARGET_DOMAIN"

    echo -e "${BLUE}${BOLD}┌──────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}${BOLD}│${NC}             ${UNDERLINE}${BOLD}Scan Configuration${NC}                   ${BLUE}${BOLD}│${NC}"
    echo -e "${BLUE}${BOLD}└──────────────────────────────────────────────────┘${NC}\n"

    echo -e " ${PURPLE}${BOLD}Target Domain${NC}    │ ${YELLOW}${BOLD}$TARGET_DOMAIN${NC} | ${GRAY}${DIM} $(date '+%Y-%m-%d %H:%M:%S')${NC}\n" 
    echo -e " ${PURPLE}${BOLD}Scan Modes${NC}       │ ${PASSIVE_SCAN:+${GREEN}${BOLD}Passive${NC}} ${ACTIVE_SCAN:+${GREEN}${BOLD}Active${NC}} ${RECURSIVE_SCAN:+${GREEN}${BOLD}Recursive(${RECURSIVE_DEPTH})${NC}}"
    echo -e " ${PURPLE}${BOLD}Wordlist${NC}         │ ${CYAN}${BOLD}$WORDLIST_PATH${NC}"
    echo -e " ${PURPLE}${BOLD}Output File${NC}      │ ${CYAN}${BOLD}$OUTPUT${NC}"
    [[ "$DEBUG" == true ]] &&echo -e " ${PURPLE}${BOLD}Debug Mode${NC}       │ ${DEBUG:+${GREEN}${BOLD}Enabled${NC}}"
    [[ "$VERBOSE" == true ]] &&echo -e " ${PURPLE}${BOLD}Verbose Mode${NC}     │ ${VERBOSE:+${GREEN}${BOLD}Enabled${NC}}"
    [[ "$RESOLVER_SCAN" == true ]] && echo -e " ${PURPLE}${BOLD}Resolver File${NC}    │ ${CYAN}${BOLD}$RESOLVER_FILE${NC}"
  
    echo -e "\n${BLUE}${BOLD}[»]${NC} ${UNDERLINE}Scan Status${NC}\n"

    # Clean and validate resolvers
    CLEAN_RESOLVERS "$RESOLVER_FILE"
    
    if [[ -n "$OUTPUT" ]]; then
        mkdir -p "$(dirname "$OUTPUT")"
    else
        OUTPUT="$PWD/${TARGET_DOMAIN}_scan.txt"
    fi
    
    # Adjusted code:
    # If recursive scan is enabled, start recursive scanning without initial scans
    if [[ "$RECURSIVE_SCAN" == true ]]; then
        echo -e "\n${CYAN}${BOLD}[RECURSIVE SCAN]${NC} Starting recursive enumeration (depth: $RECURSIVE_DEPTH)"
        RECURSIVE_SCAN "$TARGET_DOMAIN" "$RECURSIVE_DEPTH" "$OUTPUT"
    else
        # Perform scans based on enabled options
        [[ "$PASSIVE_SCAN" == true ]] && PASSIVE_SCAN "$TARGET_DOMAIN"
        [[ "$ACTIVE_SCAN" == true ]] && ACTIVE_SCAN "$TARGET_DOMAIN"
    fi
    
    echo -e "\n${BLUE}${BOLD}[»]${NC} ${UNDERLINE}Scan Completed${NC}"
    LOG "DEBUG" "SCAN_DOMAIN completed for target: $TARGET_DOMAIN"
    return 0
}

# DNS record types
declare -r DNS_RECORDS=(
    "A" "AAAA" "CNAME" "MX" "TXT" "NS" "SOA" "SRV" "PTR"
)

# Function: CHECK_DNS_TOOLS
# Description: Check if required DNS tools are installed
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

# Function: GET_DNS_RECORD
# Description: Get specific DNS record for a domain
GET_DNS_RECORD() {
    local DOMAIN="$1"
    local RECORD_TYPE="$2"
    local RESOLVER="$3"
    local TIMEOUT=2  # Add timeout for resolver queries
    
    LOG "DEBUG" "GET_DNS_RECORD: Starting query for $DOMAIN ($RECORD_TYPE)"
    [[ -n "$RESOLVER" ]] && LOG "DEBUG" "GET_DNS_RECORD: Using resolver $RESOLVER"
    
    local DIG_CMD="dig +time=$TIMEOUT"
    [[ -n "$RESOLVER" ]] && DIG_CMD="dig @$RESOLVER +time=$TIMEOUT"
    
    LOG "DEBUG" "GET_DNS_RECORD: Executing command: $DIG_CMD $RECORD_TYPE $DOMAIN"
    
    local RESULT
    RESULT=$($DIG_CMD "$RECORD_TYPE" "$DOMAIN" +short 2>/dev/null)
    
    if [[ -z "$RESULT" ]]; then
        LOG "DEBUG" "GET_DNS_RECORD: No results found for $DOMAIN ($RECORD_TYPE)"
        [[ -n "$RESOLVER" ]] && LOG "WARNING" "GET_DNS_RECORD: Resolver $RESOLVER failed"
        return 1
    fi
    
    LOG "DEBUG" "GET_DNS_RECORD: Found results for $DOMAIN ($RECORD_TYPE)"
    echo "$RESULT"
    return 0
}

# Function: ZONE_TRANSFER
# Description: Attempt zone transfer for a domain
ZONE_TRANSFER() {
    local DOMAIN="$1"
    local NS_SERVERS
    
    # Get nameservers
    NS_SERVERS=$(GET_DNS_RECORD "$DOMAIN" "NS")
    
    if [[ -z "$NS_SERVERS" ]]; then
        LOG "ERROR" "No nameservers found for $DOMAIN"
        return 1
    fi
    
    local TRANSFER_RESULT=""
    while read -r NS; do
        LOG "INFO" "Attempting zone transfer from $NS"
        TRANSFER_RESULT=$(dig @"$NS" "$DOMAIN" AXFR +short 2>/dev/null)
        if [[ -n "$TRANSFER_RESULT" ]]; then
            echo "$TRANSFER_RESULT"
            return 0
        fi
    done <<< "$NS_SERVERS"
    
    return 1
}

# Function: CLEAN_RESOLVERS
# Description: Deduplicate and validate resolvers without modifying original file
CLEAN_RESOLVERS() {
    # Skip if doing passive scan only
    if [[ "$PASSIVE_SCAN" == true ]] && [[ "$ACTIVE_SCAN" == false ]]; then
        LOG "INFO" "Skipping resolver validation for passive scan"
        return 0
    fi

    local INPUT_FILE="$1"
    local TEMP_WORKING_DIR=$(mktemp -d)
    local TEMP_FILE="$TEMP_WORKING_DIR/temp_resolvers.txt"
    local VALID_FILE="$TEMP_WORKING_DIR/valid_resolvers.txt"
    local CLEAN_FILE="$TEMP_WORKING_DIR/clean_resolvers.txt"
    local TEST_DOMAIN="google.com"
    local TIMEOUT=2
    local WORKING_COUNT=0
    local TOTAL_COUNT=0
    
    # Skip if no resolver fileprovided
    if [[ -z "$INPUT_FILE" ]]; then
        LOG "DEBUG" "No resolver file provided, skipping validation"
        return 0
    fi
    
    # Check if input file exists
    if [[ ! -f "$INPUT_FILE" ]]; then
        LOG "ERROR" "Resolver file not found: $INPUT_FILE"
        return 1
    fi
    
    echo -e "${YELLOW}${BOLD}[*]${NC} Cleaning and validating resolvers..."
    LOG "INFO" "Starting resolver validation from: $INPUT_FILE"
    
    # Initial cleanup - remove comments, empty lines, and invalid IPs
    grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' "$INPUT_FILE" | \
    while read -r IP; do
        # Validate IP format
        if [[ $(echo "$IP" | tr '.' '\n' | awk '$1 >= 0 && $1 <= 255' | wc -l) -eq 4 ]]; then
            echo "$IP"
        else
            LOG "DEBUG" "Invalid IP removed: $IP"
        fi
    done | sort -u > "$TEMP_FILE"
    
    TOTAL_COUNT=$(wc -l < "$TEMP_FILE")
    if [[ $TOTAL_COUNT -eq 0 ]]; then
        echo -e "${RED}${BOLD}[!]${NC} No valid resolver IPs found in input file"
        LOG "ERROR" "No valid resolver IPs found in $INPUT_FILE"
        rm -rf "$TEMP_WORKING_DIR"
        return 1
    fi
    
    echo -e "${YELLOW}${BOLD}[*]${NC} Testing $TOTAL_COUNT unique resolvers..."
    
    # Test each resolver with progress bar
    while read -r RESOLVER; do
        printf "\r${YELLOW}${BOLD}[*]${NC} Progress: [%-50s] %d/%d" \
               "$(printf '#%.0s' $(seq 1 $((WORKING_COUNT*50/TOTAL_COUNT))))" \
               "$WORKING_COUNT" "$TOTAL_COUNT"
        
        # Test resolver with both A and NS records
        if timeout $TIMEOUT dig @"$RESOLVER" "$TEST_DOMAIN" A +time=1 +tries=1 &>/dev/null && \
           timeout $TIMEOUT dig @"$RESOLVER" "$TEST_DOMAIN" NS +time=1 +tries=1 &>/dev/null; then
            echo "$RESOLVER" >> "$VALID_FILE"
            ((WORKING_COUNT++))
            LOG "DEBUG" "Working resolver found: $RESOLVER"
        else
            LOG "DEBUG" "Failed resolver: $RESOLVER"
        fi
    done < "$TEMP_FILE"
    
    echo # New line after progress bar
    
    # Check if we have any working resolvers
    if [[ $WORKING_COUNT -eq 0 ]]; then
        echo -e "${RED}${BOLD}[!]${NC} No working resolvers found!"
        LOG "ERROR" "No working resolvers found in $INPUT_FILE"
        rm -rf "$TEMP_WORKING_DIR"
        return 1
    fi
    
    # Set the clean resolvers file as the one to use
    cp "$VALID_FILE" "$CLEAN_FILE"
    
    # Update global RESOLVER_FILE to point to our clean temporary file
    RESOLVER_FILE="$CLEAN_FILE"
    
    echo -e "${GREEN}${BOLD}[✓]${NC} Found $WORKING_COUNT working resolvers out of $TOTAL_COUNT tested"
    LOG "INFO" "Resolver validation complete. Using $WORKING_COUNT working resolvers"
    
    # Register cleanup for temporary files on script exit
    trap 'rm -rf "$TEMP_WORKING_DIR"' EXIT
    
    return 0
}

# Adjust FORMAT_RESULTS to remove duplicate entries
FORMAT_RESULTS() {
    local DOMAIN="$1"
    local OUTPUT_FILE="$2"
    local TEMP_FILE=$(mktemp)
    
    LOG "INFO" "Formatting results for $DOMAIN"
    
    # Extract and deduplicate valid subdomains
    grep -Eh "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" "$OUTPUT_FILE" 2>/dev/null | \
        sort -u | \
        grep -v "^$DOMAIN$" > "$TEMP_FILE"
    
    # Replace original file with clean subdomain list
    mv "$TEMP_FILE" "$OUTPUT_FILE"
    
    local TOTAL=$(wc -l < "$OUTPUT_FILE")
    LOG "INFO" "Saved $TOTAL unique domains to $OUTPUT_FILE"
    
    # Calculate and display the scan duration
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    DURATION_FORMATTED=$(printf '%02dh:%02dm:%02ds' $((DURATION/3600)) $(( (DURATION%3600)/60)) $((DURATION%60)))


    echo -e "\n${BLUE}${BOLD}┌──────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}${BOLD}│${NC}             ${UNDERLINE}${BOLD}Final Scan Summary${NC}                   ${BLUE}${BOLD}│${NC}"
    echo -e "${BLUE}${BOLD}└──────────────────────────────────────────────────┘${NC}\n"
    echo -e " ${PURPLE}${BOLD}Total Subdomains${NC} │ ${GREEN}${BOLD}$TOTAL${NC} unique results"
    echo -e " ${PURPLE}${BOLD}Scan Duration${NC}    │ ${WHITE}${BOLD}$DURATION_FORMATTED${NC}"
    echo -e " ${PURPLE}${BOLD}Finished${NC}         │ ${WHITE}${BOLD}$(date '+%Y-%m-%d %H:%M:%S')${NC}"                                                        
    echo -e " ${PURPLE}${BOLD}Output Location${NC}  │ ${CYAN}${BOLD}$OUTPUT_FILE${NC}" 
    return 0
}


SHOW_VERSION
# if no arguments are passed, show help
if [ $# -eq 0 ]; then
    SHOW_HELP
    exit 1
fi

# if only one argument is passed
if [ $# -eq 1 ]; then
    if [ "${1,,}" = "install" ]; then
        ! IS_SUDO &&  echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}INSTALL Please run as root${NC}\n" && LOG "ERROR" "INSTALL Please run as root" && exit 1
        INSTALL_SCRIPT 
        echo -e "\n${GREEN}${BOLD}[INFO]${NC} ${BOLD}DeepDNS installed successfully${NC}\n"
        LOG "INFO" "INSTALLING DeepDNS" 
        exit 0
    #elif [ "${1,,}" = "uninstall" ]; then
    #    ! IS_SUDO &&  echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}UNINSTALL Please run as root${NC}\n" && LOG "ERROR" "UNINSTALL Please run as root" && exit 1
    #    echo -e "\n${GREEN}${BOLD}[INFO]${NC} ${BOLD}UNINSTALLING DeepDNS${NC}\n"
    #    UNINSTALL_SCRIPT
    #    LOG "INFO" "UNINSTALLING DeepDNS" 
    #    exit 0
    #elif [ "${1,,}" = "update" ]; then
    #    ! IS_SUDO &&  echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}UPDATE Please run as root${NC}\n" && LOG "ERROR" "UPDATE Please run as root" && exit 1  
    #    echo -e "\n${GREEN}${BOLD}[INFO]${NC} ${BOLD}UPDATING DeepDNS${NC}\n"
    #    UPDATE_SCRIPT
    #    LOG "INFO" "UPDATING DeepDNS"
    #    exit 0
    elif [ "$1" == "-h" ] || [ "$1" == "--help" ]; then
        LOG "INFO" "SHOW_HELP" 
        SHOW_HELP
        exit 0
    elif [ "$1" == "-v" ] || [ "$1" == "--version" ]; then
        LOG "INFO" "SHOW VERSION" 
        exit 0
    elif VALIDATE_DOMAIN "$1"; then   
        DOMAIN="$1"
        PASSIVE_SCAN=true
        ACTIVE_SCAN=true
        RECURSIVE_SCAN=true
    else
        LOG "INFO" "SHOW_HELP - INVALID argument"
        SHOW_HELP
        exit 1
    fi
fi

# Show version banner before parsing other arguments


# Parse arguments
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
            # Check if argument is missing
            IS_EMPTY "$2" &&  echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Domain argument missing${NC}\n" && LOG "ERROR" "Domain argument missing" && exit 1
            DOMAIN="$2"
            shift
            ;;
        -w | --wordlist)
            # Check if argument is missing
            IS_EMPTY "$2" &&  echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Wordlist argument missing${NC}\n" && LOG "ERROR" "Wordlist argument missing" && exit 1
            # Check if file exists
            ! FILE_EXISTS "$2" &&  echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Wordlist file not found: $2${NC}\n" && LOG "ERROR" "Wordlist file not found: $2" && exit 1
            # Check if file is readable
            ! FILE_READABLE "$2" &&  echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}File is not readable : $2${NC}\n" && LOG "ERROR" "Wordlist file not readable: $2" && exit 1
            WORDLIST_PATH="$2"
            shift
            ;;
        -o | --output)
            # Check if argument is missing
            IS_EMPTY "$2" &&  echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Output file argument missing${NC}\n" && LOG "ERROR" "Output file argument missing" && exit 1
            OUTPUT="$2"
            shift
            ;;
        #-t | --threads)
        #    # Check if argument is missing
        #    #IS_EMPTY "$2" &&  echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Thread count argument missing${NC}\n" && LOG "ERROR" "Thread count argument missing" && exit 1
        #    # Check if thread count is a number
        #    #IS_NUMBER "$2" ||  echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid thread count: $2${NC}\n" && LOG "ERROR" "Invalid thread count: $2" && exit 1
        #    # Check if thread count is less than 100
        #    if [ "$2" -lt 101 ]; then
        #        THREADS="$2"
        #    else
        #        LOG "ERROR" "Thread count must be less than 100"
        #        echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Thread count must be less than 100${NC}\n"
        #        exit 1
        #    fi
        #    shift
        #    ;;
        -r | --recursive)
            RECURSIVE_SCAN=true
            # Check if argument is missing
            IS_EMPTY "$2" &&  echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Recursive depth argument missing${NC}\n" && LOG "ERROR" "Recursive depth argument missing" && exit 1
            # Check if recursive depth is a number
            ! IS_NUMBER "$2" &&  echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid recursive depth: $2${NC}\n" && LOG "ERROR" "Invalid recursive depth: $2" && exit 1
            # Check if recursive depth is between 1 and 10
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
            PASSIVE_SCAN=true
            ;;

        -a | --active)
            ACTIVE_SCAN=true
            ;;
        -R | --resolver)
            
            # Check if argument is missing
            IS_EMPTY "$2" &&  echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Resolver file argument missing${NC}\n" && LOG "ERROR" "Resolver file argument missing" && exit 1
            # Check if file exists
            ! FILE_EXISTS "$2" &&  echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Resolver file not found: $2${NC}\n" && LOG "ERROR" "Resolver file not found: $2" && exit 1
            # Check if file is readable
            ! FILE_READABLE "$2" &&  echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}File is not readable : $2${NC}\n" && LOG "ERROR" "Resolver file not readable: $2" && exit 1
            # check if resolver file is empty
            FILE_EMPTY "$2" &&  echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Resolver file is empty : $2${NC}\n" && LOG "ERROR" "Resolver file is empty: $2" && exit 1
            
            RESOLVER_SCAN=true
            RESOLVER_FILE="$2"
            shift
            ;;
        --st-key)
            IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}SecurityTrails API key missing${NC}\n" && LOG "ERROR" "SecurityTrails API key missing" && exit 1
            SECURITYTRAILS_API_KEY="$2"
            PASSIVE_SCAN=true # Auto-enable passive scan
            shift
            ;;
        --vt-key)
            IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}VirusTotal API key missing${NC}\n" && LOG "ERROR" "VirusTotal API key missing" && exit 1
            VIRUSTOTAL_API_KEY="$2"
            PASSIVE_SCAN=true # Auto-enable passive scan
            shift
            ;;
        --censys-id)
            IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Censys API ID missing${NC}\n" && LOG "ERROR" "Censys API ID missing" && exit 1
            CENSYS_API_ID="$2"
            PASSIVE_SCAN true # Auto-enable passive scan
            shift
            ;;
        --censys-secret)
            IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Censys API secret missing${NC}\n" && LOG "ERROR" "Censys API secret missing" && exit 1
            CENSYS_API_SECRET="$2"
            PASSIVE_SCAN=true # Auto-enable passive scan
            shift
            ;;
        *)
            ! VALIDATE_DOMAIN "$1" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid domain: $1${NC}\n" && LOG "ERROR" "Invalid domain: $1" && exit 1
            DOMAIN="$1"
            ;;
    esac
    shift
done

#check if DEBUG is enabled
if [ "$DEBUG" = true ]; then
    #check if DEBUG_LOG exists
    if FILE_EXISTS "$DEBUG_LOG"; then
        #remove the file
        rm -f $DEBUG_LOG
    fi
    mkdir -p $LOG_DIR
    #create the file
    touch $DEBUG_LOG
fi

# Validate domain
if ! VALIDATE_DOMAIN "$DOMAIN"; then
    LOG "ERROR" "Invalid domain: $DOMAIN"
    echo -e "${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid domain: $DOMAIN${NC}"
    exit 1
fi

# Set output file if not specified
IS_EMPTY "$OUTPUT" && OUTPUT="$PWD/${DOMAIN}.txt"

# Check if output file already exists than remove it
FILE_EXISTS "$OUTPUT" && rm -f "$OUTPUT"

# Check if file is writable
FILE_WRITABLE "$OUTPUT" &&  echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Output file is not writable : $OUTPUT${NC}\n" && LOG "ERROR" "Output file is not writable: $OUTPUT" && exit 1


# Enable default scan types if none specified
if [[ "$PASSIVE_SCAN" == false ]] && [[ "$ACTIVE_SCAN" == false ]] && [[ "$RECURSIVE_SCAN" == false ]]; then
    PASSIVE_SCAN=true
    ACTIVE_SCAN=true
    LOG "INFO" "No scan type specified, enabling passive and active scans"
fi

# Add the following check:
if [[ "$RECURSIVE_SCAN" == true ]] && [[ "$PASSIVE_SCAN" == false ]] && [[ "$ACTIVE_SCAN" == false ]]; then
    LOG "ERROR" "Recursive scan requires PASSIVE_SCAN or ACTIVE_SCAN to be enabled"
    echo -e "\n${RED}${BOLD}[ERROR]${NC} Recursive scan requires either passive or active scan to be enabled.\n"
    exit 1
fi

# Execute main scan with progress indicator
if [[ -n "$DOMAIN" ]]; then
    SCAN_DOMAIN "$DOMAIN" &     wait $!
fi

# Format final results
FORMAT_RESULTS "$DOMAIN" "$OUTPUT"

exit $?