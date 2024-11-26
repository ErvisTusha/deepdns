#!/bin/bash

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
    if [ -f "/usr/local/bin/deepdns" ]; then
        echo -e "${YELLOW}${BOLD}[!]${NC} DeepDNS is already installed. Use 'update' to upgrade."
        LOG "INFO" "Installation skipped - already installed"
        return 0
    fi

    if sudo install -m 0755 -o root -g root "$0" /usr/local/bin/deepdns; then
        echo -e "${GREEN}${BOLD}[✓]${NC} Successfully installed DeepDNS:"
        echo -e "   ${CYAN}${BOLD}→${NC} Binary: /usr/local/bin/deepdns"
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
        NEW_VERSION=$(grep "VERSION=" "$TEMP_FILE" | cut -d'"' -f2)
        echo $NEW_VERSION "aaaaaaaaaaaaaaaaaaaaaa"
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
