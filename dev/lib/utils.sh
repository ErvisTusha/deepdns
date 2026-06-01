#!/bin/bash

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

    local INSTALL_SOURCE="$0"
    local SCRIPT_BASE
    SCRIPT_BASE="$(basename "$0")"
    if [[ "$SCRIPT_BASE" == "deepdns" && -f "$(cd "$(dirname "$0")/.." >/dev/null 2>&1 && pwd)/deepdns.sh" ]]; then
        INSTALL_SOURCE="$(cd "$(dirname "$0")/.." >/dev/null 2>&1 && pwd)/deepdns.sh"
    fi

    if ! bash -n "$INSTALL_SOURCE"; then
        echo -e "${RED}${BOLD}[✗]${NC} Install source failed syntax check: $INSTALL_SOURCE"
        LOG "ERROR" "Installation failed - syntax check failed for $INSTALL_SOURCE"
        return 1
    fi

    if sudo install -m 0755 -o root -g root "$INSTALL_SOURCE" /usr/local/bin/deepdns; then
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

    # Download and update
    local TEMP_FILE=$(mktemp)
    local SIG_FILE="${TEMP_FILE}.asc"
    local KEY_FILE=""
    if DOWNLOAD "$REPO_URL" "$TEMP_FILE"; then
        if [[ "$RELEASE_SIGNATURE_REQUIRED" == true || -n "$RELEASE_SIGNING_FINGERPRINT" ]]; then
            if ! DOWNLOAD "$RELEASE_SIGNATURE_URL" "$SIG_FILE"; then
                rm -f "$TEMP_FILE" "$SIG_FILE"
                echo -e "${RED}${BOLD}[✗]${NC} Failed to download release signature"
                LOG "ERROR" "Update failed - release signature download error"
                return 1
            fi

            if [[ -n "$RELEASE_SIGNING_KEY_URL" ]]; then
                KEY_FILE="${TEMP_FILE}.gpg"
                DOWNLOAD "$RELEASE_SIGNING_KEY_URL" "$KEY_FILE" >/dev/null 2>&1 || KEY_FILE=""
            fi

            if ! VERIFY_RELEASE_SIGNATURE "$TEMP_FILE" "$SIG_FILE" "$KEY_FILE" "$RELEASE_SIGNING_FINGERPRINT"; then
                rm -f "$TEMP_FILE" "$SIG_FILE" "$KEY_FILE"
                echo -e "${RED}${BOLD}[✗]${NC} Release signature verification failed"
                LOG "ERROR" "Update failed - release signature verification failed"
                return 1
            fi
        else
            echo -e "${YELLOW}${BOLD}[!]${NC} Release signature verification skipped (no signing fingerprint configured)"
            LOG "WARNING" "Release signature verification skipped"
        fi

        # Extract version from downloaded file
        NEW_VERSION=$(grep "declare -g VERSION=" "$TEMP_FILE" | cut -d'"' -f2)
        if [[ -z "$NEW_VERSION" ]] || ! grep -q '^#!/bin/bash' "$TEMP_FILE" || ! bash -n "$TEMP_FILE"; then
            rm -f "$TEMP_FILE" "$SIG_FILE" "$KEY_FILE"
            echo -e "${RED}${BOLD}[✗]${NC} Downloaded update failed validation"
            LOG "ERROR" "Update failed - downloaded script failed validation"
            return 1
        fi
        if sudo cp "$TEMP_FILE" /usr/local/bin/deepdns && sudo chmod +x /usr/local/bin/deepdns; then
            rm -f "$TEMP_FILE" "$SIG_FILE" "$KEY_FILE"
            echo -e "${GREEN}${BOLD}[✓]${NC} Successfully updated DeepDNS:"
            echo -e "   ${CYAN}${BOLD}→${NC} Binary: /usr/local/bin/deepdns"
            echo -e "   ${CYAN}${BOLD}→${NC} Updated: ${YELLOW}${BOLD}v${CURRENT_VERSION}${NC} ${GREEN}${BOLD}→${NC} ${YELLOW}${BOLD}v${NEW_VERSION}${NC}"
            echo -e "\nYou can now use 'deepdns' from anywhere"
            LOG "INFO" "Update successful from v${CURRENT_VERSION} to v${NEW_VERSION}"
            return 0
        fi
    fi

    rm -f "$TEMP_FILE" "$SIG_FILE" "$KEY_FILE"
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
