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
    local SCRIPT=""
    SCRIPT="$(basename "$0")"
    if [[ -z "$1" ]]; then
        INSTALL_DIR="/usr/local/bin"
    else
        if ! [[ -d "$1" ]]; then
            [[ "$VERBOSE" == "true" ]] && echo "ERROR:INSTALL_SCRIPT Invalid directory provided"
            [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:INSTALL_SCRIPT Invalid directory provided" >>"$DEBUG_LOG"
            return 1
        fi
        INSTALL_DIR="$1"
    fi

    if [[ "$EUID" -ne 0 ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO:INSTALL_SCRIPT User does not have root privileges"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:INSTALL_SCRIPT User does not have root privileges" >>"$DEBUG_LOG"
        return 1
    fi

    if command -v "$SCRIPT" >/dev/null 2>&1; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO:INSTALL_SCRIPT $SCRIPT is already installed"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:INSTALL_SCRIPT $SCRIPT is already installed" >>"$DEBUG_LOG"
        return 0
    fi

    NEW_NAME=$(echo "$SCRIPT" | sed 's/\.sh$//')

    cp "$0" "$INSTALL_DIR/$NEW_NAME"
    chmod +x "$INSTALL_DIR/$NEW_NAME"

    if ! command -v "$NEW_NAME" >/dev/null 2>&1; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR:INSTALL_SCRIPT Failed to install $NEW_NAME"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:INSTALL_SCRIPT Failed to install $NEW_NAME" >>"$DEBUG_LOG"
        return 1
    fi
    [[ "$VERBOSE" == "true" ]] && echo "INFO:INSTALL_SCRIPT $NEW_NAME installed successfully"
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO:INSTALL_SCRIPT $NEW_NAME installed successfully" >>"$DEBUG_LOG"
    return 0
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
