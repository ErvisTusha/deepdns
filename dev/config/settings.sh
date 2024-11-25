#!/bin/bash

# Directory settings
declare -g SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
declare -g LOG_DIR="$SCRIPT_DIR/logs"
declare -g FILES_DIR="$SCRIPT_DIR/files"

# Create required directories
mkdir -p "$LOG_DIR" "$FILES_DIR"

# Debug settings
declare -g DEBUG_LOG="$LOG_DIR/debug.log"

# Global variables
declare -g START_TIME=$(date +%s)
declare -g TEMP_DIR=""
declare -g VERBOSE=false
declare -g DEBUG=false
declare -g VERSION="2.0.0-dev"
declare -g AUTHOR="Ervis Tusha"

# Default settings
declare -g DEFAULT_RECURSIVE_DEPTH=3
declare -g DEFAULT_OUTPUT_DIR="$PWD"
declare -g OUTPUT_FORMAT="txt"
declare -g WORDLIST_PATH=""

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

declare -g VHOST_PORTS=(80 443 8080 8443)

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

# Thread count
declare -g THREAD_COUNT=10