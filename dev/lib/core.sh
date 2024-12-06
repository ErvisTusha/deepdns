#!/bin/bash

CREATE_TEMP_DIR() {
    if [[ -z "$TEMP_DIR" ]]; then
        TEMP_DIR=$(mktemp -d)
        [[ ! -d "$TEMP_DIR" ]] && mkdir -p "$TEMP_DIR"
        trap 'rm -rf "$TEMP_DIR"' EXIT
    fi
}

# Add trap for SIGINT/SIGTERM
trap 'CLEANUP; exit 130' SIGINT SIGTERM

CLEANUP() {
    local EXIT_CODE=$?

    if [[ "$CLEANUP_DONE" == "true" ]]; then
        return $EXIT_CODE
    fi
    CLEANUP_DONE="true"

    echo -e "\n${YELLOW}${BOLD}[!]${NC} Cleaning up..."
    LOG "INFO" "Cleaning up temporary files"

    # Kill any remaining background processes
    jobs -p | xargs -r kill -9 2>/dev/null

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
