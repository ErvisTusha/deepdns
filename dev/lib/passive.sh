#!/bin/bash

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
