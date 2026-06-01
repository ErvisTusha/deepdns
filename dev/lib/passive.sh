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
    local CENSYS_RESULTS="$TEMP_DIR/${DOMAIN}_censys.txt"
    local OTX_RESULTS="$TEMP_DIR/${DOMAIN}_otx.txt"
    local HACKERTARGET_RESULTS="$TEMP_DIR/${DOMAIN}_hackertarget.txt"
    local URLSCAN_RESULTS="$TEMP_DIR/${DOMAIN}_urlscan.txt"
    local WAYBACK_RESULTS="$TEMP_DIR/${DOMAIN}_wayback.txt"

    touch "$ST_RESULTS" "$CRT_RESULTS" "$VT_RESULTS" "$CENSYS_RESULTS" "$OTX_RESULTS" "$HACKERTARGET_RESULTS" "$URLSCAN_RESULTS" "$WAYBACK_RESULTS" || {
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

    echo -e "${YELLOW}${BOLD}[*]${NC} Querying Censys API..."
    LOG "DEBUG" "Querying Censys API"
    if [[ -n "$CENSYS_API_ID" && -n "$CENSYS_API_SECRET" ]]; then
        QUERY_CENSYS "$DOMAIN" >"$CENSYS_RESULTS"
        local CENSYS_COUNT=$(wc -l <"$CENSYS_RESULTS")
        echo -e "${GREEN}${BOLD}[✓]${NC} Censys: Found $CENSYS_COUNT subdomains"
    else
        echo -e "${RED}${BOLD}[!]${NC} Censys: Skipped (no credentials)"
    fi

    echo -e "${YELLOW}${BOLD}[*]${NC} Querying AlienVault OTX..."
    QUERY_ALIENVAULT "$DOMAIN" >"$OTX_RESULTS"
    echo -e "${GREEN}${BOLD}[✓]${NC} AlienVault OTX: Found $(wc -l <"$OTX_RESULTS") subdomains"

    echo -e "${YELLOW}${BOLD}[*]${NC} Querying HackerTarget..."
    QUERY_HACKERTARGET "$DOMAIN" >"$HACKERTARGET_RESULTS"
    echo -e "${GREEN}${BOLD}[✓]${NC} HackerTarget: Found $(wc -l <"$HACKERTARGET_RESULTS") subdomains"

    echo -e "${YELLOW}${BOLD}[*]${NC} Querying URLScan..."
    QUERY_URLSCAN "$DOMAIN" >"$URLSCAN_RESULTS"
    echo -e "${GREEN}${BOLD}[✓]${NC} URLScan: Found $(wc -l <"$URLSCAN_RESULTS") subdomains"

    echo -e "${YELLOW}${BOLD}[*]${NC} Querying Wayback CDX..."
    QUERY_WAYBACK "$DOMAIN" >"$WAYBACK_RESULTS"
    echo -e "${GREEN}${BOLD}[✓]${NC} Wayback CDX: Found $(wc -l <"$WAYBACK_RESULTS") subdomains"

    cat "$ST_RESULTS" "$CRT_RESULTS" "$VT_RESULTS" "$CENSYS_RESULTS" "$OTX_RESULTS" "$HACKERTARGET_RESULTS" "$URLSCAN_RESULTS" "$WAYBACK_RESULTS" 2>/dev/null | NORMALIZE_PASSIVE_RESULTS "$DOMAIN" | while read -r TARGET; do
        echo -e "${INDENT}     ${GREEN}${BOLD}[+]${NC} Found: $TARGET"
        echo "$TARGET" >>"$RESULTS_FILE"
    done

    local TOTAL=$(wc -l <"$RESULTS_FILE")
    [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && echo -e "\n${GREEN}${BOLD}[✓]${NC} Passive scan complete: $TOTAL unique results found"
    LOG "INFO" "Passive scan complete: Found $TOTAL unique subdomains"

    rm -f "$ST_RESULTS" "$CRT_RESULTS" "$VT_RESULTS" "$CENSYS_RESULTS" "$OTX_RESULTS" "$HACKERTARGET_RESULTS" "$URLSCAN_RESULTS" "$WAYBACK_RESULTS"
    return 0
}

NORMALIZE_PASSIVE_RESULTS() {
    local DOMAIN="$1"

    sed 's/\r$//' |
        tr ',' '\n' |
        sed 's/^\*\.//' |
        sed '/^$/d' |
        awk -v domain="$DOMAIN" '
            $0 == "null" { next }
            /^[A-Za-z0-9-]+$/ { print tolower($0 "." domain); next }
            /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/ {
                target = tolower($0)
                domain_l = tolower(domain)
                if (target == domain_l || target ~ ("\\." domain_l "$")) {
                    print target
                }
            }
        ' |
        sort -u
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
    RESULT=$(HTTP_GET "$API_URL" -H "APIKEY: $SECURITYTRAILS_API_KEY")
    echo "$RESULT" | jq -r '.subdomains[]' 2>/dev/null
    LOG "DEBUG" "SecurityTrails query completed for $DOMAIN"
}

QUERY_CRTSH() {
    local DOMAIN="$1"
    local API_URL="https://crt.sh/?q=%.${DOMAIN}&output=json"

    local RESULT
    RESULT=$(HTTP_GET "$API_URL")
    echo "$RESULT" | jq -r '.[].name_value' 2>/dev/null | tr '\n' ',' | tr ',' '\n' | sort -u
}

QUERY_VIRUSTOTAL() {
    local DOMAIN="$1"
    local API_URL="https://www.virustotal.com/vtapi/v2/domain/report"

    if [[ -z "$VIRUSTOTAL_API_KEY" ]]; then
        LOG "WARNING" "VirusTotal API key not configured"
        return 1
    fi

    local RESULT
    RESULT=$(curl --fail --silent --location --connect-timeout 5 --max-time 20 --retry 2 -G --data-urlencode "apikey=$VIRUSTOTAL_API_KEY" --data-urlencode "domain=$DOMAIN" "$API_URL")
    echo "$RESULT" | jq -r '.subdomains[]' 2>/dev/null
}

QUERY_CENSYS() {
    local DOMAIN="$1"
    local API_URL="https://search.censys.io/api/v2/hosts/search"

    if [[ -z "$CENSYS_API_ID" || -z "$CENSYS_API_SECRET" ]]; then
        LOG "WARNING" "Censys credentials not configured"
        return 1
    fi

    local RESULT
    RESULT=$(HTTP_POST_JSON "$API_URL" "{\"q\":\"services.tls.certificates.leaf_data.names: *.${DOMAIN} OR dns.names: *.${DOMAIN}\",\"per_page\":100}" "$CENSYS_API_ID:$CENSYS_API_SECRET")

    echo "$RESULT" | jq -r '.result.hits[]? | (.name? // empty), (.names[]? // empty), (.dns.names[]? // empty)' 2>/dev/null | sort -u
}

QUERY_ALIENVAULT() {
    local DOMAIN="$1"
    local API_URL="https://otx.alienvault.com/api/v1/indicators/domain/${DOMAIN}/passive_dns"
    local RESULT

    RESULT=$(HTTP_GET "$API_URL") || return 0
    echo "$RESULT" | jq -r '.passive_dns[]? | .hostname?, .address?' 2>/dev/null | sort -u
}

QUERY_HACKERTARGET() {
    local DOMAIN="$1"
    local API_URL="https://api.hackertarget.com/hostsearch/?q=${DOMAIN}"
    local RESULT

    RESULT=$(HTTP_GET "$API_URL") || return 0
    echo "$RESULT" | cut -d',' -f1 | sort -u
}

QUERY_URLSCAN() {
    local DOMAIN="$1"
    local API_URL="https://urlscan.io/api/v1/search/?q=domain:${DOMAIN}"
    local RESULT

    RESULT=$(HTTP_GET "$API_URL") || return 0
    echo "$RESULT" | jq -r '.results[]? | .page.domain?, .task.domain?' 2>/dev/null | sort -u
}

QUERY_WAYBACK() {
    local DOMAIN="$1"
    local API_URL="https://web.archive.org/cdx?url=*.${DOMAIN}/*&output=json&fl=original&collapse=urlkey"
    local RESULT

    RESULT=$(HTTP_GET "$API_URL") || return 0
    echo "$RESULT" | jq -r '.[1:][]? | .[0]?' 2>/dev/null | sed 's#https\?://##' | cut -d/ -f1 | sort -u
}
