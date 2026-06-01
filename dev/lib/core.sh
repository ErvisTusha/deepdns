#!/bin/bash

CREATE_TEMP_DIR() {
    if [[ -z "$TEMP_DIR" ]]; then
        TEMP_DIR=$(mktemp -d)
        [[ ! -d "$TEMP_DIR" ]] && mkdir -p "$TEMP_DIR"
        trap 'rm -rf "$TEMP_DIR"' EXIT
    fi
}

HTTP_GET() {
    local URL="$1"
    shift || true

    curl --fail --silent --location --connect-timeout 5 --max-time 20 --retry 2 "$@" "$URL"
}

HTTP_POST_JSON() {
    local URL="$1"
    local BODY="$2"
    local AUTH="${3:-}"
    local CURL_ARGS=(--fail --silent --location --connect-timeout 5 --max-time 20 --retry 2 -H "Content-Type: application/json")

    if [[ -n "$AUTH" ]]; then
        CURL_ARGS+=(-u "$AUTH")
    fi

    curl "${CURL_ARGS[@]}" --data "$BODY" "$URL"
}

JSON_ESCAPE() {
    local VALUE="$1"
    VALUE="${VALUE//\\/\\\\}"
    VALUE="${VALUE//\"/\\\"}"
    VALUE="${VALUE//$'\n'/\\n}"
    VALUE="${VALUE//$'\r'/}"
    printf "%s" "$VALUE"
}

CSV_ESCAPE() {
    local VALUE="$1"
    VALUE="${VALUE//\"/\"\"}"
    printf '"%s"' "$VALUE"
}

WRITE_FORMATTED_OUTPUT() {
    local INPUT_FILE="$1"
    local OUTPUT_FILE="$2"
    local FORMAT="${3:-txt}"
    local DOMAIN="${4:-}"

    case "${FORMAT,,}" in
    txt)
        cat "$INPUT_FILE" >"$OUTPUT_FILE"
        ;;
    csv)
        {
            printf "domain,subdomain\n"
            while IFS= read -r TARGET; do
                CSV_ESCAPE "$DOMAIN"
                printf ","
                CSV_ESCAPE "$TARGET"
                printf "\n"
            done <"$INPUT_FILE"
        } >"$OUTPUT_FILE"
        ;;
    json)
        {
            printf '{\n'
            printf '  "domain": "%s",\n' "$(JSON_ESCAPE "$DOMAIN")"
            printf '  "subdomains": [\n'
            local FIRST=true
            while IFS= read -r TARGET; do
                if [[ "$FIRST" == true ]]; then
                    FIRST=false
                else
                    printf ',\n'
                fi
                printf '    "%s"' "$(JSON_ESCAPE "$TARGET")"
            done <"$INPUT_FILE"
            printf '\n  ]\n'
            printf '}\n'
        } >"$OUTPUT_FILE"
        ;;
    *)
        LOG "ERROR" "Unsupported output format: $FORMAT"
        return 1
        ;;
    esac
}

INIT_FINDINGS() {
    local OUTPUT_BASE="$1"
    local FORMAT="${2:-txt}"

    PENTEST_FINDINGS_FILE="${OUTPUT_BASE}_findings.${FORMAT}"
    PENTEST_JSON_ITEMS_FILE="${OUTPUT_BASE}_findings.items"
    PENTEST_FINDING_COUNT=0
    : >"$PENTEST_FINDINGS_FILE"
    : >"$PENTEST_JSON_ITEMS_FILE"

    case "${FORMAT,,}" in
    json)
        printf '[\n' >"$PENTEST_FINDINGS_FILE"
        ;;
    csv)
        printf "severity,check_id,category,target,title,evidence,remediation,confidence,source,timestamp\n" >"$PENTEST_FINDINGS_FILE"
        ;;
    esac
}

WRITE_FINDING() {
    local SEVERITY="$1"
    local CHECK_ID="$2"
    local CATEGORY="$3"
    local TARGET="$4"
    local TITLE="$5"
    local EVIDENCE="$6"
    local REMEDIATION="$7"
    local CONFIDENCE="$8"
    local SOURCE="$9"
    local TIMESTAMP
    TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    [[ -z "$PENTEST_FINDINGS_FILE" ]] && return 1

    case "${OUTPUT_FORMAT,,}" in
    json)
        {
            printf '{"severity":"%s",' "$(JSON_ESCAPE "$SEVERITY")"
            printf '"check_id":"%s",' "$(JSON_ESCAPE "$CHECK_ID")"
            printf '"category":"%s",' "$(JSON_ESCAPE "$CATEGORY")"
            printf '"target":"%s",' "$(JSON_ESCAPE "$TARGET")"
            printf '"title":"%s",' "$(JSON_ESCAPE "$TITLE")"
            printf '"evidence":"%s",' "$(JSON_ESCAPE "$EVIDENCE")"
            printf '"remediation":"%s",' "$(JSON_ESCAPE "$REMEDIATION")"
            printf '"confidence":"%s",' "$(JSON_ESCAPE "$CONFIDENCE")"
            printf '"source":"%s",' "$(JSON_ESCAPE "$SOURCE")"
            printf '"timestamp":"%s"}' "$(JSON_ESCAPE "$TIMESTAMP")"
        } >>"$PENTEST_JSON_ITEMS_FILE"
        printf '\n' >>"$PENTEST_JSON_ITEMS_FILE"
        ;;
    csv)
        {
            CSV_ESCAPE "$SEVERITY"; printf ","
            CSV_ESCAPE "$CHECK_ID"; printf ","
            CSV_ESCAPE "$CATEGORY"; printf ","
            CSV_ESCAPE "$TARGET"; printf ","
            CSV_ESCAPE "$TITLE"; printf ","
            CSV_ESCAPE "$EVIDENCE"; printf ","
            CSV_ESCAPE "$REMEDIATION"; printf ","
            CSV_ESCAPE "$CONFIDENCE"; printf ","
            CSV_ESCAPE "$SOURCE"; printf ","
            CSV_ESCAPE "$TIMESTAMP"; printf "\n"
        } >>"$PENTEST_FINDINGS_FILE"
        ;;
    *)
        {
            printf "[%s] %s (%s)\n" "$SEVERITY" "$TITLE" "$CHECK_ID"
            printf "  Target: %s\n" "$TARGET"
            printf "  Category: %s\n" "$CATEGORY"
            printf "  Confidence: %s\n" "$CONFIDENCE"
            printf "  Evidence: %s\n" "$EVIDENCE"
            printf "  Remediation: %s\n\n" "$REMEDIATION"
        } >>"$PENTEST_FINDINGS_FILE"
        ;;
    esac
    PENTEST_FINDING_COUNT=$((PENTEST_FINDING_COUNT + 1))
}

FINALIZE_FINDINGS() {
    if [[ "${OUTPUT_FORMAT,,}" == "json" && -n "$PENTEST_FINDINGS_FILE" ]]; then
        : >"$PENTEST_FINDINGS_FILE"
        printf '[\n' >>"$PENTEST_FINDINGS_FILE"
        local FIRST=true
        while IFS= read -r ITEM; do
            [[ -z "$ITEM" ]] && continue
            if [[ "$FIRST" == true ]]; then
                FIRST=false
            else
                printf ',\n' >>"$PENTEST_FINDINGS_FILE"
            fi
            printf '  %s' "$ITEM" >>"$PENTEST_FINDINGS_FILE"
        done <"$PENTEST_JSON_ITEMS_FILE"
        [[ "$FIRST" == false ]] && printf '\n' >>"$PENTEST_FINDINGS_FILE"
        printf ']\n' >>"$PENTEST_FINDINGS_FILE"
        rm -f "$PENTEST_JSON_ITEMS_FILE"
    fi
}

WRITE_EVIDENCE() {
    local CHECK_ID="$1"
    local TARGET="$2"
    local CONTENT="$3"

    [[ "$PENTEST_RAW_EVIDENCE" != true ]] && return 0
    [[ -z "$PENTEST_EVIDENCE_DIR" ]] && return 0

    mkdir -p "$PENTEST_EVIDENCE_DIR"
    local SAFE_TARGET
    SAFE_TARGET="$(echo "$TARGET" | tr -c 'A-Za-z0-9._-' '_')"
    printf "%s\n" "$CONTENT" >"$PENTEST_EVIDENCE_DIR/${CHECK_ID}_${SAFE_TARGET}.txt"
}

VERIFY_RELEASE_SIGNATURE() {
    local FILE="$1"
    local SIGNATURE_FILE="$2"
    local KEY_FILE="$3"
    local FINGERPRINT="$4"

    if [[ "$RELEASE_SIGNATURE_REQUIRED" != true && -z "$FINGERPRINT" ]]; then
        LOG "WARNING" "Release signature verification skipped - no signing fingerprint configured"
        return 0
    fi

    if ! IS_INSTALLED gpg; then
        LOG "ERROR" "gpg is required for release signature verification"
        return 1
    fi

    if [[ ! -s "$SIGNATURE_FILE" ]]; then
        LOG "ERROR" "Release signature file is missing or empty"
        return 1
    fi

    local GNUPGHOME_DIR
    GNUPGHOME_DIR="$(mktemp -d)"
    chmod 700 "$GNUPGHOME_DIR"

    if [[ -n "$KEY_FILE" && -s "$KEY_FILE" ]]; then
        GNUPGHOME="$GNUPGHOME_DIR" gpg --batch --import "$KEY_FILE" >/dev/null 2>&1 || {
            rm -rf "$GNUPGHOME_DIR"
            LOG "ERROR" "Failed to import release signing key"
            return 1
        }
    fi

    if [[ -n "$FINGERPRINT" ]]; then
        GNUPGHOME="$GNUPGHOME_DIR" gpg --batch --list-keys --with-colons "$FINGERPRINT" >/dev/null 2>&1 || {
            rm -rf "$GNUPGHOME_DIR"
            LOG "ERROR" "Configured release signing fingerprint is not trusted"
            return 1
        }
    fi

    GNUPGHOME="$GNUPGHOME_DIR" gpg --batch --verify "$SIGNATURE_FILE" "$FILE" >/dev/null 2>&1
    local STATUS=$?
    rm -rf "$GNUPGHOME_DIR"

    if [[ $STATUS -ne 0 ]]; then
        LOG "ERROR" "Release signature verification failed"
        return 1
    fi

    LOG "INFO" "Release signature verification passed"
    return 0
}

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
    echo -e "  ${GREEN}${BOLD}--format${NC} <txt|json|csv>       ${BLUE}${BOLD}# Output format (default: ${YELLOW}${BOLD}${OUTPUT_FORMAT}${NC}${BLUE}${BOLD})${NC}"
    echo -e "  ${GREEN}${BOLD}-R, --resolver${NC} <file>         ${BLUE}${BOLD}# Custom resolver file${NC}"
    echo -e "  ${GREEN}${BOLD}-t, --threads${NC} <number>        ${BLUE}${BOLD}# Number of threads (default: ${YELLOW}${BOLD}10${NC}${BLUE}${BOLD}, max: 100)${NC}"
    echo -e "  ${GREEN}${BOLD}-p, --passive${NC}                 ${BLUE}${BOLD}# Enable passive scanning${NC}"
    echo -e "  ${GREEN}${BOLD}-a, --active${NC}                  ${BLUE}${BOLD}# Enable active scanning${NC}"
    echo -e "  ${GREEN}${BOLD}-r, --recursive${NC} [depth]       ${BLUE}${BOLD}# Enable recursive scanning (default: ${YELLOW}${BOLD}${DEFAULT_RECURSIVE_DEPTH}${NC}${BLUE}${BOLD})${NC}"
    echo -e "  ${GREEN}${BOLD}--pattern${NC}                     ${BLUE}${BOLD}# Enable pattern recognition${NC}"
    echo -e "  ${GREEN}${BOLD}--zone-transfer${NC}               ${BLUE}${BOLD}# Attempt DNS zone transfer checks${NC}"
    echo -e "  ${GREEN}${BOLD}--dnssec${NC}                      ${BLUE}${BOLD}# Run DNSSEC posture checks${NC}"
    echo -e "  ${GREEN}${BOLD}--pentest${NC}                     ${BLUE}${BOLD}# Run penetration-testing checks${NC}"
    echo -e "  ${GREEN}${BOLD}--profile${NC} <safe|balanced|aggressive> ${BLUE}${BOLD}# Pentest check profile${NC}"
    echo -e "  ${GREEN}${BOLD}--checks${NC} <list>               ${BLUE}${BOLD}# Comma-separated pentest checks${NC}"
    echo -e "  ${GREEN}${BOLD}--evidence-dir${NC} <dir>          ${BLUE}${BOLD}# Raw evidence output directory${NC}"
    echo -e "  ${GREEN}${BOLD}--vhost${NC}                       ${BLUE}${BOLD}# Enable virtual host scanning${NC}"
    echo -e "  ${GREEN}${BOLD}--vhost-port${NC} <ports>          ${BLUE}${BOLD}# Custom vhost ports (comma-separated, default: 80,443,8080,8443)${NC}"
    echo -e "  ${GREEN}${BOLD}--vhost-filter${NC} <values>       ${BLUE}${BOLD}# Hide matching vhost responses (comma-separated)${NC}"
    echo -e "  ${GREEN}${BOLD}--vhost-filter-type${NC} <type>    ${BLUE}${BOLD}# Filter type: status, size, words, or lines${NC}"
    echo -e "  ${GREEN}${BOLD}--raw${NC}                         ${BLUE}${BOLD}# Preserve raw text results${NC}"
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
    echo -e "      --vhost-filter 200 --vhost-filter-type status"
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
