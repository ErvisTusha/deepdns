#!/bin/bash

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
