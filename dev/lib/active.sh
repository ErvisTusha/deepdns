#!/bin/bash

WILDCARD_DETECTION() {
    local DOMAIN="$1"
    local ATTEMPTS=3
    local WILDCARD_DETECTED=false

    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}[ERROR] DOMAIN PARAMETER IS REQUIRED${NC}"
        return 1
    fi

    for ATTEMPT in $(seq 1 $ATTEMPTS); do
        local RANDOM_SUBDOMAIN="WILDCARD-$(openssl rand -hex 10)"
        local DNS_RESULT

        if ! DNS_RESULT=$(dig +short "$RANDOM_SUBDOMAIN.$DOMAIN" 2>/dev/null); then
            echo -e "${RED}[ERROR] DNS QUERY FAILED FOR $RANDOM_SUBDOMAIN.$DOMAIN${NC}"
            LOG "ERROR" "DNS QUERY FAILED FOR $RANDOM_SUBDOMAIN.$DOMAIN"
            continue
        fi

        if echo "$DNS_RESULT" | grep -q '[0-9]\|CNAME'; then
            WILDCARD_DETECTED=true
            break
        fi
        sleep 1
    done

    if [ "$WILDCARD_DETECTED" = true ]; then
        LOG "WARNING" "WILDCARD DNS DETECTED FOR $DOMAIN"
        if [[ "$RECURSIVE_SCAN_ENABLED" == false ]]; then
            echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} Wildcard DNS detected for $DOMAIN${NC}"
            echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} This may generate false positives${NC}"
            read -p "$(echo -e "${INDENT}${YELLOW}${BOLD}[?]${NC} Do you want to continue scanning? [y/N]: ")" CONTINUE
        else
            read -p "$(echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} Wildcard DNS detected, do you want to continue scanning? [y/N]: ")" CONTINUE
        fi

        if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
            echo -e "${INDENT}${RED}${BOLD}[!]${NC} SCAN ABORTED BY USER${NC}"
            return 2
        fi
        return 0
    else
        [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && echo -e "${INDENT}${GREEN}${BOLD}[✓]${NC} No wildcard DNS detected for $DOMAIN${NC}"
        LOG "INFO" "No wildcard DNS detected for $DOMAIN"
        return 0
    fi
}

CHECK_PORT() {
    local IP="$1"
    local PORT="$2"
    local TIMEOUT=2

    # Try nc with shorter timeout first
    if command -v nc >/dev/null 2>&1; then
        if timeout $TIMEOUT nc -z -w1 "$IP" "$PORT" 2>/dev/null; then
            return 0
        fi
        return 1
    fi

    # Fallback to bash TCP test with timeout
    # This ensures we don't hang on closed ports
    if timeout $TIMEOUT bash -c "</dev/tcp/$IP/$PORT" 2>/dev/null; then
        return 0
    fi

    return 1
}

VHOST_WILDCARD_DETECTION() {
    local DOMAIN="$1"
    local DOMAIN_IP="$2"
    local PORT="$3"
    local INDENT="$4"
    local ATTEMPTS=3
    local WILDCARD_DETECTED=false

    local PROTOCOL=$(DETECT_PROTOCOL "${DOMAIN_IP}" "${PORT}")

    LOG "DEBUG" "Starting VHOST wildcard detection for $DOMAIN on $PROTOCOL://$DOMAIN_IP:$PORT"

    for ATTEMPT in $(seq 1 $ATTEMPTS); do
        local RANDOM_VHOST="wildcard-$(openssl rand -hex 10).${DOMAIN}"

        # Get baseline response with random vhost
        local RESPONSE=$(curl -s -I \
            --connect-timeout 3 \
            --max-time 5 \
            -k \
            -H "Host: ${RANDOM_VHOST}" \
            "${PROTOCOL}://${DOMAIN_IP}:${PORT}" 2>/dev/null)

        local STATUS=$(echo "$RESPONSE" | grep -E "^HTTP" | cut -d' ' -f2)

        # If we get a successful response (200 or 300s) for a random hostname, it's likely a wildcard
        if IS_NUMBER "$STATUS"; then
            WILDCARD_DETECTED=true
            break
        fi
        sleep 1
    done

    if [ "$WILDCARD_DETECTED" = true ]; then
        LOG "WARNING" "VHOST WILDCARD DETECTED FOR $DOMAIN on port $PORT"
        if [[ "$RECURSIVE_SCAN_ENABLED" == false ]]; then
            echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} Virtual host wildcard detected for $DOMAIN on port $PORT"
            echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} Server responds to non-existent vhosts - results may be unreliable"
            read -p "$(echo -e "${INDENT}${YELLOW}${BOLD}[?]${NC} Do you want to continue scanning? [y/N]: ")" CONTINUE
        else
            read -p "$(echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} Virtual host wildcard detected, continue scanning? [y/N]: ")" CONTINUE
        fi

        if [[ ! "$CONTINUE" =~ ^[Yy]$ ]]; then
            echo -e "${INDENT}${RED}${BOLD}[!]${NC} VHOST SCAN ABORTED BY USER"
            return 2
        fi
        return 0
    else
        [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && echo -e "${INDENT}${GREEN}${BOLD}[✓]${NC} No virtual host wildcard detected for $DOMAIN on port $PORT"
        LOG "INFO" "No VHOST wildcard detected for $DOMAIN on port $PORT"
        return 0
    fi
}


PROCESS_ACTIVE_CHUNK() {
    local CHUNK="$1"
    local CHUNK_RESULTS="$THREAD_DIR/results_$(basename "$CHUNK")"
    local PROCESSED=0
    local CHUNK_SIZE=$(wc -l <"$CHUNK")
    LOG "DEBUG" "Processing chunk: $CHUNK with $CHUNK_SIZE entries"

    # Define per-chunk progress file
    local PROGRESS_FILE="$THREAD_DIR/progress_$(basename "$CHUNK")"
    echo "0" >"$PROGRESS_FILE"

    while read -r SUBDOMAIN; do
        local TARGET="${SUBDOMAIN}.${DOMAIN}"
        local RESOLVER=${RESOLVERS[$((RANDOM % ${#RESOLVERS[@]}))]}
        LOG "DEBUG" "Testing subdomain: $TARGET using resolver: $RESOLVER"

        if dig +short "$TARGET" "@$RESOLVER" | grep -q '^[0-9]'; then
            LOG "INFO" "Found valid subdomain: $TARGET"
            echo -e "${INDENT}     ${GREEN}${BOLD}[+]${NC} Found: $TARGET"
            echo "$TARGET" >> "$CHUNK_RESULTS"
        fi

        ((PROCESSED++))
        echo "$PROCESSED" >"$PROGRESS_FILE"
        LOG "DEBUG" "Processed $PROCESSED/$CHUNK_SIZE in current chunk"
    done <"$CHUNK"
    LOG "DEBUG" "Completed processing chunk: $CHUNK"
}


ACTIVE_SCAN() {
    local DOMAIN="$1"
    local RESULTS_FILE="${2:-${OUTPUT:-$PWD/${DOMAIN}_ACTIVE.TXT}}"
    local INDENT="$3"
    LOG "DEBUG" "Starting ACTIVE_SCAN for domain: $DOMAIN with $THREAD_COUNT threads"
    LOG "DEBUG" "Results will be written to: $RESULTS_FILE"
    LOG "DEBUG" "Using indent level: $INDENT"

    if [[ "$RECURSIVE_SCAN_ENABLED" == false ]]; then
        echo
        echo -e "${CYAN}${BOLD}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}${BOLD}│${NC}                           ${UNDERLINE}Active Scan Results${NC}                            ${CYAN}${BOLD}│${NC}"
        echo -e "${CYAN}${BOLD}└──────────────────────────────────────────────────────────────────────────┘${NC}\n"
        echo -e "\n${CYAN}${BOLD}[ACTIVE SCAN]${NC} Starting active enumeration for $DOMAIN using $THREAD_COUNT threads"
        LOG "INFO" "Starting non-recursive active scan for $DOMAIN"
    fi

    WILDCARD_DETECTION "$DOMAIN" "$INDENT"
    COMMAND_STATUS=$?
    LOG "DEBUG" "Wildcard detection returned status: $COMMAND_STATUS"
    if [ $COMMAND_STATUS == 2 ]; then
        LOG "INFO" "Aborting scan due to wildcard detection user choice"
        return 0
    fi

    if [[ -n "$WORDLIST_PATH" ]]; then
        [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && echo -e "${INDENT}${YELLOW}${BOLD}[*]${NC} Starting parallel wordlist bruteforce..."
        local TOTAL_WORDS=$(wc -l <"$WORDLIST_PATH")
        LOG "DEBUG" "Using wordlist: $WORDLIST_PATH with $TOTAL_WORDS entries"

        # Create thread directory with proper permissions and cleanup handler
        local THREAD_DIR="$TEMP_DIR/threads"
        local PROGRESS_DIR="$THREAD_DIR/progress"

        # Ensure directories exist with proper permissions
        mkdir -p "$THREAD_DIR" "$PROGRESS_DIR" || {
            LOG "ERROR" "Failed to create thread directories"
            echo -e "${RED}${BOLD}[ERROR]${NC} Failed to create thread directories"
            return 1
        }

        # Ensure directories are writable
        chmod 755 "$THREAD_DIR" "$PROGRESS_DIR" || {
            LOG "ERROR" "Failed to set directory permissions"
            return 1
        }

        # Create and initialize progress file with proper permissions
        local STATUS_FILE="$THREAD_DIR/progress_status"
        echo "0" >"$STATUS_FILE" || {
            LOG "ERROR" "Failed to create progress status file"
            return 1
        }
        chmod 644 "$STATUS_FILE" || {
            LOG "ERROR" "Failed to set progress file permissions"
            return 1
        }

        LOG "DEBUG" "Thread directories created successfully"

        local CHUNK_SIZE=$(((TOTAL_WORDS + THREAD_COUNT - 1) / THREAD_COUNT))
        LOG "DEBUG" "Splitting wordlist into chunks of size: $CHUNK_SIZE"

        # Create chunks with proper error handling
        split -l "$CHUNK_SIZE" "$WORDLIST_PATH" "$THREAD_DIR/chunk_" || {
            LOG "ERROR" "Failed to split wordlist into chunks"
            return 1
        }

        if [[ -z "$RESOLVER_FILE" ]]; then
            RESOLVERS=("1.1.1.1" "8.8.8.8" "9.9.9.9")
            LOG "DEBUG" "Using default resolvers: ${RESOLVERS[*]}"
        else
            mapfile -t RESOLVERS <"$RESOLVER_FILE"
            LOG "DEBUG" "Loaded ${#RESOLVERS[@]} resolvers from $RESOLVER_FILE"
        fi

        local PIDS=()
        for CHUNK in "$THREAD_DIR"/chunk_*; do
            LOG "DEBUG" "Launching thread for chunk: $CHUNK"
            PROCESS_ACTIVE_CHUNK "$CHUNK" &
            PIDS+=($!)
            LOG "DEBUG" "Started thread PID: ${PIDS[-1]}"
        done

        while true; do
            local RUNNING=0
            for PID in "${PIDS[@]}"; do
                if kill -0 "$PID" 2>/dev/null; then
                    ((RUNNING++))
                fi
            done

            # Sum up progress with error handling
            local CURRENT_PROGRESS=0
            local PROGRESS_FILES=("$THREAD_DIR"/progress_*)
            if [ -e "${PROGRESS_FILES[0]}" ]; then
                while read -r val; do
                    ((CURRENT_PROGRESS += val))
                done < <(cat "$THREAD_DIR"/progress_* 2>/dev/null || echo 0)
            fi

            local PROGRESS=$((CURRENT_PROGRESS * 100 / TOTAL_WORDS))
            LOG "DEBUG" "Progress: $PROGRESS% complete, $RUNNING threads active"

            printf "\r${INDENT}${YELLOW}${BOLD}[*]${NC} Progress: [${GREEN}${BOLD}%-50s${NC}] %3d%% (%d threads active) " \
                "$(printf '#%.0s' $(seq 1 $((PROGRESS / 2))))" \
                "$PROGRESS" \
                "$RUNNING"

            if [[ $RUNNING -eq 0 ]]; then
                echo
                LOG "DEBUG" "All threads completed"
                break
            fi

            sleep 1
        done

        wait
        LOG "DEBUG" "All threads finished execution"

        # Merge results from all chunks
        cat "$THREAD_DIR"/results_* >"$RESULTS_FILE" 2>/dev/null

        # Count total unique results
        local TOTAL=$(sort -u "$RESULTS_FILE" | wc -l)
        echo -e "${INDENT}${GREEN}${BOLD}[✓]${NC} Active scan complete: $TOTAL unique results found"

        LOG "DEBUG" "Cleaning up temporary thread directory: $THREAD_DIR"
        rm -rf "$THREAD_DIR" 2>/dev/null || {
            CLEANUP
        }
    fi

    LOG "DEBUG" "ACTIVE_SCAN completed for domain: $DOMAIN"
    return 0
}

# Add helper function for status colors
GET_STATUS_COLOR() {
    local STATUS=$1
    case $STATUS in
    200) echo "${GREEN}" ;;                     # Success
    301 | 302 | 307 | 308) echo "${BLUE}" ;;    # Redirects
    401 | 403) echo "${YELLOW}" ;;              # Auth required/Forbidden
    404) echo "${RED}" ;;                       # Not Found
    500 | 502 | 503 | 504) echo "${MAGENTA}" ;; # Server Errors
    *) echo "${WHITE}" ;;                       # Other codes
    esac
}

PROCESS_VHOST_CHUNK() {
    local CHUNK="$1"
    local PORT="$2"
    local CHUNK_RESULTS="$THREAD_DIR/results_$(basename "$CHUNK")_${PORT}"
    local PROCESSED=0
    local CHUNK_SIZE=$(wc -l <"$CHUNK")
    local PROGRESS_FILE="$THREAD_DIR/progress_$(basename "$CHUNK")_${PORT}"
    echo "0" >"$PROGRESS_FILE"

    # Determine protocol based on port
    local PROTOCOL="http"
    local PROTOCOL=$(DETECT_PROTOCOL "${DOMAIN_IP}" "${PORT}")

    while IFS= read -r SUBDOMAIN; do
        local VHOST="${SUBDOMAIN}.${DOMAIN}"
        # Get random User-Agent
        local RANDOM_UA=${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}

        # Start timing
        local START_TIME=$(date +%s%N)

        # Use curl with connection timeout, max time and SSL options
        local RESPONSE=$(curl -s -I \
            --connect-timeout 3 \
            --max-time 5 \
            -k \
            -A "$RANDOM_UA" \
            -H "Host: ${VHOST}" \
            "${PROTOCOL}://${DOMAIN_IP}:${PORT}" 2>/dev/null)

        # Calculate duration in milliseconds
        local END_TIME=$(date +%s%N)

        local STATUS=$(echo "$RESPONSE" | grep -E "^HTTP" | cut -d' ' -f2)
        # Update size extraction to handle missing Content-Length
        local SIZE=$(echo "$RESPONSE" | grep -i "^Content-Length:" | cut -d' ' -f2 | tr -d '\r' || echo "-")
        # Ensure SIZE is a number or "-" if not found
        if [[ ! "$SIZE" =~ ^[0-9]+$ ]]; then
            SIZE="-"
        fi
        local WORDS=$(echo "$RESPONSE" | wc -w)
        local LINES=$(echo "$RESPONSE" | wc -l)
        local DURATION=$(((END_TIME - START_TIME) / 1000000))


        #If IS_NUMBER is true
        if IS_NUMBER "$STATUS"; then
            # Apply filters if specified
            local SHOW_RESULT=true
            if [[ -n "$VHOST_FILTER" ]]; then
                case "$VHOST_FILTER_TYPE" in
                "status")
                    # Split comma-separated filters into array
                    IFS=',' read -ra FILTERS <<<"$VHOST_FILTER"
                    for FILTER in "${FILTERS[@]}"; do
                        # If any filter matches, hide the result
                        [[ "$STATUS" =~ ^($FILTER)$ ]] && SHOW_RESULT=false && break
                    done
                    ;;
                "size")
                    IFS=',' read -ra FILTERS <<<"$VHOST_FILTER"
                    for FILTER in "${FILTERS[@]}"; do
                        if [[ "$FILTER" =~ ^[0-9]+$ ]]; then
                            [[ "$SIZE" -eq "$FILTER" ]] && SHOW_RESULT=false && break
                        elif [[ "$FILTER" =~ ^\<[0-9]+$ ]]; then
                            local VAL=${FILTER#<}
                            [[ "$SIZE" -lt "$VAL" ]] && SHOW_RESULT=false && break
                        elif [[ "$FILTER" =~ ^\>[0-9]+$ ]]; then
                            local VAL=${FILTER#>}
                            [[ "$SIZE" -gt "$VAL" ]] && SHOW_RESULT=false && break
                        fi
                    done
                    ;;
                "words")
                    IFS=',' read -ra FILTERS <<<"$VHOST_FILTER"
                    for FILTER in "${FILTERS[@]}"; do
                        if [[ "$FILTER" =~ ^[0-9]+$ ]]; then
                            [[ "$WORDS" -eq "$FILTER" ]] && SHOW_RESULT=false && break
                        elif [[ "$FILTER" =~ ^\<[0-9]+$ ]]; then
                            local VAL=${FILTER#<}
                            [[ "$WORDS" -lt "$VAL" ]] && SHOW_RESULT=false && break
                        elif [[ "$FILTER" =~ ^\>[0-9]+$ ]]; then
                            local VAL=${FILTER#>}
                            [[ "$WORDS" -gt "$VAL" ]] && SHOW_RESULT=false && break
                        fi
                    done
                    ;;
                "lines")
                    IFS=',' read -ra FILTERS <<<"$VHOST_FILTER"
                    for FILTER in "${FILTERS[@]}"; do
                        if [[ "$FILTER" =~ ^[0-9]+$ ]]; then
                            [[ "$LINES" -eq "$FILTER" ]] && SHOW_RESULT=false && break
                        elif [[ "$FILTER" =~ ^\<[0-9]+$ ]]; then
                            local VAL=${FILTER#<}
                            [[ "$LINES" -lt "$VAL" ]] && SHOW_RESULT=false && break
                        elif [[ "$FILTER" =~ ^\>[0-9]+$ ]]; then
                            local VAL=${FILTER#>}
                            [[ "$LINES" -gt "$VAL" ]] && SHOW_RESULT=false && break
                        fi
                    done
                    ;;
                esac
            fi

            if [[ "$SHOW_RESULT" == true ]]; then
                {
                    flock 200
                    printf "\033[2K\r" # Clear current line
                    local STATUS_COLOR=$(GET_STATUS_COLOR "$STATUS")
                    echo -e "${INDENT}   ${GREEN}${BOLD}[+]${NC} Found: ${PROTOCOL}://${VHOST}"
                    echo -e "${INDENT}      └─▶ IP: ${DOMAIN_IP} ${PROTOCOL}://${DOMAIN}:${PORT}"
                    echo -e "${INDENT}      [${BOLD}Status: ${STATUS_COLOR}${STATUS}${NC}, ${BOLD}Size: ${BLUE}${SIZE}${NC}, ${BOLD}Words: ${YELLOW}${WORDS}${NC}, ${BOLD}Lines: ${MAGENTA}${LINES}${NC}, ${BOLD}Duration: ${CYAN}${DURATION}ms${NC}]"

                    if [[ "$RAW_OUTPUT" == true ]]; then
                        echo "${DOMAIN_IP}    ${VHOST}" >>"$CHUNK_RESULTS"
                    else
                        echo "${VHOST}:${PORT} ${PROTOCOL}://${DOMAIN}:${PORT} (Status: ${STATUS})" >>"$CHUNK_RESULTS"
                    fi
                } 200>"$STATUS_FILE.lock"
            fi
        fi

        ((PROCESSED++))
        echo "$PROCESSED" >"$PROGRESS_FILE"
    done <"$CHUNK"
}


VHOST_SCAN() {
    local DOMAIN="$1"
    local OUTPUT_FILE="$2"
    local FOUND_COUNT=0
    local INDENT="$3"

    # Array of common browser User-Agents
    local USER_AGENTS=(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
        "Mozilla/5.0 (Linux; Android 10; Pixel 3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"
        "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Brave/91.0.4472.124 Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Brave/91.0.4472.124 Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Brave/91.0.4472.124 Mobile Safari/537.36"
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Brave/91.0.4472.124 Mobile/15E148 Safari/604.1"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Brave/89.0"
        "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Brave/89.0"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
        "Mozilla/5.0 (Linux; Android 10; Pixel 3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"
        "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Brave/91.0.4472.124 Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Brave/91.0.4472.124 Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Brave/91.0.4472.124 Mobile Safari/537.36"
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Brave/91.0.4472.124 Mobile/15E148 Safari/604.1"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Brave/89.0"
        "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Brave/89.0"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
    )

    if [[ "$RECURSIVE_SCAN_ENABLED" == false ]]; then
        echo -e "\n${CYAN}${BOLD}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}${BOLD}│${NC}                         ${UNDERLINE}${BOLD}Virtual Host Scan Results${NC}                        ${CYAN}${BOLD}│${NC}"
        echo -e "${CYAN}${BOLD}└──────────────────────────────────────────────────────────────────────────┘${NC}\n"
    fi

    LOG "INFO" "Starting VHOST scan for $DOMAIN"
    local TOTAL_WORDS=$(wc -l <"$WORDLIST_PATH")
    local THREAD_DIR="$TEMP_DIR/vhost_threads"
    mkdir -p "$THREAD_DIR"

    local STATUS_FILE="$THREAD_DIR/progress"
    echo "0" >"$STATUS_FILE"

    local CHUNK_SIZE=$(((TOTAL_WORDS + THREAD_COUNT - 1) / THREAD_COUNT))
    LOG "DEBUG" "Splitting wordlist into chunks of size: $CHUNK_SIZE"
    split -l "$CHUNK_SIZE" "$WORDLIST_PATH" "$THREAD_DIR/chunk_"
    # Get IP address of domain from hosts file
    local DOMAIN_IP=$(grep -E "^([0-9]{1,3}\.){3}[0-9]{1,3}[[:space:]]+$DOMAIN" /etc/hosts | awk '{print $1}')

    #if domain is not found in hosts file, use dig to resolve it
    if [ -z "$DOMAIN_IP" ]; then
        DOMAIN_IP=$(dig +short "$DOMAIN" | head -n1)
    fi

    #if domain is still not resolved, skip the chunk
    if [ -z "$DOMAIN_IP" ]; then
        LOG "ERROR" "Failed to resolve domain: $DOMAIN"
        echo -e "${INDENT}${RED}[ERROR]${NC} Failed to resolve domain: $DOMAIN"
        return 1
    fi

    # Make sure VHOST_PORTS is reset to original ports for each new domain
    if [[ "$RECURSIVE_SCAN_ENABLED" == true ]]; then
        # Store original ports array
        if [[ -z "${ORIGINAL_VHOST_PORTS[*]}" ]]; then
            ORIGINAL_VHOST_PORTS=("${VHOST_PORTS[@]}")
        else
            # Reset to original ports for new subdomain
            VHOST_PORTS=("${ORIGINAL_VHOST_PORTS[@]}")
        fi
    fi

    # Check which ports are open before starting the scan
    local OPEN_PORTS=()
    echo -e "${INDENT}${YELLOW}${BOLD}[*]${NC} Checking for open ports..."

    for PORT in "${VHOST_PORTS[@]}"; do
        echo -n -e "${INDENT}   ${YELLOW}${BOLD}[*]${NC} Testing port ${WHITE}${BOLD}$PORT${NC}... "
        if CHECK_PORT "$DOMAIN_IP" "$PORT"; then
            OPEN_PORTS+=("$PORT")
            echo -e "${GREEN}${BOLD}OPEN${NC}"
        else
            echo -e "${RED}${BOLD}CLOSED${NC}"
            LOG "INFO" "Port $PORT is closed on $DOMAIN_IP"
        fi
    done

    if [ ${#OPEN_PORTS[@]} -eq 0 ]; then
        echo -e "${INDENT}${RED}${BOLD}[!]${NC} No open ports found, skipping VHOST scan"
        LOG "WARNING" "No open ports found for VHOST scan on $DOMAIN"
        return 0
    fi

    echo -e "${INDENT}${GREEN}${BOLD}[✓]${NC} Found ${#OPEN_PORTS[@]} open ports: ${WHITE}${BOLD}${OPEN_PORTS[*]}${NC}"

    # Replace original VHOST_PORTS with only open ports
    VHOST_PORTS=("${OPEN_PORTS[@]}")

    # Continue with existing VHOST scan code for open ports
    for PORT in "${VHOST_PORTS[@]}"; do
        echo -e "${INDENT}${YELLOW}${BOLD}[*]${NC} Starting scan on port ${WHITE}${BOLD}$PORT${NC}"

        VHOST_WILDCARD_DETECTION "$DOMAIN" "$DOMAIN_IP" "$PORT" "$INDENT"
        COMMAND_STATUS=$?
        if [ $COMMAND_STATUS == 2 ]; then
            LOG "INFO" "Aborting VHOST scan on port $PORT due to wildcard detection"
            continue
        fi

        local PIDS=()

        # Launch parallel threads for current port
        for CHUNK in "$THREAD_DIR"/chunk_*; do
            PROCESS_VHOST_CHUNK "$CHUNK" "$PORT" &
            PIDS+=($!)
            LOG "DEBUG" "Started VHOST thread PID: ${PIDS[-1]} for port $PORT"
        done

        # Monitor progress for current port
        while true; do
            local RUNNING=0
            for PID in "${PIDS[@]}"; do
                if kill -0 "$PID" 2>/dev/null; then
                    ((RUNNING++))
                fi
            done

            # Calculate progress for current port
            local CURRENT_PROGRESS=0
            for PF in "$THREAD_DIR"/progress_*_${PORT}; do
                if [[ -f "$PF" ]]; then
                    local VAL=$(cat "$PF")
                    ((CURRENT_PROGRESS += VAL))
                fi
            done

            local PROGRESS=$((CURRENT_PROGRESS * 100 / TOTAL_WORDS))

            printf "\r${INDENT}${YELLOW}${BOLD}[*]${NC} Progress: [${GREEN}${BOLD}%-50s${NC}] %3d%% (%d threads active) " \
                "$(printf '#%.0s' $(seq 1 $((PROGRESS / 2))))" \
                "$PROGRESS" \
                "$RUNNING"

            if [[ $RUNNING -eq 0 ]]; then
                echo
                break
            fi

            sleep 1
        done

        # Combine results for current port
        if find "$THREAD_DIR" -name "results_chunk_*_${PORT}" -type f | grep -q .; then
            cat "$THREAD_DIR"/results_chunk_*_${PORT} | sort -u >"$THREAD_DIR/port_${PORT}_results"
            PORT_COUNT=$(wc -l <"$THREAD_DIR/port_${PORT}_results")
        else
            PORT_COUNT=0
        fi

        #clear last line of progress bar and print on same line
        echo -e -n "\033[1A\033[2K\r"
        echo -e "${INDENT}${GREEN}${BOLD}[✓]${NC} Port ${WHITE}${BOLD}$PORT${NC} scan complete (Found: ${WHITE}${BOLD}${PORT_COUNT}${NC} hosts)"

        # Cleanup temporary files for current port
        rm -f "$THREAD_DIR"/progress_*_${PORT}
        rm -f "$THREAD_DIR"/results_chunk_*_${PORT}
    done

    # Combine all port results at the end
    if find "$THREAD_DIR" -name "port_*_results" -type f | grep -q .; then
        cat "$THREAD_DIR"/port_*_results | sort -u >"$OUTPUT_FILE"
        FOUND_COUNT=$(wc -l <"$OUTPUT_FILE")
        [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && echo -e "${GREEN}${BOLD}[✓]${NC} VHOST scan complete: Found ${WHITE}${BOLD}${FOUND_COUNT}${NC} hosts"
    fi

    # Final cleanup
    rm -rf "$THREAD_DIR"
    return 0
}
