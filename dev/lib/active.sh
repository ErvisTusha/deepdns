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

    # Try with timeout and nc (netcat) first
    if command -v nc >/dev/null 2>&1; then
        if timeout $TIMEOUT nc -z -w1 "$IP" "$PORT" >/dev/null 2>&1; then
            return 0
        fi
    fi

    # Fallback to pure bash if nc is not available
    if (</dev/tcp/$IP/$PORT) >/dev/null 2>&1; then
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
        if [[ "$STATUS" =~ ^(200|30[0-9])$ ]]; then
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

ACTIVE_SCAN() {
    local DOMAIN="$1"
    local RESULTS_FILE="${2:-${OUTPUT:-$PWD/${DOMAIN}_active.txt}}"
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

        local THREAD_DIR="$TEMP_DIR/threads"
        mkdir -p "$THREAD_DIR/progress" 2>/dev/null
        LOG "DEBUG" "Created thread progress directory: $THREAD_DIR/progress"

        local STATUS_FILE="$THREAD_DIR/progress_status"
        echo "0" >"$STATUS_FILE"
        LOG "DEBUG" "Initialized progress tracking file: $STATUS_FILE"

        local CHUNK_SIZE=$(((TOTAL_WORDS + THREAD_COUNT - 1) / THREAD_COUNT))
        LOG "DEBUG" "Splitting wordlist into chunks of size: $CHUNK_SIZE"
        split -l "$CHUNK_SIZE" "$WORDLIST_PATH" "$THREAD_DIR/chunk_"

        if [[ -z "$RESOLVER_FILE" ]]; then
            RESOLVERS=("1.1.1.1" "8.8.8.8" "9.9.9.9")
            LOG "DEBUG" "Using default resolvers: ${RESOLVERS[*]}"
        else
            mapfile -t RESOLVERS <"$RESOLVER_FILE"
            LOG "DEBUG" "Loaded ${#RESOLVERS[@]} resolvers from $RESOLVER_FILE"
        fi

        PROCESS_CHUNK() {
            local chunk="$1"
            local chunk_results="$THREAD_DIR/results_$(basename "$chunk")"
            local processed=0
            local chunk_size=$(wc -l <"$chunk")
            LOG "DEBUG" "Processing chunk: $chunk with $chunk_size entries"

            # Define per-chunk progress file
            local progress_file="$THREAD_DIR/progress_$(basename "$chunk")"
            echo "0" >"$progress_file"

            while read -r SUBDOMAIN; do
                local TARGET="${SUBDOMAIN}.${DOMAIN}"
                local resolver=${RESOLVERS[$((RANDOM % ${#RESOLVERS[@]}))]}
                LOG "DEBUG" "Testing subdomain: $TARGET using resolver: $resolver"

                if dig +short "$TARGET" "@$resolver" | grep -q '^[0-9]'; then
                    echo "$TARGET" >>"$chunk_results"
                    LOG "INFO" "Found valid subdomain: $TARGET"
                    printf "\r%-100s\r" " "
                    echo -e "${INDENT}     ${GREEN}${BOLD}[+]${NC} Found: $TARGET"
                fi

                ((processed++))
                # Update per-chunk progress file
                echo "$processed" >"$progress_file"
                LOG "DEBUG" "Processed $processed/$chunk_size in current chunk"
            done <"$chunk"
            LOG "DEBUG" "Completed processing chunk: $chunk"
        }

        local pids=()
        for chunk in "$THREAD_DIR"/chunk_*; do
            LOG "DEBUG" "Launching thread for chunk: $chunk"
            PROCESS_CHUNK "$chunk" &
            pids+=($!)
            LOG "DEBUG" "Started thread PID: ${pids[-1]}"
        done

        while true; do
            local running=0
            for pid in "${pids[@]}"; do
                if kill -0 "$pid" 2>/dev/null; then
                    ((running++))
                fi
            done

            # Sum up progress with error handling
            local current_progress=0
            local progress_files=("$THREAD_DIR"/progress_*)
            if [ -e "${progress_files[0]}" ]; then
                while read -r val; do
                    ((current_progress += val))
                done < <(cat "$THREAD_DIR"/progress_* 2>/dev/null || echo 0)
            fi

            local progress=$((current_progress * 100 / TOTAL_WORDS))
            LOG "DEBUG" "Progress: $progress% complete, $running threads active"

            printf "\r${INDENT}${YELLOW}${BOLD}[*]${NC} Progress: [${GREEN}${BOLD}%-50s${NC}] %3d%% (%d threads active) " \
                "$(printf '#%.0s' $(seq 1 $((progress / 2))))" \
                "$progress" \
                "$running"

            if [[ $running -eq 0 ]]; then
                echo
                LOG "DEBUG" "All threads completed"
                break
            fi

            sleep 1
        done

        wait
        LOG "DEBUG" "All threads finished execution"

        echo -e -n "\033[1A\033[2K\r"
        if find "$THREAD_DIR" -name "results_chunk_*" -type f | grep -q .; then
            LOG "DEBUG" "Combining results from all chunks"
            find "$THREAD_DIR" -name "results_chunk_*" -type f -exec cat {} + | sort -u >"$RESULTS_FILE"
            local TOTAL=$(wc -l <"$RESULTS_FILE")
            LOG "INFO" "Active scan complete: Found $TOTAL unique subdomains"
            echo -e "${INDENT}${GREEN}${BOLD}[✓]${NC} Active scan complete: $TOTAL unique results found"
        else
            LOG "WARNING" "No subdomains found during active scan"
            [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} No subdomains found"
        fi

        LOG "DEBUG" "Cleaning up temporary thread directory: $THREAD_DIR"
        rm -rf "$THREAD_DIR"
    fi

    LOG "DEBUG" "ACTIVE_SCAN completed for domain: $DOMAIN"
    return 0
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
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0"
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0"
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

        PROCESS_VHOST_CHUNK() {
            local chunk="$1"
            local port="$2"
            local chunk_results="$THREAD_DIR/results_$(basename "$chunk")_${port}"
            local processed=0
            local chunk_size=$(wc -l <"$chunk")
            local progress_file="$THREAD_DIR/progress_$(basename "$chunk")_${port}"
            echo "0" >"$progress_file"

            # Determine protocol based on port
            local PROTOCOL="http"
            local PROTOCOL=$(DETECT_PROTOCOL "${DOMAIN_IP}" "${port}")

            # Add helper function for status colors
            get_status_color() {
                local status=$1
                case $status in
                200) echo "${GREEN}" ;;                     # Success
                301 | 302 | 307 | 308) echo "${BLUE}" ;;    # Redirects
                401 | 403) echo "${YELLOW}" ;;              # Auth required/Forbidden
                404) echo "${RED}" ;;                       # Not Found
                500 | 502 | 503 | 504) echo "${MAGENTA}" ;; # Server Errors
                *) echo "${WHITE}" ;;                       # Other codes
                esac
            }

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
                    "${PROTOCOL}://${DOMAIN_IP}:${port}" 2>/dev/null)

                # Calculate duration in milliseconds
                local END_TIME=$(date +%s%N)

                local STATUS=$(echo "$RESPONSE" | grep -E "^HTTP" | cut -d' ' -f2)
                local SIZE=$(echo "$RESPONSE" | grep -E "^Content-Length" | cut -d' ' -f2 | awk '{print int($1)}')
                local WORDS=$(echo "$RESPONSE" | wc -w)
                local LINES=$(echo "$RESPONSE" | wc -l)
                local DURATION=$(((END_TIME - START_TIME) / 1000000))

                if [[ "$STATUS" =~ ^(200|30[0-9])$ ]]; then
                    # Apply filters if specified
                    local SHOW_RESULT=true
                    if [[ -n "$VHOST_FILTER" ]]; then
                        case "$VHOST_FILTER_TYPE" in
                            "status")
                                # Split comma-separated filters into array
                                IFS=',' read -ra FILTERS <<< "$VHOST_FILTER"
                                for filter in "${FILTERS[@]}"; do
                                    # If any filter matches, hide the result
                                    [[ "$STATUS" =~ ^($filter)$ ]] && SHOW_RESULT=false && break
                                done
                                ;;
                            "size")
                                IFS=',' read -ra FILTERS <<< "$VHOST_FILTER"
                                for filter in "${FILTERS[@]}"; do
                                    if [[ "$filter" =~ ^[0-9]+$ ]]; then
                                        [[ "$SIZE" -eq "$filter" ]] && SHOW_RESULT=false && break
                                    elif [[ "$filter" =~ ^\<[0-9]+$ ]]; then
                                        local val=${filter#<}
                                        [[ "$SIZE" -lt "$val" ]] && SHOW_RESULT=false && break
                                    elif [[ "$filter" =~ ^\>[0-9]+$ ]]; then
                                        local val=${filter#>}
                                        [[ "$SIZE" -gt "$val" ]] && SHOW_RESULT=false && break
                                    fi
                                done
                                ;;
                            "words")
                                IFS=',' read -ra FILTERS <<< "$VHOST_FILTER"
                                for filter in "${FILTERS[@]}"; do
                                    if [[ "$filter" =~ ^[0-9]+$ ]]; then
                                        [[ "$WORDS" -eq "$filter" ]] && SHOW_RESULT=false && break
                                    elif [[ "$filter" =~ ^\<[0-9]+$ ]]; then
                                        local val=${filter#<}
                                        [[ "$WORDS" -lt "$val" ]] && SHOW_RESULT=false && break
                                    elif [[ "$filter" =~ ^\>[0-9]+$ ]]; then
                                        local val=${filter#>}
                                        [[ "$WORDS" -gt "$val" ]] && SHOW_RESULT=false && break
                                    fi
                                done
                                ;;
                            "lines")
                                IFS=',' read -ra FILTERS <<< "$VHOST_FILTER"
                                for filter in "${FILTERS[@]}"; do
                                    if [[ "$filter" =~ ^[0-9]+$ ]]; then
                                        [[ "$LINES" -eq "$filter" ]] && SHOW_RESULT=false && break
                                    elif [[ "$filter" =~ ^\<[0-9]+$ ]]; then
                                        local val=${filter#<}
                                        [[ "$LINES" -lt "$val" ]] && SHOW_RESULT=false && break
                                    elif [[ "$filter" =~ ^\>[0-9]+$ ]]; then
                                        local val=${filter#>}
                                        [[ "$LINES" -gt "$val" ]] && SHOW_RESULT=false && break
                                    fi
                                done
                                ;;
                        esac
                    fi

                    if [[ "$SHOW_RESULT" == true ]]; then
                        {
                            flock 200
                            printf "\033[2K\r" # Clear current line
                            local STATUS_COLOR=$(get_status_color "$STATUS")
                            echo -e "${INDENT}   ${GREEN}${BOLD}[+]${NC} Found: ${PROTOCOL}://${VHOST}"
                            echo -e "${INDENT}      └─▶ IP: ${DOMAIN_IP} ${PROTOCOL}://${DOMAIN}:${port}"
                            echo -e "${INDENT}      [${BOLD}Status: ${STATUS_COLOR}${STATUS}${NC}, ${BOLD}Size: ${BLUE}${SIZE}${NC}, ${BOLD}Words: ${YELLOW}${WORDS}${NC}, ${BOLD}Lines: ${MAGENTA}${LINES}${NC}, ${BOLD}Duration: ${CYAN}${DURATION}ms${NC}]"

                            if [[ "$RAW_OUTPUT" == true ]]; then
                                echo "${DOMAIN_IP}    ${VHOST}" >>"$chunk_results"
                            else
                                echo "${VHOST}:${port} ${PROTOCOL}://${DOMAIN}:${port} (Status: ${STATUS})" >>"$chunk_results"
                            fi
                        } 200>"$STATUS_FILE.lock"
                    fi
                fi

                ((processed++))
                echo "$processed" >"$progress_file"
            done <"$chunk"
        }

        local pids=()

        # Launch parallel threads for current port
        for chunk in "$THREAD_DIR"/chunk_*; do
            PROCESS_VHOST_CHUNK "$chunk" "$PORT" &
            pids+=($!)
            LOG "DEBUG" "Started VHOST thread PID: ${pids[-1]} for port $PORT"
        done

        # Monitor progress for current port
        while true; do
            local running=0
            for pid in "${pids[@]}"; do
                if kill -0 "$pid" 2>/dev/null; then
                    ((running++))
                fi
            done

            # Calculate progress for current port
            local current_progress=0
            for pf in "$THREAD_DIR"/progress_*_${PORT}; do
                if [[ -f "$pf" ]]; then
                    local val=$(cat "$pf")
                    ((current_progress += val))
                fi
            done

            local progress=$((current_progress * 100 / TOTAL_WORDS))

            printf "\r${INDENT}${YELLOW}${BOLD}[*]${NC} Progress: [${GREEN}${BOLD}%-50s${NC}] %3d%% (%d threads active) " \
                "$(printf '#%.0s' $(seq 1 $((progress / 2))))" \
                "$progress" \
                "$running"

            if [[ $running -eq 0 ]]; then
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
        [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && echo -e  "${GREEN}${BOLD}[✓]${NC} VHOST scan complete: Found ${WHITE}${BOLD}${FOUND_COUNT}${NC} hosts"
    fi

    # Final cleanup
    rm -rf "$THREAD_DIR"
    return 0
}
