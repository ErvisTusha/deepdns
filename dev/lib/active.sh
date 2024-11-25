#!/bin/bash

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

    PROCESS_VHOST_CHUNK() {
        local chunk="$1"
        local port="$2"
        local chunk_results="$THREAD_DIR/results_$(basename "$chunk")_${port}"
        local processed=0
        local chunk_size=$(wc -l <"$chunk")
        local progress_file="$THREAD_DIR/progress_$(basename "$chunk")_${port}"
        echo "0" >"$progress_file"

        # Get IP address of domain
        local DOMAIN_IP=$(dig +short "${DOMAIN}" | head -n 1)

        # Determine protocol based on port
        local PROTOCOL="http"
        local PROTOCOL=$(DETECT_PROTOCOL "${DOMAIN_IP}" "${port}")

        while IFS= read -r SUBDOMAIN; do
            local VHOST="${SUBDOMAIN}.${DOMAIN}"

            # Use curl with connection timeout, max time and SSL options
            local RESPONSE=$(curl -s -I \
                --connect-timeout 3 \
                --max-time 5 \
                -k \
                -H "Host: ${VHOST}" \
                "${PROTOCOL}://${DOMAIN_IP}:${port}" 2>/dev/null)

            local STATUS=$(echo "$RESPONSE" | grep -E "^HTTP" | cut -d' ' -f2)

            if [[ "$STATUS" =~ ^(200|30[0-9])$ ]]; then
                {
                    flock 200
                    printf "\033[2K\r" # Clear current line
                    echo -e "${INDENT}   ${GREEN}${BOLD}[+]${NC} Found: ${VHOST}"
                    echo -e "${INDENT}      └─▶ IP: ${DOMAIN_IP} ${PROTOCOL}://${DOMAIN}:${port} (Status: ${STATUS})"
                    echo "${VHOST}:${port} ${PROTOCOL}://${DOMAIN}:${port} (Status: ${STATUS})" >>"$chunk_results"
                } 200>"$STATUS_FILE.lock"
            fi

            ((processed++))
            echo "$processed" >"$progress_file"
        done <"$chunk"
    }

    # Process one port at a time
    for PORT in "${VHOST_PORTS[@]}"; do
        echo -e "${INDENT}${YELLOW}${BOLD}[*]${NC} Starting scan on port ${WHITE}${BOLD}$PORT${NC}"
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
        [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && echo -e "\n${GREEN}${BOLD}[✓]${NC} VHOST scan complete: Found ${WHITE}${BOLD}${FOUND_COUNT}${NC} hosts"
    fi

    # Final cleanup
    rm -rf "$THREAD_DIR"
    return 0
}

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
