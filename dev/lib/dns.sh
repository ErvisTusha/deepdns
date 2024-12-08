#!/bin/bash

CHECK_DNS_TOOLS() {
    local MISSING_TOOLS=()
    local REQUIRED_TOOLS=("dig" "host" "nslookup")

    for TOOL in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$TOOL" >/dev/null 2>&1; then
            MISSING_TOOLS+=("$TOOL")
        fi
    done

    if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
        LOG "ERROR" "Missing required tools: ${MISSING_TOOLS[*]}"
        echo -e "${RED}${BOLD}[ERROR]${NC} Missing required tools: ${MISSING_TOOLS[*]}"
        echo -e "Please install: ${YELLOW}${BOLD}dnsutils${NC}"
        return 1
    fi
    return 0
}

declare -A RESOLVER_HEALTH
declare -A RESOLVER_LAST_USED

SELECT_RESOLVER() {
    local BEST_RESOLVER=""
    local MIN_TIME=$(($(date +%s) - 2)) # 2 second cooldown

    # Find least recently used healthy resolver
    for RESOLVER in "${RESOLVERS[@]}"; do
        local LAST_USED=${RESOLVER_LAST_USED[$RESOLVER]:-0}
        local HEALTH=${RESOLVER_HEALTH[$RESOLVER]:-100}

        if [[ $LAST_USED -lt $MIN_TIME && $HEALTH -gt 20 ]]; then
            BEST_RESOLVER=$RESOLVER
            MIN_TIME=$LAST_USED
        fi
    done

    # If no resolver found, take any with health > 20
    if [[ -z "$BEST_RESOLVER" ]]; then
        for RESOLVER in "${RESOLVERS[@]}"; do
            if [[ ${RESOLVER_HEALTH[$RESOLVER]:-100} -gt 20 ]]; then
                BEST_RESOLVER=$RESOLVER
                break
            fi
        done
    fi

    # Last resort - take first resolver and reset its health
    if [[ -z "$BEST_RESOLVER" ]]; then
        BEST_RESOLVER=${RESOLVERS[0]}
        RESOLVER_HEALTH[$BEST_RESOLVER]=100
    fi

    RESOLVER_LAST_USED[$BEST_RESOLVER]=$(date +%s)
    echo "$BEST_RESOLVER"
}

UPDATE_RESOLVER_HEALTH() {
    local RESOLVER="$1"
    local SUCCESS="$2"

    if [[ $SUCCESS -eq 0 ]]; then
        RESOLVER_HEALTH[$RESOLVER]=$((${RESOLVER_HEALTH[$RESOLVER]:-100} + 5))
        [[ ${RESOLVER_HEALTH[$RESOLVER]} -gt 100 ]] && RESOLVER_HEALTH[$RESOLVER]=100
    else
        RESOLVER_HEALTH[$RESOLVER]=$((${RESOLVER_HEALTH[$RESOLVER]:-100} - 20))
        [[ ${RESOLVER_HEALTH[$RESOLVER]} -lt 0 ]] && RESOLVER_HEALTH[$RESOLVER]=0
    fi
}

CHECK_SUBDOMAIN() {
    local DOMAIN="$1"
    local TIMEOUT=2
    local MAX_RETRIES=2
    local RETRY_COUNT=0

    if [[ -z "$RESOLVERS" ]]; then
        if [[ -f "$RESOLVER_FILE" ]]; then
            mapfile -t RESOLVERS <"$RESOLVER_FILE"
        else
            RESOLVERS=("1.1.1.1" "8.8.8.8" "9.9.9.9")
        fi
    fi

    local RESOLVER=$(SELECT_RESOLVER)

    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
        # Check with dig
        local DIG_RESULT
        DIG_RESULT=$(dig +short "@$RESOLVER" "$DOMAIN" A +time=$TIMEOUT 2>/dev/null)

        if [[ -n "$DIG_RESULT" ]]; then
            # Validate each IP in result
            while read -r IP; do
                if VALIDATE_IP "$IP"; then
                    # Double check with host command
                    if host "$DOMAIN" "$RESOLVER" &>/dev/null; then
                        LOG "DEBUG" "Subdomain $DOMAIN verified (A: $IP) using resolver $RESOLVER"
                        UPDATE_RESOLVER_HEALTH "$RESOLVER" 0
                        return 0
                    fi
                fi
            done <<<"$DIG_RESULT"
        fi

        # Check CNAME as fallback
        local CNAME_RESULT
        CNAME_RESULT=$(dig +short "@$RESOLVER" "$DOMAIN" CNAME +time=$TIMEOUT 2>/dev/null)

        if [[ -n "$CNAME_RESULT" ]] && [[ "$CNAME_RESULT" =~ \.$DOMAIN$ ]]; then
            if host "$DOMAIN" "$RESOLVER" &>/dev/null; then
                LOG "DEBUG" "Subdomain $DOMAIN verified (CNAME: $CNAME_RESULT) using resolver $RESOLVER"
                UPDATE_RESOLVER_HEALTH "$RESOLVER" 0
                return 0
            fi
        fi

        ((RETRY_COUNT++))
        [ $RETRY_COUNT -lt $MAX_RETRIES ] && sleep 1
    done

    LOG "DEBUG" "Subdomain $DOMAIN not verified using resolver $RESOLVER"
    UPDATE_RESOLVER_HEALTH "$RESOLVER" 1
    return 1
}

SCAN_PATTERN_CHUNK() {
    local CHUNK="$1"
    local CHUNK_RESULTS="$THREAD_DIR/results_$(basename "$CHUNK")"

    while IFS=: read -r CATEGORY PATTERN; do
        # Check for interrupt before processing each pattern
        if [[ "$INTERRUPT_RECEIVED" == "true" ]]; then
            LOG "DEBUG" "Pattern scan interrupted in chunk processing"
            return 1
        fi

        local VARIATIONS=(
            "$PATTERN"
            "${PATTERN}-${DOMAIN%%.*}"
            "${DOMAIN%%.*}-${PATTERN}"
            "v1-$PATTERN"
            "v2-$PATTERN"
            "$PATTERN-v1"
            "$PATTERN-v2"
            "$PATTERN-api"
            "api-$PATTERN"
        )

        for VARIANT in "${VARIATIONS[@]}"; do
            if [[ "$INTERRUPT_RECEIVED" == "true" ]]; then
                return 1
            fi
            local SUBDOMAIN="${VARIANT}.$DOMAIN"

            if CHECK_SUBDOMAIN "$SUBDOMAIN"; then
                {
                    flock -x 200
                    printf "\033[2K\r" 
                    echo -e "${INDENT}     ${GREEN}${BOLD}[+]${NC} Found ${WHITE}${BOLD}$CATEGORY${NC} pattern: ${YELLOW}${BOLD}$SUBDOMAIN${NC}"
                    echo "${CATEGORY}:${PATTERN}:${SUBDOMAIN}" >>"$CHUNK_RESULTS"
                } 200>"$LOCK_FILE"
            fi
        done

        # Update progress with improved lock handling
        (
            if flock -n 200; then
                local CURRENT=$(cat "$PROGRESS_FILE" 2>/dev/null || echo "0")
                echo $((CURRENT + 1)) >"$PROGRESS_FILE"
                local PROGRESS=$((CURRENT * 100 / TOTAL_PATTERNS))
                printf "\r${INDENT}${YELLOW}${BOLD}[*]${NC} Progress: [${GREEN}${BOLD}%-50s${NC}] %3d%% " \
                    "$(printf '#%.0s' $(seq 1 $((PROGRESS / 2))))" \
                    "$PROGRESS"
            fi
        ) 200>"$LOCK_FILE"
    done < <(cat "$CHUNK" 2>/dev/null || true)
}

DNS_PATTERN_RECOGNITION() {
    local DOMAIN="$1"
    local OUTPUT_FILE="$2"
    local FOUND_COUNT=0
    local RESULTS_FILE="$TEMP_DIR/pattern_results.txt"
    local THREAD_DIR="$TEMP_DIR/pattern_threads"
    local LOCK_DIR="$THREAD_DIR/locks"
    local PROGRESS_FILE="$THREAD_DIR/progress"
    local LOCK_FILE="$LOCK_DIR/progress.lock"
    
    # Create required directories first
    for DIR in "$THREAD_DIR" "$LOCK_DIR"; do
        if ! mkdir -p "$DIR"; then
            LOG "ERROR" "Failed to create directory: $DIR"
            return 1
        fi
    done

    # Create and initialize required files with proper permissions
    for FILE in "$PROGRESS_FILE" "$LOCK_FILE"; do
        if ! touch "$FILE" 2>/dev/null || ! chmod 644 "$FILE" 2>/dev/null; then
            LOG "ERROR" "Failed to create/set permissions for file: $FILE"
            return 1
        fi
    done

    # Ensure progress file exists
    touch "$PROGRESS_FILE" || {
        LOG "ERROR" "Failed to create progress file"
        return 1
    }

    # Create lock file if it doesn't exist
    touch "$PROGRESS_FILE.lock" || {
        LOG "ERROR" "Failed to create progress lock file"
        return 1
    }

    # Add tracking file for already found patterns
    local GLOBAL_PATTERNS_FILE="$TEMP_DIR/global_patterns.txt"
    [[ ! -f "$GLOBAL_PATTERNS_FILE" ]] && touch "$GLOBAL_PATTERNS_FILE"

    declare -A PATTERNS=(
        ["development"]="dev test stage staging uat qa beta demo poc sandbox alpha preview review canary"
        ["infrastructure"]="api ws rest graphql grpc soap rpc gateway proxy cdn edge cache redis"
        ["admin"]="admin administrator manage portal console cpanel whm webmin"
        ["services"]="app mobile auth login sso oauth service app-service microservice"
        ["storage"]="storage static assets img images media files docs documents s3 backup archive"
        ["mail"]="mail smtp pop3 imap webmail exchange postfix mx mailer newsletter"
        ["internal"]="internal intranet corp private local dev-internal stg-internal prod-internal"
        ["monitoring"]="monitor status health metrics grafana prometheus uptimerobot uptime ping nagios zabbix kibana observability"
        ["security"]="vpn remote ssl secure auth security waf firewall scan antivirus"
        ["environments"]="prod production staging dev development test testing hotfix release rc qa"
        ["databases"]="db database mysql mongodb postgres postgresql redis elastic solr"
        ["networking"]="ns dns mx router gateway proxy lb loadbalancer traffic nat"
        ["collaboration"]="git gitlab github bitbucket svn jira confluence wiki team chat slack"
        ["analytics"]="analytics tracking stats statistics metric grafana kibana elk splunk graylog"
        ["regions"]="us eu asia af sa na oc aus nz uk fr de us-east us-west eu-west eu-east ap-south ap-northeast ap-southeast al it es az ca"
        ["cloud"]="aws gcp azure cloud k8s kubernetes docker container pod swarm"
        ["ci"]="ci cd jenkins travis circleci gitlab-ci github-actions"
        ["cdn"]="cdn cloudflare akamai fastly cloudfront"
        ["proxy"]="proxy forward reverse nginx haproxy squid varnish"
        ["gateway"]="gateway ingress egress"
        ["registry"]="registry docker-registry container-registry"
        ["queue"]="queue kafka rabbitmq zeromq"
        ["search"]="search elasticsearch solr lucene"
        ["auth"]="auth oauth sso openid ldap identity"
        ["web"]="web app frontend ui mobile"
        ["control"]="control panel dashboard management"
    )

    mkdir -p "$THREAD_DIR"
    echo "0" >"$PROGRESS_FILE"

    # Setup pattern header
    if [[ "$RECURSIVE_SCAN_ENABLED" == false ]]; then
        echo -e "\n${CYAN}${BOLD}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}${BOLD}│${NC}                       ${UNDERLINE}Pattern Recognition Results${NC}                        ${CYAN}${BOLD}│${NC}"
        echo -e "${CYAN}${BOLD}└──────────────────────────────────────────────────────────────────────────┘${NC}\n"
    fi
    LOG "INFO" "Starting pattern recognition for $DOMAIN"

    echo -e "${INDENT}${CYAN}${BOLD}[*]${NC} ${WHITE}${BOLD}Pattern Recognition${NC} for ${YELLOW}${BOLD}$DOMAIN${NC}"

    #WILDCARD_DETECTION "$DOMAIN" "$INDENT"
    COMMAND_STATUS=$?
    LOG "DEBUG" "Wildcard detection returned status: $COMMAND_STATUS"
    if [ $COMMAND_STATUS == 2 ]; then
        LOG "INFO" "Aborting scan due to wildcard detection user choice"
        return 0
    fi

    # Calculate total patterns
    for CATEGORY in "${!PATTERNS[@]}"; do
        for PATTERN in ${PATTERNS[$CATEGORY]}; do
            ((TOTAL_PATTERNS++))
        done
    done

    if [ $TOTAL_PATTERNS -eq 0 ]; then
        LOG "ERROR" "No patterns found to scan"
        echo -e "${RED}${BOLD}[!]${NC} No patterns found to scan"
        return 1
    fi

    LOG "DEBUG" "Found $TOTAL_PATTERNS patterns to scan"

    # Create pattern chunks
    local CHUNK_SIZE=$(((TOTAL_PATTERNS + THREAD_COUNT - 1) / THREAD_COUNT))
    local CURRENT_CHUNK=0
    local CURRENT_CHUNK_FILE="$THREAD_DIR/chunk_$CURRENT_CHUNK"
    local PATTERN_COUNT=0

    # Create directory for chunks
    mkdir -p "$THREAD_DIR"
    echo -e "${INDENT}${YELLOW}${BOLD}[*]${NC} Scanning $TOTAL_PATTERNS patterns for $DOMAIN"
    # Prepare pattern chunks
    for CATEGORY in "${!PATTERNS[@]}"; do
        for PATTERN in ${PATTERNS[$CATEGORY]}; do
            echo "$CATEGORY:$PATTERN" >>"$THREAD_DIR/chunk_$CURRENT_CHUNK"
            ((PATTERN_COUNT++))

            if [ $PATTERN_COUNT -eq $CHUNK_SIZE ]; then
                ((CURRENT_CHUNK++))
                PATTERN_COUNT=0
            fi
        done
    done

    # Launch threads
    local PIDS=()
    for CHUNK in "$THREAD_DIR"/chunk_*; do
        SCAN_PATTERN_CHUNK "$CHUNK" &
        PIDS+=($!)
    done

    # Monitor progress with interrupt handling
    while true; do
        if [[ "$INTERRUPT_RECEIVED" == "true" ]]; then
            LOG "DEBUG" "Pattern scan interrupted in progress monitoring"
            break
        fi

        local RUNNING=0
        for PID in "${PIDS[@]}"; do
            if kill -0 "$PID" 2>/dev/null; then
                ((RUNNING++))
            fi
        done

        [[ $RUNNING -eq 0 ]] && break
        sleep 1
    done
    echo # New line after progress complete

    # Collect and process results
    if find "$THREAD_DIR" -name "results_chunk_*" -type f | grep -q .; then
        cat "$THREAD_DIR"/results_chunk_* | sort -u >"$RESULTS_FILE"
        FOUND_COUNT=$(wc -l <"$RESULTS_FILE")
    fi

    # Add result display vars
    local CATEGORY_COUNTS=()
    local TOTAL_FOUND=0

    echo -e -n "\033[1A\033[2K\r"
    echo -e "${INDENT}${GREEN}${BOLD}[✓]${NC} Pattern scan complete. Processing results..."

    if [[ -f "$RESULTS_FILE" ]]; then
        echo -e "${INDENT}     ${CYAN}${BOLD}[*]${NC} Pattern scan summary by category:"

        local CURRENT_CATEGORY=""
        local CATEGORY_COUNT=0
        local NEW_FINDINGS=0

        while IFS=: read -r CATEGORY PATTERN SUBDOMAIN; do
            # Skip if this pattern:subdomain was already found
            if grep -q "^${CATEGORY}:${PATTERN}:${SUBDOMAIN}$" "$GLOBAL_PATTERNS_FILE"; then
                continue
            fi

            # Add to global patterns file
            echo "${CATEGORY}:${PATTERN}:${SUBDOMAIN}" >>"$GLOBAL_PATTERNS_FILE"

            if [[ "$CURRENT_CATEGORY" != "$CATEGORY" ]]; then
                [[ -n "$CURRENT_CATEGORY" ]] && [[ $CATEGORY_COUNT -gt 0 ]] &&
                    echo -e "${INDENT}           ${GRAY}${BOLD}Total:${NC} ${WHITE}${BOLD}$CATEGORY_COUNT${NC}"
                [[ $CATEGORY_COUNT -gt 0 ]] && echo
                echo -e "${INDENT}           ${CYAN}${BOLD}[*]${NC} ${WHITE}${BOLD}${CATEGORY}${NC}:"
                CURRENT_CATEGORY="$CATEGORY"
                CATEGORY_COUNT=0
            fi
            ((CATEGORY_COUNT++))
            ((TOTAL_FOUND++))
            ((NEW_FINDINGS++))
            echo -e "${INDENT}           ${GREEN}${BOLD}├─${NC} ${SUBDOMAIN}"
            echo "$SUBDOMAIN" >>"$OUTPUT_FILE"
        done <"$RESULTS_FILE"

        # Only show category total if we found anything
        [[ $CATEGORY_COUNT -gt 0 ]] &&
            echo -e "${INDENT}           ${GRAY}${BOLD}Total:${NC} ${WHITE}${BOLD}$CATEGORY_COUNT${NC}"

        if [[ $NEW_FINDINGS -gt 0 ]]; then
            echo -e "\n${INDENT}${GREEN}${BOLD}[✓]${NC} Found ${WHITE}${BOLD}${NEW_FINDINGS}${NC} new subdomains across all patterns for ${YELLOW}${BOLD}${DOMAIN}${NC}"
        else
            echo -e "\n${INDENT}${YELLOW}${BOLD}[!]${NC} No new patterns found"
        fi
    fi

    # Cleanup temporary files but preserve global patterns file
    rm -rf "$THREAD_DIR"
    rm -f "$RESULTS_FILE"

    # If this is not a recursive scan, cleanup the global patterns file
    [[ "$RECURSIVE_SCAN_ENABLED" == false ]] && rm -f "$GLOBAL_PATTERNS_FILE"

    # Add cleanup trap for pattern recognition
    trap 'rm -rf "$THREAD_DIR" "$LOCK_DIR" 2>/dev/null' EXIT

    return 0
}

