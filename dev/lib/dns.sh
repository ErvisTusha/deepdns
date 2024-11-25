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
    local best_resolver=""
    local min_time=$(($(date +%s) - 2)) # 2 second cooldown

    # Find least recently used healthy resolver
    for resolver in "${RESOLVERS[@]}"; do
        local last_used=${RESOLVER_LAST_USED[$resolver]:-0}
        local health=${RESOLVER_HEALTH[$resolver]:-100}

        if [[ $last_used -lt $min_time && $health -gt 20 ]]; then
            best_resolver=$resolver
            min_time=$last_used
        fi
    done

    # If no resolver found, take any with health > 20
    if [[ -z "$best_resolver" ]]; then
        for resolver in "${RESOLVERS[@]}"; do
            if [[ ${RESOLVER_HEALTH[$resolver]:-100} -gt 20 ]]; then
                best_resolver=$resolver
                break
            fi
        done
    fi

    # Last resort - take first resolver and reset its health
    if [[ -z "$best_resolver" ]]; then
        best_resolver=${RESOLVERS[0]}
        RESOLVER_HEALTH[$best_resolver]=100
    fi

    RESOLVER_LAST_USED[$best_resolver]=$(date +%s)
    echo "$best_resolver"
}

UPDATE_RESOLVER_HEALTH() {
    local resolver="$1"
    local success="$2"

    if [[ $success -eq 0 ]]; then
        RESOLVER_HEALTH[$resolver]=$((${RESOLVER_HEALTH[$resolver]:-100} + 5))
        [[ ${RESOLVER_HEALTH[$resolver]} -gt 100 ]] && RESOLVER_HEALTH[$resolver]=100
    else
        RESOLVER_HEALTH[$resolver]=$((${RESOLVER_HEALTH[$resolver]:-100} - 20))
        [[ ${RESOLVER_HEALTH[$resolver]} -lt 0 ]] && RESOLVER_HEALTH[$resolver]=0
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

    # Function to validate IP address format
    VALIDATE_IP() {
        local IP="$1"
        if [[ ! "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return 1
        fi

        # Check each octet
        local IFS='.'
        read -ra OCTETS <<<"$IP"
        for OCTET in "${OCTETS[@]}"; do
            if [[ "$OCTET" -lt 0 || "$OCTET" -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    }

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

DNS_PATTERN_RECOGNITION() {
    local DOMAIN="$1"
    local OUTPUT_FILE="$2"
    local FOUND_COUNT=0
    local RESULTS_FILE="$TEMP_DIR/pattern_results.txt"
    local THREAD_DIR="$TEMP_DIR/pattern_threads"
    local PROGRESS_FILE="$THREAD_DIR/progress"
    local TOTAL_PATTERNS=0

    # Add tracking file for already found patterns
    local GLOBAL_PATTERNS_FILE="$TEMP_DIR/global_patterns.txt"
    [[ ! -f "$GLOBAL_PATTERNS_FILE" ]] && touch "$GLOBAL_PATTERNS_FILE"

    declare -A PATTERNS=(
        ["development"]="dev test stage staging uat qa beta demo poc sandbox alpha preview review canary"
        ["infrastructure"]="api ws rest graphql grpc soap rpc gateway proxy cdn edge cache redis"
        ["admin"]="admin administrator manage portal dashboard console control panel cpanel whm webmin"
        ["services"]="app web mobile m api auth login sso oauth service app-service microservice"
        ["storage"]="storage cdn static assets img images media files docs documents s3 backup archive"
        ["mail"]="mail smtp pop3 imap webmail exchange postfix mx mailer newsletter"
        ["internal"]="internal intranet corp private local dev-internal stg-internal prod-internal"
        ["monitoring"]="monitor status health metrics grafana prometheus uptimerobot uptime ping nagios zabbix kibana observability"
        ["security"]="vpn remote gateway ssl secure auth security waf firewall scan antivirus"
        ["environments"]="prod production staging dev development test testing hotfix release rc qa"
        ["databases"]="db database mysql mongodb postgres postgresql redis elastic elastic-search solr"
        ["networking"]="ns dns mx router gateway proxy lb loadbalancer traffic nat vpn"
        ["collaboration"]="git gitlab github bitbucket svn jira confluence wiki docs team chat slack"
        ["analytics"]="analytics tracking stats statistics metric grafana kibana elk splunk graylog"
        ["regions"]="us eu asia af sa na oc aus nz uk fr de us-east us-west eu-west eu-east ap-south ap-northeast ap-southeast al it es az ca"
        ["cloud"]="aws gcp azure cloud k8s kubernetes docker container pod swarm"
        ["ci"]="ci cd jenkins travis circleci gitlab-ci github-actions"
        ["cdn"]="cdn cloudflare akamai fastly cloudfront"
        ["proxy"]="proxy forward reverse nginx haproxy squid varnish"
        ["gateway"]="gateway api ingress egress"
        ["registry"]="registry docker-registry container-registry"
        ["queue"]="queue kafka rabbitmq zeromq redis"
        ["search"]="search elasticsearch solr lucene"
        ["auth"]="auth oauth sso openid ldap identity"
        ["web"]="web app frontend ui mobile api"
        ["api"]="api rest graphql grpc rpc soap ws"
        ["control"]="control panel dashboard admin portal console management"
        #["debug"]="www m api debug trace tracepoint breakpoint"
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

    WILDCARD_DETECTION "$DOMAIN" "$INDENT"
    COMMAND_STATUS=$?
    LOG "DEBUG" "Wildcard detection returned status: $COMMAND_STATUS"
    if [ $COMMAND_STATUS == 2 ]; then
        LOG "INFO" "Aborting scan due to wildcard detection user choice"
        return 0
    fi

    # Calculate total patterns
    for category in "${!PATTERNS[@]}"; do
        for pattern in ${PATTERNS[$category]}; do
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
    local chunk_size=$(((TOTAL_PATTERNS + THREAD_COUNT - 1) / THREAD_COUNT))
    local current_chunk=0
    local current_chunk_file="$THREAD_DIR/chunk_$current_chunk"
    local pattern_count=0

    # Create directory for chunks
    mkdir -p "$THREAD_DIR"
    echo -e "${INDENT}${YELLOW}${BOLD}[*]${NC} Scanning $TOTAL_PATTERNS patterns for $DOMAIN"
    # Prepare pattern chunks
    for category in "${!PATTERNS[@]}"; do
        for pattern in ${PATTERNS[$category]}; do
            echo "$category:$pattern" >>"$THREAD_DIR/chunk_$current_chunk"
            ((pattern_count++))

            if [ $pattern_count -eq $chunk_size ]; then
                ((current_chunk++))
                pattern_count=0
            fi
        done
    done

    scan_pattern_chunk() {
        local chunk="$1"
        local chunk_results="$THREAD_DIR/results_$(basename "$chunk")"

        while IFS=: read -r category pattern; do
            local variations=(
                "$pattern"
                "${pattern}-${DOMAIN%%.*}"
                "${DOMAIN%%.*}-${pattern}"
                "v1-$pattern"
                "v2-$pattern"
                "$pattern-v1"
                "$pattern-v2"
                "$pattern-api"
                "api-$pattern"
            )

            for variant in "${variations[@]}"; do
                local subdomain="${variant}.$DOMAIN"

                if CHECK_SUBDOMAIN "$subdomain"; then
                    {
                        flock 200
                        printf "\033[2K\r" # Clear current line
                        echo -e "${INDENT}     ${GREEN}${BOLD}[+]${NC} Found ${WHITE}${BOLD}$category${NC} pattern: ${YELLOW}${BOLD}$subdomain${NC}"
                        echo "${category}:${pattern}:${subdomain}" >>"$chunk_results"
                    } 200>"$PROGRESS_FILE.lock"
                fi
            done

            # Update progress atomically
            (
                flock 200
                local current=$(cat "$PROGRESS_FILE")
                echo $((current + 1)) >"$PROGRESS_FILE"

                # Calculate and show progress
                local progress=$((current * 100 / TOTAL_PATTERNS))
                printf "\r${INDENT}${YELLOW}${BOLD}[*]${NC} Progress: [${GREEN}${BOLD}%-50s${NC}] %3d%% " \
                    "$(printf '#%.0s' $(seq 1 $((progress / 2))))" \
                    "$progress"
            ) 200>"$PROGRESS_FILE.lock"
        done < <(while read -r line; do
            echo "${line}"
        done <"$chunk")
    }

    # Launch threads
    local pids=()
    for chunk in "$THREAD_DIR"/chunk_*; do
        scan_pattern_chunk "$chunk" &
        pids+=($!)
    done

    # Monitor progress - simplified to avoid multiple progress bars
    while true; do
        local running=0
        for pid in "${pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                ((running++))
            fi
        done

        [[ $running -eq 0 ]] && break
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

        while IFS=: read -r category pattern subdomain; do
            # Skip if this pattern:subdomain was already found
            if grep -q "^${category}:${pattern}:${subdomain}$" "$GLOBAL_PATTERNS_FILE"; then
                continue
            fi

            # Add to global patterns file
            echo "${category}:${pattern}:${subdomain}" >>"$GLOBAL_PATTERNS_FILE"

            if [[ "$CURRENT_CATEGORY" != "$category" ]]; then
                [[ -n "$CURRENT_CATEGORY" ]] && [[ $CATEGORY_COUNT -gt 0 ]] &&
                    echo -e "${INDENT}           ${GRAY}${BOLD}Total:${NC} ${WHITE}${BOLD}$CATEGORY_COUNT${NC}"
                [[ $CATEGORY_COUNT -gt 0 ]] && echo
                echo -e "${INDENT}           ${CYAN}${BOLD}[*]${NC} ${WHITE}${BOLD}${category}${NC}:"
                CURRENT_CATEGORY="$category"
                CATEGORY_COUNT=0
            fi
            ((CATEGORY_COUNT++))
            ((TOTAL_FOUND++))
            ((NEW_FINDINGS++))
            echo -e "${INDENT}           ${GREEN}${BOLD}├─${NC} ${subdomain}"
            echo "$subdomain" >>"$OUTPUT_FILE"
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

    return 0
}
