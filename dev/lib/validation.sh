#!/bin/bash

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

VALIDATE_DOMAIN() {
    LOG "DEBUG" "Starting VALIDATE_DOMAIN with input: $1"
    if ! [[ "$1" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        LOG "ERROR" "VALIDATE_DOMAIN $1 - Invalid domain"
        return 1
    fi
    LOG "INFO" "VALIDATE_DOMAIN $1 - OK"
    return 0
}

VALIDATE_API_KEY() {
    local KEY="$1"
    local TYPE="$2"

    [[ "$API_VALIDATION_ENABLED" == false ]] && return 0

    case "$TYPE" in
    "ST") [[ ${#KEY} -eq 32 && $KEY =~ ^[A-Za-z0-9]+$ ]] ;;
    "VT") [[ ${#KEY} -eq 64 && $KEY =~ ^[A-Za-z0-9]+$ ]] ;;
    "CENSYS") [[ ${#KEY} -ge 32 && $KEY =~ ^[A-Za-z0-9_-]+$ ]] ;;
    *) return 1 ;;
    esac
    LOG "DEBUG" "Validated $TYPE API key"
    return $?
}

VALIDATE_WORDLIST_CHUNK() {
    local CHUNK="$1"
    local CHUNK_RESULTS="$THREAD_DIR/results_$(basename "$CHUNK")"
    local PROCESSED=0
    local CHUNK_SIZE=$(wc -l <"$CHUNK")

    while read -r WORD; do
        if [[ "$WORD" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] && [[ ${#WORD} -le 63 ]]; then
            echo "$WORD" >>"$CHUNK_RESULTS"
            ((PROCESSED++))
        else
            LOG "DEBUG" "Invalid word removed: $WORD"
        fi

        (
            flock 200
            local CURRENT=$(cat "$PROGRESS_FILE")
            echo $((CURRENT + 1)) >"$PROGRESS_FILE"
        ) 200>"$PROGRESS_FILE.lock"
    done < <(tr '[:upper:]' '[:lower:]' <"$CHUNK")
}

CLEAN_WORDLIST() {
    local INPUT_FILE="$1"
    #local THREAD_COUNT="${2:-10}"
    local TOTAL_COUNT=0
    local WORKING_COUNT=0
    local THREAD_DIR="$TEMP_DIR/wordlist_threads"
    local PROGRESS_FILE="$THREAD_DIR/progress"
    local CLEAN_FILE="$TEMP_DIR/clean_wordlist.txt"

    #if ACTIVE_SCAN_ENABLED and VHOST_SCAN_ENABLED are false, skip wordlist validation
    if [[ "$ACTIVE_SCAN_ENABLED" == false ]] && [[ "$VHOST_SCAN_ENABLED" == false ]]; then
        LOG "INFO" "Skipping wordlist validation"
        return 0
    fi

    # if WORDLIST is empty, check if os is kali linux use seclists /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
    if [ -z "$INPUT_FILE" ]; then
        INPUT_FILE=$WORDLIST_PATH
    fi

    if [[ ! -f "$INPUT_FILE" ]]; then
        LOG "ERROR" "Wordlist file not found: $INPUT_FILE"
        echo -e "${RED}${BOLD}[ERROR]${NC} Wordlist file not found: $INPUT_FILE"
        exit 1
    fi
    echo -e "\n"
    echo -e "${CYAN}${BOLD}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}${BOLD}│${NC}                           ${UNDERLINE}${BOLD}Wordlist Validation${NC}                            ${CYAN}${BOLD}│${NC}"
    echo -e "${CYAN}${BOLD}└──────────────────────────────────────────────────────────────────────────┘${NC}"

    echo -e "\n${YELLOW}${BOLD}[*]${NC} Cleaning and validating wordlist..."
    LOG "INFO" "Starting wordlist validation from: $INPUT_FILE"

    mkdir -p "$THREAD_DIR"

    echo "0" >"$PROGRESS_FILE"

    TOTAL_COUNT=$(grep -Ec '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$' "$INPUT_FILE")

    if [[ $TOTAL_COUNT -eq 0 ]]; then
        echo -e "${RED}${BOLD}[!]${NC} No valid entries found in wordlist"
        LOG "ERROR" "No valid entries found in $INPUT_FILE"
        rm -rf "$THREAD_DIR"
        exit 1 # Changed from return 1 to exit 1
    fi

    echo -e "${YELLOW}${BOLD}[*]${NC} Processing $TOTAL_COUNT unique entries..."

    local CHUNK_SIZE=$(((TOTAL_COUNT + THREAD_COUNT - 1) / THREAD_COUNT))
    LOG "DEBUG" "Splitting wordlist into chunks of size: $CHUNK_SIZE"
    tr -d '\000' <"$INPUT_FILE" | tr -d '\0' | grep -E '^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$' | split -l "$CHUNK_SIZE" - "$THREAD_DIR/chunk_"

    local PIDS=()
    for CHUNK in "$THREAD_DIR"/chunk_*; do
        LOG "DEBUG" "Launching validation thread for chunk: $CHUNK"
        VALIDATE_WORDLIST_CHUNK "$CHUNK" &
        PIDS+=($!)
        LOG "DEBUG" "Started wordlist validation thread PID: ${PIDS[-1]}"
    done

    while true; do
        local RUNNING=0
        for PID in "${PIDS[@]}"; do
            if kill -0 "$PID" 2>/dev/null; then
                ((RUNNING++))
            fi
        done

        local CURRENT_PROGRESS=$(cat "$PROGRESS_FILE")
        local PROGRESS=$((CURRENT_PROGRESS * 100 / TOTAL_COUNT))

        printf "\r${YELLOW}${BOLD}[*]${NC} Progress: [${GREEN}${BOLD}%-50s${NC}] %3d%% (%d threads active) " \
            "$(printf '#%.0s' $(seq 1 $((PROGRESS / 2))))" \
            "$PROGRESS" \
            "$RUNNING"

        if [[ $RUNNING -eq 0 ]]; then
            echo
            break
        fi

        sleep 1
    done

    if find "$THREAD_DIR" -name "results_chunk_*" -type f | grep -q .; then
        cat "$THREAD_DIR"/results_chunk_* | sort -u >"$CLEAN_FILE"
        WORKING_COUNT=$(wc -l <"$CLEAN_FILE")
    fi

    if [[ $WORKING_COUNT -eq 0 ]]; then
        echo -e "${RED}${BOLD}[!]${NC} No valid words found!"
        LOG "ERROR" "No valid words found in $INPUT_FILE"
        rm -rf "$THREAD_DIR"
        return 1
    fi

    WORDLIST_PATH="$CLEAN_FILE"
    echo -e -n "\033[1A\033[2K\r"
    echo -e "${GREEN}${BOLD}[✓]${NC} Found $WORKING_COUNT valid entries out of $TOTAL_COUNT tested"
    LOG "INFO" "Wordlist validation complete. Using $WORKING_COUNT valid entries"

    rm -rf "$THREAD_DIR"

    return 0
}

VALIDATE_RESOLVER_CHUNK() {
    local CHUNK="$1"
    local CHUNK_RESULTS="$THREAD_DIR/results_$(basename "$CHUNK")"
    local PROCESSED=0
    local CHUNK_SIZE=$(wc -l <"$CHUNK")

    while read -r RESOLVER; do
        if timeout $TIMEOUT dig @"$RESOLVER" "$TEST_DOMAIN" A +time=1 +tries=1 &>/dev/null &&
            timeout $TIMEOUT dig @"$RESOLVER" "$TEST_DOMAIN" NS +time=1 +tries=1 &>/dev/null; then
            echo "$RESOLVER" >>"$CHUNK_RESULTS"
            LOG "DEBUG" "Working resolver found: $RESOLVER"
        else
            LOG "DEBUG" "Failed resolver: $RESOLVER"
        fi

        ((PROCESSED++))
        local CURRENT=$(cat "$PROGRESS_FILE")
        echo $((CURRENT + 1)) >"$PROGRESS_FILE"
    done <"$CHUNK"
}

CLEAN_RESOLVERS() {
    local INPUT_FILE="$1"
    local TEMP_FILE="$TEMP_DIR/temp_resolvers.txt"
    local VALID_FILE="$TEMP_DIR/valid_resolvers.txt"
    local CLEAN_FILE="$TEMP_DIR/clean_resolvers.txt"
    local TEST_DOMAIN="google.com"
    local TIMEOUT=2
    local WORKING_COUNT=0
    local TOTAL_COUNT=0
    #local THREAD_COUNT=50

    #if ACTIVE_SCAN_ENABLED and PATTERN_RECOGNITION_ENABLED are false, skip resolver validation
    if [[ "$ACTIVE_SCAN_ENABLED" == false ]] && [[ "$PATTERN_RECOGNITION_ENABLED" == false ]]; then
        LOG "INFO" "Skipping resolver validation"
        return 0
    fi

    if [[ -z "$INPUT_FILE" ]]; then
        LOG "DEBUG" "No resolver file provided, skipping validation"
        return 0
    fi

    if [[ ! -f "$INPUT_FILE" ]]; then
        LOG "ERROR" "Resolver file not found: $INPUT_FILE"
        return 1
    fi
    echo -e "\n"
    echo -e "${CYAN}${BOLD}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}${BOLD}│${NC}                           ${UNDERLINE}${BOLD}Resolver Validation${NC}                            ${CYAN}${BOLD}│${NC}"
    echo -e "${CYAN}${BOLD}└──────────────────────────────────────────────────────────────────────────┘${NC}"

    echo -e "\n${YELLOW}${BOLD}[*]${NC} Cleaning and validating resolvers..."
    LOG "INFO" "Starting resolver validation from: $INPUT_FILE"

    grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' "$INPUT_FILE" |
        while read -r IP; do
            if [[ $(echo "$IP" | tr '.' '\n' | awk '$1 >= 0 && $1 <= 255' | wc -l) -eq 4 ]]; then
                echo "$IP"
            else
                LOG "DEBUG" "Invalid IP removed: $IP"
            fi
        done | sort -u >"$TEMP_FILE"

    TOTAL_COUNT=$(wc -l <"$TEMP_FILE")
    if [[ $TOTAL_COUNT -eq 0 ]]; then
        echo -e "${RED}${BOLD}[!]${NC} No valid resolver IPs found in input file"
        LOG "ERROR" "No valid resolver IPs found in $INPUT_FILE"
        exit 1
    fi

    echo -e "${YELLOW}${BOLD}[*]${NC} Testing $TOTAL_COUNT unique resolvers..."

    local THREAD_DIR="$TEMP_DIR/resolver_threads"
    mkdir -p "$THREAD_DIR"

    local PROGRESS_FILE="$THREAD_DIR/progress"
    echo "0" >"$PROGRESS_FILE"

    local CHUNK_SIZE=$(((TOTAL_COUNT + THREAD_COUNT - 1) / THREAD_COUNT))
    split -l "$CHUNK_SIZE" "$TEMP_FILE" "$THREAD_DIR/chunk_"

    local PIDS=()
    for CHUNK in "$THREAD_DIR"/chunk_*; do
        LOG "DEBUG" "Launching validation thread for chunk: $CHUNK"
        VALIDATE_RESOLVER_CHUNK "$CHUNK" &
        PIDS+=($!)
        LOG "DEBUG" "Started resolver validation thread PID: ${PIDS[-1]}"
    done

    while true; do
        local RUNNING=0
        for PID in "${PIDS[@]}"; do
            if kill -0 "$PID" 2>/dev/null; then
                ((RUNNING++))
            fi
        done

        local CURRENT_PROGRESS=$(cat "$PROGRESS_FILE")
        local PROGRESS=$((CURRENT_PROGRESS * 100 / TOTAL_COUNT))

        printf "\r${YELLOW}${BOLD}[*]${NC} Progress: [${GREEN}${BOLD}%-50s${NC}] %3d%% (%d threads active) " \
            "$(printf '#%.0s' $(seq 1 $((PROGRESS / 2))))" \
            "$PROGRESS" \
            "$RUNNING"

        if [[ $RUNNING -eq 0 ]]; then
            echo
            break
        fi

        sleep 1
    done

    if find "$THREAD_DIR" -name "results_chunk_*" -type f | grep -q .; then
        cat "$THREAD_DIR"/results_chunk_* | sort -u >"$CLEAN_FILE"
        WORKING_COUNT=$(wc -l <"$CLEAN_FILE")
    fi

    if [[ $WORKING_COUNT -eq 0 ]]; then
        echo -e "${RED}${BOLD}[!]${NC} No working resolvers found!"
        LOG "ERROR" "No working resolvers found in $INPUT_FILE"
        rm -rf "$THREAD_DIR"
        return 1
    fi

    RESOLVER_FILE="$CLEAN_FILE"
    echo -e -n "\033[1A\033[2K\r"
    echo -e "${GREEN}${BOLD}[✓]${NC} Found $WORKING_COUNT working resolvers out of $TOTAL_COUNT tested"
    LOG "INFO" "Resolver validation complete. Using $WORKING_COUNT working resolvers"

    rm -rf "$THREAD_DIR"

    return 0
}
