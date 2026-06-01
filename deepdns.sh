#!/bin/bash
#
######################################################################
#         DeepDNS - Advanced DNS Enumeration Script                  #
#  Author: Ervis Tusha               X: htts://x.com/ET              #
#  License: MIT        GitHub: https://github.com/ErvisTusha/deepdns #
######################################################################
#

# From BashFrame selected functions
LOG() {
    # $1 = STATUS
    # $2 = MESSAGE
    # $3 = DEBUG_LOG
    # if $1 is empty, return 1
    # if $2 is empty, return 1
    # if $1 is not valid, set to INFO

    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: LOG() no status provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: LOG() no message provided"
        return 1
    fi
    #check if $1 is INFO, WARNING, ERROR, DEBUG else add INFO to $1
    if ! [[ "$1" =~ ^(INFO|WARNING|ERROR|DEBUG)$ ]]; then
        STATUS="[INFO] : $1"
    else
        STATUS="$1"
        #if $2 provided then DEBUG_LOG=$2
        if [[ -z "$2" ]]; then
            DEBUG_LOG=$2
        fi
    fi

    MESSAGE="$2"
    #check if $3 is set then DEBUG_LOG=$3
    if [[ -n "$3" ]]; then
        DEBUG_LOG="$3"
    fi

    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') [$STATUS] : $MESSAGE" >>"$DEBUG_LOG"
    [[ "$VERBOSE" == "true" ]] && echo "[$STATUS] : $MESSAGE"

    return 0
}

IS_INSTALLED() {
    if [[ -z "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No package name provided"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No package name provided" >>"$DEBUG_LOG"
        return 1
    fi

    if command -v "$1" &>/dev/null; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: Package $1 is installed"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Package $1 is installed" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: Package $1 is not installed"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Package $1 is not installed" >>"$DEBUG_LOG"
        return 1
    fi
}

DOWNLOAD() {
    # Function to download files
    # Usage: DOWNLOAD <URL> [DESTINATION]

    local URL="$1"
    local DESTINATION="$2"

    if [[ -z "$URL" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No URL provided"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No URL provided" >>"$DEBUG_LOG"
        return 1
    fi

    if [[ -z "$DESTINATION" ]]; then
        DESTINATION_FILE="${URL##*/}"
        DESTINATION="${PWD}/${DESTINATION_FILE}"
    fi
    # Check if the destination folder is writable
    if ! IS_WRITABLE "$(dirname "$DESTINATION")"; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: Destination $DESTINATION is not writable"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: Destination $DESTINATION is not writable" >>"$DEBUG_LOG"
        return 1
    fi

    [[ "$VERBOSE" == "true" ]] && echo "INFO: Downloading $URL to $DESTINATION"
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Downloading $URL to $DESTINATION" >>"$DEBUG_LOG"

    if command -v curl >/dev/null 2>&1; then
        curl -L "$URL" -o "$DESTINATION"
        STATUS=$?
    elif command -v wget >/dev/null 2>&1; then
        wget "$URL" -O "$DESTINATION"
        STATUS=$?
    else
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: curl or wget not found"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: curl or wget not found" >>"$DEBUG_LOG"
        return 1
    fi

    if [[ "$STATUS" -ne 0 ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: Download failed"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: Download failed" >>"$DEBUG_LOG"
        return 1
    fi

    [[ "$VERBOSE" == "true" ]] && echo "INFO: Download successful"
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Download successful" >>"$DEBUG_LOG"
    return 0
}

ASK_USER() {
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No question provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No question provided"
        return 1
    fi
    [[ "$VERBOSE" == "true" ]] && echo "INFO: $1"
    [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: $1" >>"$DEBUG_LOG"
    local QUESTION="$1"
    local MAX_ATTEMPTS="${2:-3}"
    local ANSWER
    local ATTEMPTS=0
    while true; do
        read -r -p "$QUESTION " ANSWER
        if [[ "$ANSWER" =~ ^[Yy]$ ]]; then
            [[ "$VERBOSE" == "true" ]] && echo "INFO: User answered yes"
            [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: User answered yes" >>"$DEBUG_LOG"
            return 0
        elif [[ "$ANSWER" =~ ^[Nn]$ ]]; then
            [[ "$VERBOSE" == "true" ]] && echo "INFO: User answered no"
            [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: User answered no" >>"$DEBUG_LOG"
            return 1
        else
            ((ATTEMPTS++))
            if [[ "$ATTEMPTS" -ge "$MAX_ATTEMPTS" ]]; then
                [[ "$VERBOSE" == "true" ]] && echo "INFO: Maximum attempts reached"
                [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Maximum attempts reached" >>"$DEBUG_LOG"
                return 1
            fi
        fi
    done
}

IS_EMPTY() {
    if [[ -z "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: Variable is empty"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Variable is empty" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: Variable is not empty"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: Variable is not empty" >>"$DEBUG_LOG"
        return 1
    fi
}

IS_NUMBER() {
    # check if is empty
    if [[ -z "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No variable provided"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No variable provided" >>"$DEBUG_LOG"
        return 1
    fi
    # Check if the variable is numeric
    if [[ "$1" =~ ^[0-9]+$ ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: $1 is numeric"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: $1 is numeric" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: $1 is not numeric"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: $1 is not numeric" >>"$DEBUG_LOG"
        return 1
    fi
}

VAL_IP() {
    # Check if the IP address is empty
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No IP address provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No IP address provided"
        return 1
    fi

    # Check if the IP address is valid
    if [[ "$1" =~ ^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$ ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: IP address is valid"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: IP address is valid" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: IP address is not valid"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: IP address is not valid" >>"$DEBUG_LOG"
        return 1
    fi
}

FILE_EXISTS() {
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No file provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No file provided"
        return 1
    fi
    if [[ -f "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File $1 exists"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File $1 exists" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File $1 does not exist"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File $1 does not exist" >>"$DEBUG_LOG"
        return 1
    fi
}

FILE_EMPTY() {
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No file provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No file provided"
        return 1
    fi

    if [[ -s "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File $1 is not empty"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File $1 is not empty" >>"$DEBUG_LOG"
        return 1
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File $1 is empty"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File $1 is empty" >>"$DEBUG_LOG"
        return 0
    fi
}

IS_READABLE() {
    # check if argument $1 is empty
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No file or directory provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No file or directory provided"
        return 1
    fi
    # check if the file or directory is readable
    if [[ -r "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File or directory $1 is readable"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File or directory $1 is readable" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File or directory $1 is not readable"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File or directory $1 is not readable" >>"$DEBUG_LOG"
        return 1
    fi
}

IS_WRITABLE() {
    # check if argument $1 is empty
    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: No file or directory provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: No file or directory provided"
        return 1
    fi
    # check if the file or directory is writable
    if [[ -w "$1" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File or directory $1 is writable"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File or directory $1 is writable" >>"$DEBUG_LOG"
        return 0
    else
        [[ "$VERBOSE" == "true" ]] && echo "INFO: File or directory $1 is not writable"
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') INFO: File or directory $1 is not writable" >>"$DEBUG_LOG"
        return 1
    fi
}

GENERATE_RANDOM() {
    # $1 = length
    # $2 = type
    # return = random string
    # if $1 is empty, return 1
    # if $2 is empty, return 1
    # if $2 is not valid, return 1
    # if $1 is not numeric, return 1

    if [[ -z "$1" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:GENERATE_RANDOM No length provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR:GENERATE_RANDOM No length provided"
        return 1
    fi
    if [[ -z "$2" ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:GENERATE_RANDOM No type provided" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR:GENERATE_RANDOM No type provided"
        return 1
    fi
    if ! [[ "$2" =~ ^[a-zA-Z]+$ ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:GENERATE_RANDOM Invalid type" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR:GENERATE_RANDOM Invalid type"
        return 1
    fi
    if ! [[ "$1" =~ ^[0-9]+$ ]]; then
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR:GENERATE_RANDOM Length is not numeric" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR:GENERATE_RANDOM Length is not numeric"
        return 1
    fi

    local LENGTH=$1
    local TYPE=$2
    local RESULT=""
    local CHARS

    case "$TYPE" in
    1 | "numbers")
        CHARS="0123456789"
        ;;
    2 | "characters")
        CHARS="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ;;
    3 | "mixed")
        CHARS="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        ;;
    *)
        [[ "$DEBUG" == "true" ]] && echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: GENERATE_RANDOM Invalid type" >>"$DEBUG_LOG"
        [[ "$VERBOSE" == "true" ]] && echo "ERROR: GENERATE_RANDOM Invalid type"
        return 1
        ;;
    esac

    for ((i = 1; i <= LENGTH; i++)); do
        RESULT="${RESULT}${CHARS:RANDOM%${#CHARS}:1}"
    done

    echo "$RESULT"
}


# Directory settings
declare -g SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
declare -g HOME_DIR="$HOME/.deepdns"
declare -g LOG_DIR="$HOME_DIR/logs"
declare -g FILES_DIR="$HOME_DIR/files"
# Create required directories if they don't exist
[[ ! -d "$HOME_DIR" ]] && mkdir -p "$HOME_DIR"
[[ ! -d "$LOG_DIR" ]] && mkdir -p "$LOG_DIR"
[[ ! -d "$FILES_DIR" ]] && mkdir -p "$FILES_DIR"
# Debug settings
declare -g DEBUG_LOG="$LOG_DIR/debug.log"
# Global variables
declare -g SCRIPT="$(basename "$0")"
declare -g DOMAIN=""
declare -g OUTPUT=""
declare -g START_TIME=$(date +%s)
declare -g TEMP_DIR=""
declare -g VERBOSE=false
declare -g DEBUG=false
declare -g VERSION="3.0.0"
declare -g AUTHOR="Ervis Tusha"
# Default settings
declare -g DEFAULT_RECURSIVE_DEPTH=3
declare -g DEFAULT_OUTPUT_DIR="$PWD"
declare -g OUTPUT_FORMAT="txt"
declare -g WORDLIST_PATH="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
# API Keys
declare -g SECURITYTRAILS_API_KEY=""
declare -g VIRUSTOTAL_API_KEY=""
declare -g CENSYS_API_ID=""
declare -g CENSYS_API_SECRET=""
# Feature flags
declare -g ACTIVE_SCAN_ENABLED=false
declare -g RECURSIVE_SCAN_ENABLED=false
declare -g VHOST_SCAN_ENABLED=false
declare -g PATTERN_RECOGNITION_ENABLED=false
declare -g ZONE_TRANSFER_ENABLED=false
declare -g DNSSEC_SCAN_ENABLED=false
declare -g PENTEST_SCAN_ENABLED=false
declare -g RESOLVER_SCAN=false
declare -g API_VALIDATION_ENABLED=true
declare -g RESOLVER_FILE=""
declare -g VHOST_PORTS=(80 443)
# Colors
declare -r RED='\033[0;31m'
declare -r GREEN='\033[0;32m'
declare -r YELLOW='\033[1;33m'
declare -r BLUE='\033[0;34m'
declare -r CYAN='\033[0;36m'
declare -r NC='\033[0m'
declare -r BOLD='\033[1m'
declare -r GRAY='\033[0;90m'
declare -r PURPLE='\033[0;35m'
declare -r MAGENTA='\033[0;35m'
declare -r DIM='\033[2m'
declare -r UNDERLINE='\033[4m'
declare -r WHITE='\033[1;37m'
declare -g CLEANUP_DONE=false
declare -g INTERRUPT_RECEIVED=false
# Response filtering
declare -g VHOST_FILTER=""
declare -g VHOST_FILTER_TYPE="status" # status, size, words, lines
# Thread count
declare -g THREAD_COUNT=10
# GitHub repository URL
declare -g REPO_URL="https://raw.githubusercontent.com/ErvisTusha/deepdns/main/deepdns.sh"
declare -g RELEASE_SIGNATURE_URL="${REPO_URL}.asc"
declare -g RELEASE_SIGNING_KEY_URL="https://raw.githubusercontent.com/ErvisTusha/deepdns/main/security/deepdns-release.gpg"
declare -g RELEASE_SIGNING_FINGERPRINT=""
declare -g RELEASE_SIGNATURE_REQUIRED=false
# Raw output flag
declare -g RAW_OUTPUT=false
# Pentest checks
declare -g PENTEST_PROFILE="safe"
declare -g PENTEST_CHECKS=""
declare -g PENTEST_EVIDENCE_DIR=""
declare -g PENTEST_FINDINGS_FILE=""
declare -g PENTEST_JSON_ITEMS_FILE=""
declare -g PENTEST_FINDING_COUNT=0
declare -g PENTEST_RAW_EVIDENCE=true


# From core.sh
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


# From utils.sh
INSTALL_SCRIPT() {
    LOG "INFO" "Starting DeepDNS installation"
    if ! sudo -v &>/dev/null; then
        echo -e "${RED}${BOLD}[ERROR]${NC} Sudo access required for installation"
        LOG "ERROR" "Installation failed - no sudo access"
        return 1
    fi
    echo -e "\n${CYAN}${BOLD}[*]${NC} Installing DeepDNS..."
    # Create required directories with correct permissions
    local HOME_DIR="$HOME/.deepdns"
    local LOG_DIR="$HOME_DIR/logs"
    local FILES_DIR="$HOME_DIR/files"
    
    mkdir -p "$HOME_DIR" "$LOG_DIR" "$FILES_DIR"
    chmod 755 "$HOME_DIR"
    chmod 755 "$LOG_DIR"
    chmod 755 "$FILES_DIR"
    if [ -f "/usr/local/bin/deepdns" ]; then
        echo -e "${YELLOW}${BOLD}[!]${NC} DeepDNS is already installed. Use 'update' to upgrade."
        LOG "INFO" "Installation skipped - already installed"
        return 0
    fi
    local INSTALL_SOURCE="$0"
    local SCRIPT_BASE
    SCRIPT_BASE="$(basename "$0")"
    if [[ "$SCRIPT_BASE" == "deepdns" && -f "$(cd "$(dirname "$0")/.." >/dev/null 2>&1 && pwd)/deepdns.sh" ]]; then
        INSTALL_SOURCE="$(cd "$(dirname "$0")/.." >/dev/null 2>&1 && pwd)/deepdns.sh"
    fi
    if ! bash -n "$INSTALL_SOURCE"; then
        echo -e "${RED}${BOLD}[✗]${NC} Install source failed syntax check: $INSTALL_SOURCE"
        LOG "ERROR" "Installation failed - syntax check failed for $INSTALL_SOURCE"
        return 1
    fi
    if sudo install -m 0755 -o root -g root "$INSTALL_SOURCE" /usr/local/bin/deepdns; then
        echo -e "${GREEN}${BOLD}[✓]${NC} Successfully installed DeepDNS:"
        echo -e "   ${CYAN}${BOLD}→${NC} Binary: /usr/local/bin/deepdns"
        echo -e "   ${CYAN}${BOLD}→${NC} Config: $HOME_DIR"
        echo -e "\nYou can now use 'deepdns' from anywhere"
        LOG "INFO" "Installation successful"
        return 0
    else
        echo -e "${RED}${BOLD}[✗]${NC} Failed to install DeepDNS"
        LOG "ERROR" "Installation failed - copy error"
        return 1
    fi
}
UPDATE_SCRIPT() {
    LOG "INFO" "Starting DeepDNS update"
    local CURRENT_VERSION="$VERSION"
    local NEW_VERSION
    echo -e "\n${CYAN}${BOLD}[*]${NC} Updating DeepDNS..."
    echo -e "   ${CYAN}${BOLD}→${NC} Current version: ${YELLOW}${BOLD}${CURRENT_VERSION}${NC}"
    # Check if installed
    if [ ! -f "/usr/local/bin/deepdns" ]; then
        echo -e "${YELLOW}${BOLD}[!]${NC} DeepDNS is not installed. Use 'install' first."
        LOG "ERROR" "Update failed - not installed"
        return 1
    fi
    # Verify sudo access
    if ! sudo -v &>/dev/null; then
        echo -e "${RED}${BOLD}[ERROR]${NC} Sudo access required for update"
        LOG "ERROR" "Update failed - no sudo access"
        return 1
    fi
    # Download and update
    local TEMP_FILE=$(mktemp)
    local SIG_FILE="${TEMP_FILE}.asc"
    local KEY_FILE=""
    if DOWNLOAD "$REPO_URL" "$TEMP_FILE"; then
        if [[ "$RELEASE_SIGNATURE_REQUIRED" == true || -n "$RELEASE_SIGNING_FINGERPRINT" ]]; then
            if ! DOWNLOAD "$RELEASE_SIGNATURE_URL" "$SIG_FILE"; then
                rm -f "$TEMP_FILE" "$SIG_FILE"
                echo -e "${RED}${BOLD}[✗]${NC} Failed to download release signature"
                LOG "ERROR" "Update failed - release signature download error"
                return 1
            fi
            if [[ -n "$RELEASE_SIGNING_KEY_URL" ]]; then
                KEY_FILE="${TEMP_FILE}.gpg"
                DOWNLOAD "$RELEASE_SIGNING_KEY_URL" "$KEY_FILE" >/dev/null 2>&1 || KEY_FILE=""
            fi
            if ! VERIFY_RELEASE_SIGNATURE "$TEMP_FILE" "$SIG_FILE" "$KEY_FILE" "$RELEASE_SIGNING_FINGERPRINT"; then
                rm -f "$TEMP_FILE" "$SIG_FILE" "$KEY_FILE"
                echo -e "${RED}${BOLD}[✗]${NC} Release signature verification failed"
                LOG "ERROR" "Update failed - release signature verification failed"
                return 1
            fi
        else
            echo -e "${YELLOW}${BOLD}[!]${NC} Release signature verification skipped (no signing fingerprint configured)"
            LOG "WARNING" "Release signature verification skipped"
        fi
        # Extract version from downloaded file
        NEW_VERSION=$(grep "declare -g VERSION=" "$TEMP_FILE" | cut -d'"' -f2)
        if [[ -z "$NEW_VERSION" ]] || ! grep -q '^#!/bin/bash' "$TEMP_FILE" || ! bash -n "$TEMP_FILE"; then
            rm -f "$TEMP_FILE" "$SIG_FILE" "$KEY_FILE"
            echo -e "${RED}${BOLD}[✗]${NC} Downloaded update failed validation"
            LOG "ERROR" "Update failed - downloaded script failed validation"
            return 1
        fi
        if sudo cp "$TEMP_FILE" /usr/local/bin/deepdns && sudo chmod +x /usr/local/bin/deepdns; then
            rm -f "$TEMP_FILE" "$SIG_FILE" "$KEY_FILE"
            echo -e "${GREEN}${BOLD}[✓]${NC} Successfully updated DeepDNS:"
            echo -e "   ${CYAN}${BOLD}→${NC} Binary: /usr/local/bin/deepdns"
            echo -e "   ${CYAN}${BOLD}→${NC} Updated: ${YELLOW}${BOLD}v${CURRENT_VERSION}${NC} ${GREEN}${BOLD}→${NC} ${YELLOW}${BOLD}v${NEW_VERSION}${NC}"
            echo -e "\nYou can now use 'deepdns' from anywhere"
            LOG "INFO" "Update successful from v${CURRENT_VERSION} to v${NEW_VERSION}"
            return 0
        fi
    fi
    rm -f "$TEMP_FILE" "$SIG_FILE" "$KEY_FILE"
    echo -e "${RED}${BOLD}[✗]${NC} Failed to update DeepDNS"
    LOG "ERROR" "Update failed - download/copy error"
    return 1
}
UNINSTALL_SCRIPT() {
    LOG "INFO" "Starting DeepDNS uninstallation"
    echo -e "\n${CYAN}${BOLD}[*]${NC} Uninstalling DeepDNS..."
    if [ ! -f "/usr/local/bin/deepdns" ]; then
        echo -e "${YELLOW}${BOLD}[!]${NC} DeepDNS is not installed"
        LOG "INFO" "Uninstall skipped - not installed"
        return 0
    fi
    if ! sudo -v &>/dev/null; then
        echo -e "${RED}${BOLD}[ERROR]${NC} Sudo access required for uninstallation"
        LOG "ERROR" "Uninstall failed - no sudo access"
        return 1
    fi
    if sudo rm -f /usr/local/bin/deepdns; then
        echo -e "${GREEN}${BOLD}[✓]${NC} Successfully uninstalled DeepDNS:"
        echo -e "   ${CYAN}${BOLD}→${NC} Removed: /usr/local/bin/deepdns"
        echo -e "\nDeepDNS has been completely removed from your system"
        LOG "INFO" "Uninstall successful"
        return 0
    else
        echo -e "${RED}${BOLD}[✗]${NC} Failed to uninstall DeepDNS"
        LOG "ERROR" "Uninstall failed - removal error"
        return 1
    fi
}
DETECT_PROTOCOL() {
    local DOMAIN="$1"
    local PORT="$2"
    # Try HTTPS first
    if curl -s -k --head \
        --connect-timeout 2 \
        --max-time 3 \
        "https://${DOMAIN}:${PORT}" >/dev/null 2>&1; then
        echo "https"
        return 0
    fi
    # Try HTTP if HTTPS failed
    if curl -s --head \
        --connect-timeout 2 \
        --max-time 3 \
        "http://${DOMAIN}:${PORT}" >/dev/null 2>&1; then
        echo "http"
        return 0
    fi
    # Default to http if both fail
    echo "http"
    return 1
}


# From validation.sh
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
    local VALID=1
    case "$TYPE" in
    "ST") [[ ${#KEY} -eq 32 && $KEY =~ ^[A-Za-z0-9]+$ ]] && VALID=0 ;;
    "VT") [[ ${#KEY} -eq 64 && $KEY =~ ^[A-Za-z0-9]+$ ]] && VALID=0 ;;
    "CENSYS") [[ ${#KEY} -ge 32 && $KEY =~ ^[A-Za-z0-9_-]+$ ]] && VALID=0 ;;
    *) return 1 ;;
    esac
    if [[ $VALID -eq 0 ]]; then
        LOG "DEBUG" "Validated $TYPE API key"
        return 0
    fi
    LOG "ERROR" "Invalid $TYPE API key"
    return 1
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
        exit 1
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


# From dns.sh
CHECK_DNS_TOOLS() {
    local MISSING_TOOLS=()
    local REQUIRED_TOOLS=("dig" "host" "nslookup")
    for TOOL in "${REQUIRED_TOOLS[@]}"; do
        if ! IS_INSTALLED "$TOOL"; then
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
declare -g SELECTED_RESOLVER=""
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
    SELECTED_RESOLVER="$BEST_RESOLVER"
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
    return 0
}
CHECK_SUBDOMAIN() {
    local DOMAIN="$1"
    local TIMEOUT=2
    local MAX_RETRIES=2
    local RETRY_COUNT=0
    if [[ ${#RESOLVERS[@]} -eq 0 ]]; then
        if [[ -f "$RESOLVER_FILE" ]]; then
            mapfile -t RESOLVERS <"$RESOLVER_FILE"
        else
            RESOLVERS=("1.1.1.1" "8.8.8.8" "9.9.9.9")
        fi
    fi
    SELECT_RESOLVER >/dev/null
    local RESOLVER="$SELECTED_RESOLVER"
    while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
        # Check with dig
        local DIG_RESULT
        DIG_RESULT=$(dig +short "@$RESOLVER" "$DOMAIN" A +time=$TIMEOUT 2>/dev/null)
        if [[ -n "$DIG_RESULT" ]]; then
            # Validate each IP in result
            while read -r IP; do
                if VAL_IP "$IP"; then
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
        if [[ -n "$CNAME_RESULT" ]]; then
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
DNS_ZONE_TRANSFER() {
    local DOMAIN="$1"
    local RESULTS_FILE="$2"
    local REPORT_FILE="${3:-}"
    local NS_SERVERS
    local FOUND=false
    NS_SERVERS=$(dig +short NS "$DOMAIN" 2>/dev/null | sed 's/\.$//' | sort -u)
    if [[ -z "$NS_SERVERS" ]]; then
        LOG "WARNING" "No nameservers found for zone transfer: $DOMAIN"
        return 1
    fi
    [[ -n "$REPORT_FILE" ]] && {
        printf "Zone transfer report for %s\n" "$DOMAIN"
        printf "Generated: %s\n\n" "$(date '+%Y-%m-%d %H:%M:%S')"
    } >"$REPORT_FILE"
    echo -e "\n${CYAN}${BOLD}[ZONE TRANSFER]${NC} Checking AXFR exposure for $DOMAIN"
    while IFS= read -r NS; do
        [[ -z "$NS" ]] && continue
        echo -e "${YELLOW}${BOLD}[*]${NC} Trying AXFR from ${WHITE}${BOLD}$NS${NC}"
        LOG "INFO" "Attempting zone transfer for $DOMAIN from $NS"
        local AXFR_OUTPUT
        AXFR_OUTPUT=$(dig @"$NS" "$DOMAIN" AXFR +time=5 +tries=1 2>/dev/null || true)
        if echo "$AXFR_OUTPUT" | grep -Eq '\sIN\s+(A|AAAA|CNAME|MX|NS|TXT|SRV)\s'; then
            FOUND=true
            echo -e "${RED}${BOLD}[!]${NC} Zone transfer succeeded from $NS"
            [[ -n "$REPORT_FILE" ]] && {
                printf "AXFR succeeded from %s\n" "$NS"
                printf "%s\n\n" "$AXFR_OUTPUT"
            } >>"$REPORT_FILE"
            echo "$AXFR_OUTPUT" |
                awk -v domain="$DOMAIN" '$1 ~ "\\." domain "\\.?$" { gsub(/\.$/, "", $1); print $1 }' |
                sort -u >>"$RESULTS_FILE"
        else
            echo -e "${GREEN}${BOLD}[✓]${NC} AXFR refused by $NS"
            [[ -n "$REPORT_FILE" ]] && printf "AXFR refused by %s\n" "$NS" >>"$REPORT_FILE"
        fi
    done <<<"$NS_SERVERS"
    "$FOUND"
}
DNS_OUTPUT_HAS_RECORD() {
    local OUTPUT="$1"
    local RECORD_TYPE="$2"
    echo "$OUTPUT" | awk -v type="$RECORD_TYPE" '
        $0 !~ /^;/ && $0 ~ ("[[:space:]]IN[[:space:]]" type "([[:space:]]|$)") {
            found = 1
        }
        END { exit(found ? 0 : 1) }
    '
}
DNSSEC_SCAN() {
    local DOMAIN="$1"
    local REPORT_FILE="$2"
    local DNSKEY_OUTPUT
    local DS_OUTPUT
    local SOA_DNSSEC_OUTPUT
    echo -e "\n${CYAN}${BOLD}[DNSSEC]${NC} Checking DNSSEC posture for $DOMAIN"
    LOG "INFO" "Starting DNSSEC scan for $DOMAIN"
    DNSKEY_OUTPUT=$(dig "$DOMAIN" DNSKEY +dnssec +multi +time=5 +tries=1 2>/dev/null || true)
    DS_OUTPUT=$(dig "$DOMAIN" DS +dnssec +multi +time=5 +tries=1 2>/dev/null || true)
    SOA_DNSSEC_OUTPUT=$(dig "$DOMAIN" SOA +dnssec +multi +time=5 +tries=1 2>/dev/null || true)
    {
        printf "DNSSEC report for %s\n" "$DOMAIN"
        printf "Generated: %s\n\n" "$(date '+%Y-%m-%d %H:%M:%S')"
        printf "== DNSKEY ==\n%s\n\n" "$DNSKEY_OUTPUT"
        printf "== DS ==\n%s\n\n" "$DS_OUTPUT"
        printf "== SOA +dnssec ==\n%s\n" "$SOA_DNSSEC_OUTPUT"
    } >"$REPORT_FILE"
    if DNS_OUTPUT_HAS_RECORD "$DNSKEY_OUTPUT" "DNSKEY"; then
        echo -e "${GREEN}${BOLD}[✓]${NC} DNSKEY records found"
    else
        echo -e "${YELLOW}${BOLD}[!]${NC} DNSKEY records not found"
    fi
    if DNS_OUTPUT_HAS_RECORD "$DS_OUTPUT" "DS"; then
        echo -e "${GREEN}${BOLD}[✓]${NC} DS records found at parent"
    else
        echo -e "${YELLOW}${BOLD}[!]${NC} DS records not found at parent"
    fi
    if echo "$SOA_DNSSEC_OUTPUT" | grep -q ' ad;'; then
        echo -e "${GREEN}${BOLD}[✓]${NC} Authenticated DNSSEC response observed"
    else
        echo -e "${YELLOW}${BOLD}[!]${NC} Authenticated DNSSEC response not observed"
    fi
    echo -e "${GREEN}${BOLD}[✓]${NC} DNSSEC report saved: ${CYAN}${BOLD}$REPORT_FILE${NC}"
    return 0
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
    # Calculate total patterns
    local TOTAL_PATTERNS=0
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
    fi
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
    return 0
}


# From passive.sh
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


# From active.sh
WILDCARD_DETECTION() {
    local DOMAIN="$1"
    local ATTEMPTS=3
    local WILDCARD_DETECTED=false
    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}[ERROR] DOMAIN PARAMETER IS REQUIRED${NC}"
        return 1
    fi
    for ATTEMPT in $(seq 1 $ATTEMPTS); do
        local RANDOM_SUBDOMAIN="WILDCARD-$(GENERATE_RANDOM 20 mixed)"
        local DNS_RESULT
        if ! DNS_RESULT=$(dig +short "$RANDOM_SUBDOMAIN.$DOMAIN" +time=2 +tries=1 2>/dev/null); then
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
            ASK_USER "$(echo -e "${INDENT}${YELLOW}${BOLD}[?]${NC} Do you want to continue scanning? [y/N]:")"
            CONTINUE_STATUS=$?
        else
            ASK_USER "$(echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} Wildcard DNS detected, do you want to continue scanning? [y/N]:")"
            CONTINUE_STATUS=$?
        fi
        if [[ $CONTINUE_STATUS -ne 0 ]]; then
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
        local RANDOM_VHOST="wildcard-$(GENERATE_RANDOM 20 mixed).${DOMAIN}"
        # Get baseline response with random vhost
        local RESPONSE=$(curl -s -I \
            --connect-timeout 3 \
            --max-time 5 \
            -k \
            -H "Host: ${RANDOM_VHOST}" \
            "${PROTOCOL}://${DOMAIN_IP}:${PORT}" 2>/dev/null)
        local STATUS=$(echo "$RESPONSE" | grep -E "^HTTP" | cut -d' ' -f2)
        # Successful responses for random hosts are strong wildcard signals.
        if [[ "$STATUS" =~ ^[23][0-9][0-9]$ ]]; then
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
            ASK_USER "$(echo -e "${INDENT}${YELLOW}${BOLD}[?]${NC} Do you want to continue scanning? [y/N]:")"
            CONTINUE_STATUS=$?
        else
            ASK_USER "$(echo -e "${INDENT}${YELLOW}${BOLD}[!]${NC} Virtual host wildcard detected, continue scanning? [y/N]:")"
            CONTINUE_STATUS=$?
        fi
        if [[ $CONTINUE_STATUS -ne 0 ]]; then
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
        if dig +short "$TARGET" "@$RESOLVER" +time=2 +tries=1 | grep -q '^[0-9]'; then
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
        if [[ "$TOTAL_WORDS" -eq 0 ]]; then
            LOG "ERROR" "Wordlist is empty: $WORDLIST_PATH"
            echo -e "${RED}${BOLD}[ERROR]${NC} Wordlist is empty: $WORDLIST_PATH"
            return 1
        fi
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
        if find "$THREAD_DIR" -name "results_*" -type f | grep -q .; then
            cat "$THREAD_DIR"/results_* >"$RESULTS_FILE" 2>/dev/null
        else
            : >"$RESULTS_FILE"
        fi
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
                        [[ "$STATUS" == "$FILTER" ]] && SHOW_RESULT=false && break
                    done
                    ;;
                "size")
                    IFS=',' read -ra FILTERS <<<"$VHOST_FILTER"
                    for FILTER in "${FILTERS[@]}"; do
                        if [[ "$FILTER" =~ ^[0-9]+$ ]]; then
                            [[ "$SIZE" =~ ^[0-9]+$ && "$SIZE" -eq "$FILTER" ]] && SHOW_RESULT=false && break
                        elif [[ "$FILTER" =~ ^\<[0-9]+$ ]]; then
                            local VAL=${FILTER#<}
                            [[ "$SIZE" =~ ^[0-9]+$ && "$SIZE" -lt "$VAL" ]] && SHOW_RESULT=false && break
                        elif [[ "$FILTER" =~ ^\>[0-9]+$ ]]; then
                            local VAL=${FILTER#>}
                            [[ "$SIZE" =~ ^[0-9]+$ && "$SIZE" -gt "$VAL" ]] && SHOW_RESULT=false && break
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
        "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36"
    )
    if [[ "$RECURSIVE_SCAN_ENABLED" == false ]]; then
        echo -e "\n${CYAN}${BOLD}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${CYAN}${BOLD}│${NC}                         ${UNDERLINE}${BOLD}Virtual Host Scan Results${NC}                        ${CYAN}${BOLD}│${NC}"
        echo -e "${CYAN}${BOLD}└──────────────────────────────────────────────────────────────────────────┘${NC}\n"
    fi
    LOG "INFO" "Starting VHOST scan for $DOMAIN"
    local TOTAL_WORDS=$(wc -l <"$WORDLIST_PATH")
    if [[ "$TOTAL_WORDS" -eq 0 ]]; then
        LOG "ERROR" "Wordlist is empty: $WORDLIST_PATH"
        echo -e "${RED}${BOLD}[ERROR]${NC} Wordlist is empty: $WORDLIST_PATH"
        return 1
    fi
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
        DOMAIN_IP=$(dig +short "$DOMAIN" A | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | head -n1)
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


# From pentest.sh
PENTEST_PROFILE_CHECKS() {
    case "${PENTEST_PROFILE,,}" in
    safe)
        echo "takeover dns mail http tls"
        ;;
    balanced)
        echo "takeover dns mail http tls cloud"
        ;;
    aggressive)
        echo "takeover dns mail http tls cloud"
        ;;
    *)
        echo "takeover dns mail http tls"
        ;;
    esac
}
PENTEST_CHECK_ENABLED() {
    local CHECK="$1"
    if [[ -n "$PENTEST_CHECKS" ]]; then
        [[ ",$PENTEST_CHECKS," == *",$CHECK,"* ]]
        return $?
    fi
    [[ " $(PENTEST_PROFILE_CHECKS) " == *" $CHECK "* ]]
}
PENTEST_TARGET_LIMIT() {
    case "${PENTEST_PROFILE,,}" in
    safe) echo 25 ;;
    balanced) echo 75 ;;
    aggressive) echo 0 ;;
    *) echo 25 ;;
    esac
}
RUN_PENTEST_CHECKS() {
    local DOMAIN="$1"
    local TARGETS_FILE="$2"
    local OUTPUT_BASE="$3"
    local TARGETS="$TEMP_DIR/pentest_targets.txt"
    [[ "$PENTEST_SCAN_ENABLED" != true ]] && return 0
    if [[ -z "$PENTEST_EVIDENCE_DIR" ]]; then
        PENTEST_EVIDENCE_DIR="${OUTPUT_BASE}_evidence"
    fi
    INIT_FINDINGS "$OUTPUT_BASE" "$OUTPUT_FORMAT"
    mkdir -p "$PENTEST_EVIDENCE_DIR"
    {
        printf "%s\n" "$DOMAIN"
        [[ -f "$TARGETS_FILE" ]] && cat "$TARGETS_FILE"
    } | sed 's/:.*$//' | grep -E "^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$" | sort -u >"$TARGETS"
    echo -e "\n${CYAN}${BOLD}[PENTEST]${NC} Running ${WHITE}${BOLD}${PENTEST_PROFILE}${NC} profile checks"
    PENTEST_CHECK_ENABLED takeover && PENTEST_TAKEOVER_CHECK "$DOMAIN" "$TARGETS"
    PENTEST_CHECK_ENABLED dns && PENTEST_DNS_CHECK "$DOMAIN" "$TARGETS"
    PENTEST_CHECK_ENABLED mail && PENTEST_MAIL_CHECK "$DOMAIN"
    PENTEST_CHECK_ENABLED http && PENTEST_HTTP_CHECK "$DOMAIN" "$TARGETS"
    PENTEST_CHECK_ENABLED tls && PENTEST_TLS_CHECK "$DOMAIN" "$TARGETS"
    PENTEST_CHECK_ENABLED cloud && PENTEST_CLOUD_CHECK "$DOMAIN" "$TARGETS"
    FINALIZE_FINDINGS
    echo -e "${GREEN}${BOLD}[✓]${NC} Pentest findings saved: ${CYAN}${BOLD}$PENTEST_FINDINGS_FILE${NC}"
    echo -e "${GREEN}${BOLD}[✓]${NC} Raw evidence saved: ${CYAN}${BOLD}$PENTEST_EVIDENCE_DIR${NC}"
}
PENTEST_EACH_TARGET() {
    local TARGETS_FILE="$1"
    local LIMIT
    LIMIT="$(PENTEST_TARGET_LIMIT)"
    if [[ "$LIMIT" -eq 0 ]]; then
        cat "$TARGETS_FILE"
    else
        head -n "$LIMIT" "$TARGETS_FILE"
    fi
}
PENTEST_TAKEOVER_PROVIDER() {
    local CNAME="$1"
    case "$CNAME" in
    *s3.amazonaws.com* | *s3-website*amazonaws.com*) echo "aws-s3" ;;
    *github.io*) echo "github-pages" ;;
    *herokuapp.com*) echo "heroku" ;;
    *azurewebsites.net* | *cloudapp.net*) echo "azure" ;;
    *netlify.app*) echo "netlify" ;;
    *vercel.app*) echo "vercel" ;;
    *pages.dev*) echo "cloudflare-pages" ;;
    *statuspage.io*) echo "statuspage" ;;
    *readme.io*) echo "readme" ;;
    *unbouncepages.com*) echo "unbounce" ;;
    *) return 1 ;;
    esac
}
PENTEST_TAKEOVER_CHECK() {
    local DOMAIN="$1"
    local TARGETS_FILE="$2"
    local TARGET CNAME PROVIDER HTTP_BODY EVIDENCE
    while IFS= read -r TARGET; do
        [[ "$TARGET" == "$DOMAIN" ]] && continue
        CNAME="$(dig +short "$TARGET" CNAME +time=3 +tries=1 2>/dev/null | tr '[:upper:]' '[:lower:]' | sed 's/\.$//' | head -n1)"
        [[ -z "$CNAME" ]] && continue
        if PROVIDER="$(PENTEST_TAKEOVER_PROVIDER "$CNAME")"; then
            HTTP_BODY="$(curl --silent --location --connect-timeout 4 --max-time 8 "https://$TARGET" "http://$TARGET" 2>/dev/null | head -c 4000 || true)"
            EVIDENCE="CNAME points to $CNAME ($PROVIDER)"
            WRITE_EVIDENCE "takeover" "$TARGET" "CNAME: $CNAME"$'\n'"HTTP sample:"$'\n'"$HTTP_BODY"
            if echo "$HTTP_BODY" | grep -Eiq "NoSuchBucket|There isn't a GitHub Pages site here|No such app|not found|project not found"; then
                WRITE_FINDING "high" "takeover_confirmed" "takeover" "$TARGET" "Potential subdomain takeover fingerprint confirmed" "$EVIDENCE; HTTP body contains provider not-found fingerprint" "Claim or remove the dangling third-party resource and delete stale DNS records." "high" "dns,http"
            else
                WRITE_FINDING "medium" "takeover_potential" "takeover" "$TARGET" "Potential dangling third-party CNAME" "$EVIDENCE" "Verify the third-party resource exists and remove stale DNS records if unclaimed." "medium" "dns"
            fi
        fi
    done < <(PENTEST_EACH_TARGET "$TARGETS_FILE")
}
PENTEST_DNS_CHECK() {
    local DOMAIN="$1"
    local TARGETS_FILE="$2"
    local CAA WILDCARD NS SOA TARGET CNAME CNAME_A
    CAA="$(dig +short "$DOMAIN" CAA +time=3 +tries=1 2>/dev/null)"
    WRITE_EVIDENCE "dns_caa" "$DOMAIN" "$CAA"
    if [[ -z "$CAA" ]]; then
        WRITE_FINDING "low" "dns_caa_missing" "dns" "$DOMAIN" "CAA records are missing" "No CAA records returned for $DOMAIN" "Add CAA records to constrain certificate issuance." "medium" "dns"
    fi
    WILDCARD="$(dig +short "wildcard-$(GENERATE_RANDOM 12 mixed).$DOMAIN" A +time=3 +tries=1 2>/dev/null)"
    WRITE_EVIDENCE "dns_wildcard" "$DOMAIN" "$WILDCARD"
    if [[ -n "$WILDCARD" ]]; then
        WRITE_FINDING "medium" "dns_wildcard_enabled" "dns" "$DOMAIN" "Wildcard DNS appears enabled" "Random hostname resolved to: $WILDCARD" "Review wildcard DNS because it can hide stale assets and inflate scan results." "medium" "dns"
    fi
    while IFS= read -r NS; do
        [[ -z "$NS" ]] && continue
        SOA="$(dig @"$NS" "$DOMAIN" SOA +time=3 +tries=1 2>/dev/null || true)"
        WRITE_EVIDENCE "dns_ns_soa" "$NS" "$SOA"
        if ! DNS_OUTPUT_HAS_RECORD "$SOA" "SOA"; then
            WRITE_FINDING "medium" "dns_lame_nameserver" "dns" "$NS" "Nameserver did not return SOA for zone" "$NS did not return an SOA record for $DOMAIN" "Fix delegation or remove lame nameserver entries." "medium" "dns"
        fi
    done < <(dig +short "$DOMAIN" NS 2>/dev/null | sed 's/\.$//')
    while IFS= read -r TARGET; do
        CNAME="$(dig +short "$TARGET" CNAME +time=3 +tries=1 2>/dev/null | sed 's/\.$//' | head -n1)"
        [[ -z "$CNAME" ]] && continue
        CNAME_A="$(dig +short "$CNAME" A +time=3 +tries=1 2>/dev/null)"
        if [[ -z "$CNAME_A" ]]; then
            WRITE_FINDING "medium" "dns_dangling_cname" "dns" "$TARGET" "CNAME target does not resolve" "$TARGET CNAME points to $CNAME but no A record was returned" "Remove stale CNAMEs or restore the target service." "medium" "dns"
        fi
    done < <(PENTEST_EACH_TARGET "$TARGETS_FILE")
}
PENTEST_MAIL_CHECK() {
    local DOMAIN="$1"
    local TXT DMARC MTASTS TLSRPT SELECTOR DKIM
    TXT="$(dig +short "$DOMAIN" TXT +time=3 +tries=1 2>/dev/null)"
    WRITE_EVIDENCE "mail_txt" "$DOMAIN" "$TXT"
    if ! echo "$TXT" | grep -qi "v=spf1"; then
        WRITE_FINDING "medium" "mail_spf_missing" "mail" "$DOMAIN" "SPF record is missing" "No v=spf1 TXT record found" "Publish an SPF record for authorized mail senders." "high" "dns"
    elif echo "$TXT" | grep -Eqi "\\+all| all"; then
        WRITE_FINDING "high" "mail_spf_permissive" "mail" "$DOMAIN" "SPF policy is overly permissive" "SPF record allows all senders" "Replace permissive SPF all-mechanisms with -all or a tighter policy." "high" "dns"
    fi
    DMARC="$(dig +short "_dmarc.$DOMAIN" TXT +time=3 +tries=1 2>/dev/null)"
    WRITE_EVIDENCE "mail_dmarc" "$DOMAIN" "$DMARC"
    if ! echo "$DMARC" | grep -qi "v=DMARC1"; then
        WRITE_FINDING "medium" "mail_dmarc_missing" "mail" "$DOMAIN" "DMARC record is missing" "No _dmarc TXT record found" "Publish a DMARC policy and monitoring address." "high" "dns"
    elif echo "$DMARC" | grep -qi "p=none"; then
        WRITE_FINDING "low" "mail_dmarc_monitor_only" "mail" "$DOMAIN" "DMARC policy is monitor-only" "$DMARC" "Move toward quarantine or reject once reports are reviewed." "medium" "dns"
    fi
    MTASTS="$(dig +short "_mta-sts.$DOMAIN" TXT +time=3 +tries=1 2>/dev/null)"
    TLSRPT="$(dig +short "_smtp._tls.$DOMAIN" TXT +time=3 +tries=1 2>/dev/null)"
    [[ -z "$MTASTS" ]] && WRITE_FINDING "low" "mail_mta_sts_missing" "mail" "$DOMAIN" "MTA-STS TXT record is missing" "No _mta-sts TXT record found" "Deploy MTA-STS if the domain receives mail." "medium" "dns"
    [[ -z "$TLSRPT" ]] && WRITE_FINDING "low" "mail_tls_rpt_missing" "mail" "$DOMAIN" "TLS-RPT TXT record is missing" "No _smtp._tls TXT record found" "Deploy TLS-RPT to receive SMTP TLS failure reports." "medium" "dns"
    for SELECTOR in default google selector1 selector2 k1 mail dkim; do
        DKIM="$(dig +short "${SELECTOR}._domainkey.$DOMAIN" TXT +time=2 +tries=1 2>/dev/null)"
        [[ -n "$DKIM" ]] && WRITE_EVIDENCE "mail_dkim_${SELECTOR}" "$DOMAIN" "$DKIM"
    done
}
PENTEST_HTTP_CHECK() {
    local DOMAIN="$1"
    local TARGETS_FILE="$2"
    local TARGET RESPONSE HEADERS URL SCHEME
    while IFS= read -r TARGET; do
        for SCHEME in https http; do
            URL="${SCHEME}://${TARGET}"
            RESPONSE="$(curl --silent --location --head --connect-timeout 4 --max-time 8 "$URL" 2>/dev/null || true)"
            [[ -z "$RESPONSE" ]] && continue
            WRITE_EVIDENCE "http_headers" "${SCHEME}_${TARGET}" "$RESPONSE"
            HEADERS="$(echo "$RESPONSE" | tr '[:upper:]' '[:lower:]')"
            [[ "$SCHEME" == "https" && "$HEADERS" != *"strict-transport-security:"* ]] &&
                WRITE_FINDING "medium" "http_hsts_missing" "http" "$TARGET" "HSTS header is missing" "$URL did not return Strict-Transport-Security" "Add HSTS after confirming HTTPS is enforced for the host." "medium" "http"
            [[ "$HEADERS" != *"content-security-policy:"* ]] &&
                WRITE_FINDING "low" "http_csp_missing" "http" "$TARGET" "Content-Security-Policy header is missing" "$URL did not return Content-Security-Policy" "Add a CSP appropriate for the application." "medium" "http"
            [[ "$HEADERS" != *"x-content-type-options:"* ]] &&
                WRITE_FINDING "low" "http_xcto_missing" "http" "$TARGET" "X-Content-Type-Options header is missing" "$URL did not return X-Content-Type-Options" "Set X-Content-Type-Options: nosniff." "medium" "http"
            echo "$RESPONSE" | grep -iq "^Server:" &&
                WRITE_FINDING "info" "http_server_header" "http" "$TARGET" "Server header is exposed" "$(echo "$RESPONSE" | grep -i '^Server:' | head -n1)" "Remove or minimize server version disclosure where possible." "medium" "http"
            break
        done
    done < <(PENTEST_EACH_TARGET "$TARGETS_FILE")
}
PENTEST_TLS_CHECK() {
    local DOMAIN="$1"
    local TARGETS_FILE="$2"
    local TARGET CERT_OUTPUT VERIFY EXPIRE_EPOCH NOW_EPOCH DAYS_LEFT NOT_AFTER
    IS_INSTALLED openssl || return 0
    while IFS= read -r TARGET; do
        CERT_OUTPUT="$(timeout 10 openssl s_client -servername "$TARGET" -connect "$TARGET:443" -verify_return_error </dev/null 2>&1 || true)"
        [[ -z "$CERT_OUTPUT" ]] && continue
        WRITE_EVIDENCE "tls_cert" "$TARGET" "$CERT_OUTPUT"
        VERIFY="$(echo "$CERT_OUTPUT" | grep -i 'Verify return code:' | tail -n1)"
        if [[ -n "$VERIFY" && "$VERIFY" != *"(0)"* ]]; then
            WRITE_FINDING "medium" "tls_verify_failed" "tls" "$TARGET" "TLS certificate verification failed" "$VERIFY" "Install a valid publicly trusted certificate chain for this hostname." "medium" "openssl"
        fi
        NOT_AFTER="$(echo "$CERT_OUTPUT" | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2- || true)"
        if [[ -n "$NOT_AFTER" ]]; then
            EXPIRE_EPOCH="$(date -d "$NOT_AFTER" +%s 2>/dev/null || true)"
            NOW_EPOCH="$(date +%s)"
            if [[ -n "$EXPIRE_EPOCH" ]]; then
                DAYS_LEFT=$(((EXPIRE_EPOCH - NOW_EPOCH) / 86400))
                if [[ "$DAYS_LEFT" -lt 0 ]]; then
                    WRITE_FINDING "high" "tls_cert_expired" "tls" "$TARGET" "TLS certificate is expired" "Certificate expired on $NOT_AFTER" "Renew and deploy a valid certificate." "high" "openssl"
                elif [[ "$DAYS_LEFT" -le 30 ]]; then
                    WRITE_FINDING "medium" "tls_cert_expiring" "tls" "$TARGET" "TLS certificate expires soon" "Certificate expires on $NOT_AFTER ($DAYS_LEFT days)" "Renew the certificate before expiry." "high" "openssl"
                fi
            fi
        fi
    done < <(PENTEST_EACH_TARGET "$TARGETS_FILE")
}
PENTEST_CLOUD_CHECK() {
    local DOMAIN="$1"
    local TARGETS_FILE="$2"
    local TARGET CNAME HEADERS EVIDENCE PROVIDER
    while IFS= read -r TARGET; do
        CNAME="$(dig +short "$TARGET" CNAME +time=2 +tries=1 2>/dev/null | tr '[:upper:]' '[:lower:]' | sed 's/\.$//' | head -n1)"
        HEADERS="$(curl --silent --head --connect-timeout 3 --max-time 6 "https://$TARGET" 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)"
        EVIDENCE="$CNAME"$'\n'"$HEADERS"
        PROVIDER=""
        [[ "$EVIDENCE" == *cloudflare* || "$EVIDENCE" == *cf-ray* ]] && PROVIDER="Cloudflare"
        [[ "$EVIDENCE" == *akamai* ]] && PROVIDER="Akamai"
        [[ "$EVIDENCE" == *fastly* ]] && PROVIDER="Fastly"
        [[ "$EVIDENCE" == *amazonaws* || "$EVIDENCE" == *cloudfront* ]] && PROVIDER="AWS"
        [[ "$EVIDENCE" == *azure* ]] && PROVIDER="Azure"
        [[ "$EVIDENCE" == *vercel* ]] && PROVIDER="Vercel"
        [[ "$EVIDENCE" == *netlify* ]] && PROVIDER="Netlify"
        if [[ -n "$PROVIDER" ]]; then
            WRITE_EVIDENCE "cloud_fingerprint" "$TARGET" "$EVIDENCE"
            WRITE_FINDING "info" "cloud_fingerprint" "cloud" "$TARGET" "Cloud/CDN provider fingerprinted" "Detected provider: $PROVIDER" "Use provider context to validate ownership and takeover risk." "medium" "dns,http"
        fi
    done < <(PENTEST_EACH_TARGET "$TARGETS_FILE")
}


# From scan.sh
SCAN_DOMAIN() {
    local TARGET_DOMAIN="$1"
    LOG "DEBUG" "Starting SCAN_DOMAIN for target: $TARGET_DOMAIN"
    if [[ -z "$OUTPUT" ]]; then
        mkdir -p "$DEFAULT_OUTPUT_DIR"
        OUTPUT="${DEFAULT_OUTPUT_DIR}/${TARGET_DOMAIN}.${OUTPUT_FORMAT:-txt}"
    else
        mkdir -p "$(dirname "$OUTPUT")"
    fi
    if [[ -d "$OUTPUT" ]]; then
        LOG "ERROR" "Output path is a directory: $OUTPUT"
        echo -e "${RED}${BOLD}[ERROR]${NC} Output path is a directory: $OUTPUT"
        exit 1
    fi
    local OUTPUT_EXISTS=false
    [[ -e "$OUTPUT" ]] && OUTPUT_EXISTS=true
    local OUTPUT_CHECK_FILE
    OUTPUT_CHECK_FILE="$(mktemp "$(dirname "$OUTPUT")/.deepdns-write-check.XXXXXX" 2>/dev/null)" || {
        LOG "ERROR" "Cannot write to output file: $OUTPUT"
        echo -e "${RED}${BOLD}[ERROR]${NC} Cannot write to output file: $OUTPUT"
        exit 1
    }
    rm -f "$OUTPUT_CHECK_FILE"
    echo -e "${BLUE}${BOLD}┌──────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}${BOLD}│${NC}                           ${UNDERLINE}${BOLD}Scan Configuration${NC}                             ${BLUE}${BOLD}│${NC}"
    echo -e "${BLUE}${BOLD}└──────────────────────────────────────────────────────────────────────────┘${NC}\n"
    echo -e " ${PURPLE}${BOLD}Target Domain${NC}    │ ${YELLOW}${BOLD}$TARGET_DOMAIN${NC} | ${GRAY}${DIM}$(date '+%Y-%m-%d %H:%M:%S')${NC}\n"
    local SCAN_MODES=""
    [[ "$PASSIVE_SCAN_ENABLED" == true ]] && SCAN_MODES+="${GREEN}${BOLD}Passive${NC} "
    [[ "$ACTIVE_SCAN_ENABLED" == true ]] && SCAN_MODES+="${GREEN}${BOLD}Active${NC} "
    [[ "$RECURSIVE_SCAN_ENABLED" == true ]] && SCAN_MODES+="${GREEN}${BOLD}Recursive(${RECURSIVE_DEPTH})${NC} "
    [[ "$VHOST_SCAN_ENABLED" == true ]] && SCAN_MODES+="${GREEN}${BOLD}VHost(${VHOST_PORTS[@]})${NC} "
    [[ "$PATTERN_RECOGNITION_ENABLED" == true ]] && SCAN_MODES+="${GREEN}${BOLD}Pattern${NC} "
    [[ "$ZONE_TRANSFER_ENABLED" == true ]] && SCAN_MODES+="${GREEN}${BOLD}ZoneTransfer${NC} "
    [[ "$DNSSEC_SCAN_ENABLED" == true ]] && SCAN_MODES+="${GREEN}${BOLD}DNSSEC${NC} "
    [[ "$PENTEST_SCAN_ENABLED" == true ]] && SCAN_MODES+="${GREEN}${BOLD}Pentest(${PENTEST_PROFILE})${NC} "
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
    local ZONE_OUT="$TEMP_DIR/${TARGET_DOMAIN}_zone_tmp.txt"
    local FINAL_TMP="$TEMP_DIR/${TARGET_DOMAIN}_final_tmp.txt"
    local REPORT_PREFIX="${OUTPUT%.*}"
    local PENTEST_TARGETS="$TEMP_DIR/${TARGET_DOMAIN}_pentest_targets.txt"
    if [[ "$RECURSIVE_SCAN_ENABLED" == true ]]; then
        echo -e "\n${CYAN}${BOLD}[RECURSIVE SCAN]${NC} Starting recursive enumeration (depth: $RECURSIVE_DEPTH)"
        RECURSIVE_SCAN "$TARGET_DOMAIN" "$RECURSIVE_DEPTH" "$FINAL_TMP"
    else
        [[ "$PASSIVE_SCAN_ENABLED" == true ]] && PASSIVE_SCAN "$TARGET_DOMAIN" "$PASSIVE_OUT"
        [[ "$ACTIVE_SCAN_ENABLED" == true ]] && ACTIVE_SCAN "$TARGET_DOMAIN" "$ACTIVE_OUT"
        [[ "$VHOST_SCAN_ENABLED" == true ]] && VHOST_SCAN "$TARGET_DOMAIN" "$VHOST_OUT"
        [[ "$PATTERN_RECOGNITION_ENABLED" == true ]] && DNS_PATTERN_RECOGNITION "$TARGET_DOMAIN" "$PATTERN_OUT"
        [[ "$ZONE_TRANSFER_ENABLED" == true ]] && DNS_ZONE_TRANSFER "$TARGET_DOMAIN" "$ZONE_OUT" "${REPORT_PREFIX}_zone_transfer.txt"
        [[ "$DNSSEC_SCAN_ENABLED" == true ]] && DNSSEC_SCAN "$TARGET_DOMAIN" "${REPORT_PREFIX}_dnssec.txt"
        find "$TEMP_DIR" -maxdepth 1 -type f -name "${TARGET_DOMAIN}_*_tmp.txt" -exec cat {} + 2>/dev/null | sort -u >"$FINAL_TMP"
    fi
    if [[ "$PENTEST_SCAN_ENABLED" == true ]]; then
        cp "$FINAL_TMP" "$PENTEST_TARGETS" 2>/dev/null || : >"$PENTEST_TARGETS"
        RUN_PENTEST_CHECKS "$TARGET_DOMAIN" "$PENTEST_TARGETS" "$REPORT_PREFIX"
    fi
    # Check if output file exists and prompt for overwrite
    if [[ "$OUTPUT_EXISTS" == true ]]; then
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
    local TOTAL=0
    local END_TIME
    local DURATION
    local DURATION_FORMATTED
    LOG "INFO" "Formatting results for $DOMAIN"
    if [[ "$RAW_OUTPUT" == true ]]; then
        if [[ -s "$OUTPUT_FILE" ]]; then
            sort -u "$OUTPUT_FILE" >"$TEMP_FILE"
            mv "$TEMP_FILE" "$OUTPUT_FILE"
            TOTAL=$(wc -l <"$OUTPUT_FILE")
            LOG "INFO" "Saved $TOTAL raw entries to $OUTPUT_FILE"
        else
            find "${TEMP_DIR}" -type f -name "*_results" -exec cat {} + | sort -u >"$OUTPUT_FILE"
            TOTAL=$(wc -l <"$OUTPUT_FILE")
            LOG "WARNING" "No direct results found, recovered $TOTAL entries from scan files"
        fi
    else
        {
            if [[ -s "$OUTPUT_FILE" ]]; then
                cat "$OUTPUT_FILE"
            fi
            find "${TEMP_DIR}" -type f -name "*_results" -exec cat {} + 2>/dev/null
        } | grep -Eh "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}($|:[0-9]+)" |
          sort -u |
          grep -v "^$DOMAIN$" >"$TEMP_FILE"
        TOTAL=$(wc -l <"$TEMP_FILE")
        WRITE_FORMATTED_OUTPUT "$TEMP_FILE" "$OUTPUT_FILE" "$OUTPUT_FORMAT" "$DOMAIN"
        LOG "INFO" "Saved $TOTAL unique domains to $OUTPUT_FILE"
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
    rm -f "$TEMP_FILE"
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




trap 'CLEANUP' SIGINT SIGTERM

# Setup initial state
CREATE_TEMP_DIR

if [ $# -eq 0 ]; then
    SHOW_HELP
    exit 1
fi

# Command line argument parsing
if [ $# -eq 1 ]; then
    case "${1,,}" in
        "install")
            INSTALL_SCRIPT
            exit $?
            ;;
        "update")
            UPDATE_SCRIPT
            exit $?
            ;;
        "uninstall")
            UNINSTALL_SCRIPT
            exit $?
            ;;
        "-h" | "--help")
            LOG "INFO" "SHOW_HELP"
            SHOW_HELP
            exit 0
            ;;
        "-v" | "--version")
            LOG "INFO" "SHOW VERSION"
            SHOW_VERSION
            exit 0
            ;;
        *)
            if VALIDATE_DOMAIN "$1"; then
                DOMAIN="$1"
                PASSIVE_SCAN_ENABLED=true
                ACTIVE_SCAN_ENABLED=true
                PATTERN_RECOGNITION_ENABLED=true
                VHOST_SCAN_ENABLED=true
                ZONE_TRANSFER_ENABLED=true
                DNSSEC_SCAN_ENABLED=true
                PENTEST_SCAN_ENABLED=true
                RECURSIVE_SCAN_ENABLED=false
            else
                LOG "INFO" "SHOW_HELP - INVALID argument"
                SHOW_HELP
                exit 1
            fi
            ;;
    esac
fi

while [[ "$#" -gt 0 ]]; do
    case $1 in
    -D | --debug)
        DEBUG=true
        if [[ "$2" != "" ]] && [[ ! "$2" =~ ^- ]]; then
            DEBUG_LOG="$2"
            shift
        fi
        ;;
    -V | --verbose)
        VERBOSE=true
        ;;
    -d | --domain)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Domain argument missing${NC}\n" && LOG "ERROR" "Domain argument missing" && exit 1
        DOMAIN="$2"
        shift
        ;;
    -w | --wordlist)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Wordlist argument missing${NC}\n" && LOG "ERROR" "Wordlist argument missing" && exit 1
        ! FILE_EXISTS "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Wordlist file not found: $2${NC}\n" && LOG "ERROR" "Wordlist file not found: $2" && exit 1
        ! IS_READABLE "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}File is not readable : $2${NC}\n" && LOG "ERROR" "Wordlist file not readable: $2" && exit 1
        WORDLIST_PATH="$2"
        shift
        ;;
    -o | --output)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Output file argument missing${NC}\n" && LOG "ERROR" "Output file argument missing" && exit 1
        OUTPUT="$2"
        shift
        ;;
    --format)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Output format missing${NC}\n" && LOG "ERROR" "Output format missing" && exit 1
        case "${2,,}" in
            txt | json | csv)
                OUTPUT_FORMAT="${2,,}"
                ;;
            *)
                echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid output format. Use: txt, json, or csv${NC}\n"
                LOG "ERROR" "Invalid output format: $2"
                exit 1
                ;;
        esac
        shift
        ;;
    -r | --recursive)
        RECURSIVE_SCAN_ENABLED=true
        RECURSIVE_DEPTH="$DEFAULT_RECURSIVE_DEPTH"
        if [[ -n "$2" && ! "$2" =~ ^- ]]; then
            ! IS_NUMBER "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid recursive depth: $2${NC}\n" && LOG "ERROR" "Invalid recursive depth: $2" && exit 1
            if [ "$2" -gt 0 ] && [ "$2" -lt 11 ]; then
                RECURSIVE_DEPTH="$2"
            else
                LOG "ERROR" "Recursive depth must be between 1 and 10"
                echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Recursive depth must be between 1 and 10${NC}\n"
                exit 1
            fi
            shift
        fi
        ;;
    -p | --passive)
        PASSIVE_SCAN_ENABLED=true
        ;;

    -a | --active)
        ACTIVE_SCAN_ENABLED=true
        ;;
    -R | --resolver)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Resolver file argument missing${NC}\n" && LOG "ERROR" "Resolver file argument missing" && exit 1
        ! FILE_EXISTS "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Resolver file not found: $2${NC}\n" && LOG "ERROR" "Resolver file not found: $2" && exit 1
        ! IS_READABLE "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}File is not readable : $2${NC}\n" && LOG "ERROR" "Resolver file not readable: $2" && exit 1
        FILE_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Resolver file is empty : $2${NC}\n" && LOG "ERROR" "Resolver file is empty: $2" && exit 1

        RESOLVER_SCAN=true
        RESOLVER_FILE="$2"
        shift
        ;;
    --st-key)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}SecurityTrails API key missing${NC}\n" && LOG "ERROR" "SecurityTrails API key missing" && exit 1
        ! VALIDATE_API_KEY "$2" "ST" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid SecurityTrails API key format${NC}\n" && LOG "ERROR" "Invalid SecurityTrails API key format" && exit 1
        SECURITYTRAILS_API_KEY="$2"
        PASSIVE_SCAN_ENABLED=true
        shift
        ;;
    --vt-key)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}VirusTotal API key missing${NC}\n" && LOG "ERROR" "VirusTotal API key missing" && exit 1
        VIRUSTOTAL_API_KEY="$2"
        PASSIVE_SCAN_ENABLED=true
        shift
        ;;
    --censys-id)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Censys API ID missing${NC}\n" && LOG "ERROR" "Censys API ID missing" && exit 1
        CENSYS_API_ID="$2"
        PASSIVE_SCAN_ENABLED=true
        shift
        ;;
    --censys-secret)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Censys API secret missing${NC}\n" && LOG "ERROR" "Censys API secret missing" && exit 1
        CENSYS_API_SECRET="$2"
        PASSIVE_SCAN_ENABLED=true
        shift
        ;;
    --vhost)
        VHOST_SCAN_ENABLED=true
        ;;
    --pattern)
        PATTERN_RECOGNITION_ENABLED=true
        ;;
    --zone-transfer)
        ZONE_TRANSFER_ENABLED=true
        ;;
    --dnssec)
        DNSSEC_SCAN_ENABLED=true
        ;;
    --pentest)
        PENTEST_SCAN_ENABLED=true
        ;;
    --profile)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Pentest profile missing${NC}\n" && LOG "ERROR" "Pentest profile missing" && exit 1
        case "${2,,}" in
            safe | balanced | aggressive)
                PENTEST_PROFILE="${2,,}"
                PENTEST_SCAN_ENABLED=true
                ;;
            *)
                echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid pentest profile. Use: safe, balanced, or aggressive${NC}\n"
                LOG "ERROR" "Invalid pentest profile: $2"
                exit 1
                ;;
        esac
        shift
        ;;
    --checks)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Pentest checks list missing${NC}\n" && LOG "ERROR" "Pentest checks list missing" && exit 1
        PENTEST_CHECKS="${2,,}"
        PENTEST_SCAN_ENABLED=true
        shift
        ;;
    --evidence-dir)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Evidence directory missing${NC}\n" && LOG "ERROR" "Evidence directory missing" && exit 1
        PENTEST_EVIDENCE_DIR="$2"
        PENTEST_SCAN_ENABLED=true
        shift
        ;;
    --vhost-port)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Port list missing${NC}\n" && LOG "ERROR" "Port list missing" && exit 1
        # Remove duplicate ports using sort -u
        VHOST_PORTS=($(echo "$2" | tr ',' '\n' | sort -un | tr '\n' ' '))
        # Validate ports
        for port in "${VHOST_PORTS[@]}"; do
            if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
                echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid port number: $port${NC}\n"
                LOG "ERROR" "Invalid port number: $port"
                exit 1
            fi
        done
        LOG "DEBUG" "Using unique ports: ${VHOST_PORTS[*]}"
        shift
        ;;
    --vhost-filter)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Filter argument missing${NC}\n" && LOG "ERROR" "Filter argument missing" && exit 1
        # Remove duplicate filters
        VHOST_FILTER=$(echo "$2" | tr ',' '\n' | sort -u | tr '\n' ',' | sed 's/,$//')
        LOG "DEBUG" "Using unique filters: $VHOST_FILTER"
        shift
        ;;
    --vhost-filter-type)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Filter type argument missing${NC}\n" && LOG "ERROR" "Filter type argument missing" && exit 1
        case "${2,,}" in
            "status"|"size"|"words"|"lines")
                VHOST_FILTER_TYPE="$2"
                ;;
            *)
                echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid filter type. Use: status, size, words, or lines${NC}\n"
                LOG "ERROR" "Invalid filter type: $2"
                exit 1
                ;;
        esac
        shift
        ;;
    --vhost-filter-value)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Filter value argument missing${NC}\n" && LOG "ERROR" "Filter value argument missing" && exit 1
        VHOST_FILTER=$(echo "$2" | tr ',' '\n' | sort -u | tr '\n' ',' | sed 's/,$//')
        LOG "DEBUG" "Using unique filters: $VHOST_FILTER"
        shift
        ;;
    -t | --threads)
        IS_EMPTY "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Thread count missing${NC}\n" && LOG "ERROR" "Thread count missing" && exit 1
        ! IS_NUMBER "$2" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid thread count: $2${NC}\n" && LOG "ERROR" "Invalid thread count: $2" && exit 1
        if [ "$2" -gt 0 ] && [ "$2" -le 100 ]; then
            THREAD_COUNT="$2"
        else
            LOG "ERROR" "Thread count must be between 1 and 50"
            echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Thread count must be between 1 and 50${NC}\n"
            exit 1
        fi
        shift
        ;;
    --raw)
        RAW_OUTPUT=true
        ;;
    *)
        ! VALIDATE_DOMAIN "$1" && echo -e "\n${RED}${BOLD}[ERROR]${NC} ${BOLD}Invalid domain: $1${NC}\n" && LOG "ERROR" "Invalid domain: $1" && exit 1
        DOMAIN="$1"
        ;;
    esac
    shift
done

# Main execution
if [ "$DEBUG" = true ]; then
    # Ensure log directory exists
    mkdir -p "$(dirname "$DEBUG_LOG")"

    if [[ -f "$DEBUG_LOG" ]]; then
        rm -f "$DEBUG_LOG" || {
            echo -e "\n${RED}${BOLD}[ERROR]${NC} Unable to remove log file: $DEBUG_LOG"
            exit 1
            CLEANUP
        }
    fi

    touch "$DEBUG_LOG" || {
        echo -e "\n${RED}${BOLD}[ERROR]${NC} Unable to create log file: $DEBUG_LOG"
        exit 1
    }
fi

# Modify the main scanning section to include interrupt checks:
if [[ -n "$DOMAIN" ]]; then
    SCAN_DOMAIN "$DOMAIN" || {
        echo -e "\n${RED}${BOLD}[ERROR]${NC} Scan failed for domain: $DOMAIN"
        exit 1
    }
fi

FORMAT_RESULTS "$DOMAIN" "$OUTPUT"
exit $?

