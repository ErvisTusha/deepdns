#!/usr/bin/env bash

set -o pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "${TEST_DIR}/../.." >/dev/null 2>&1 && pwd)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/deepdns-tests.XXXXXX")"

PASS_COUNT=0
FAIL_COUNT=0
TEST_CASE_DIR=""

cleanup() {
    rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

export HOME="$TEST_ROOT/home"
mkdir -p "$HOME"

source "$REPO_ROOT/dev/vendor/bashframe.sh"
source "$REPO_ROOT/dev/config/settings.sh"
source "$REPO_ROOT/dev/lib/core.sh"
source "$REPO_ROOT/dev/lib/utils.sh"
source "$REPO_ROOT/dev/lib/validation.sh"
source "$REPO_ROOT/dev/lib/dns.sh"
source "$REPO_ROOT/dev/lib/passive.sh"
source "$REPO_ROOT/dev/lib/active.sh"
source "$REPO_ROOT/dev/lib/pentest.sh"
source "$REPO_ROOT/dev/lib/scan.sh"

TEMP_DIR="$TEST_ROOT/tmp"
mkdir -p "$TEMP_DIR"
DEBUG=false
VERBOSE=false
RAW_OUTPUT=false
START_TIME="$(date +%s)"

pass() {
    printf "ok - %s\n" "$1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
    local NAME="$1"
    local DETAILS="$2"

    printf "not ok - %s\n" "$NAME"
    if [[ -n "$DETAILS" ]]; then
        printf "%s\n" "$DETAILS" | sed 's/^/  /'
    fi
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

run_test() {
    local NAME="$1"
    shift
    local SAFE_NAME="${NAME//[^a-zA-Z0-9_]/_}"
    local OUTPUT

    TEST_CASE_DIR="$TEST_ROOT/cases/$SAFE_NAME"
    mkdir -p "$TEST_CASE_DIR"

    if OUTPUT="$("$@" 2>&1)"; then
        pass "$NAME"
    else
        fail "$NAME" "$OUTPUT"
    fi
}

assert_success() {
    local OUTPUT

    if OUTPUT="$("$@" 2>&1)"; then
        return 0
    fi

    printf "expected success: %s\nstatus output: %s\n" "$*" "$OUTPUT"
    return 1
}

assert_failure() {
    if "$@" >/dev/null 2>&1; then
        printf "expected failure: %s\n" "$*"
        return 1
    fi

    return 0
}

assert_eq() {
    local EXPECTED="$1"
    local ACTUAL="$2"

    if [[ "$EXPECTED" == "$ACTUAL" ]]; then
        return 0
    fi

    printf "expected: <%s>\nactual:   <%s>\n" "$EXPECTED" "$ACTUAL"
    return 1
}

assert_file_equals() {
    local FILE="$1"
    local EXPECTED="$2"
    local ACTUAL

    ACTUAL="$(cat "$FILE")"
    assert_eq "$EXPECTED" "$ACTUAL"
}

test_val_ip_accepts_valid_ipv4() {
    assert_success VAL_IP "0.0.0.0" &&
        assert_success VAL_IP "192.168.1.1" &&
        assert_success VAL_IP "255.255.255.255"
}

test_val_ip_rejects_invalid_ipv4() {
    assert_failure VAL_IP "256.1.1.1" &&
        assert_failure VAL_IP "1.2.3" &&
        assert_failure VAL_IP "1.2.3.4.5" &&
        assert_failure VAL_IP "one.two.three.four"
}

test_validate_domain_accepts_domain_names() {
    assert_success VALIDATE_DOMAIN "example.com" &&
        assert_success VALIDATE_DOMAIN "sub.example.co.uk" &&
        assert_success VALIDATE_DOMAIN "EXAMPLE.io"
}

test_validate_domain_rejects_bad_domain_names() {
    assert_failure VALIDATE_DOMAIN "localhost" &&
        assert_failure VALIDATE_DOMAIN "example" &&
        assert_failure VALIDATE_DOMAIN "example.123" &&
        assert_failure VALIDATE_DOMAIN "bad domain.com"
}

test_validate_api_key_enforces_known_formats() {
    local ST_KEY
    local INVALID_ST_KEY
    local VT_KEY
    local CENSYS_KEY

    ST_KEY="$(printf 'A%.0s' {1..32})"
    INVALID_ST_KEY="$(printf 'A%.0s' {1..31})!"
    VT_KEY="$(printf 'B%.0s' {1..64})"
    CENSYS_KEY="$(printf 'c%.0s' {1..30})_1"
    API_VALIDATION_ENABLED=true

    assert_success VALIDATE_API_KEY "$ST_KEY" "ST" &&
        assert_failure VALIDATE_API_KEY "$INVALID_ST_KEY" "ST" &&
        assert_success VALIDATE_API_KEY "$VT_KEY" "VT" &&
        assert_failure VALIDATE_API_KEY "short" "VT" &&
        assert_success VALIDATE_API_KEY "$CENSYS_KEY" "CENSYS" &&
        assert_failure VALIDATE_API_KEY "$ST_KEY" "UNKNOWN"
}

test_validate_api_key_can_be_disabled() {
    API_VALIDATION_ENABLED=false
    assert_success VALIDATE_API_KEY "not-a-real-key" "ST"
    local STATUS=$?
    API_VALIDATION_ENABLED=true
    return "$STATUS"
}

test_utility_predicates() {
    local EMPTY_FILE="$TEST_CASE_DIR/empty.txt"
    local NONEMPTY_FILE="$TEST_CASE_DIR/nonempty.txt"
    local MISSING_FILE="$TEST_CASE_DIR/missing.txt"

    : >"$EMPTY_FILE"
    printf "content\n" >"$NONEMPTY_FILE"

    assert_success FILE_EMPTY "$EMPTY_FILE" &&
        assert_failure FILE_EMPTY "$NONEMPTY_FILE" &&
        assert_success FILE_EXISTS "$NONEMPTY_FILE" &&
        assert_failure FILE_EXISTS "$MISSING_FILE" &&
        assert_success IS_READABLE "$NONEMPTY_FILE" &&
        assert_success IS_WRITABLE "$NONEMPTY_FILE"
}

test_value_predicates() {
    assert_success IS_EMPTY "" &&
        assert_failure IS_EMPTY "value" &&
        assert_success IS_NUMBER "0" &&
        assert_success IS_NUMBER "42" &&
        assert_failure IS_NUMBER "-1" &&
        assert_failure IS_NUMBER "12a" &&
        assert_failure IS_NUMBER ""
}

test_update_resolver_health_clamps_bounds() {
    RESOLVER_HEALTH=()

    UPDATE_RESOLVER_HEALTH "1.1.1.1" 0
    assert_eq "100" "${RESOLVER_HEALTH["1.1.1.1"]}" &&
        RESOLVER_HEALTH["8.8.8.8"]=10 &&
        UPDATE_RESOLVER_HEALTH "8.8.8.8" 1 &&
        assert_eq "0" "${RESOLVER_HEALTH["8.8.8.8"]}" &&
        RESOLVER_HEALTH["9.9.9.9"]=98 &&
        UPDATE_RESOLVER_HEALTH "9.9.9.9" 0 &&
        assert_eq "100" "${RESOLVER_HEALTH["9.9.9.9"]}" &&
        RESOLVER_HEALTH["4.4.4.4"]=50 &&
        UPDATE_RESOLVER_HEALTH "4.4.4.4" 1 &&
        assert_eq "30" "${RESOLVER_HEALTH["4.4.4.4"]}"
}

test_select_resolver_uses_first_healthy_resolver() {
    RESOLVERS=("1.1.1.1" "8.8.8.8" "9.9.9.9")
    RESOLVER_HEALTH=()
    RESOLVER_LAST_USED=()

    local CHOSEN
    CHOSEN="$(SELECT_RESOLVER)"
    assert_eq "1.1.1.1" "$CHOSEN"
}

test_select_resolver_resets_first_resolver_when_all_unhealthy() {
    RESOLVERS=("1.1.1.1" "8.8.8.8")
    RESOLVER_HEALTH=()
    RESOLVER_LAST_USED=()
    RESOLVER_HEALTH["1.1.1.1"]=10
    RESOLVER_HEALTH["8.8.8.8"]=20

    local CHOSEN
    local CHOSEN_FILE="$TEST_CASE_DIR/chosen.txt"
    SELECT_RESOLVER >"$CHOSEN_FILE"
    CHOSEN="$(cat "$CHOSEN_FILE")"
    assert_eq "1.1.1.1" "$CHOSEN" &&
        assert_eq "100" "${RESOLVER_HEALTH["1.1.1.1"]}"
}

test_select_resolver_persists_last_used_without_subshell() {
    RESOLVERS=("1.1.1.1")
    RESOLVER_HEALTH=()
    RESOLVER_LAST_USED=()
    SELECTED_RESOLVER=""

    SELECT_RESOLVER >/dev/null

    [[ "$SELECTED_RESOLVER" == "1.1.1.1" ]] &&
        [[ -n "${RESOLVER_LAST_USED["1.1.1.1"]}" ]]
}

test_normalize_passive_results_expands_labels_and_wildcards() {
    local ACTUAL
    ACTUAL="$(printf "%s\n" "www" "*.api.example.com" "bad value" "cdn.example.com" "shorturl.at" | NORMALIZE_PASSIVE_RESULTS "example.com")"

    assert_eq $'api.example.com\ncdn.example.com\nwww.example.com' "$ACTUAL"
}

test_dns_output_has_record_ignores_question_section() {
    local OUTPUT=$';vulnweb.com. IN DNSKEY\nvulnweb.com. 900 IN SOA ns.example.com. hostmaster.example.com. 1 2 3 4 5'

    assert_failure DNS_OUTPUT_HAS_RECORD "$OUTPUT" "DNSKEY"
}

test_dns_output_has_record_accepts_answer_section() {
    local OUTPUT=$'example.com. 300 IN DNSKEY 256 3 13 abcdef\n;example.com. IN DNSKEY'

    assert_success DNS_OUTPUT_HAS_RECORD "$OUTPUT" "DNSKEY"
}

test_size_filter_ignores_missing_content_length() {
    local SIZE="-"
    local FILTER="<100"
    local VAL=${FILTER#<}

    if [[ "$SIZE" =~ ^[0-9]+$ && "$SIZE" -lt "$VAL" ]]; then
        return 1
    fi

    return 0
}

test_format_results_filters_sorts_and_deduplicates() {
    TEMP_DIR="$TEST_CASE_DIR/temp"
    RAW_OUTPUT=false
    mkdir -p "$TEMP_DIR"

    local OUTPUT_FILE="$TEST_CASE_DIR/results.txt"
    printf "%s\n" \
        "www.example.com" \
        "example.com" \
        "invalid" \
        "api.example.com" \
        "api.example.com" \
        "https://bad.example.com" \
        "admin.example.com:8443" >"$OUTPUT_FILE"
    printf "%s\n" "dev.example.com" "www.example.com" >"$TEMP_DIR/extra_results"

    FORMAT_RESULTS "example.com" "$OUTPUT_FILE" >/dev/null

    assert_file_equals "$OUTPUT_FILE" $'admin.example.com:8443\napi.example.com\ndev.example.com\nwww.example.com'
}

test_format_results_raw_mode_only_sorts_and_deduplicates() {
    TEMP_DIR="$TEST_CASE_DIR/temp"
    RAW_OUTPUT=true
    mkdir -p "$TEMP_DIR"

    local OUTPUT_FILE="$TEST_CASE_DIR/raw-results.txt"
    printf "%s\n" "b.example.com" "a.example.com" "b.example.com" >"$OUTPUT_FILE"

    FORMAT_RESULTS "example.com" "$OUTPUT_FILE" >/dev/null
    local STATUS=$?
    RAW_OUTPUT=false

    [[ $STATUS -eq 0 ]] &&
        assert_file_equals "$OUTPUT_FILE" $'a.example.com\nb.example.com'
}

test_write_formatted_output_json() {
    local INPUT_FILE="$TEST_CASE_DIR/input.txt"
    local OUTPUT_FILE="$TEST_CASE_DIR/output.json"
    printf "%s\n" "api.example.com" "www.example.com" >"$INPUT_FILE"

    WRITE_FORMATTED_OUTPUT "$INPUT_FILE" "$OUTPUT_FILE" "json" "example.com"

    assert_file_equals "$OUTPUT_FILE" $'{\n  "domain": "example.com",\n  "subdomains": [\n    "api.example.com",\n    "www.example.com"\n  ]\n}'
}

test_write_formatted_output_csv() {
    local INPUT_FILE="$TEST_CASE_DIR/input.txt"
    local OUTPUT_FILE="$TEST_CASE_DIR/output.csv"
    printf "%s\n" "api.example.com" "www.example.com" >"$INPUT_FILE"

    WRITE_FORMATTED_OUTPUT "$INPUT_FILE" "$OUTPUT_FILE" "csv" "example.com"

    assert_file_equals "$OUTPUT_FILE" $'domain,subdomain\n"example.com","api.example.com"\n"example.com","www.example.com"'
}

test_verify_release_signature_skips_when_unconfigured() {
    RELEASE_SIGNATURE_REQUIRED=false
    RELEASE_SIGNING_FINGERPRINT=""

    VERIFY_RELEASE_SIGNATURE "$TEST_CASE_DIR/missing.sh" "$TEST_CASE_DIR/missing.asc" "" ""
}

test_pentest_profile_check_selection() {
    PENTEST_PROFILE="safe"
    assert_success PENTEST_CHECK_ENABLED takeover &&
        assert_success PENTEST_CHECK_ENABLED mail &&
        assert_failure PENTEST_CHECK_ENABLED cloud &&
        PENTEST_PROFILE="balanced" &&
        assert_success PENTEST_CHECK_ENABLED cloud
}

test_pentest_explicit_checks_override_profile() {
    PENTEST_PROFILE="balanced"
    PENTEST_CHECKS="mail,tls"
    assert_success PENTEST_CHECK_ENABLED mail &&
        assert_success PENTEST_CHECK_ENABLED tls &&
        assert_failure PENTEST_CHECK_ENABLED takeover
    local STATUS=$?
    PENTEST_CHECKS=""
    return "$STATUS"
}

test_pentest_takeover_provider_matches_common_services() {
    assert_eq "aws-s3" "$(PENTEST_TAKEOVER_PROVIDER "bucket.s3.amazonaws.com")" &&
        assert_eq "github-pages" "$(PENTEST_TAKEOVER_PROVIDER "user.github.io")" &&
        assert_eq "vercel" "$(PENTEST_TAKEOVER_PROVIDER "site.vercel.app")"
}

test_write_finding_json_outputs_valid_shape() {
    local OUTPUT_BASE="$TEST_CASE_DIR/findings"
    OUTPUT_FORMAT="json"
    INIT_FINDINGS "$OUTPUT_BASE" "$OUTPUT_FORMAT"
    WRITE_FINDING "medium" "check_id" "dns" "example.com" "Title" "Evidence" "Fix it" "high" "unit"
    FINALIZE_FINDINGS
    OUTPUT_FORMAT="txt"

    grep -q '"severity":"medium"' "${OUTPUT_BASE}_findings.json" &&
        grep -q '"check_id":"check_id"' "${OUTPUT_BASE}_findings.json" &&
        grep -q '^\[$' "${OUTPUT_BASE}_findings.json" &&
        grep -q '^\]$' "${OUTPUT_BASE}_findings.json"
}

test_write_finding_json_handles_multiple_findings() {
    local OUTPUT_BASE="$TEST_CASE_DIR/findings"
    OUTPUT_FORMAT="json"
    INIT_FINDINGS "$OUTPUT_BASE" "$OUTPUT_FORMAT"
    WRITE_FINDING "low" "one" "dns" "a.example.com" "One" "Evidence" "Fix" "medium" "unit"
    WRITE_FINDING "high" "two" "dns" "b.example.com" "Two" "Evidence" "Fix" "high" "unit"
    FINALIZE_FINDINGS
    OUTPUT_FORMAT="txt"

    grep -q '"check_id":"one"' "${OUTPUT_BASE}_findings.json" &&
        grep -q '"check_id":"two"' "${OUTPUT_BASE}_findings.json" &&
        grep -q '},$' "${OUTPUT_BASE}_findings.json"
}

test_write_evidence_sanitizes_filename() {
    PENTEST_EVIDENCE_DIR="$TEST_CASE_DIR/evidence"
    PENTEST_RAW_EVIDENCE=true
    WRITE_EVIDENCE "http" "https://api.example.com:443" "headers"

    compgen -G "$PENTEST_EVIDENCE_DIR/http_*.txt" >/dev/null
}

test_ask_user_yes_no_handling() {
    printf 'y\n' | ASK_USER "Continue?" >/dev/null
    local YES_STATUS=$?
    printf 'n\n' | ASK_USER "Continue?" >/dev/null
    local NO_STATUS=$?

    [[ $YES_STATUS -eq 0 ]] && [[ $NO_STATUS -ne 0 ]]
}

test_generate_random_mixed_output() {
    local VALUE
    VALUE="$(GENERATE_RANDOM 16 mixed)"

    [[ ${#VALUE} -eq 16 ]] && [[ "$VALUE" =~ ^[A-Za-z0-9]+$ ]]
}

test_download_rejects_missing_url() {
    assert_failure DOWNLOAD "" "$TEST_CASE_DIR/out.txt"
}

test_download_rejects_unwritable_destination() {
    assert_failure DOWNLOAD "https://example.com/file.txt" "$TEST_CASE_DIR/missing/out.txt"
}

run_test "VAL_IP accepts valid IPv4 addresses" test_val_ip_accepts_valid_ipv4
run_test "VAL_IP rejects invalid IPv4 addresses" test_val_ip_rejects_invalid_ipv4
run_test "VALIDATE_DOMAIN accepts domain names" test_validate_domain_accepts_domain_names
run_test "VALIDATE_DOMAIN rejects bad domain names" test_validate_domain_rejects_bad_domain_names
run_test "VALIDATE_API_KEY enforces known formats" test_validate_api_key_enforces_known_formats
run_test "VALIDATE_API_KEY can be disabled" test_validate_api_key_can_be_disabled
run_test "utility file predicates work" test_utility_predicates
run_test "value predicates work" test_value_predicates
run_test "UPDATE_RESOLVER_HEALTH clamps bounds" test_update_resolver_health_clamps_bounds
run_test "SELECT_RESOLVER uses first healthy resolver" test_select_resolver_uses_first_healthy_resolver
run_test "SELECT_RESOLVER resets first resolver when all unhealthy" test_select_resolver_resets_first_resolver_when_all_unhealthy
run_test "SELECT_RESOLVER persists state without subshell" test_select_resolver_persists_last_used_without_subshell
run_test "NORMALIZE_PASSIVE_RESULTS expands labels and wildcards" test_normalize_passive_results_expands_labels_and_wildcards
run_test "DNS_OUTPUT_HAS_RECORD ignores question section" test_dns_output_has_record_ignores_question_section
run_test "DNS_OUTPUT_HAS_RECORD accepts answer section" test_dns_output_has_record_accepts_answer_section
run_test "VHOST size filter ignores missing content length" test_size_filter_ignores_missing_content_length
run_test "FORMAT_RESULTS filters, sorts, and deduplicates" test_format_results_filters_sorts_and_deduplicates
run_test "FORMAT_RESULTS raw mode sorts and deduplicates" test_format_results_raw_mode_only_sorts_and_deduplicates
run_test "WRITE_FORMATTED_OUTPUT writes JSON" test_write_formatted_output_json
run_test "WRITE_FORMATTED_OUTPUT writes CSV" test_write_formatted_output_csv
run_test "VERIFY_RELEASE_SIGNATURE skips when unconfigured" test_verify_release_signature_skips_when_unconfigured
run_test "PENTEST profile check selection works" test_pentest_profile_check_selection
run_test "PENTEST explicit checks override profile" test_pentest_explicit_checks_override_profile
run_test "PENTEST takeover provider matches common services" test_pentest_takeover_provider_matches_common_services
run_test "WRITE_FINDING writes JSON findings" test_write_finding_json_outputs_valid_shape
run_test "WRITE_FINDING handles multiple JSON findings" test_write_finding_json_handles_multiple_findings
run_test "WRITE_EVIDENCE sanitizes filenames" test_write_evidence_sanitizes_filename
run_test "ASK_USER handles yes and no answers" test_ask_user_yes_no_handling
run_test "GENERATE_RANDOM produces mixed output" test_generate_random_mixed_output
run_test "DOWNLOAD rejects missing URL" test_download_rejects_missing_url
run_test "DOWNLOAD rejects unwritable destination" test_download_rejects_unwritable_destination

printf "\n%d passed, %d failed\n" "$PASS_COUNT" "$FAIL_COUNT"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
