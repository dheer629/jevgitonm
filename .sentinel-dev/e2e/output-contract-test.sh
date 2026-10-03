#!/usr/bin/env bash
# Offline regression tests; function overrides stay inside subshells.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
source "$ROOT/KubeOps_Sentinel.sh"
command -v jq >/dev/null 2>&1 || { printf 'Required regression dependency missing: jq\n' >&2; exit 2; }
test_dir=$(mktemp -d)
trap 'rm -rf -- "$test_dir"' EXIT
printf 'header\nscope\nreport body\n' > "$test_dir/report"
mkdir "$test_dir/runtime"
passed=0 failed=0

run_case() {
    local name=$1
    shift
    if ( "$@" ); then
        printf 'PASS %s\n' "$name"
        ((passed+=1))
    else
        printf 'FAIL %s\n' "$name" >&2
        ((failed+=1))
    fi
}
expect_status() {
    [[ $1 == "$2" ]] || { printf 'Expected exit %s, observed %s\n' "$2" "$1" >&2; return 1; }
}
expect_empty_output() {
    [[ ! -s $test_dir/out ]] || { printf 'Unexpected report output:\n' >&2; command cat "$test_dir/out" >&2; return 1; }
}
fixture_runtime() {
    dependency_detect() { :; }
    init_runtime() { RUN_DIR=$test_dir/runtime; }
    bootstrap_scope() { :; }
    log_audit() { :; }
    SENTINEL_CONTEXT=fixture-context SENTINEL_NAMESPACE=fixture-namespace
    fixture_report() { printf 'fixture report body\n'; return "$collector_status"; }
    health_report() { fixture_report; }
    resources_report() { fixture_report; }
    gitops_report() { fixture_report; }
    certificates_report() { fixture_report; }
    triage_report() { fixture_report; }
    triage_workload_report() { fixture_report; }
    capabilities_report() { fixture_report; }
    doctor_report() { fixture_report; }
}
missing_jq_emitter() {
    has() { [[ $1 != jq ]] && command -v "$1" >/dev/null 2>&1; }
    local rc=0
    json_report_emit "$test_dir/report" fixture 0 > "$test_dir/out" 2> "$test_dir/err" || rc=$?
    expect_status "$rc" 2 || return
    expect_empty_output
}
missing_jq_preflight() {
    dependency_detect() { :; }
    has() { [[ $1 != jq ]] && command -v "$1" >/dev/null 2>&1; }
    init_runtime() { printf 'UNEXPECTED RUNTIME\n'; return 99; }
    bootstrap_scope() { printf 'UNEXPECTED BOOTSTRAP\n'; return 99; }
    local rc=0
    main --health --json > "$test_dir/out" 2> "$test_dir/err" || rc=$?
    expect_status "$rc" 2 || return
    expect_empty_output
}
unsupported_json_mode() {
    dependency_detect() { :; }
    init_runtime() { printf 'UNEXPECTED RUNTIME\n'; return 99; }
    local rc=0
    main "$@" --json > "$test_dir/out" 2> "$test_dir/err" || rc=$?
    expect_status "$rc" 2 || return
    expect_empty_output
}
json_report_status() {
    local collector_status=$1 rc=0
    shift
    fixture_runtime
    main "$@" --json > "$test_dir/out" 2> "$test_dir/err" || rc=$?
    expect_status "$rc" "$collector_status" || return
    command jq -es --argjson status "$collector_status" '
        length == 1 and (.[0] |
            .application == "KubeOps Sentinel" and
            .context == "fixture-context" and .namespace == "fixture-namespace" and
            .exit_status == $status and .lines == ["fixture report body", ""])
    ' "$test_dir/out" >/dev/null
}
text_report_status() {
    local collector_status=$1 format=$2 rc=0
    fixture_runtime
    local -a args=(--health)
    [[ $format != quiet ]] || args+=(--quiet)
    main "${args[@]}" > "$test_dir/out" 2> "$test_dir/err" || rc=$?
    expect_status "$rc" "$collector_status" || return
    if [[ $format == quiet ]]; then
        [[ $(< "$test_dir/out") == 'fixture report body' ]]
    else
        command grep -q '^Health | ' "$test_dir/out" &&
            command grep -qx 'fixture report body' "$test_dir/out"
    fi
}
emitter_failure() {
    local collector_status=$1 format=$2 rc=0
    fixture_runtime
    local -a args=(--health)
    case $format in
        json) args+=(--json); jq() { return 7; };;
        json-input) args+=(--json); tail() { return 7; };;
        quiet) args+=(--quiet); tail() { return 7; };;
        text) cat() { return 7; };;
    esac
    main "${args[@]}" > "$test_dir/out" 2> "$test_dir/err" || rc=$?
    expect_status "$rc" 2
}
capture_write_failure() {
    local collector_status=0 rc=0
    fixture_runtime
    redact() { printf 'partial report\n'; return 73; }
    main --health > "$test_dir/out" 2> "$test_dir/err" || rc=$?
    expect_status "$rc" 2 || return
    expect_empty_output
}
capture_allocation_failure() {
    local collector_status=0 rc=0
    fixture_runtime
    CURRENT_REPORT=$test_dir/report
    mktemp() { return 1; }
    main --health > "$test_dir/out" 2> "$test_dir/err" || rc=$?
    expect_status "$rc" 2 || return
    expect_empty_output
}

run_case 'JSON emitter requires jq and emits no fallback' missing_jq_emitter
run_case 'JSON preflight rejects missing jq before runtime and bootstrap' missing_jq_preflight
run_case 'JSON rejects dashboard mode before runtime' unsupported_json_mode
run_case 'JSON rejects developer mode before runtime' unsupported_json_mode --dev-self-test
run_case 'JSON rejects evidence mode before runtime' unsupported_json_mode --evidence fixture
for mode in health resources gitops certificates triage triage-workload capabilities doctor; do
    args=("--$mode")
    [[ $mode != triage-workload ]] || args+=(Deployment/fixture)
    for status in 0 1 3 4; do
        run_case "$mode JSON preserves collector status $status" json_report_status "$status" "${args[@]}"
    done
done
for format in text quiet; do
    for status in 0 1 3 4; do
        run_case "$format preserves collector status $status" text_report_status "$status" "$format"
    done
done
for format in json json-input quiet text; do
    for status in 0 1; do
        run_case "$format emission failure overrides collector status $status" emitter_failure "$status" "$format"
    done
done
run_case 'Capture write failure discards partial output and exits 2' capture_write_failure
run_case 'Capture allocation failure cannot emit a previous report' capture_allocation_failure
printf 'OUTPUT CONTRACT: %s/%s PASS\n' "$passed" "$((passed+failed))"
((failed==0))
