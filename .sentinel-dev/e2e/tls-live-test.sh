#!/usr/bin/env bash
set -o pipefail
ROOT=$(git rev-parse --show-toplevel 2>/dev/null || { cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P; })
cd -- "$ROOT"
source ./KubeOps_Sentinel.sh
umask 077
mkdir -p -- "$PWD/sentinel-output/validation"
RUN_DIR=$(mktemp -d "$PWD/sentinel-output/validation/.tls-live.XXXXXXXX") || exit 1
CACHE_DIR=$RUN_DIR/cache
mkdir "$CACHE_DIR"
SENTINEL_CONTEXT=local-fixture SENTINEL_NAMESPACE=sentinel-validation
CERT_WARN_DAYS=90 CERT_CRIT_DAYS=30 TLS_TIMEOUT=2
report="$PWD/sentinel-output/validation/tls-gitops-e2e.md"
server_pid='' stall_pid=''
finish() {
    [[ -n $server_pid ]] && kill "$server_pid" 2>/dev/null
    [[ -n $stall_pid ]] && kill "$stall_pid" 2>/dev/null
    [[ -n $server_pid ]] && wait "$server_pid" 2>/dev/null
    [[ -n $stall_pid ]] && wait "$stall_pid" 2>/dev/null
    rm -rf -- "$RUN_DIR"
}
trap finish EXIT
printf '# Actual TLS and GitOps validation\n\nDate: %s\n\nEnvironment: %s; %s. Source: `KubeOps_Sentinel.sh`.\n\n' "$(date -u +%FT%TZ)" "$(uname -sr)" "$(openssl version)" > "$report"
printf '| Case | Actual input | Expected | Observed | Result |\n|---|---|---|---|---|\n' >> "$report"
failures=0
record() {
    local title=$1 input=$2 expected=$3 actual=$4 status=PASS
    [[ "$expected" == "$actual" ]] || { status=FAIL; ((failures+=1)); }
    printf '| %s | %s | %s | %s | %s |\n' "$title" "$input" "$expected" "$actual" "$status" >> "$report"
}
openssl req -x509 -newkey rsa:2048 -nodes -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' -days 10 -keyout "$RUN_DIR/key.pem" -out "$RUN_DIR/valid.pem" >/dev/null 2>&1 || exit 2
openssl x509 -in "$RUN_DIR/valid.pem" -signkey "$RUN_DIR/key.pem" -days 0 -out "$RUN_DIR/expired.pem" 2>/dev/null || exit 3
sleep 1  # OpenSSL 3.5 rejects negative -days; 0 days yields an immediately expired leaf.
port=$((30000+RANDOM%20000))
while nc -z 127.0.0.1 "$port" 2>/dev/null; do ((port+=1)); done
start_server() {
    [[ -n $server_pid ]] && { kill "$server_pid" 2>/dev/null; wait "$server_pid" 2>/dev/null; }
    openssl s_server -accept "127.0.0.1:$port" -cert "$1" -key "$RUN_DIR/key.pem" -quiet -www >/dev/null 2>&1 &
    server_pid=$!
    sleep 0.3
    kill -0 "$server_pid" 2>/dev/null
}
start_server "$RUN_DIR/valid.pem" || exit 4
export SSL_CERT_FILE="$RUN_DIR/valid.pem"
tls_report localhost "$port" 2>&1 | redact > sentinel-output/validation/tls-valid.txt
rc=${PIPESTATUS[0]}
record 'Trusted SAN match' 'loopback OpenSSL server; host=localhost, trusted 10-day X.509 certificate' 0 "$rc"
if grep -q 'Verify return code: 0 (ok)' sentinel-output/validation/tls-valid.txt; then result=VERIFIED; else result=UNVERIFIED; fi
record 'Certificate chain validation' 'actual trusted self-signed test leaf' VERIFIED "$result"
if grep -q 'TLS 1.2.*SUPPORTED' sentinel-output/validation/tls-valid.txt && grep -q 'TLS 1.3.*SUPPORTED' sentinel-output/validation/tls-valid.txt; then result=SUPPORTED; else result=UNKNOWN; fi
record 'TLS 1.2 and 1.3' 'independent real version-specific handshakes' SUPPORTED "$result"
tls_report 127.0.0.1 "$port" 2>&1 | redact > sentinel-output/validation/tls-wrong-host.txt
rc=${PIPESTATUS[0]}
record 'Hostname mismatch' 'IP target=127.0.0.1; certificate has only DNS:localhost SAN' 1 "$rc"
unset SSL_CERT_FILE
tls_report localhost "$port" 2>&1 | redact > sentinel-output/validation/tls-untrusted.txt
rc=${PIPESTATUS[0]}
record 'Untrusted chain' 'same local test certificate; system trust store' 1 "$rc"
start_server "$RUN_DIR/expired.pem" || exit 5
export SSL_CERT_FILE="$RUN_DIR/expired.pem"
tls_report localhost "$port" 2>&1 | redact > sentinel-output/validation/tls-expired.txt
rc=${PIPESTATUS[0]}
record 'Expired certificate handshake' 'actual X.509 leaf signed with -days 0 and checked after expiry' 1 "$rc"
pem=$(cat "$RUN_DIR/expired.pem")
certificate_chain_metadata fixture fixture "$pem" > sentinel-output/validation/tls-expired-metadata.txt
if grep -q '^\[EXPIRED\]' sentinel-output/validation/tls-expired-metadata.txt; then result=EXPIRED; else result=INCORRECT; fi
record 'Expired X.509 inventory' 'metadata from actual expired certificate' EXPIRED "$result"
unset SSL_CERT_FILE pem
kill "$server_pid"; wait "$server_pid" 2>/dev/null; server_pid=''
tls_report localhost "$port" 2>&1 | redact > sentinel-output/validation/tls-closed-port.txt
rc=${PIPESTATUS[0]}
record 'Connection refused' 'loopback port after test server shutdown' 1 "$rc"
nc -lk 127.0.0.1 "$port" >/dev/null 2>&1 &
stall_pid=$!
sleep 0.3
start=$(date +%s)
tls_report 127.0.0.1 "$port" 2>&1 | redact > sentinel-output/validation/tls-timeout.txt
rc=${PIPESTATUS[0]}; elapsed=$(( $(date +%s)-start ))
record 'Server accepts TCP but sends no TLS' "local nc listener; 2-second per-probe limit; wall=${elapsed}s" 3 "$rc"
kill "$stall_pid"; wait "$stall_pid" 2>/dev/null; stall_pid=''
nc -lk 127.0.0.1 "$port" >/dev/null 2>&1 &
stall_pid=$!
has() { [[ $1 != timeout ]] && command -v "$1" >/dev/null 2>&1; }
start=$(date +%s)
tls_report 127.0.0.1 "$port" 2>&1 | redact > sentinel-output/validation/tls-timeout-no-timeout-command.txt
rc=${PIPESTATUS[0]}; elapsed=$(( $(date +%s)-start ))
record 'Bounded fallback without timeout utility' "local stalled server; timeout hidden; wall=${elapsed}s" 3 "$rc"
has() { command -v "$1" >/dev/null 2>&1; }
gitops_certificate_self_tests > sentinel-output/validation/gitops-certificate-embedded-fixtures.txt 2>&1
record 'Embedded GitOps/certificate fixtures' 'projected APIs; exact SHA; generation lag; linked Helm readiness; X.509; scope guards' 0 "$?"
printf '\nTest cert validity:\n\n```text\n' >> "$report"
openssl x509 -in "$RUN_DIR/valid.pem" -noout -subject -dates -ext subjectAltName >> "$report"
printf '```\n\nAll TLS endpoints were temporary loopback processes. Private keys were generated only in the temporary test directory and removed by cleanup. Reports contain metadata only. No Kubernetes API or Git mutation was executed by this TLS test.\n\nAggregate failures: %s\n' "$failures" >> "$report"
printf 'TLS actual e2e failures=%s; report=%s\n' "$failures" "$report"
((failures==0))
