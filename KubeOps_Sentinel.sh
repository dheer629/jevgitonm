#!/usr/bin/env bash
# KubeOps Sentinel -- a single-file, read-only Kubernetes operations console.
# Runtime files are private, local, sanitized projections, never kubeconfig copies.
# Developer publishing is isolated; the only cluster write exception is an
# explicitly guarded post-push Flux reconciliation in developer release mode.
set -o pipefail
set +x
export -n SPLUNK_TOKEN 2>/dev/null || :
umask 077

# 01 Constants and session state
APP_NAME="KubeOps Sentinel"
APP_VERSION="1.0.1"
APP_BUILD="production"
SOURCE_FILE="${BASH_SOURCE[0]}"
SENTINEL_CONTEXT="${SNTL_CONTEXT:-}"
SENTINEL_NAMESPACE="${SNTL_NAMESPACE:-}"
REFRESH="${SNTL_REFRESH:-5}"
OUTPUT_DIR="${SNTL_OUTPUT_DIR:-./sentinel-output}"
RUN_DIR= CACHE_DIR= CURRENT_REPORT= CURRENT_TITLE= SELECTED_POD=
AUTH_STATUS=UNKNOWN API_STATUS=UNKNOWN API_LATENCY=UNKNOWN RBAC_STATUS=UNKNOWN
METRICS_STATUS=NOT_PROBED GITOPS_STATUS=NOT_PROBED CERT_STATUS=NOT_PROBED
KUBECTL_VERSION=UNKNOWN SERVER_VERSION=UNKNOWN API_FINGERPRINT=UNAVAILABLE
KUBECONFIG_MODE='KUBECTL DEFAULT'
[[ ${KUBECONFIG+x} ]] && KUBECONFIG_MODE=EXPLICIT
MODE=dashboard FORCE_REFRESH=0 NO_COLOR_FLAG=0 INTERACTIVE=0 SCOPE_READY=0
API_TIMEOUT=10 LOG_TIMEOUT=20 TLS_TIMEOUT=8 SPLUNK_TIMEOUT=20
CPU_WARN=80 CPU_CRIT=90 MEM_WARN=80 MEM_CRIT=90 CERT_WARN_DAYS=90 CERT_CRIT_DAYS=30
UI_COLS=120 UI_ROWS=30 UI_ACTIVE=0 UI_LAST_LINES=0 UI_STTY=
FILTER= SORT_BY=name EVIDENCE_ID= EVIDENCE_MODE=9
declare -a ACTIVE_PIDS=()
declare -A DEPENDENCIES=()
C_RESET= C_GREEN= C_YELLOW= C_RED= C_CYAN= C_BLUE= C_DIM=

# 02 Terminal and input primitives
has() { command -v "$1" >/dev/null 2>&1; }
now_epoch() { printf '%(%s)T\n' -1; }
timestamp() { TZ=UTC printf '%(%Y-%m-%dT%H:%M:%SZ)T\n' -1; }
terminal_size() {
    local c=${COLUMNS:-120} r=${LINES:-30}
    if has tput && [[ ${TERM:-dumb} != dumb && -t 1 ]]; then
        c=$(tput cols 2>/dev/null) r=$(tput lines 2>/dev/null)
    fi
    [[ $c =~ ^[0-9]+$ ]] || c=120
    [[ $r =~ ^[0-9]+$ ]] || r=30
    ((c < 40)) && c=40
    ((r < 12)) && r=12
    UI_COLS=$c UI_ROWS=$r
}
color_init() {
    if [[ -t 1 && ${TERM:-dumb} != dumb && ! ${NO_COLOR+x} && $NO_COLOR_FLAG == 0 ]]; then
        C_RESET=$'\033[0m' C_GREEN=$'\033[32m' C_YELLOW=$'\033[33m'
        C_RED=$'\033[31m' C_CYAN=$'\033[36m' C_BLUE=$'\033[34m' C_DIM=$'\033[2m'
    fi
}
status_label() {
    local color=$C_CYAN
    case $1 in OK|PASS|AUTHENTICATED) color=$C_GREEN;; WARN|DEGRADED|UNKNOWN) color=$C_YELLOW;; FAIL|EXPIRED|CRITICAL|AUTH_ERROR|RBAC_DENIED) color=$C_RED;; esac
    printf '%s[%s]%s' "$color" "$1" "$C_RESET"
}
rule() { local line; printf -v line '%*s' "$((UI_COLS-1))" ''; printf '%s\n' "${line// /=}"; }
truncate_text() {
    local text=$1 width=$2
    if ((${#text} > width)); then printf '%s~' "${text:0:width-1}"; else printf '%s' "$text"; fi
}
prompt() {
    REPLY=
    [[ -t 0 && $INTERACTIVE == 1 ]] || return 1
    printf '%s ' "$1" >&2
    IFS= read -r REPLY
}
choose() {
    local title=$1 item i=0 n
    shift
    (($#)) || return 1
    printf '\n%s\n' "$title" >&2
    for item in "$@"; do ((i+=1)); printf '[%3d] %s\n' "$i" "$item" | redact >&2; done
    prompt 'Select number (0 = back):' || return 1
    [[ $REPLY =~ ^[0-9]{1,6}$ ]] || return 1
    n=$((10#$REPLY))
    ((n>0 && n<=$#)) || return 1
    REPLY=${!n}
}

# 03 Central redaction. Conservative removal of the rest of a sensitive line
# intentionally favors confidentiality over preserving a log message verbatim.
redact() {
    if ! has awk; then
        local line low pem=0
        while IFS= read -r line || [[ -n $line ]]; do
            line=${line//[$'\001'-$'\010'$'\013'-$'\037'$'\177']/}
            low=${line,,}
            if [[ $low == *'-----begin '*'private key-----'* ]]; then pem=1; printf '[REDACTED PRIVATE KEY]\n'; continue; fi
            if ((pem)); then [[ $low == *'-----end '*'private key-----'* ]] && pem=0; continue; fi
            case $low in *authorization*|*bearer*|*token*|*password*|*passwd*|*secret=*|*apikey*|*api_key*|*client_secret*|*://*@*|*eyj*) printf '[REDACTED]\n';;
                *) printf '%s\n' "$line";; esac
        done
        return
    fi
    LC_ALL=C awk '
    BEGIN { pem=0 }
    {
      gsub(/\033\[[0-9;?]*[ -\/]*[@-~]/, ""); gsub(/[\001-\010\013-\037\177]/, "")
      low=tolower($0)
      if (low ~ /-----begin .*private key-----/) {pem=1; print "[REDACTED PRIVATE KEY]"; next}
      if (pem) {if (low ~ /-----end .*private key-----/) pem=0; next}
      s=$0
      while (match(s, /[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\/ @]*@/)) {
        p=substr(s,RSTART,RLENGTH); sub(/:\/\/.*/, "://[REDACTED]@",p)
        s=substr(s,1,RSTART-1) p substr(s,RSTART+RLENGTH)
        # Stop re-matching the replacement itself.
        sub(/\[REDACTED\]@/, "[REDACTED]_AT_",s)
      }
      gsub(/\[REDACTED\]_AT_/, "[REDACTED]@",s)
      low=tolower(s)
      if (match(low, /(authorization["\047 ]*[:=]|bearer[[:space:]]+|(^|[^a-z0-9_])(token|password|passwd|secret|apikey|api_key|client_secret|access_token|refresh_token|id_token)["\047 ]*[:=])/))
        s=substr(s,1,RSTART-1) "[REDACTED]"
      if (match(s, /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/))
        s=substr(s,1,RSTART-1) "[REDACTED]" substr(s,RSTART+RLENGTH)
      print s
    }'
}
sanitize_url() {
    local value=$1 scheme rest
    value=${value%%\?*}; value=${value%%\#*}
    if [[ $value == *://* ]]; then
        scheme=${value%%://*} rest=${value#*://}
        if [[ ${rest%%/*} == *@* ]]; then rest="[REDACTED]@${rest#*@}"; fi
        value="$scheme://$rest"
    fi
    printf '%s\n' "$value" | redact
}
safe_id() {
    local value=$1
    value=${value//[^a-zA-Z0-9._-]/_}; value=${value#.}; value=${value#.}
    [[ -n $value && $value != -* ]] || value="incident_${value}"
    printf '%.80s' "$value"
}
log_audit() {
    [[ -n $RUN_DIR && -d $RUN_DIR ]] || return 0
    printf '%s\tcontext=%s\tnamespace=%s\t%s\n' "$(timestamp)" "$SENTINEL_CONTEXT" "$SENTINEL_NAMESPACE" "$*" | redact >> "$RUN_DIR/application.log"
}

# 04 Error classes, bounded processes and cleanup
classify_error() {
    local rc=$1 message=${2,,}
    case $rc in 124|137|143) printf 'API_TIMEOUT\n'; return;; 127) printf 'COMMAND_MISSING\n'; return;; esac
    case $message in
        *forbidden*|*'cannot list'*|*'cannot get'*|*'permission denied'*) printf 'RBAC_DENIED\n';;
        *unauthorized*|*'provide credentials'*|*'must be logged'*|*'token has expired'*|*'invalid_grant'*|*'credential'*|*'exec plugin'*|*'authentication'*) printf 'AUTH_ERROR\n';;
        *'connection refused'*|*'unable to connect'*|*'no such host'*|*'network is unreachable'*|*'x509:'*|*'tls handshake'*) printf 'NETWORK_ERROR\n';;
        *'timed out'*|*'deadline exceeded'*|*'timeout exceeded'*|*'i/o timeout'*|*'request timeout'*|*'timeout awaiting'*) printf 'API_TIMEOUT\n';;
        *'no matches for kind'*|*'not found'*|*'have a resource type'*|*'could not find the requested resource'*) printf 'RESOURCE_NOT_FOUND\n';;
        *'metrics api not available'*|*'metrics not available'*) printf 'METRICS_UNAVAILABLE\n';;
        *'parse'*|*'invalid character'*|*'cannot unmarshal'*) printf 'PARSE_ERROR\n';;
        *) if ((rc==0)); then printf 'OK\n'; else printf 'UNKNOWN\n'; fi;;
    esac
}
kill_tree() {
    local pid=$1 child
    [[ $pid =~ ^[0-9]+$ && $pid != $$ && $pid != "$BASHPID" ]] || return 0
    if has ps && has awk; then
        while IFS= read -r child; do [[ -n $child ]] && kill_tree "$child"; done < <(ps -eo pid=,ppid= 2>/dev/null | awk -v p="$pid" '$2==p {print $1}')
    fi
    kill -TERM "$pid" 2>/dev/null || :
}
run_bounded() {
    local seconds=$1 pid guard rc input_fd
    shift
    [[ $seconds =~ ^[1-9][0-9]*$ ]] || return 2
    # Keep exec credential plugin stdin connected for normal OIDC authentication.
    exec {input_fd}<&0
    if has timeout; then
        [[ ${1:-} == command ]] && shift
        command timeout --foreground --signal=TERM --kill-after=2 "${seconds}s" "$@" <&"$input_fd" &
    else
        "$@" <&"$input_fd" &
    fi
    pid=$! ACTIVE_PIDS+=("$!")
    exec {input_fd}<&-
    if ! has timeout; then
        (sleep "$seconds"; kill_tree "$pid"; sleep 2; kill -KILL "$pid" 2>/dev/null || :) &
        guard=$! ACTIVE_PIDS+=("$!")
    fi
    wait "$pid"; rc=$?
    if [[ -n ${guard:-} ]]; then kill_tree "$guard"; wait "$guard" 2>/dev/null || :; fi
    # Entries are removed to avoid killing a recycled PID during later cleanup.
    local -a keep=(); local p
    for p in "${ACTIVE_PIDS[@]}"; do [[ $p == "$pid" || $p == "${guard:-}" ]] || keep+=("$p"); done
    ACTIVE_PIDS=("${keep[@]}")
    return "$rc"
}
cleanup() {
    local rc=$? p
    trap - EXIT INT TERM HUP
    for p in "${ACTIVE_PIDS[@]}"; do kill_tree "$p"; done
    # Collectors run in command substitutions, so their PID arrays are isolated.
    # Stop any remaining direct children as well, then their descendants.
    if has ps && has awk; then
        local cleanup_parent=$BASHPID
        local -a remaining_children=()
        mapfile -t remaining_children < <(ps -eo pid=,ppid= 2>/dev/null | awk -v parent="$cleanup_parent" '$2==parent {print $1}')
        for p in "${remaining_children[@]}"; do kill_tree "$p"; done
    fi
    if [[ -t 1 && ${TERM:-dumb} != dumb ]]; then
        printf '\033[0m\033[?25h'
        ((UI_ACTIVE)) && printf '\033[?1049l'
    fi
    if [[ -n $UI_STTY ]] && has stty; then stty "$UI_STTY" 2>/dev/null || :; fi
    if declare -F dev_cleanup >/dev/null; then dev_cleanup; fi
    # Only the mktemp-created cache is removed; explicit exports and logs persist.
    if [[ -n $RUN_DIR && $RUN_DIR == "$OUTPUT_DIR"/.session.* && -d $RUN_DIR && ! -L $RUN_DIR ]]; then
        if [[ -f $RUN_DIR/application.log ]]; then
            cp -- "$RUN_DIR/application.log" "$OUTPUT_DIR/application-${RUN_DIR##*.}.log" 2>/dev/null || :
        fi
        rm -rf -- "$RUN_DIR"
    fi
    unset SPLUNK_TOKEN
    return "$rc"
}

# 05 Dependencies and private local runtime
dependency_detect() {
    local cmd
    for cmd in kubectl helm flux jq openssl curl timeout sha256sum column tput base64 awk sed grep sort uniq date less git shellcheck inotifywait flock; do
        if has "$cmd"; then DEPENDENCIES[$cmd]=AVAILABLE; else DEPENDENCIES[$cmd]='NOT INSTALLED'; fi
    done
}
init_runtime() {
    local working parent resolved
    working=$(pwd -P) || return 2
    # Resolve the parent after mkdir, then ensure symlinks cannot redirect writes
    # outside the current working tree. Absolute --output is allowed inside it.
    case $OUTPUT_DIR in /*) ;; *) OUTPUT_DIR="$working/$OUTPUT_DIR";; esac
    [[ $OUTPUT_DIR != *$'\n'* && $OUTPUT_DIR != *$'\r'* ]] || { printf 'Invalid output path\n' >&2; return 2; }
    parent=$OUTPUT_DIR
    while [[ ! -e $parent ]]; do parent=${parent%/*}; [[ -n $parent ]] || parent=/; done
    resolved=$(cd -- "$parent" 2>/dev/null && pwd -P) || return 2
    [[ $resolved == "$working" || $resolved == "$working/"* ]] || { printf 'Output must remain below working directory: %s\n' "$working" >&2; return 2; }
    [[ /${OUTPUT_DIR#/}/ != */../* && ! -L $OUTPUT_DIR ]] || { printf 'Unsafe output path\n' >&2; return 2; }
    mkdir -p -- "$OUTPUT_DIR" || return 2
    OUTPUT_DIR=$(cd -- "$OUTPUT_DIR" && pwd -P) || return 2
    [[ $OUTPUT_DIR == "$working" || $OUTPUT_DIR == "$working/"* ]] || return 2
    [[ ! -L $OUTPUT_DIR ]] || return 2
    RUN_DIR=$(mktemp -d "$OUTPUT_DIR/.session.XXXXXXXX") || return 2
    CACHE_DIR="$RUN_DIR/cache"
    mkdir -- "$CACHE_DIR" || return 2
    printf '{"items":[]}\n' > "$RUN_DIR/empty.json"
    : > "$RUN_DIR/findings.tsv"
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
    trap terminal_size WINCH
    [[ -t 0 && -t 1 && $DEV_NON_INTERACTIVE == 0 ]] && INTERACTIVE=1
    if [[ -t 0 ]] && has stty; then UI_STTY=$(stty -g 2>/dev/null); fi
    log_audit 'session started'
}

# 06 Scope engine: immutable within a session except explicit Change Scope.
scope_args_safe() {
    local arg
    for arg in "$@"; do
        case $arg in
            -A|-A?*|-n|-n?*|--all-namespaces*|--namespace*|--context*|--kube-context*|--kubeconfig*|--cache-dir*|--server*|--token*|--user*|--cluster*|--as*|--certificate-authority*|--client*|--insecure*|--request-timeout*|--raw*|--filename*|-f|-f?*|--kustomize*|-k|-k?*|--watch*|-w|-w?*)
                printf 'SCOPE_REJECTED: caller scope/transport/watch override\n' >&2; return 2;;
        esac
    done
}
allowed_resource() {
    local scope=$1 resources=$2 res
    local -a entries
    IFS=, read -r -a entries <<< "$resources"
    for res in "${entries[@]}"; do
        case "$scope:$res" in
            ns:pods|ns:pod|ns:deployments|ns:statefulsets|ns:daemonsets|ns:replicasets|ns:jobs|ns:cronjobs|ns:services|ns:endpoints|ns:endpointslices*|ns:persistentvolumeclaims|ns:pvc|ns:events|ns:ingresses*|ns:secrets|ns:configmaps|ns:pods.metrics.k8s.io|ns:gitrepositories.source.toolkit.fluxcd.io|ns:ocirepositories.source.toolkit.fluxcd.io|ns:helmrepositories.source.toolkit.fluxcd.io|ns:kustomizations.kustomize.toolkit.fluxcd.io|ns:helmreleases.helm.toolkit.fluxcd.io|ns:certificates.cert-manager.io|ns:certificaterequests.cert-manager.io|ns:issuers.cert-manager.io) ;;
            cluster:namespaces|cluster:namespace|cluster:nodes|cluster:nodes.metrics.k8s.io|cluster:persistentvolumes|cluster:pv|cluster:storageclasses*|cluster:volumeattachments*|cluster:customresourcedefinitions*|cluster:crds|cluster:clusterissuers.cert-manager.io|cluster:validatingwebhookconfigurations*|cluster:mutatingwebhookconfigurations*) ;;
            *) printf 'RESOURCE_REJECTED: %s/%s\n' "$scope" "$res" >&2; return 2;;
        esac
    done
}
kctl_dispatch() {
    local scope=$1 verb=$2; shift 2
    [[ -n $SENTINEL_CONTEXT ]] || { printf 'NOT_CONFIGURED: context\n' >&2; return 2; }
    scope_args_safe "$@" || return
    local -a argv=(kubectl --context "$SENTINEL_CONTEXT" "--request-timeout=${API_TIMEOUT}s" --cache-dir "$RUN_DIR/kubectl-cache")
    if [[ $scope == ns ]]; then
        [[ -n $SENTINEL_NAMESPACE ]] || { printf 'NOT_CONFIGURED: namespace\n' >&2; return 2; }
        argv+=(-n "$SENTINEL_NAMESPACE")
    fi
    case $verb in
        get) allowed_resource "$scope" "${1:-}" || return;;
        auth) [[ ${1:-} == can-i && ( ${2:-} == get || ${2:-} == list ) ]] || return 2;;
        logs) [[ $scope == ns && ${1:-} != -* && -n ${1:-} ]] || return 2;;
        top) [[ ( $scope == ns && ${1:-} == pods ) || ( $scope == cluster && ${1:-} == nodes ) ]] || return 2;;
        version|api-resources) [[ $scope == cluster ]] || return 2;;
        *) printf 'READ_ONLY: unsupported operation\n' >&2; return 2;;
    esac
    local seconds=$API_TIMEOUT
    [[ $verb == logs ]] && seconds=$LOG_TIMEOUT
    run_bounded "$seconds" command "${argv[@]}" "$verb" "$@"
}
kctl_ns() { kctl_dispatch ns "$@"; }
kctl_cluster() { kctl_dispatch cluster "$@"; }
helm_ns() {
    local verb=${1:-}; shift || return 2
    scope_args_safe "$@" || return
    case $verb in list|status|history) ;; *) return 2;; esac
    run_bounded "$API_TIMEOUT" command helm --kube-context "$SENTINEL_CONTEXT" -n "$SENTINEL_NAMESPACE" "$verb" "$@"
}
flux_read() {
    [[ ${1:-} == get ]] || return 2
    scope_args_safe "$@" || return
    run_bounded "$API_TIMEOUT" command flux --context "$SENTINEL_CONTEXT" -n "$SENTINEL_NAMESPACE" "$@"
}

# 07 Cache and safe collectors. No raw object JSON is ever persisted.
cache_file() { printf '%s/%s.json\n' "$CACHE_DIR" "$1"; }
cache_status() { if [[ -f $CACHE_DIR/$1.status ]]; then cat -- "$CACHE_DIR/$1.status"; else printf 'NOT_COLLECTED\n'; fi; }
cache_age() {
    local value=0
    [[ -f $CACHE_DIR/$1.time ]] && read -r value < "$CACHE_DIR/$1.time"
    printf '%s\n' "$(( $(now_epoch) - value ))"
}
cache_fresh() { [[ $FORCE_REFRESH == 0 && -f $CACHE_DIR/$1.status ]] && (( $(cache_age "$1") < $2 )); }
cache_record() {
    printf '%s\n' "$2" > "$CACHE_DIR/$1.status"
    now_epoch > "$CACHE_DIR/$1.time"
    log_audit "collector=$1 status=$2"
}
capture_command() {
    local error_file=$1 error_fd error_pid rc
    shift
    exec {error_fd}> >(redact > "$error_file")
    error_pid=$!
    "$@" 2>&"$error_fd"; rc=$?
    exec {error_fd}>&-
    wait "$error_pid" 2>/dev/null || :
    return "$rc"
}
json_sanitize() {
    # Applied AFTER module allow-list projections. Descriptions/messages may
    # contain credentials; sanitize strings without breaking JSON escaping.
    jq '
      def clean:
        if type=="object" then with_entries(select(.key | test("^(data|stringData|managedFields|password|passwd|token|access_token|refresh_token|client_secret|privateKey|tls.key)$";"i")|not) | .value |= clean)
        elif type=="array" then map(clean)
        elif type=="string" then
          if test("BEGIN .*PRIVATE KEY|authorization[\" ]*[:=]|bearer[[:space:]]+|(^|[^a-z0-9_])(token|password|passwd|secret|apikey|api_key|client_secret)[\" ]*[:=]";"i") then "[REDACTED]"
          else gsub("(?<s>[a-zA-Z][a-zA-Z0-9+.-]*://)[^/ @]*@";"\(.s)[REDACTED]@") | gsub("eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+";"[REDACTED]") | gsub("[\u0000-\u0008\u000b-\u001f\u007f]";"") end
        else . end; clean'
}
collect_json() {
    local key=$1 ttl=$2 scope=$3 resource=$4 projection=$5 fallback=${6:-}
    local raw rc err state path
    [[ $key =~ ^[a-zA-Z0-9_.-]+$ && $key != .* ]] || return 2
    if cache_fresh "$key" "$ttl"; then [[ $(cache_status "$key") == OK || $(cache_status "$key") == EMPTY_RESULT ]]; return; fi
    mkdir "$CACHE_DIR/$key.lock" 2>/dev/null || return 1
    path="$CACHE_DIR/$key.json"
    err="$CACHE_DIR/$key.error"
    rm -f -- "$path" "$CACHE_DIR/$key.txt"
    if ! has jq; then
        if [[ -n $fallback ]]; then
            raw=$(capture_command "$err" "kctl_$scope" get "$resource" -o "custom-columns=$fallback"); rc=$?
            if ((rc==0)); then printf '%s\n' "$raw" | redact > "$CACHE_DIR/$key.txt"; state=DEGRADED; else state=$(classify_error "$rc" "$(cat "$err")"); fi
        else state=COMMAND_MISSING; printf 'jq required for this collector\n' > "$err"; fi
        cache_record "$key" "$state"; rmdir "$CACHE_DIR/$key.lock"; return 1
    fi
    raw=$(capture_command "$err" "kctl_$scope" get "$resource" -o json); rc=$?
    if ((rc!=0)); then state=$(classify_error "$rc" "$(cat "$err")")
    elif ! printf '%s\n' "$raw" | jq -e 'type=="object" and (.items|type=="array")' >/dev/null 2>&1; then state=PARSE_ERROR
    elif printf '%s\n' "$raw" | jq "$projection" 2> >(redact >> "$err") | json_sanitize > "$path.new"; then
        if jq -e 'type=="object" and (.items|type=="array")' "$path.new" >/dev/null 2>&1; then
            mv -- "$path.new" "$path"; state=OK
            [[ $(jq '.items|length' "$path") == 0 ]] && state=EMPTY_RESULT
        else state=PARSE_ERROR; fi
    else state=PARSE_ERROR; fi
    unset raw
    rm -f -- "$path.new"
    cache_record "$key" "$state"
    rmdir "$CACHE_DIR/$key.lock"
    [[ $state == OK || $state == EMPTY_RESULT ]]
}
collect_text() {
    local key=$1 ttl=$2 raw rc state err
    shift 2
    [[ $key =~ ^[a-zA-Z0-9_.-]+$ && $key != .* ]] || return 2
    if cache_fresh "$key" "$ttl"; then [[ $(cache_status "$key") == OK || $(cache_status "$key") == EMPTY_RESULT ]]; return; fi
    mkdir "$CACHE_DIR/$key.lock" 2>/dev/null || return 1
    err="$CACHE_DIR/$key.error"
    raw=$(capture_command "$err" "$@"); rc=$?
    if ((rc==0)); then
        if has jq && printf '%s\n' "$raw" | jq -e 'type=="array" or type=="object"' >/dev/null 2>&1; then
            printf '%s\n' "$raw" | json_sanitize > "$CACHE_DIR/$key.txt"
        else printf '%s\n' "$raw" | redact > "$CACHE_DIR/$key.txt"; fi
        state=OK; [[ -n $raw ]] || state=EMPTY_RESULT
    else
        rm -f -- "$CACHE_DIR/$key.txt"
        state=$(classify_error "$rc" "$(cat "$err")")
    fi
    cache_record "$key" "$state"; rmdir "$CACHE_DIR/$key.lock"
    [[ $state == OK || $state == EMPTY_RESULT ]]
}

# 08 Kubeconfig, authentication and bootstrap
config_query() { run_bounded "$API_TIMEOUT" command kubectl config "$@"; }
bootstrap_scope() {
    local raw rc current start elapsed nsread
    local -a contexts=() namespaces=()
    has kubectl || { printf 'COMMAND_MISSING: kubectl\n' >&2; return 2; }
    # Never set KUBECONFIG unless --kubeconfig explicitly requested it.
    raw=$(capture_command "$RUN_DIR/config.error" config_query get-contexts -o name); rc=$?
    ((rc==0)) || { printf 'KUBECONFIG: %s\n' "$(classify_error "$rc" "$(cat "$RUN_DIR/config.error")")" >&2; return 2; }
    while IFS= read -r current; do [[ -n $current ]] && contexts+=("$current"); done <<< "$raw"
    ((${#contexts[@]})) || { printf 'NOT_CONFIGURED: no Kubernetes contexts\n' >&2; return 2; }
    if [[ -z $SENTINEL_CONTEXT ]]; then
        if ((INTERACTIVE)); then choose 'AVAILABLE KUBERNETES CONTEXTS' "${contexts[@]}" || return 2; SENTINEL_CONTEXT=$REPLY
        else SENTINEL_CONTEXT=$(config_query current-context 2>/dev/null) || return 2; fi
    fi
    local found=0
    for current in "${contexts[@]}"; do [[ $current == "$SENTINEL_CONTEXT" ]] && found=1; done
    ((found)) || { printf 'NOT_CONFIGURED: context does not exist\n' >&2; return 2; }
    [[ $SENTINEL_CONTEXT != -* && $SENTINEL_CONTEXT != *$'\n'* ]] || return 2
    start=$(now_epoch)
    raw=$(capture_command "$RUN_DIR/auth.error" kctl_cluster get namespaces -o 'jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}'); rc=$?
    elapsed=$(( $(now_epoch)-start )); API_LATENCY="$((elapsed*1000)) ms (1s clock resolution)"
    if ((rc==0)); then AUTH_STATUS=AUTHENTICATED API_STATUS=OK nsread=OK
    else
        nsread=$(classify_error "$rc" "$(cat "$RUN_DIR/auth.error")")
        if [[ $nsread == RBAC_DENIED ]]; then AUTH_STATUS=UNKNOWN API_STATUS=OK
        else AUTH_STATUS=$nsread API_STATUS=$nsread; printf 'Authentication/API: %s\n' "$nsread" >&2; return 3; fi
    fi
    printf '%s\n' "$nsread" > "$CACHE_DIR/namespaces.status"
    while IFS= read -r current; do [[ -n $current ]] && namespaces+=("$current"); done <<< "$raw"
    if [[ -z $SENTINEL_NAMESPACE ]]; then
        if ((INTERACTIVE)) && ((${#namespaces[@]})); then
            choose 'AVAILABLE NAMESPACES' "${namespaces[@]}" || return 2; SENTINEL_NAMESPACE=$REPLY
        elif ((INTERACTIVE)); then
            printf 'Namespace list: %s. Select a known namespace explicitly.\n' "$nsread" >&2
            prompt 'Namespace:' || return 2; SENTINEL_NAMESPACE=$REPLY
        else
            printf 'A namespace is required in noninteractive mode: --namespace NAME\n' >&2; return 2
        fi
    fi
    [[ $SENTINEL_NAMESPACE =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ && ${#SENTINEL_NAMESPACE} -le 63 ]] || { printf 'Invalid namespace\n' >&2; return 2; }
    # This still works for namespace-only RBAC even when namespace enumeration is forbidden.
    collect_pods >/dev/null
    current=$(cache_status pods)
    case $current in
        OK|EMPTY_RESULT|DEGRADED) AUTH_STATUS=AUTHENTICATED; RBAC_STATUS=OK;;
        RBAC_DENIED) RBAC_STATUS=PARTIAL;;
        RESOURCE_NOT_FOUND) printf 'Namespace/resource not found: %s\n' "$SENTINEL_NAMESPACE" >&2; return 2;;
        *) AUTH_STATUS=$current API_STATUS=$current; printf 'Namespace/API: %s\n' "$current" >&2; return 3;;
    esac
    SCOPE_READY=1
    collect_text rbac 300 rbac_probe >/dev/null
    if [[ -f $CACHE_DIR/rbac.txt ]]; then
        local capability
        while IFS= read -r capability; do
            [[ $capability == *RBAC_DENIED* || $capability == *UNKNOWN* ]] && RBAC_STATUS=PARTIAL
        done < "$CACHE_DIR/rbac.txt"
    fi
    collect_text api_version 300 kctl_cluster version -o json >/dev/null
    if has jq && [[ -s $CACHE_DIR/api_version.txt ]]; then
        KUBECTL_VERSION=$(jq -r '.clientVersion.gitVersion // "UNKNOWN"' "$CACHE_DIR/api_version.txt" 2>/dev/null)
        SERVER_VERSION=$(jq -r '.serverVersion.gitVersion // "UNKNOWN"' "$CACHE_DIR/api_version.txt" 2>/dev/null)
    fi
    # A one-field projection extracts no kubeconfig credentials or certificate data.
    raw=$(run_bounded "$API_TIMEOUT" command kubectl --context "$SENTINEL_CONTEXT" config view --minify -o 'jsonpath={.clusters[0].cluster.server}' 2>/dev/null)
    if [[ -n $raw ]] && has sha256sum; then API_FINGERPRINT=$(printf '%s' "$raw" | sha256sum); API_FINGERPRINT=${API_FINGERPRINT%% *}; fi
    unset raw
    collect_text discovery 300 kctl_cluster api-resources --verbs=list -o name >/dev/null
    if [[ -f $CACHE_DIR/discovery.txt ]]; then
        if grep -q 'gitrepositories.source.toolkit.fluxcd.io' "$CACHE_DIR/discovery.txt"; then GITOPS_STATUS=FLUX; else GITOPS_STATUS=NOT_INSTALLED; fi
        if grep -q 'certificates.cert-manager.io' "$CACHE_DIR/discovery.txt"; then CERT_STATUS=CERT_MANAGER; else CERT_STATUS=TLS_SECRETS; fi
    else GITOPS_STATUS=$(cache_status discovery); CERT_STATUS=$GITOPS_STATUS; fi
    collect_metrics >/dev/null 2>&1
    METRICS_STATUS=$(cache_status metrics)
    log_audit 'scope locked'
    return 0
}
rbac_probe() {
    local resource answer rc scope verb
    for resource in pods pods/log events deployments services secrets nodes; do
        scope=ns verb=list
        [[ $resource == pods/log ]] && verb=get
        [[ $resource == nodes ]] && scope=cluster
        answer=$("kctl_$scope" auth can-i "$verb" "$resource" 2>&1); rc=$?
        if [[ $answer == yes ]]; then printf '%s\t%s\tOK\n' "$resource" "$verb"
        elif [[ $answer == no* ]]; then printf '%s\t%s\tRBAC_DENIED\n' "$resource" "$verb"
        else printf '%s\t%s\t%s\n' "$resource" "$verb" "$(classify_error "$rc" "$answer")"; fi
    done
}
scope_report() {
    printf 'Application: %s %s (%s)\nTimestamp: %s\nHost: %s\n' "$APP_NAME" "$APP_VERSION" "$APP_BUILD" "$(timestamp)" "${HOSTNAME:-UNKNOWN}"
    printf 'Context: %s\nNamespace: %s\nMode: READ-ONLY SUPERVISION\n' "$SENTINEL_CONTEXT" "$SENTINEL_NAMESPACE"
    printf 'KUBECONFIG MODE: %s\n' "$KUBECONFIG_MODE"
    [[ $KUBECONFIG_MODE == EXPLICIT ]] && printf 'KUBECONFIG: %s\n' "${KUBECONFIG:-}"
    printf 'API endpoint SHA256: %s\nkubectl: %s\nServer: %s\n' "$API_FINGERPRINT" "$KUBECTL_VERSION" "$SERVER_VERSION"
    printf 'Authentication: %s\nAPI: %s\nAPI latency: %s\nRBAC: %s\n' "$AUTH_STATUS" "$API_STATUS" "$API_LATENCY" "$RBAC_STATUS"
}
diagnostics_report() {
    scope_report
    printf '\nDEPENDENCIES\n'
    local cmd
    for cmd in kubectl helm flux jq openssl curl timeout sha256sum column tput base64 awk sed grep sort uniq date git shellcheck; do printf '%-18s %s\n' "$cmd" "${DEPENDENCIES[$cmd]:-UNKNOWN}"; done
    printf '\nRBAC (read capabilities only)\n'
    collect_text rbac 300 rbac_probe >/dev/null
    [[ -f $CACHE_DIR/rbac.txt ]] && cat "$CACHE_DIR/rbac.txt"
    printf '\nMETRICS: %s\nGITOPS: %s\nCERTIFICATES: %s\n' "$METRICS_STATUS" "$GITOPS_STATUS" "$CERT_STATUS"
    splunk_diagnostics
}

# Pure offline integration fixtures exercise the real wrappers/cache/bootstrap.
# Function overrides exist only inside this subshell; no mock tool is installed.
core_integration_tests() (
    has jq || { printf 'SKIP core JSON fixtures: jq unavailable\n'; return 0; }
    local fixture_dir saved_run=$RUN_DIR original_config=${KUBECONFIG-} original_set=${KUBECONFIG+x}
    fixture_dir=$(mktemp -d "$RUN_DIR/core-fixture.XXXXXXXX") || return 1
    RUN_DIR=$fixture_dir CACHE_DIR="$fixture_dir/cache"
    mkdir -- "$CACHE_DIR" || return 1
    : > "$fixture_dir/calls"
    SENTINEL_CONTEXT=fixture-context SENTINEL_NAMESPACE=fixture-namespace
    INTERACTIVE=0 FORCE_REFRESH=0 CORE_FIXTURE_MODE=healthy
    # This suite is explicitly offline. bootstrap_scope checks for kubectl before
    # reaching the mocked run_bounded wrapper, so advertise only the fixture's
    # mocked kubectl while still requiring the real jq gated above. This keeps
    # deterministic self-tests runnable on clean CI hosts without Kubernetes.
    has() {
        case $1 in
            kubectl|jq) return 0;;
            *) command -v "$1" >/dev/null 2>&1;;
        esac
    }
    run_bounded() {
        shift
        [[ ${1:-} == command ]] && shift
        [[ ${1:-} == kubectl ]] || return 127
        shift
        local context='' namespace='' verb resource output='' arg
        while (($#)); do
            case $1 in
                --context) context=$2; shift 2;;
                -n) namespace=$2; shift 2;;
                --request-timeout=*|--cache-dir=*) shift;;
                --cache-dir) shift 2;;
                *) break;;
            esac
        done
        verb=${1:-}; resource=${2:-}
        printf '%s|%s|%s|%s\n' "$context" "$namespace" "$verb" "$resource" >> "$fixture_dir/calls"
        case "$verb:$resource" in
            config:get-contexts) printf 'fixture-context\nother-context\n'; return;;
            config:current-context) printf 'fixture-context\n'; return;;
            config:view) printf 'https://fixture.invalid'; return;;
        esac
        [[ $context == fixture-context ]] || { printf 'context scope not injected\n' >&2; return 2; }
        case "$verb:$resource" in
            auth:can-i) printf 'yes\n'; return;;
            version:*) printf '{"clientVersion":{"gitVersion":"fixture"},"serverVersion":{"gitVersion":"fixture"}}\n'; return;;
            api-resources:*) printf 'pods\n'; return;;
            get:namespaces)
                case $CORE_FIXTURE_MODE in
                    namespace-denied) printf 'Forbidden: cannot list namespaces\n' >&2; return 1;;
                    expired) printf 'Unauthorized: token has expired\n' >&2; return 1;;
                    network) printf 'connection refused\n' >&2; return 1;;
                    *) printf 'fixture-namespace\n'; return;;
                esac;;
            get:pods)
                [[ $namespace == fixture-namespace ]] || return 2
                case $CORE_FIXTURE_MODE in
                    denied) printf 'Forbidden: cannot list pods\n' >&2; return 1;;
                    malformed) printf '{broken}\n'; return;;
                    empty) printf '{"items":[]}\n'; return;;
                esac
                for arg in "$@"; do [[ $arg == custom-columns=* ]] && { printf 'NAME PHASE\nfixture-pod Running\n'; return; }; done
                printf '%s\n' '{"kind":"PodList","items":[{"kind":"Pod","metadata":{"name":"fixture-pod","namespace":"fixture-namespace","annotations":{"private":"fixture-omit-annotation"}},"spec":{"containers":[{"name":"app","image":"example.invalid/app:v1","env":[{"name":"PASSWORD","value":"fixture-omit-env"}],"command":["fixture-omit-command"],"resources":{"requests":{"cpu":"250m","memory":"32Mi"}}}]},"status":{"phase":"Running"}}]}'
                return;;
            get:pods.metrics.k8s.io) printf 'Forbidden: cannot list pod metrics\n' >&2; return 1;;
            *) printf '{"items":[]}\n'; return;;
        esac
    }
    core_fixture_assert() { "$@" || { printf 'FAIL core fixture: %s\n' "$*" >&2; return 1; }; }
    collect_json testpods 30 ns pods "$JQ_SAFE_POD" || return 1
    [[ $(cache_status testpods) == OK ]] || return 1
    jq -e '.items[0].spec.containers[0].resources.requests.cpu=="250m" and (.items[0].spec.containers[0].env[0]|has("value")|not)' "$CACHE_DIR/testpods.json" >/dev/null || return 1
    ! grep -q 'fixture-omit' "$CACHE_DIR/testpods.json" || return 1
    local calls_before calls_after
    calls_before=$(wc -l < "$fixture_dir/calls")
    collect_json testpods 30 ns pods "$JQ_SAFE_POD" || return 1
    calls_after=$(wc -l < "$fixture_dir/calls")
    [[ $calls_before == "$calls_after" ]] || return 1
    FORCE_REFRESH=1 CORE_FIXTURE_MODE=denied
    collect_json testpods 30 ns pods "$JQ_SAFE_POD" && return 1
    [[ $(cache_status testpods) == RBAC_DENIED && ! -e $CACHE_DIR/testpods.json ]] || return 1
    CORE_FIXTURE_MODE=malformed
    collect_json testpods 30 ns pods "$JQ_SAFE_POD" && return 1
    [[ $(cache_status testpods) == PARSE_ERROR && ! -e $CACHE_DIR/testpods.json ]] || return 1
    CORE_FIXTURE_MODE=empty
    collect_json testpods 30 ns pods "$JQ_SAFE_POD" || return 1
    [[ $(cache_status testpods) == EMPTY_RESULT ]] || return 1
    CORE_FIXTURE_MODE=healthy FORCE_REFRESH=0
    mkdir "$CACHE_DIR/overlap.lock" || return 1
    collect_json overlap 5 ns pods "$JQ_SAFE_POD" && return 1
    local output
    output=$(printf '%s\n' '{"password":"fixture-omit-password","nested":{"token":"fixture-omit-token","text":"Authorization: fixture-omit-auth"},"image":"safe"}' | json_sanitize) || return 1
    [[ $output != *fixture-omit* && $output == *safe* ]] || return 1
    export KUBECONFIG='/fixture/one config:/fixture/two'
    KUBECONFIG_MODE=EXPLICIT CORE_FIXTURE_MODE=namespace-denied
    bootstrap_scope >/dev/null 2>&1 || return 1
    [[ $KUBECONFIG == '/fixture/one config:/fixture/two' && $AUTH_STATUS == AUTHENTICATED && $SCOPE_READY == 1 ]] || return 1
    unset KUBECONFIG
    KUBECONFIG_MODE='KUBECTL DEFAULT' CORE_FIXTURE_MODE=healthy
    bootstrap_scope >/dev/null 2>&1 || return 1
    [[ ! ${KUBECONFIG+x} ]] || return 1
    CORE_FIXTURE_MODE=expired
    bootstrap_scope >/dev/null 2>&1; [[ $? == 3 && $AUTH_STATUS == AUTH_ERROR ]] || return 1
    CORE_FIXTURE_MODE=network
    bootstrap_scope >/dev/null 2>&1; [[ $? == 3 && $API_STATUS == NETWORK_ERROR ]] || return 1
    CORE_FIXTURE_MODE=healthy FORCE_REFRESH=1
    has() { [[ $1 != jq ]] && command -v "$1" >/dev/null 2>&1; }
    collect_json nojq 5 ns pods "$JQ_SAFE_POD" 'NAME:.metadata.name,PHASE:.status.phase' && return 1
    [[ $(cache_status nojq) == DEGRADED && -s $CACHE_DIR/nojq.txt && ! -e $CACHE_DIR/nojq.json ]] || return 1
    printf 'PASS core wrapper, cache, redaction, explicit/default kubeconfig, RBAC, auth, network and jq fallback integration fixtures\n'
)

# 10 Kubernetes collectors / 11 Metrics / 16 Findings
# Quantity and effective-request rules:
# https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
# https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/
# JSON projections intentionally omit literal environment values, commands, probe
# arguments, arbitrary annotations, and Secret payloads BEFORE entering the cache.
read -r -d '' JQ_SAFE_POD <<'JQ' || :
def smeta: {name,namespace,uid,creationTimestamp,deletionTimestamp,generation,ownerReferences,labels,
  annotations: ((.annotations // {}) | with_entries(select(.key == "meta.helm.sh/release-name" or .key == "meta.helm.sh/release-namespace")))};
def scon: {name,image,resources,restartPolicy,ports,volumeMounts,
  env: [(.env // [])[] | {name,valueFrom}],envFrom};
def svol: {name,persistentVolumeClaim,emptyDir,
  secret:(if .secret then (.secret | {secretName,optional}) else null end),
  configMap:(if .configMap then (.configMap | {name,optional}) else null end),
  projected:(if .projected then {sources:[.projected.sources[]? |
    {secret:(if .secret then (.secret | {name,optional}) else null end),
     configMap:(if .configMap then (.configMap | {name,optional}) else null end),
     serviceAccountToken:(if .serviceAccountToken then {path:.serviceAccountToken.path} else null end)}]} else null end)};
def sspec: {nodeName,serviceAccountName,restartPolicy,overhead,resources,schedulingGates,
  containers:[.containers[]? | scon],initContainers:[.initContainers[]? | scon],
  ephemeralContainers:[.ephemeralContainers[]? | scon],volumes:[.volumes[]? | svol]};
{apiVersion,kind,items:[.items[]? | {kind,metadata:(.metadata|smeta),spec:(.spec|sspec),status}]}
JQ

read -r -d '' JQ_QUANTITIES <<'JQ' || :
def quantity:
  if . == null then null else
  try (tostring | capture("^(?<v>[+-]?(?:[0-9]+(?:\\.[0-9]*)?|\\.[0-9]+))(?<s>[eE][+-]?[0-9]+|[EPTGMK]i|[EPTGMkKmun]?)$") |
    (.v|tonumber) * (if .s == "" then 1 elif .s == "n" then 1e-9 elif .s == "u" then 1e-6 elif .s == "m" then 0.001
    elif .s == "k" or .s == "K" then 1000 elif .s == "M" then 1e6 elif .s == "G" then 1e9
    elif .s == "T" then 1e12 elif .s == "P" then 1e15 elif .s == "E" then 1e18
    elif .s == "Ki" then 1024 elif .s == "Mi" then 1048576 elif .s == "Gi" then 1073741824
    elif .s == "Ti" then 1099511627776 elif .s == "Pi" then 1125899906842624 elif .s == "Ei" then 1152921504606846976
    else ("1" + .s | tonumber) end)) catch null // null end;
def q($r): quantity | if . == null or . < 0 or (isfinite|not) then null elif $r == "cpu" then . * 1000 else . end;
def q_state($r): if . == null then "UNAVAILABLE" else q($r) // "PARSE_ERROR" end;
def round2: . * 100 | round / 100;
def cpu_fmt: if type == "number" then "\(round2)m" else (. // "N/A") end;
def mem_fmt: if type != "number" then (. // "N/A") elif . >= 1073741824 then "\((. / 1073741824)|round2) GiB" else "\((. / 1048576)|round2) MiB" end;
def pct($u;$d): if ($u|type) == "number" and ($d|type) == "number" and $d > 0 then (($u/$d*100)|round2|tostring)+"%" else "N/A" end;
def epoch: if . == null then null else try (sub("\\.[0-9]+Z$";"Z")|fromdateiso8601) catch null end;
def age: epoch | if . == null then "UNKNOWN" else (now - . | floor) as $s |
  if $s >= 86400 then "\(($s/86400)|floor)d" elif $s >= 3600 then "\(($s/3600)|floor)h" elif $s >= 60 then "\(($s/60)|floor)m" else "\($s)s" end end;
def activepod: .status.phase != "Succeeded" and .status.phase != "Failed";
def owner($w): (.metadata.ownerReferences // [] | map(select(.controller == true)) | .[0]) as $o |
  if $o == null then "Pod/"+.metadata.name elif $o.kind == "ReplicaSet" then
    ([$w.items[]? | select(.kind == "ReplicaSet" and .metadata.name == $o.name) | .metadata.ownerReferences[]? | select(.controller == true and .kind == "Deployment")][0]) as $d |
    if $d then "Deployment/"+$d.name else "ReplicaSet/"+$o.name end else $o.kind+"/"+$o.name end;
def effective($which;$r):
  . as $p | ((.spec.containers // []) + (.spec.initContainers // [])) as $all |
  if (.spec.resources[$which][$r] // null) != null then "UNSUPPORTED_POD_LEVEL"
  elif (.status.resize // "") != "" or any(.status.conditions[]?; (.type=="PodResizePending" or .type=="PodResizeInProgress") and .status=="True") then "RESIZE_NOT_VERIFIED"
  elif any($all[]; (.resources[$which][$r] // null) != null and (.resources[$which][$r] | q($r)) == null) then "PARSE_ERROR"
  elif (.spec.overhead[$r] // null) != null and (.spec.overhead[$r] | q($r)) == null then "PARSE_ERROR"
  elif $which == "limits" and any($all[]; (.resources.limits[$r] // null) == null) then "UNBOUNDED"
  elif all($all[]; (.resources[$which][$r] // null) == null) and (.spec.overhead[$r] // null) == null then "UNSET"
  else
    ([.spec.containers[]? | (.resources[$which][$r] | q($r)) // 0] | add // 0) as $apps |
    (reduce (.spec.initContainers // [])[] as $c ({side:0,peak:0};
      (($c.resources[$which][$r] | q($r)) // 0) as $v |
      if $c.restartPolicy == "Always" then .side += $v | .peak = ([.peak,.side]|max)
      else .peak = ([.peak,($v+.side)]|max) end)) as $init |
    ([($apps+$init.side),$init.peak]|max) + ((.spec.overhead[$r] | q($r)) // 0)
  end;
def statuslabel:
  if .metadata.deletionTimestamp then "Terminating" else
  ([.status.initContainerStatuses[]?,.status.containerStatuses[]? | .state.waiting.reason // empty][0]) //
  .status.reason // .status.phase // "UNKNOWN" end;
def usage($metric;$r):
  . as $pod |
  (if $pod.status.phase=="Running" then [$pod.spec.containers[]?.name] + [$pod.spec.initContainers[]?|select(.restartPolicy=="Always")|.name]
   else [] end) + [$pod.status.containerStatuses[]?,$pod.status.initContainerStatuses[]?,$pod.status.ephemeralContainerStatuses[]?|select(.state.running!=null)|.name] | unique as $expected |
  if $metric == null then "N/A" elif ($metric.containers|length) == 0 then "N/A"
  elif ([$metric.containers[].name]|length) != ([$metric.containers[].name]|unique|length) then "PARSE_ERROR"
  elif ($expected - [$metric.containers[].name] | length)>0 then "INCOMPLETE"
  elif any($metric.containers[]; (.usage[$r]|q($r)) == null) then "PARSE_ERROR"
  else ([$metric.containers[] | .usage[$r]|q($r)]|add) end;
JQ

json_cache_path() {
    local key=$1 state
    state=$(cache_status "$key")
    case $state in OK|EMPTY_RESULT)
        if [[ -s $CACHE_DIR/$key.json ]]; then printf '%s\n' "$CACHE_DIR/$key.json"; return; fi ;;
    esac
    [[ -s $RUN_DIR/empty-list.json ]] || printf '{"items":[]}\n' > "$RUN_DIR/empty-list.json"
    printf '%s\n' "$RUN_DIR/empty-list.json"
}

data_source() {
    local key=$1 updated=UNKNOWN stamp
    if [[ -s $CACHE_DIR/$key.time ]]; then
        read -r stamp < "$CACHE_DIR/$key.time"
        updated=$(date -u -d "@$stamp" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null) || updated="epoch:$stamp"
    fi
    printf 'SOURCE\t%s\tSTATUS\t%s\tUPDATED\t%s\tCACHE AGE\t%s sec\n' "$key" "$(cache_status "$key")" "$updated" "$(cache_age "$key")"
}

fallback_report() {
    local key=$1
    data_source "$key"
    if [[ -s $CACHE_DIR/$key.txt ]]; then cat -- "$CACHE_DIR/$key.txt"; else printf '%s\t%s\n' "$key" "$(cache_status "$key")"; fi
    printf 'INTERPRETATION\tStructured analysis requires jq; missing data is UNKNOWN.\n'
}

collect_pods() {
    collect_json pods 5 ns pods "$JQ_SAFE_POD" 'NAME:.metadata.name,PHASE:.status.phase,NODE:.spec.nodeName,IP:.status.podIP,CREATED:.metadata.creationTimestamp' || :
}

collect_workloads() {
    local projection
    projection=${JQ_SAFE_POD%\{apiVersion*}
    projection+=' {apiVersion,kind,items:[.items[]? | {kind,metadata:(.metadata|smeta),spec:{replicas:.spec.replicas,suspend:.spec.suspend,schedule:.spec.schedule,completions:.spec.completions,parallelism:.spec.parallelism,selector:.spec.selector,template:(if .spec.template then {metadata:(.spec.template.metadata|smeta),spec:(.spec.template.spec|sspec)} else null end)},status}]}'
    collect_json workloads 5 ns deployments,statefulsets,daemonsets,replicasets,jobs,cronjobs "$projection" 'KIND:.kind,NAME:.metadata.name,DESIRED:.spec.replicas,READY:.status.readyReplicas,AVAILABLE:.status.availableReplicas' || :
}

collect_metrics() {
    collect_json metrics 5 ns pods.metrics.k8s.io '{items:[.items[]? | {metadata:{name:.metadata.name,namespace:.metadata.namespace},timestamp,window,containers:[.containers[]?|{name,usage}]}]}' '' || :
    METRICS_STATUS=$(cache_status metrics)
    case $METRICS_STATUS in RESOURCE_NOT_FOUND|COMMAND_MISSING) METRICS_STATUS=METRICS_UNAVAILABLE ;; esac
}

collect_events() {
    collect_json events 10 ns events '{items:[.items[]?|{metadata:{name:.metadata.name,namespace:.metadata.namespace,creationTimestamp:.metadata.creationTimestamp},eventTime,firstTimestamp,lastTimestamp,type,reason,involvedObject:{kind:.involvedObject.kind,name:.involvedObject.name,namespace:.involvedObject.namespace,uid:.involvedObject.uid},message,count,series,source,reportingComponent}]}' 'TIME:.lastTimestamp,TYPE:.type,REASON:.reason,OBJECT:.involvedObject.name,COUNT:.count,MESSAGE:.message' || :
}

collect_network() {
    collect_json services 5 ns services '{items:[.items[]?|{kind,metadata:{name:.metadata.name,namespace:.metadata.namespace,creationTimestamp:.metadata.creationTimestamp},spec:{type:.spec.type,selector:.spec.selector,clusterIP:.spec.clusterIP,clusterIPs:.spec.clusterIPs,externalName:.spec.externalName,externalIPs:.spec.externalIPs,ports:.spec.ports,publishNotReadyAddresses:.spec.publishNotReadyAddresses},status}]}' 'NAME:.metadata.name,TYPE:.spec.type,CLUSTER-IP:.spec.clusterIP,EXTERNAL-IP:.status.loadBalancer.ingress[*].ip,PORTS:.spec.ports[*].port' || :
    collect_json endpointslices 5 ns endpointslices.discovery.k8s.io '{items:[.items[]?|{metadata:{name:.metadata.name,namespace:.metadata.namespace,labels:.metadata.labels},addressType,ports,endpoints:[.endpoints[]?|{addresses,conditions,hostname,nodeName,targetRef:{kind:.targetRef.kind,name:.targetRef.name,uid:.targetRef.uid}}]}]}' 'NAME:.metadata.name,ADDRESS-TYPE:.addressType,ADDRESSES:.endpoints[*].addresses[*],READY:.endpoints[*].conditions.ready' || :
    collect_json endpoints 5 ns endpoints '{items:[.items[]?|{metadata:{name:.metadata.name,namespace:.metadata.namespace},subsets:[.subsets[]?|{ports,addresses:[.addresses[]?|{ip,nodeName,targetRef:{kind:.targetRef.kind,name:.targetRef.name}}],notReadyAddresses:[.notReadyAddresses[]?|{ip,nodeName,targetRef:{kind:.targetRef.kind,name:.targetRef.name}}]}]}]}' 'NAME:.metadata.name,READY:.subsets[*].addresses[*].ip,NOT-READY:.subsets[*].notReadyAddresses[*].ip' || :
    collect_json ingresses 10 ns ingresses.networking.k8s.io '{items:[.items[]?|{metadata:{name:.metadata.name,namespace:.metadata.namespace},spec:{ingressClassName:.spec.ingressClassName,defaultBackend:.spec.defaultBackend,rules:.spec.rules,tls:.spec.tls},status}]}' 'NAME:.metadata.name,CLASS:.spec.ingressClassName,HOSTS:.spec.rules[*].host,TLS-SECRETS:.spec.tls[*].secretName' || :
}

collect_storage() {
    collect_json pvcs 5 ns persistentvolumeclaims '{items:[.items[]?|{metadata:{name:.metadata.name,namespace:.metadata.namespace,creationTimestamp:.metadata.creationTimestamp},spec:{volumeName:.spec.volumeName,storageClassName:.spec.storageClassName,accessModes:.spec.accessModes,resources:.spec.resources,volumeMode:.spec.volumeMode},status}]}' 'NAME:.metadata.name,STATUS:.status.phase,VOLUME:.spec.volumeName,CAPACITY:.status.capacity.storage,CLASS:.spec.storageClassName' || :
}

resource_rows_json() {
    local p m w
    p=$(json_cache_path pods); m=$(json_cache_path metrics); w=$(json_cache_path workloads)
    jq -c --slurpfile mx "$m" --slurpfile wx "$w" "$JQ_QUANTITIES"'
      ($mx[0].items // [] | map({key:.metadata.name,value:.})|from_entries) as $metrics |
      [.items[]? | . as $p | ($metrics[.metadata.name] // null) as $m |
       {pod:.metadata.name,uid:.metadata.uid,ready:((([.status.containerStatuses[]?|select(.ready==true)]|length)|tostring)+"/"+((.spec.containers|length)|tostring)),
        status:statuslabel,phase:(.status.phase // "UNKNOWN"),active:activepod,
        restarts:([.status.containerStatuses[]?,.status.initContainerStatuses[]?,.status.ephemeralContainerStatuses[]?|.restartCount // 0]|add // 0),
        created:.metadata.creationTimestamp,age:(.metadata.creationTimestamp|age),ip:(.status.podIP // "-"),
        owner:owner($wx[0]),node:(.spec.nodeName // "UNSCHEDULED"),
        cpu:usage($m;"cpu"),memory:usage($m;"memory"),cpu_request:effective("requests";"cpu"),
        cpu_limit:effective("limits";"cpu"),memory_request:effective("requests";"memory"),memory_limit:effective("limits";"memory"),
        metrics_timestamp:($m.timestamp // "UNAVAILABLE"),metrics_window:($m.window // "UNAVAILABLE"),
        containers:([.spec.containers[]?,.spec.initContainers[]?,.spec.ephemeralContainers[]?|.name]|join(",")),
        images:([.spec.containers[]?,.spec.initContainers[]?,.spec.ephemeralContainers[]?|.image]|join(","))}]
    ' "$p"
}

resources_report() {
    collect_pods; collect_workloads; collect_metrics
    data_source pods; data_source metrics
    if ! has jq; then fallback_report pods; return; fi
    if [[ $(cache_status pods) != OK && $(cache_status pods) != EMPTY_RESULT ]]; then return 1; fi
    local rows
    rows=$(mktemp "$RUN_DIR/resource-rows.XXXXXX") || return 1
    if ! resource_rows_json > "$rows"; then printf 'RESOURCES\tPARSE_ERROR\n'; rm -f -- "$rows"; return 1; fi
    printf 'POD\tREADY\tSTATUS\tRESTARTS\tAGE\tCPU USED\tCPU REQ\tCPU LIMIT\tMEM USED\tMEM REQ\tMEM LIMIT\tCPU/REQ\tCPU/LIMIT\tMEM/REQ\tMEM/LIMIT\tNODE\tIP\tOWNER\tCONTAINERS\tIMAGES\n'
    jq -r --arg filter "${RESOURCE_FILTER:-}" --arg sort "${RESOURCE_SORT:-name}" "$JQ_QUANTITIES"'
      map(select($filter == "" or ([.pod,.node,.owner,.status,.containers,.images]|join(" ")|test($filter;"i")))) |
      (if $sort == "cpu" then sort_by(if (.cpu|type)=="number" then -.cpu else 0 end)
       elif $sort == "memory" then sort_by(if (.memory|type)=="number" then -.memory else 0 end)
       elif $sort == "restarts" then sort_by(-.restarts) elif $sort == "age" then sort_by(.created)
       elif $sort == "status" then sort_by(.status) elif $sort == "node" then sort_by(.node) else sort_by(.pod) end)[] |
      [.pod,.ready,.status,.restarts,.age,(.cpu|cpu_fmt),(.cpu_request|cpu_fmt),(.cpu_limit|cpu_fmt),
       (.memory|mem_fmt),(.memory_request|mem_fmt),(.memory_limit|mem_fmt),pct(.cpu;.cpu_request),pct(.cpu;.cpu_limit),
       pct(.memory;.memory_request),pct(.memory;.memory_limit),.node,.ip,.owner,.containers,.images]|@tsv' "$rows" || printf 'FILTER/FORMAT\tPARSE_ERROR (check regular expression)\n'
    jq -r "$JQ_QUANTITIES"'
      def total($k): map(select(.active)) as $a | [$a[]|.[$k]] as $v |
       if ($a|length)==0 then 0 elif any($v[]; . == "PARSE_ERROR") then "PARSE_ERROR"
       elif any($v[]; type != "number") then "INCOMPLETE [known="+(([$v[]|select(type=="number")]|add // 0)|round2|tostring)+"]" else ($v|add) end;
      "TOTALS (active pods; requests include init/sidecar peak and overhead; quantities are CPU millicores / memory bytes)",
      (["CPU USED",(total("cpu")|cpu_fmt),"CPU REQUEST",(total("cpu_request")|cpu_fmt),"CPU LIMIT",(total("cpu_limit")|cpu_fmt)]|@tsv),
      (["MEM USED",(total("memory")|mem_fmt),"MEM REQUEST",(total("memory_request")|mem_fmt),"MEM LIMIT",(total("memory_limit")|mem_fmt)]|@tsv),
      (["MEM MiB/GiB"] + (["memory","memory_request","memory_limit"]|map(. as $k | $k))|@tsv),
      (["MEM TOTALS MiB/GiB",(total("memory")|if type=="number" then "\((./1048576)|round2) / \((./1073741824)|round2)" else . end),
       (total("memory_request")|if type=="number" then "\((./1048576)|round2) / \((./1073741824)|round2)" else . end),
       (total("memory_limit")|if type=="number" then "\((./1048576)|round2) / \((./1073741824)|round2)" else . end)]|@tsv),
      (["METRICS UPDATED",([.[].metrics_timestamp|select(.!="UNAVAILABLE")]|min // "UNAVAILABLE"),"WINDOW",([.[].metrics_window]|unique|join(","))]|@tsv)
    ' "$rows"
    printf 'LIMITATIONS\tUNSET is not zero; UNBOUNDED means one or more container limits are absent; pod-level resources and active resize reservations are explicitly not inferred.\n'
    rm -f -- "$rows"
}

containers_report() {
    local selected=${1:-} p m
    collect_pods; collect_metrics
    data_source pods; data_source metrics
    if ! has jq; then fallback_report pods; return; fi
    p=$(json_cache_path pods); m=$(json_cache_path metrics)
    printf 'POD\tCONTAINER\tTYPE\tSTATE\tREADY\tRESTARTS\tCPU USED\tCPU REQ\tCPU LIMIT\tMEM USED\tMEM REQ\tMEM LIMIT\tIMAGE\tIMAGE ID\tLAST TERMINATION\n'
    jq -r --arg pod "$selected" --slurpfile mx "$m" "$JQ_QUANTITIES"'
      ($mx[0].items // [] | map({key:.metadata.name,value:.})|from_entries) as $metrics |
      .items[]? | select($pod=="" or .metadata.name==$pod) | . as $p |
      (([.spec.containers[]?|.+{sentinel_type:"APP"}])+([.spec.initContainers[]?|.+{sentinel_type:(if .restartPolicy=="Always" then "SIDECAR" else "INIT" end)}])+([.spec.ephemeralContainers[]?|.+{sentinel_type:"EPHEMERAL"}]))[] | . as $c |
      ([$p.status.containerStatuses[]?,$p.status.initContainerStatuses[]?,$p.status.ephemeralContainerStatuses[]?|select(.name==$c.name)][0] // {}) as $s |
      ([$metrics[$p.metadata.name].containers[]?|select(.name==$c.name)][0] // {}) as $m |
      [$p.metadata.name,.name,.sentinel_type,($s.state.waiting.reason // $s.state.terminated.reason // (if $s.state.running then "Running" else "UNKNOWN" end)),
       (if $s.ready==null then "UNKNOWN" else ($s.ready|tostring) end),($s.restartCount // 0),
       ($m.usage.cpu|q("cpu")|cpu_fmt),(.resources.requests.cpu|if .==null then "UNSET" else q("cpu") // "PARSE_ERROR" end|cpu_fmt),
       (.resources.limits.cpu|if .==null then "UNSET" else q("cpu") // "PARSE_ERROR" end|cpu_fmt),
       ($m.usage.memory|q("memory")|mem_fmt),(.resources.requests.memory|if .==null then "UNSET" else q("memory") // "PARSE_ERROR" end|mem_fmt),
       (.resources.limits.memory|if .==null then "UNSET" else q("memory") // "PARSE_ERROR" end|mem_fmt),.image,($s.imageID // "UNKNOWN"),
       ($s.lastState.terminated|if . then "\(.reason // "UNKNOWN") exit=\(.exitCode) at=\(.finishedAt)" else "-" end)]|@tsv' "$p"
}

workloads_report() {
    collect_workloads; data_source workloads
    if ! has jq; then fallback_report workloads; return; fi
    printf 'KIND\tNAME\tDESIRED\tREADY\tAVAILABLE\tUPDATED/SUCCEEDED\tSTATUS\tDETAIL\n'
    jq -r '.items[]? | . as $x |
      (if .kind=="DaemonSet" then (.status.desiredNumberScheduled // "UNKNOWN") elif .kind=="Job" then (.spec.completions // 1) elif .kind=="CronJob" then "N/A" else (.spec.replicas // 1) end) as $desired |
      (if .kind=="DaemonSet" then (.status.numberReady // 0) elif .kind=="Job" then (.status.succeeded // 0) elif .kind=="CronJob" then (.status.active // []|length) else (.status.readyReplicas // 0) end) as $ready |
      (if .kind=="CronJob" then (if .spec.suspend then "SUSPENDED" else "INFO" end)
       elif any(.status.conditions[]?; .type=="Failed" and .status=="True") then "FAIL"
       elif .kind=="Job" then (if $ready >= $desired then "OK" else "ACTIVE" end)
       elif .kind=="ReplicaSet" and $desired==0 then "SCALED_ZERO"
       elif ($desired|type)!="number" then "UNKNOWN_DESIRED"
       elif $ready < $desired then "FAIL"
       elif ((.status.observedGeneration // 0) < (.metadata.generation // 0)) then "WARN_UNOBSERVED"
       else "OK" end) as $health |
      [.kind,.metadata.name,$desired,$ready,(.status.availableReplicas // .status.numberAvailable // "N/A"),
       (.status.updatedReplicas // .status.updatedNumberScheduled // .status.succeeded // "N/A"),$health,
       ([.status.conditions[]?|select(.status=="False" or .type=="Failed")|(.reason // .type)+": "+(.message // "")]|join("; "))]|@tsv' "$(json_cache_path workloads)"
}

events_report() {
    local mode=${1:-all}
    collect_events; [[ $mode == csv || $mode == raw ]] || data_source events
    if ! has jq; then fallback_report events; return; fi
    local p; p=$(json_cache_path events)
    if [[ $mode == raw ]]; then jq . "$p"; return; fi
    jq -r --arg mode "$mode" '
      def fields: [.eventTime // .series.lastObservedTime // .lastTimestamp // .firstTimestamp // .metadata.creationTimestamp,
       .type,.reason,((.involvedObject.kind // "Object")+"/"+(.involvedObject.name // "UNKNOWN")),
       .involvedObject.namespace // .metadata.namespace,.message,(.series.count // .count // 1),(.reportingComponent // .source.component // "UNKNOWN")];
      (["TIMESTAMP","TYPE","REASON","OBJECT","NAMESPACE","MESSAGE","COUNT","SOURCE"] | if $mode=="csv" then @csv else @tsv end),
      ([.items[]? | select($mode!="warnings" or .type=="Warning") | fields] | sort_by(.[0])[] | if $mode=="csv" then @csv else @tsv end)
    ' "$p"
}

images_report() {
    collect_pods; data_source pods
    if ! has jq; then fallback_report pods; return; fi
    printf 'POD\tCONTAINER\tDECLARED IMAGE\tRUNTIME IMAGE ID\tTAG\tDECLARED DIGEST\tMUTABLE TAG\tDIGEST EVIDENCE\n'
    jq -r '.items[]? | . as $p | (.spec.containers[]?,.spec.initContainers[]?,.spec.ephemeralContainers[]?) | . as $c |
      ([$p.status.containerStatuses[]?,$p.status.initContainerStatuses[]?,$p.status.ephemeralContainerStatuses[]?|select(.name==$c.name)][0] // {}) as $s |
      (.image|split("@")|.[1] // "-") as $digest |
      (.image|split("@")|.[0]|split("/")|last|if contains(":") then split(":")|last else "latest (implicit)" end) as $tag |
      (.image|(try capture("@(?<d>sha256:[a-fA-F0-9]{64})$").d catch null) // null) as $declared |
      ($s.imageID // ""|(try capture("(?:@|://)(?<d>sha256:[a-fA-F0-9]{64})$").d catch null) // null) as $runtime |
      [$p.metadata.name,.name,.image,($s.imageID // "UNKNOWN"),$tag,$digest,(if $digest=="-" then "YES" else "NO (digest pinned)" end),
       (if $declared==null or $runtime==null then "NOT_VERIFIED" elif $declared==$runtime then "DIGEST_MATCH" else "POTENTIAL_DRIFT: index/manifest representation not verified" end)]|@tsv' "$(json_cache_path pods)"
}

nodes_report() {
    collect_pods; collect_workloads
    collect_json nodes 10 cluster nodes '{items:[.items[]?|{metadata:{name:.metadata.name,labels:.metadata.labels},spec:{unschedulable:.spec.unschedulable,taints:.spec.taints},status:{capacity:.status.capacity,allocatable:.status.allocatable,conditions:.status.conditions,nodeInfo:{kubeletVersion:.status.nodeInfo.kubeletVersion,osImage:.status.nodeInfo.osImage,containerRuntimeVersion:.status.nodeInfo.containerRuntimeVersion}}}]}' 'NAME:.metadata.name,CPU:.status.capacity.cpu,CPU-ALLOC:.status.allocatable.cpu,MEM:.status.capacity.memory,MEM-ALLOC:.status.allocatable.memory,UNSCHEDULABLE:.spec.unschedulable' || :
    collect_json nodemetrics 5 cluster nodes.metrics.k8s.io '{items:[.items[]?|{metadata:{name:.metadata.name},timestamp,window,usage}]}' '' || :
    data_source nodes; data_source nodemetrics
    if ! has jq; then fallback_report nodes; return; fi
    local rows
    rows=$(mktemp "$RUN_DIR/node-pods.XXXXXX") || return 1
    resource_rows_json > "$rows" || { printf 'NODE RESERVATIONS\tPARSE_ERROR\n'; rm -f -- "$rows"; return 1; }
    printf 'SCOPE\tCapacity/actual usage: entire node. Requested/limits/pods: selected namespace only. Cluster reservation headroom: UNKNOWN.\n'
    printf 'NODE\tPOOL / ROLE\tZONE\tCPU CAPACITY\tCPU ALLOC\tNS CPU REQ\tNS CPU LIMIT\tCPU USED\tCPU/ALLOC\tCPU ACTUAL HEADROOM\tMEM CAPACITY\tMEM ALLOC\tNS MEM REQ\tNS MEM LIMIT\tMEM USED\tMEM/ALLOC\tMEM ACTUAL HEADROOM\tNS PODS\tSTATUS\n'
    jq -r --slurpfile px "$rows" --slurpfile mx "$(json_cache_path nodemetrics)" --arg pods_status "$(cache_status pods)" "$JQ_QUANTITIES"'
      def reservation($a;$k): if $pods_status!="OK" and $pods_status!="EMPTY_RESULT" then $pods_status
        elif any($a[]; (.[$k]|type)!="number") then "INCOMPLETE" else ([$a[]|.[$k]]|add // 0) end;
      ($mx[0].items // []|map({key:.metadata.name,value:.})|from_entries) as $metrics |
      .items[]? | . as $n | [(.metadata.labels // {})|to_entries[]?|select(.key|test("(^|/)(nodepool|agentpool|pool)$|node-role.kubernetes.io/|nodegroup|node-pool"))|.key+"="+.value] as $labels |
      [$px[0][]|select(.node==$n.metadata.name and .active)] as $pods |
      ($metrics[.metadata.name].usage.cpu|q_state("cpu")) as $cpu | ($metrics[.metadata.name].usage.memory|q_state("memory")) as $mem |
      (.status.allocatable.cpu|q_state("cpu")) as $ca | (.status.allocatable.memory|q_state("memory")) as $ma |
      [.metadata.name,($labels|if length==0 then "UNDISCOVERED" else join(",") end),(.metadata.labels["topology.kubernetes.io/zone"] // "-"),
       (.status.capacity.cpu|q_state("cpu")|cpu_fmt),($ca|cpu_fmt),(reservation($pods;"cpu_request")|cpu_fmt),(reservation($pods;"cpu_limit")|cpu_fmt),($cpu|cpu_fmt),pct($cpu;$ca),
       (if ($cpu|type)=="number" and ($ca|type)=="number" then ($ca-$cpu|cpu_fmt) else "N/A" end),
       (.status.capacity.memory|q_state("memory")|mem_fmt),($ma|mem_fmt),(reservation($pods;"memory_request")|mem_fmt),(reservation($pods;"memory_limit")|mem_fmt),($mem|mem_fmt),pct($mem;$ma),
       (if ($mem|type)=="number" and ($ma|type)=="number" then ($ma-$mem|mem_fmt) else "N/A" end),
       (if $pods_status=="OK" or $pods_status=="EMPTY_RESULT" then ($pods|length) else $pods_status end),
       (([.status.conditions[]?|select((.type=="Ready" and .status!="True") or (.type!="Ready" and .status=="True"))|.type+"="+.status] + (if any(.status.conditions[]?;.type=="Ready") then [] else ["Ready=UNKNOWN"] end) + (if .spec.unschedulable then ["SchedulingDisabled"] else [] end))|if length==0 then "OK" else join(",") end)]|@tsv' "$(json_cache_path nodes)"
    printf 'NODE POOL GROUPS\nPOOL / ROLE\tNODE COUNT\n'
    jq -r '[.items[]?|{pool:([(.metadata.labels // {})|to_entries[]?|select(.key|test("(^|/)(nodepool|agentpool|pool)$|node-role.kubernetes.io/|nodegroup|node-pool"))|.key+"="+.value]|sort|if length==0 then "UNDISCOVERED" else join(",") end)}]|group_by(.pool)[]|[.[0].pool,length]|@tsv' "$(json_cache_path nodes)"
    rm -f -- "$rows"
}

network_rows_json() {
    jq -c --slurpfile px "$(json_cache_path pods)" --slurpfile sx "$(json_cache_path endpointslices)" --slurpfile ex "$(json_cache_path endpoints)" \
      --arg slices_state "$(cache_status endpointslices)" --arg endpoints_state "$(cache_status endpoints)" --arg pods_state "$(cache_status pods)" '
      def available($s): $s=="OK" or $s=="EMPTY_RESULT";
      [.items[]? | . as $svc |
       [($svc.spec.selector // {})|to_entries[]] as $selector |
       [$px[0].items[]? | select(($selector|length)>0) | . as $pod | select(all($selector[]; $pod.metadata.labels[.key]==.value))] as $pods |
       [$sx[0].items[]?|select(.metadata.labels["kubernetes.io/service-name"]==$svc.metadata.name)] as $slices |
       [$slices[].endpoints[]? | select(.conditions.ready != false)] as $ready |
       [$ex[0].items[]?|select(.metadata.name==$svc.metadata.name)] as $ep |
       (if available($slices_state) and ($slices|length)>0 then "EndpointSlice"
        elif available($endpoints_state) then "Endpoints"
        elif available($slices_state) then "EndpointSlice" else "UNKNOWN" end) as $source |
       (if $source=="EndpointSlice" then ([$ready[].addresses[]?]|unique|length)
        elif $source=="Endpoints" then ([$ep[].subsets[]?.addresses[]?.ip]|unique|length) else null end) as $count |
       (if $source=="EndpointSlice" then ([$ready[].targetRef|select(.kind=="Pod")|.name]|unique)
        elif $source=="Endpoints" then ([$ep[].subsets[]?.addresses[]?.targetRef|select(.kind=="Pod")|.name]|unique) else [] end) as $represented |
       {name:.metadata.name,type:(.spec.type // "ClusterIP"),cluster_ip:(.spec.clusterIP // "-"),
        selector:($selector|map(.key+"="+.value)|join(",")),
        pods:(if available($pods_state) then ($pods|map(.metadata.name)) else null end),
        ready_endpoints:$count,endpoint_source:$source,
        addresses:(if $source=="EndpointSlice" then [$ready[].addresses[]?]|unique elif $source=="Endpoints" then [$ep[].subsets[]?.addresses[]?.ip]|unique else [] end),
        ports:(.spec.ports // []|map("\(.port):\(.targetPort // .port)/\(.protocol // "TCP")")|join(",")),
        endpoint_ports:([$slices[].ports[]?|"\(.port // "UNKNOWN")/\(.protocol // "TCP")"]|unique|join(",")),
        external:([.status.loadBalancer.ingress[]?|.ip // .hostname]|join(",")),
        selector_ready_missing:([$pods[]|select(any(.status.conditions[]?; .type=="Ready" and .status=="True"))|.metadata.name] - $represented),
        status:(if .spec.type=="ExternalName" then "N/A_EXTERNAL_NAME"
          elif ($selector|length)==0 then "INFO_MANUAL_ENDPOINTS"
          elif .spec.clusterIP=="None" and $count==0 then "INFO_HEADLESS_NO_READY_ENDPOINTS"
          elif $count==null then "UNKNOWN_ENDPOINTS"
          elif $count==0 then "WARN_NO_READY_ENDPOINTS"
          elif .spec.type=="LoadBalancer" and (.status.loadBalancer.ingress // []|length)==0 then "WARN_LB_PENDING"
          elif available($pods_state) and ([$pods[]|select(any(.status.conditions[]?; .type=="Ready" and .status=="True"))|.metadata.name] - $represented|length)>0 then "WARN_READY_POD_NOT_REPRESENTED"
          else "OK" end)}]' "$(json_cache_path services)"
}

network_report() {
    collect_pods; collect_network
    data_source services; data_source endpointslices; data_source endpoints; data_source ingresses
    if ! has jq; then fallback_report services; fallback_report endpointslices; fallback_report ingresses; return; fi
    printf 'SERVICE\tTYPE\tCLUSTER IP\tSELECTOR\tMATCHED PODS\tREADY ADDRESSES\tSOURCE\tADDRESSES\tSERVICE PORTS\tENDPOINT PORTS\tEXTERNAL\tSTATUS\tMISSING READY PODS\n'
    network_rows_json | jq -r '.[]|[.name,.type,.cluster_ip,.selector,(.pods|if .==null then "UNKNOWN" else join(",") end),(.ready_endpoints // "UNKNOWN"),.endpoint_source,(.addresses|join(",")),.ports,.endpoint_ports,.external,.status,(.selector_ready_missing|join(","))]|@tsv'
    printf 'INGRESS\tCLASS\tHOST\tPATH\tSERVICE\tPORT\tTLS SECRET\tLOADBALANCER\n'
    jq -r '.items[]? | . as $i | (.spec.rules // [{}])[] | . as $r | (.http.paths // [{}])[] |
      [$i.metadata.name,($i.spec.ingressClassName // "default"),($r.host // "*"),(.path // "/"),(.backend.service.name // $i.spec.defaultBackend.service.name // "NON_SERVICE/UNKNOWN"),
       (.backend.service.port.number // .backend.service.port.name // $i.spec.defaultBackend.service.port.number // "-"),
       ([$i.spec.tls[]?|.secretName]|join(",")),([$i.status.loadBalancer.ingress[]?|.ip // .hostname]|join(","))]|@tsv' "$(json_cache_path ingresses)"
    printf 'INTERPRETATION\tReady EndpointSlice addresses use ready != false; address count can differ from pod count on dual-stack clusters. Pod identity is used for missing-backend findings. Selectorless and headless services require intent review.\n'
}

storage_report() {
    collect_storage
    collect_json pvs 300 cluster persistentvolumes '{items:[.items[]?|{metadata:{name:.metadata.name},spec:{capacity:.spec.capacity,accessModes:.spec.accessModes,persistentVolumeReclaimPolicy:.spec.persistentVolumeReclaimPolicy,storageClassName:.spec.storageClassName,claimRef:{namespace:.spec.claimRef.namespace,name:.spec.claimRef.name}},status}]}' 'NAME:.metadata.name,STATUS:.status.phase,CLASS:.spec.storageClassName,CAPACITY:.spec.capacity.storage,CLAIM-NS:.spec.claimRef.namespace,CLAIM:.spec.claimRef.name' || :
    collect_json storageclasses 300 cluster storageclasses.storage.k8s.io '{items:[.items[]?|{metadata:{name:.metadata.name},provisioner,reclaimPolicy,volumeBindingMode,allowVolumeExpansion}]}' 'NAME:.metadata.name,PROVISIONER:.provisioner,BINDING:.volumeBindingMode,RECLAIM:.reclaimPolicy' || :
    collect_json volumeattachments 30 cluster volumeattachments.storage.k8s.io '{items:[.items[]?|{metadata:{name:.metadata.name},spec:{attacher:.spec.attacher,nodeName:.spec.nodeName,source:{persistentVolumeName:.spec.source.persistentVolumeName}},status:{attached:.status.attached,attachError:.status.attachError,detachError:.status.detachError}}]}' 'NAME:.metadata.name,NODE:.spec.nodeName,PV:.spec.source.persistentVolumeName,ATTACHED:.status.attached' || :
    data_source pvcs; data_source pvs; data_source storageclasses; data_source volumeattachments
    if ! has jq; then fallback_report pvcs; fallback_report pvs; fallback_report storageclasses; fallback_report volumeattachments; return; fi
    printf 'PVC\tSTATUS\tVOLUME\tREQUEST\tCAPACITY\tACCESS\tSTORAGE CLASS\tCONDITIONS\n'
    jq -r '.items[]?|[.metadata.name,(.status.phase // "UNKNOWN"),(.spec.volumeName // "-"),(.spec.resources.requests.storage // "UNSET"),(.status.capacity.storage // "UNKNOWN"),(.spec.accessModes // []|join(",")),(.spec.storageClassName // "default"),([.status.conditions[]?|.type+"="+.status]|join(","))]|@tsv' "$(json_cache_path pvcs)"
    printf 'PV (selected namespace claims plus unbound volumes)\tSTATUS\tCAPACITY\tCLASS\tRECLAIM\tCLAIM\n'
    jq -r --arg ns "$SENTINEL_NAMESPACE" '.items[]?|select(.spec.claimRef.namespace==$ns or .spec.claimRef.namespace==null)|[.metadata.name,.status.phase,.spec.capacity.storage,.spec.storageClassName,.spec.persistentVolumeReclaimPolicy,((.spec.claimRef.namespace // "-")+"/"+(.spec.claimRef.name // "-"))]|@tsv' "$(json_cache_path pvs)"
    printf 'STORAGE CLASS\tPROVISIONER\tRECLAIM\tBINDING MODE\tEXPANSION\n'
    jq -r '.items[]?|[.metadata.name,.provisioner,.reclaimPolicy,.volumeBindingMode,(.allowVolumeExpansion // false)]|@tsv' "$(json_cache_path storageclasses)"
    printf 'VOLUME ATTACHMENT (selected namespace claims)\tNODE\tPV\tATTACHED\tERROR\n'
    jq -r --slurpfile px "$(json_cache_path pvcs)" '[$px[0].items[]?|.spec.volumeName] as $volumes | .items[]?|. as $v|select($volumes|index($v.spec.source.persistentVolumeName))|[.metadata.name,.spec.nodeName,.spec.source.persistentVolumeName,.status.attached,([.status.attachError.message,.status.detachError.message]|map(select(.!=null))|join("; "))]|@tsv' "$(json_cache_path volumeattachments)"
}

select_pod() {
    collect_pods
    local -a names=()
    if has jq; then mapfile -t names < <(jq -r '.items[]?.metadata.name' "$(json_cache_path pods)")
    elif [[ -s $CACHE_DIR/pods.txt ]]; then mapfile -t names < <(awk 'NR>1 {print $1}' "$CACHE_DIR/pods.txt"); fi
    ((${#names[@]})) || { printf 'POD SELECTION\t%s\n' "$(cache_status pods)"; return 1; }
    choose 'Select pod' "${names[@]}" || return 1
    SELECTED_POD=$REPLY
}

inspector_report() {
    local pod=$1 p
    collect_pods; collect_workloads; collect_events; collect_network; collect_storage
    data_source pods
    if ! has jq; then fallback_report pods; return; fi
    p=$(json_cache_path pods)
    if ! jq -e --arg name "$pod" 'any(.items[]?; .metadata.name==$name)' "$p" >/dev/null; then printf 'POD\tRESOURCE_NOT_FOUND\n'; return 1; fi
    jq -r --arg pod "$pod" --slurpfile wx "$(json_cache_path workloads)" "$JQ_QUANTITIES"'
      .items[]?|select(.metadata.name==$pod)|
      (["POD",.metadata.name,"OWNER",owner($wx[0]),"NODE",(.spec.nodeName // "UNSCHEDULED")]|@tsv),
      (["PHASE",.status.phase,"QOS",.status.qosClass,"IP",(.status.podIP // "-"),"SERVICE ACCOUNT",(.spec.serviceAccountName // "default")]|@tsv),
      ("CONDITIONS\tSTATUS\tREASON\tMESSAGE"),
      (.status.conditions[]?|[.type,.status,.reason,.message]|@tsv),
      ("REFERENCES (names only; no Secret values)\tCONTAINER / VOLUME\tNAME\tMOUNT / KEY"),
      ((.spec.containers[]?,.spec.initContainers[]?,.spec.ephemeralContainers[]?)|. as $c|
        (.env[]?|select(.valueFrom.secretKeyRef)|["SECRET ENV",$c.name,.valueFrom.secretKeyRef.name,.valueFrom.secretKeyRef.key]|@tsv),
        (.env[]?|select(.valueFrom.configMapKeyRef)|["CONFIGMAP ENV",$c.name,.valueFrom.configMapKeyRef.name,.valueFrom.configMapKeyRef.key]|@tsv),
        (.envFrom[]?|select(.secretRef)|["SECRET ENVFROM",$c.name,.secretRef.name,"keys not retrieved"]|@tsv),
        (.envFrom[]?|select(.configMapRef)|["CONFIGMAP ENVFROM",$c.name,.configMapRef.name,"-"]|@tsv),
        (.volumeMounts[]?|["VOLUME MOUNT",$c.name,.name,.mountPath]|@tsv)),
      (.spec.volumes[]?|. as $v|
        (select(.secret)|["SECRET VOLUME",.name,.secret.secretName,"-"]|@tsv),
        (select(.configMap)|["CONFIGMAP VOLUME",.name,.configMap.name,"-"]|@tsv),
        (select(.persistentVolumeClaim)|["PVC",.name,.persistentVolumeClaim.claimName,"-"]|@tsv),
        (.projected.sources[]?|select(.secret)|["PROJECTED SECRET",$v.name,.secret.name,"-"]|@tsv),
        (.projected.sources[]?|select(.configMap)|["PROJECTED CONFIGMAP",$v.name,.configMap.name,"-"]|@tsv))' "$p"
    containers_report "$pod"
    printf 'RELATED EVENTS\nTIMESTAMP\tTYPE\tREASON\tMESSAGE\tCOUNT\n'
    jq -r --arg pod "$pod" '[.items[]?|select(.involvedObject.kind=="Pod" and .involvedObject.name==$pod)|[.eventTime // .lastTimestamp // .metadata.creationTimestamp,.type,.reason,.message,.series.count // .count // 1]]|sort_by(.[0])[]|@tsv' "$(json_cache_path events)"
    printf 'SERVICE RELATIONSHIPS\nSERVICE\tREADY ENDPOINT ADDRESSES\tSTATUS\n'
    network_rows_json | jq -r --arg pod "$pod" '.[]|select(.pods!=null and (.pods|index($pod)))|[.name,.ready_endpoints,.status]|@tsv'
    printf 'CERTIFICATE REFERENCES\tReferenced Secret names above can be correlated in Certificate/TLS Auditor; Secret payloads are never included in inspection.\n'
}

inspector_menu() {
    local out
    select_pod || return
    out=$(mktemp "$RUN_DIR/inspector.XXXXXX") || return
    inspector_report "$SELECTED_POD" > "$out"
    view_file "$out" "Pod inspector: $SELECTED_POD"
    rm -f -- "$out"
}

findings_add() {
    local severity=$1 category=$2 resource=$3 issue=$4 evidence=$5 field
    local -a fields=()
    for field in "$severity" "$category" "$resource" "$issue" "$evidence"; do
        field=${field//$'\t'/ }; field=${field//$'\n'/ }; field=${field//$'\r'/ }
        fields+=("$field")
    done
    printf '%s\t%s\t%s\t%s\t%s\n' "${fields[@]}" | redact >> "$RUN_DIR/findings.tsv"
}

findings_ingest() {
    local severity category resource issue evidence
    while IFS=$'\t' read -r severity category resource issue evidence; do
        [[ -n $severity ]] && findings_add "$severity" "$category" "$resource" "$issue" "${evidence:-OBSERVED API status}"
    done
}

health_pod_findings() {
    jq -r "$JQ_QUANTITIES"'
      .items[]? | . as $p | ("Pod/"+.metadata.name) as $name |
      (if .status.phase=="Failed" then ["FAIL","PODS",$name,"Pod failed: "+(.status.reason // "Failed"),"OBSERVED pod phase/reason"]
       elif .status.phase=="Pending" then ["WARN","PODS",$name,"Pod Pending","OBSERVED pod phase; scheduling events below"]
       elif .status.phase=="Running" and any(.status.conditions[]?;.type=="Ready" and .status!="True") then ["FAIL","PODS",$name,"Running pod is not Ready","OBSERVED Pod Ready condition"]
       elif .status.phase=="Running" and (any(.status.conditions[]?;.type=="Ready")|not) then ["UNKNOWN","PODS",$name,"Pod Ready condition is absent","Readiness NOT VERIFIED; Running phase alone does not prove readiness"]
       elif .status.phase==null or .status.phase=="Unknown" then ["UNKNOWN","PODS",$name,"Pod phase unavailable or Unknown","OBSERVED status.phase"] else empty end | @tsv),
      (.status.conditions[]?|select(.type=="PodScheduled" and .status=="False")|["WARN","SCHEDULING",$name,(.reason // "Unschedulable")+": "+(.message // ""),"OBSERVED PodScheduled=False"]|@tsv),
      ((.status.containerStatuses[]?,.status.initContainerStatuses[]?,.status.ephemeralContainerStatuses[]?)|. as $c |
        (if (.state.waiting.reason // "" | test("CrashLoopBackOff|ImagePullBackOff|ErrImagePull|CreateContainerConfigError|CreateContainerError|RunContainerError|InvalidImageName")) then
          ["FAIL","CONTAINERS",($name+"/"+.name),.state.waiting.reason+": "+(.state.waiting.message // ""),"OBSERVED waiting container status"]
         elif .state.waiting.reason=="ContainerCreating" and (now-($p.metadata.creationTimestamp|epoch // now))>300 then
          ["WARN","CONTAINERS",($name+"/"+.name),"ContainerCreating; pod older than 5 minutes","OBSERVED pod age; container wait start is not reported"] else empty end|@tsv),
        (if .state.terminated.reason=="OOMKilled" then ["FAIL","CONTAINERS",($name+"/"+.name),"Current termination OOMKilled","OBSERVED state.terminated.reason"]
         elif .lastState.terminated.reason=="OOMKilled" then ["WARN","CONTAINERS",($name+"/"+.name),"Previous termination OOMKilled","OBSERVED lastState; may be recovered"] else empty end|@tsv),
        (if .ready==false and $p.status.phase=="Running" and (([$p.spec.containers[]?.name]+[$p.spec.initContainers[]?|select(.restartPolicy=="Always")|.name]|index($c.name))!=null) then
          ["WARN","CONTAINERS",($name+"/"+.name),"Container is not ready","OBSERVED container ready=false; readiness timing/intent requires review"] else empty end|@tsv),
        (if (.restartCount // 0)>=5 then ["WARN","RESTARTS",($name+"/"+.name),"Restart count "+(.restartCount|tostring),"OBSERVED cumulative count; not a restart rate"] else empty end|@tsv)),
      (if .metadata.deletionTimestamp!=null then ["INFO","PODS",$name,"Pod terminating","OBSERVED deletionTimestamp"] else empty end|@tsv)
    ' "$(json_cache_path pods)" | findings_ingest
}

health_workload_findings() {
    jq -r '
      .items[]? | ("\(.kind)/\(.metadata.name)") as $name |
      (if .kind=="DaemonSet" then (.status.desiredNumberScheduled // null) else (.spec.replicas // 1) end) as $desired |
      (if .kind=="DaemonSet" then (.status.numberReady // 0) else (.status.readyReplicas // 0) end) as $ready |
      (if .kind=="DaemonSet" and $desired==null then ["UNKNOWN","WORKLOADS",$name,"Desired scheduled count is absent","DaemonSet availability NOT VERIFIED"] else empty end|@tsv),
      (if (.kind=="Deployment" or .kind=="StatefulSet" or .kind=="DaemonSet") and ($desired|type)=="number" and $ready < $desired then
        ["FAIL","WORKLOADS",$name,"Ready replicas \($ready)/\($desired)","OBSERVED desired and ready counts"] else empty end|@tsv),
      (if .kind=="Deployment" and (.status.availableReplicas // 0)<$desired then
        ["FAIL","WORKLOADS",$name,"Available replicas \(.status.availableReplicas // 0)/\($desired)","OBSERVED deployment availability"] else empty end|@tsv),
      (if .kind=="StatefulSet" and .status.currentRevision!=null and .status.updateRevision!=null and .status.currentRevision!=.status.updateRevision then
        ["WARN","WORKLOADS",$name,"Current and update revisions differ","OBSERVED rollout state; update strategy may intentionally partition"] else empty end|@tsv),
      (if .kind=="Job" and any(.status.conditions[]?;.type=="Failed" and .status=="True") then
        ["FAIL","JOBS",$name,"Job Failed",([.status.conditions[]?|select(.type=="Failed")|.reason // "Failed"]|join(","))] else empty end|@tsv),
      (if .kind=="CronJob" and .spec.suspend==true then ["INFO","CRONJOBS",$name,"CronJob suspended","OBSERVED spec.suspend; intent not inferred"] else empty end|@tsv),
      (if .kind!="Job" and .kind!="CronJob" and (.metadata.generation // 0)>(.status.observedGeneration // 0) then
        ["WARN","WORKLOADS",$name,"Controller has not observed latest generation","OBSERVED metadata.generation > status.observedGeneration"] else empty end|@tsv)
    ' "$(json_cache_path workloads)" | findings_ingest
}

health_network_findings() {
    network_rows_json | jq -r '.[]|select(.status|startswith("WARN"))|
      ["WARN","NETWORK",("Service/"+.name),.status,("OBSERVED "+.endpoint_source+" ready addresses="+(.ready_endpoints|tostring)+" missing ready pods="+(.selector_ready_missing|join(",")))]|@tsv' | findings_ingest
    jq -r '.items[]?|select(.status.phase=="Lost" or .status.phase=="Pending")|
      [(if .status.phase=="Lost" then "FAIL" else "WARN" end),"STORAGE",("PVC/"+.metadata.name),"PVC "+.status.phase,"OBSERVED PVC phase; Pending may be WaitForFirstConsumer"]|@tsv' "$(json_cache_path pvcs)" | findings_ingest
    jq -r --arg ns "$SENTINEL_NAMESPACE" '.items[]?|select(.spec.claimRef.namespace==$ns and (.status.phase=="Released" or .status.phase=="Failed"))|
      [(if .status.phase=="Failed" then "FAIL" else "WARN" end),"STORAGE",("PV/"+.metadata.name),"PV "+.status.phase,"OBSERVED PV phase; reclaim policy/intent require review"]|@tsv' "$(json_cache_path pvs)" | findings_ingest
    jq -r --slurpfile px "$(json_cache_path pvcs)" '[$px[0].items[]?|.spec.volumeName] as $volumes | .items[]?|. as $v|select($volumes|index($v.spec.source.persistentVolumeName))|
      select(.status.attachError!=null or .status.detachError!=null)|["FAIL","STORAGE",("VolumeAttachment/"+.metadata.name),([.status.attachError.message,.status.detachError.message]|map(select(.!=null))|join("; ")),"OBSERVED attach/detach error"]|@tsv' "$(json_cache_path volumeattachments)" | findings_ingest
}

health_event_findings() {
    jq -r '
      [.items[]?|select(.type=="Warning")]|group_by([.involvedObject.uid,.involvedObject.name,.reason,.message])[]|.[0] as $e|
      ["WARN","EVENTS",(($e.involvedObject.kind // "Object")+"/"+($e.involvedObject.name // "UNKNOWN")),
       ($e.reason // "Warning")+": "+($e.message // ""),
       ("OBSERVED retained event count="+([.[]|.series.count // .count // 1]|add|tostring)+" latest="+([.[]|.eventTime // .lastTimestamp // .metadata.creationTimestamp]|max // "UNKNOWN"))]|@tsv
    ' "$(json_cache_path events)" | findings_ingest
    # Exact object links only: no inference that a shared symptom proves causation.
    jq -r --slurpfile px "$(json_cache_path pods)" --slurpfile wx "$(json_cache_path workloads)" "$JQ_QUANTITIES"'
      .items[]?|select(.reason=="FailedScheduling" and .involvedObject.kind=="Pod")|. as $e|
      $px[0].items[]?|select(.metadata.name==$e.involvedObject.name and .status.phase=="Pending" and ($e.involvedObject.uid==null or .metadata.uid==$e.involvedObject.uid))|
      . as $p | owner($wx[0]) as $owner |
      ["INFO","CORRELATION",("Pod/"+.metadata.name),
       ($owner+" -> Pod Pending -> FailedScheduling -> "+($e.message // "reason unavailable")),
       "OBSERVED owner/event chain; root cause NOT VERIFIED"]|@tsv' "$(json_cache_path events)" | findings_ingest
}

health_pressure_findings() {
    resource_rows_json | jq -r --argjson cw "${CPU_WARN:-80}" --argjson cc "${CPU_CRIT:-90}" --argjson mw "${MEM_WARN:-80}" --argjson mc "${MEM_CRIT:-90}" '
      .[]|select(.active)|. as $p |
      (["cpu","memory","cpu_request","cpu_limit","memory_request","memory_limit"][] as $k|
        select($p[$k]=="PARSE_ERROR" or $p[$k]=="INCOMPLETE" or $p[$k]=="UNSUPPORTED_POD_LEVEL" or $p[$k]=="RESIZE_NOT_VERIFIED")|
        ["UNKNOWN","RESOURCE_PRESSURE",("Pod/"+$p.pod),($k+"="+$p[$k]),"Resource pressure NOT VERIFIED for this quantity"]|@tsv),
      ([{label:"CPU",used:.cpu,base:.cpu_request,denominator:"request",warn:$cw,critical:$cc},
        {label:"CPU",used:.cpu,base:.cpu_limit,denominator:"limit",warn:$cw,critical:$cc},
        {label:"MEM",used:.memory,base:.memory_request,denominator:"request",warn:$mw,critical:$mc},
        {label:"MEM",used:.memory,base:.memory_limit,denominator:"limit",warn:$mw,critical:$mc}][] |
       select((.used|type)=="number" and (.base|type)=="number" and .base>0)|(.used/.base*100) as $pc|select($pc>.warn)|
       [(if $pc>.critical and .denominator=="limit" then "FAIL" else "WARN" end),"RESOURCE_PRESSURE",("Pod/"+$p.pod),
        .label+"/"+.denominator+"="+(($pc*10|round/10)|tostring)+"%",
        "OBSERVED usage / "+.denominator+"; request saturation is not node pressure"]|@tsv)' | findings_ingest
    jq -r --slurpfile mx "$(json_cache_path nodemetrics)" --argjson cw "${CPU_WARN:-80}" --argjson cc "${CPU_CRIT:-90}" --argjson mw "${MEM_WARN:-80}" --argjson mc "${MEM_CRIT:-90}" "$JQ_QUANTITIES"'
      ($mx[0].items // []|map({key:.metadata.name,value:.})|from_entries) as $metrics |
      .items[]?|. as $n|($metrics[.metadata.name]) as $m|
      (if any(.status.conditions[]?;.type=="Ready") then empty else ["UNKNOWN","NODES",("Node/"+.metadata.name),"Node Ready condition is absent","Node readiness NOT VERIFIED"] end|@tsv),
      ([{r:"cpu",label:"CPU"},{r:"memory",label:"MEM"}][]|. as $d|
        ($n.status.allocatable[$d.r]|q_state($d.r)) as $alloc|($m.usage[$d.r]|q_state($d.r)) as $usage|
        select(($alloc|type)!="number" or $usage=="PARSE_ERROR")|
        ["UNKNOWN","NODE_PRESSURE",("Node/"+$n.metadata.name),($d.label+" allocatable="+($alloc|tostring)+" usage="+($usage|tostring)),"Node utilization NOT VERIFIED"]|@tsv),
      (.status.conditions[]?|select((.type=="Ready" and .status!="True") or (.type!="Ready" and .status=="True"))|
       ["FAIL","NODES",("Node/"+$n.metadata.name),(.type+"="+.status+": "+(.reason // "")),"OBSERVED node condition"]|@tsv),
      ([{r:"cpu",label:"CPU",warn:$cw,critical:$cc},{r:"memory",label:"MEM",warn:$mw,critical:$mc}][]|. as $d|
       ($m.usage[$d.r]|q($d.r)) as $used|($n.status.allocatable[$d.r]|q($d.r)) as $base|
       select($used!=null and $base!=null and $base>0)|($used/$base*100) as $pc|select($pc>$d.warn)|
       [(if $pc>$d.critical then "FAIL" else "WARN" end),"NODE_PRESSURE",("Node/"+$n.metadata.name),$d.label+"/allocatable="+(($pc*10|round/10)|tostring)+"%","OBSERVED node usage divided by allocatable"]|@tsv)
    ' "$(json_cache_path nodes)" | findings_ingest
}

health_report() {
    local key state overall=0 unknown=0 ok=0 failed=0 warnings=0 collector
    : > "$RUN_DIR/findings.tsv"
    collect_pods; collect_workloads; collect_metrics; collect_events
    # Reports here prime the same caches used by interactive views and evidence.
    network_report >/dev/null
    storage_report >/dev/null
    nodes_report >/dev/null
    if declare -F gitops_report >/dev/null; then gitops_report >/dev/null; fi
    if declare -F helm_report >/dev/null; then helm_report >/dev/null; fi
    if declare -F certificates_report >/dev/null; then certificates_report >/dev/null; fi
    printf 'KUBERNETES HEALTH & READINESS\nCONTEXT\t%s\nNAMESPACE\t%s\nTIME\t%s\n' "$SENTINEL_CONTEXT" "$SENTINEL_NAMESPACE" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'AUTHENTICATION\t%s\nAPI\t%s\nAPI LATENCY\t%s\nRBAC\t%s\n' "${AUTH_STATUS:-UNKNOWN}" "${API_STATUS:-UNKNOWN}" "${API_LATENCY:-UNKNOWN}" "${RBAC_STATUS:-UNKNOWN}"
    case ${AUTH_STATUS:-UNKNOWN}:${API_STATUS:-UNKNOWN} in *AUTH_ERROR*|*AUTH_REQUIRED*|*NETWORK_ERROR*|*API_TIMEOUT*) overall=3 ;; esac
    printf 'CATEGORY\tCOLLECTOR STATUS\tCACHE AGE (sec)\n'
    for key in pods workloads services endpointslices endpoints ingresses pvcs pvs storageclasses volumeattachments events nodes metrics nodemetrics flux_gitrepositories flux_kustomizations flux_helmrepositories flux_helmreleases helm cert_certificates cert_certificaterequests cert_issuers cert_clusterissuers tls_certificates; do
        state=$(cache_status "$key")
        printf '%s\t%s\t%s\n' "$key" "$state" "$(cache_age "$key")"
        case $state in
            OK|EMPTY_RESULT) ((ok+=1)) ;;
            RESOURCE_NOT_FOUND|NOT_CONFIGURED)
                case $key in flux_*|cert_*|endpointslices|endpoints) findings_add INFO CAPABILITY "$key" 'Not installed or not served' "$state" ;; *) ((unknown+=1)); findings_add UNKNOWN CAPABILITY "$key" 'Data unavailable' "$state" ;; esac ;;
            AUTH_ERROR|AUTH_REQUIRED|NETWORK_ERROR|API_TIMEOUT) overall=3; ((unknown+=1)); findings_add UNKNOWN API "$key" 'Collector unavailable' "$state" ;;
            *) ((unknown+=1)); findings_add UNKNOWN CAPABILITY "$key" 'Coverage unavailable; no healthy/zero claim' "$state" ;;
        esac
    done
    if has jq; then
        for collector in health_pod_findings health_workload_findings health_network_findings health_event_findings health_pressure_findings; do
            if ! "$collector"; then findings_add UNKNOWN ANALYSIS "$collector" 'PARSE_ERROR' 'Analysis incomplete; inspect collector diagnostics'; ((unknown+=1)); fi
        done
        if declare -F gitops_findings >/dev/null; then gitops_findings; fi
        if declare -F certificates_findings >/dev/null; then certificates_findings; fi
    else
        findings_add UNKNOWN ANALYSIS namespace 'Structured health analysis requires jq' 'Observed custom-column tables are available in resource views'
    fi
    if has awk; then
        awk '!seen[$0]++' "$RUN_DIR/findings.tsv" > "$RUN_DIR/findings-unique.tsv"
        mv -- "$RUN_DIR/findings-unique.tsv" "$RUN_DIR/findings.tsv"
        failed=$(awk -F '\t' '$1=="FAIL" || $1=="CRITICAL" {n++} END{print n+0}' "$RUN_DIR/findings.tsv")
        warnings=$(awk -F '\t' '$1=="WARN" {n++} END{print n+0}' "$RUN_DIR/findings.tsv")
    fi
    ((failed>0 && overall!=3)) && overall=1
    printf '\nFINDINGS\nSEVERITY\tCATEGORY\tRESOURCE\tISSUE\tEVIDENCE\n'
    cat -- "$RUN_DIR/findings.tsv"
    printf '\nCOUNTS\tFAIL %s\tWARN %s\tAVAILABLE COLLECTORS %s\tUNKNOWN COLLECTORS %s\n' "$failed" "$warnings" "$ok" "$unknown"
    printf 'INTERPRETATION\tCounts describe observed findings and evidence coverage; no percentage health score. Warning events may describe recovered historical conditions.\n'
    printf 'EXIT STATUS\t%s\t0=no observed FAIL (coverage may be incomplete); 1=operational FAIL; 3=authentication/API failure\n' "$overall"
    return "$overall"
}

summary_report() {
    local key
    collect_pods; collect_workloads; collect_metrics; collect_storage; collect_events
    if ! has jq; then fallback_report pods; return; fi
    printf 'LIVE SUMMARY\tSOURCE Kubernetes APIs / metrics.k8s.io\tPODS %s\tMETRICS %s\tCACHE %ss\n' "$(cache_status pods)" "$(cache_status metrics)" "$(cache_age pods)"
    if [[ $(cache_status pods) == OK || $(cache_status pods) == EMPTY_RESULT ]]; then
        jq -r '
          (["PODS",(.items|length),"READY",([.items[]?|select(any(.status.conditions[]?;.type=="Ready" and .status=="True"))]|length),
           "FAILED",([.items[]?|select(.status.phase=="Failed")]|length),"PENDING",([.items[]?|select(.status.phase=="Pending")]|length),
           "RESTARTS",([.items[]?|.status.containerStatuses[]?,.status.initContainerStatuses[]?|.restartCount // 0]|add // 0)]|@tsv)
        ' "$(json_cache_path pods)"
    fi
    for key in workloads pvcs events; do
        case $(cache_status "$key") in
            OK|EMPTY_RESULT)
                case $key in
                    workloads) jq -r '["Deployment","StatefulSet","DaemonSet"][] as $k | [.items[]?|select(.kind==$k)] as $w |
                      [$k,(if $k=="DaemonSet" and any($w[];.status.desiredNumberScheduled==null) then "UNKNOWN" else ([ $w[]|select((if $k=="DaemonSet" then (.status.numberReady // 0)>=(.status.desiredNumberScheduled // 0) else (.status.readyReplicas // 0)>=(.spec.replicas // 1) end))]|length|tostring) end)+"/"+($w|length|tostring)]|@tsv' "$(json_cache_path workloads)" ;;
                    pvcs) jq -r '["PVC BOUND",([.items[]?|select(.status.phase=="Bound")]|length|tostring)+"/"+(.items|length|tostring)]|@tsv' "$(json_cache_path pvcs)" ;;
                    events) jq -r '["WARNING EVENTS",([.items[]?|select(.type=="Warning")]|length)]|@tsv' "$(json_cache_path events)" ;;
                esac ;;
            *) printf '%s\t%s\n' "$key" "$(cache_status "$key")" ;;
        esac
    done
    if [[ $(cache_status pods) != OK && $(cache_status pods) != EMPTY_RESULT ]]; then
        printf 'RESOURCE TOTALS\t%s (pod inventory unavailable)\n' "$(cache_status pods)"
    else
      resource_rows_json | jq -r "$JQ_QUANTITIES"'
      map(select(.active)) as $a |
      def sumknown($k): [$a[]|.[$k]] as $v | if any($v[];type!="number") then "INCOMPLETE" else ($v|add // 0) end;
      (["CPU USED",(sumknown("cpu")|cpu_fmt),"CPU REQUEST",(sumknown("cpu_request")|cpu_fmt),"MEM USED",(sumknown("memory")|mem_fmt),"MEM REQUEST",(sumknown("memory_request")|mem_fmt)]|@tsv),
      "TOP CPU (active pods)",
      ($a|map(select((.cpu|type)=="number"))|sort_by(-.cpu)|.[:5][]|[.pod,(.cpu|cpu_fmt),(.cpu_request|cpu_fmt),(.cpu_limit|cpu_fmt),pct(.cpu;.cpu_request),.node]|@tsv),
      "TOP MEMORY (active pods)",
      ($a|map(select((.memory|type)=="number"))|sort_by(-.memory)|.[:5][]|[.pod,(.memory|mem_fmt),(.memory_request|mem_fmt),(.memory_limit|mem_fmt),pct(.memory;.memory_request),.node]|@tsv)'
    fi
    printf 'FLUX\t%s\tHELM\t%s\tCERTIFICATES\t%s\n' "$(cache_status flux_kustomizations)" "$(cache_status helm)" "$(cache_status cert_certificates)"
    if [[ -s $RUN_DIR/findings.tsv ]]; then printf 'RECENT FINDINGS (from last health audit; refresh Health for complete checks)\n'; awk 'NR<=5' "$RUN_DIR/findings.tsv"; fi
}

resource_self_tests() {
    has jq || { printf 'SKIP resource arithmetic: jq unavailable\n'; return 0; }
    local result
    result=$(jq -n "$JQ_QUANTITIES"'
      [
       ("250m"|q("cpu"))==250, ("1"|q("cpu"))==1000, ("2.5"|q("cpu"))==2500,
       ("250000000n"|q("cpu"))==250, ("500000u"|q("cpu"))==500,
       ("512Mi"|q("memory"))==536870912, ("2Gi"|q("memory"))==2147483648,
       ("1Ti"|q("memory"))==1099511627776, ("1G"|q("memory"))==1000000000,
       ("1e3"|quantity)==1000, ("broken"|quantity)==null,
       ({spec:{containers:[{resources:{requests:{cpu:"500m"}}}],initContainers:[{resources:{requests:{cpu:"2"}}}],overhead:{cpu:"50m"}}}|effective("requests";"cpu"))==2050,
       ({spec:{containers:[{resources:{requests:{cpu:"1"}}}],initContainers:[{restartPolicy:"Always",resources:{requests:{cpu:"200m"}}},{resources:{requests:{cpu:"2"}}},{restartPolicy:"Always",resources:{requests:{cpu:"300m"}}}],overhead:{cpu:"50m"}}}|effective("requests";"cpu"))==2250,
       ({spec:{containers:[{resources:{requests:{cpu:"1"}}},{resources:{requests:{cpu:"broken"}}}]}}|effective("requests";"cpu"))=="PARSE_ERROR",
       ({spec:{containers:[{}]}}|effective("requests";"cpu"))=="UNSET",
       ({spec:{containers:[{}]}}|effective("limits";"cpu"))=="UNBOUNDED",
       ({spec:{containers:[{}],resources:{requests:{cpu:"1"}}}}|effective("requests";"cpu"))=="UNSUPPORTED_POD_LEVEL"
      ] | if all(.[]; .==true) then "PASS resource quantity/effective-request invariants" else error("resource arithmetic invariant failed: \(.)") end' -r) || return 1
    printf '%s\n' "$result"
}

# Offline report tests run in an isolated subshell. They never contact a cluster,
# change the caller's functions, or leave an application supporting source file.
resource_integration_tests() (
    has jq || { printf 'SKIP resource report fixtures: jq unavailable\n'; exit 0; }
    local test_root rc func errors=0
    test_root=$(mktemp -d "$RUN_DIR/resource-fixtures.XXXXXX") || exit 1
    trap 'rm -rf -- "$test_root"' EXIT
    RUN_DIR=$test_root CACHE_DIR=$test_root/cache
    mkdir -p "$CACHE_DIR" || exit 1
    SENTINEL_NAMESPACE=fixture-ns SENTINEL_CONTEXT=fixture-context
    AUTH_STATUS=AUTHENTICATED API_STATUS=OK API_LATENCY='fixture' RBAC_STATUS=OK
    FORCE_REFRESH=0 RESOURCE_FILTER= RESOURCE_SORT=name
    cache_status() { if [[ -f $CACHE_DIR/$1.status ]]; then cat "$CACHE_DIR/$1.status"; else printf 'NOT_COLLECTED\n'; fi; }
    cache_age() { printf '0\n'; }
    collect_json() {
        local key=$1 projection=$5 fixture="$RUN_DIR/$1.fixture.json"
        printf '%s\n' "$key" >> "$RUN_DIR/calls"
        if [[ ${FIXTURE_DENIED:-} == "$key" ]]; then
            rm -f -- "$CACHE_DIR/$key.json"
            printf 'RBAC_DENIED\n' > "$CACHE_DIR/$key.status"; return 1
        fi
        [[ -s $fixture ]] || printf '{"items":[]}\n' > "$fixture"
        if jq "$projection" "$fixture" > "$CACHE_DIR/$key.json"; then
            printf 'OK\n' > "$CACHE_DIR/$key.status"
        else printf 'PARSE_ERROR\n' > "$CACHE_DIR/$key.status"; return 1; fi
    }
    # Isolate optional modules: the focused fixture suite has no external CLI calls.
    gitops_report() { :; }; helm_report() { :; }; certificates_report() { :; }
    gitops_findings() { :; }; certificates_findings() { :; }
    cat > "$RUN_DIR/pods.fixture.json" <<'JSON'
{"items":[{"kind":"Pod","metadata":{"name":"fixture-pod","uid":"fixture-uid","namespace":"fixture-ns","creationTimestamp":"2026-01-01T00:00:00Z","labels":{"app":"fixture"},"ownerReferences":[{"kind":"ReplicaSet","name":"fixture-rs","controller":true}]},"spec":{"nodeName":"fixture-node","containers":[{"name":"app","image":"fixture/app:latest","env":[{"name":"CONFIG","value":"OMIT_LITERAL_VALUE"},{"name":"FROM_SECRET","valueFrom":{"secretKeyRef":{"name":"settings","key":"keyname"}}}],"command":["OMIT_COMMAND"],"resources":{"requests":{"cpu":"1","memory":"512Mi"},"limits":{"cpu":"2","memory":"1Gi"}},"volumeMounts":[{"name":"config","mountPath":"/etc/config"}]}],"initContainers":[{"name":"sidecar","restartPolicy":"Always","image":"fixture/sidecar:v1","resources":{"requests":{"cpu":"200m","memory":"10Mi"},"limits":{"cpu":"500m","memory":"100Mi"}}}],"volumes":[{"name":"config","secret":{"secretName":"settings"}}],"overhead":{"cpu":"50m","memory":"5Mi"}},"status":{"phase":"Running","qosClass":"Burstable","podIP":"192.0.2.1","conditions":[{"type":"Ready","status":"False"}],"containerStatuses":[{"name":"app","ready":false,"restartCount":8,"state":{"waiting":{"reason":"CrashLoopBackOff","message":"fixture failure"}},"lastState":{"terminated":{"reason":"OOMKilled","exitCode":137,"finishedAt":"2026-01-01T01:00:00Z"}}}],"initContainerStatuses":[{"name":"sidecar","ready":true,"restartCount":0,"state":{"running":{"startedAt":"2026-01-01T00:00:01Z"}}}]}}]}
JSON
    cat > "$RUN_DIR/workloads.fixture.json" <<'JSON'
{"items":[{"kind":"Deployment","metadata":{"name":"fixture","generation":2},"spec":{"replicas":2},"status":{"readyReplicas":0,"availableReplicas":0,"observedGeneration":1}},{"kind":"ReplicaSet","metadata":{"name":"fixture-rs","ownerReferences":[{"kind":"Deployment","name":"fixture","controller":true}]},"spec":{"replicas":2},"status":{"readyReplicas":0}}]}
JSON
    cat > "$RUN_DIR/metrics.fixture.json" <<'JSON'
{"items":[{"metadata":{"name":"fixture-pod"},"timestamp":"2026-01-01T02:00:00Z","window":"30s","containers":[{"name":"app","usage":{"cpu":"312000000n","memory":"600Mi"}},{"name":"sidecar","usage":{"cpu":"50000000n","memory":"20Mi"}}]}]}
JSON
    cat > "$RUN_DIR/services.fixture.json" <<'JSON'
{"items":[{"metadata":{"name":"fixture"},"spec":{"selector":{"app":"fixture"},"type":"ClusterIP","clusterIP":"192.0.2.10","ports":[{"port":80,"targetPort":8080}]}},{"metadata":{"name":"headless"},"spec":{"selector":{"app":"fixture"},"clusterIP":"None","ports":[{"port":80}]}},{"metadata":{"name":"external"},"spec":{"type":"ExternalName","externalName":"example.invalid"}}]}
JSON
    cat > "$RUN_DIR/endpointslices.fixture.json" <<'JSON'
{"items":[{"metadata":{"name":"fixture-1","labels":{"kubernetes.io/service-name":"fixture"}},"ports":[{"port":8080}],"endpoints":[{"addresses":["192.0.2.1"],"conditions":{"ready":true},"targetRef":{"kind":"Pod","name":"fixture-pod"}}]}]}
JSON
    printf '{"items":[{"metadata":{"name":"headless"}}]}\n' > "$RUN_DIR/endpoints.fixture.json"
    cat > "$RUN_DIR/events.fixture.json" <<'JSON'
{"items":[{"metadata":{"name":"warning","namespace":"fixture-ns","creationTimestamp":"2026-01-01T00:00:00Z"},"lastTimestamp":"2026-01-01T02:00:00Z","type":"Warning","reason":"BackOff","involvedObject":{"kind":"Pod","name":"fixture-pod","namespace":"fixture-ns","uid":"fixture-uid"},"message":"Back-off restarting failed container","count":8}]}
JSON
    cat > "$RUN_DIR/nodes.fixture.json" <<'JSON'
{"items":[{"metadata":{"name":"fixture-node","labels":{"topology.kubernetes.io/zone":"fixture-zone","nodepool":"workers"}},"status":{"capacity":{"cpu":"4","memory":"8Gi"},"allocatable":{"cpu":"3800m","memory":"7Gi"},"conditions":[{"type":"Ready","status":"True"}]}}]}
JSON
    printf '{"items":[{"metadata":{"name":"fixture-node"},"usage":{"cpu":"2","memory":"4Gi"}}]}\n' > "$RUN_DIR/nodemetrics.fixture.json"
    for func in resources_report containers_report workloads_report images_report nodes_report network_report storage_report events_report summary_report; do
        "$func" > "$RUN_DIR/$func.out" 2> "$RUN_DIR/$func.err"; rc=$?
        if ((rc!=0)) || [[ -s $RUN_DIR/$func.err ]]; then printf 'FAIL report %s rc=%s\n' "$func" "$rc"; cat "$RUN_DIR/$func.err"; ((errors+=1)); fi
    done
    inspector_report fixture-pod > "$RUN_DIR/inspector.out" 2> "$RUN_DIR/inspector.err"; rc=$?
    if ((rc!=0)) || [[ -s $RUN_DIR/inspector.err ]]; then printf 'FAIL inspector\n'; ((errors+=1)); fi
    health_report > "$RUN_DIR/health.out" 2> "$RUN_DIR/health.err"; rc=$?
    if ((rc!=1)) || [[ -s $RUN_DIR/health.err ]]; then printf 'FAIL health operational exit code\n'; ((errors+=1)); fi
    jq -e '.items[0].spec.containers[0].env[0].value==null and .items[0].spec.containers[0].command==null' "$CACHE_DIR/pods.json" >/dev/null || ((errors+=1))
    resource_rows_json | jq -e 'length==1 and .[0].cpu==362 and .[0].cpu_request==1250 and .[0].owner=="Deployment/fixture"' >/dev/null || ((errors+=1))
    grep -q 'fixture/app:latest' "$RUN_DIR/images_report.out" || ((errors+=1))
    network_rows_json | jq -e 'length==3 and .[0].ready_endpoints==1 and .[1].status=="INFO_HEADLESS_NO_READY_ENDPOINTS"' >/dev/null || ((errors+=1))
    resource_case() {
        local name=$1 input=$2 expected=$3 actual=$4 result=PASS
        if [[ $expected != "$actual" ]]; then result=FAIL; ((errors+=1)); fi
        printf '%s\t%s\tINPUT %s\tEXPECTED %s\tACTUAL %s\n' "$result" "$name" "$input" "$expected" "$actual"
    }
    cp "$CACHE_DIR/pods.json" "$RUN_DIR/saved-pods.json"
    cp "$CACHE_DIR/metrics.json" "$RUN_DIR/saved-metrics.json"
    jq '.items[0].status.conditions=[] | .items[0].status.containerStatuses=[]' "$RUN_DIR/saved-pods.json" > "$CACHE_DIR/pods.json"
    : > "$RUN_DIR/findings.tsv"; health_pod_findings
    resource_case POD_READY_ABSENT 'Running pod with no Ready condition' UNKNOWN "$(awk -F '\t' '$4=="Pod Ready condition is absent" {print $1}' "$RUN_DIR/findings.tsv")"
    jq '.items[0].containers |= map(select(.name=="sidecar"))' "$RUN_DIR/saved-metrics.json" > "$CACHE_DIR/metrics.json"
    resource_case METRIC_COVERAGE 'Running two-container pod; only sidecar has metrics; app status absent' INCOMPLETE "$(resource_rows_json | jq -r '.[0].cpu')"
    jq '.items[0].containers += [.items[0].containers[0]]' "$RUN_DIR/saved-metrics.json" > "$CACHE_DIR/metrics.json"
    resource_case DUPLICATE_METRICS 'duplicate metrics container names' PARSE_ERROR "$(resource_rows_json | jq -r '.[0].cpu')"
    jq '.items[0].containers[0].usage.cpu="not-a-quantity"' "$RUN_DIR/saved-metrics.json" > "$CACHE_DIR/metrics.json"
    resource_case MALFORMED_METRIC 'CPU not-a-quantity' PARSE_ERROR "$(resource_rows_json | jq -r '.[0].cpu')"
    resource_case NEGATIVE_RESOURCE 'CPU -500m' PARSE_ERROR "$(jq -nr "$JQ_QUANTITIES"'"-500m" | q_state("cpu")')"
    cp "$RUN_DIR/saved-pods.json" "$CACHE_DIR/pods.json"
    cp "$RUN_DIR/saved-metrics.json" "$CACHE_DIR/metrics.json"
    jq '.items[0].endpoints += [(.items[0].endpoints[0]|.addresses=["2001:db8::1"])]' "$CACHE_DIR/endpointslices.json" > "$RUN_DIR/dual-stack.json"
    cp "$RUN_DIR/dual-stack.json" "$CACHE_DIR/endpointslices.json"
    resource_case DUAL_STACK_SERVICE 'one backend pod with IPv4 and IPv6 addresses' '2 addresses;0 missing pods' "$(network_rows_json | jq -r '.[0]|"\(.ready_endpoints) addresses;\(.selector_ready_missing|length) missing pods"')"
    cp "$RUN_DIR/nodes.fixture.json" "$RUN_DIR/saved-nodes.json"
    jq 'del(.items[0].metadata.labels) | .items[0].status.capacity.cpu="broken" | .items[0].status.allocatable.memory=null | .items[0].status.conditions=[]' "$RUN_DIR/saved-nodes.json" > "$RUN_DIR/nodes.fixture.json"
    nodes_report > "$RUN_DIR/node-edge.out" 2> "$RUN_DIR/node-edge.err"
    resource_case NODE_LABELS_ABSENT 'node labels absent' 0 "$(wc -c < "$RUN_DIR/node-edge.err" | tr -d ' ')"
    resource_case NODE_CAPACITY_PARSE 'node CPU capacity broken; memory allocatable absent; Ready absent' 'PARSE_ERROR;UNAVAILABLE;Ready=UNKNOWN' "$(awk -F '\t' '$1=="fixture-node" {print $4";"$12";"$19}' "$RUN_DIR/node-edge.out")"
    cp "$RUN_DIR/saved-nodes.json" "$RUN_DIR/nodes.fixture.json"
    cp "$RUN_DIR/workloads.fixture.json" "$RUN_DIR/saved-workloads.json"
    jq '.items += [{kind:"DaemonSet",metadata:{name:"fixture-ds"},spec:{},status:{}}]' "$RUN_DIR/saved-workloads.json" > "$RUN_DIR/workloads.fixture.json"
    workloads_report > "$RUN_DIR/workload-edge.out"
    resource_case DAEMONSET_DESIRED_ABSENT 'DaemonSet status not populated yet' UNKNOWN_DESIRED "$(awk -F '\t' '$2=="fixture-ds" {print $7}' "$RUN_DIR/workload-edge.out")"
    cp "$RUN_DIR/saved-workloads.json" "$RUN_DIR/workloads.fixture.json"
    FIXTURE_DENIED=metrics
    collect_metrics
    resource_rows_json | jq -e '.[0].cpu=="N/A" and .[0].memory=="N/A"' >/dev/null || ((errors+=1))
    FIXTURE_DENIED=pods
    summary_report > "$RUN_DIR/denied.out" 2> "$RUN_DIR/denied.err"
    grep -q 'RESOURCE TOTALS.*RBAC_DENIED' "$RUN_DIR/denied.out" || ((errors+=1))
    FIXTURE_DENIED=
    collect_pods
    jq '.items[0] as $p | {items:[range(0;501) as $i | $p | .metadata.name=("fixture-pod-"+($i|tostring))]}' "$CACHE_DIR/pods.json" > "$RUN_DIR/pods.fixture.json"
    : > "$RUN_DIR/calls"
    resources_report > "$RUN_DIR/large.out" 2> "$RUN_DIR/large.err"
    if [[ $(wc -l < "$RUN_DIR/calls") != 3 || -s $RUN_DIR/large.err ]]; then printf 'FAIL bulk API collection\n'; ((errors+=1)); fi
    resource_rows_json | jq -e 'length==501' >/dev/null || ((errors+=1))
    printf '{"items":[]}\n' > "$RUN_DIR/pods.fixture.json"
    collect_pods
    resource_rows_json | jq -e 'length==0' >/dev/null || ((errors+=1))
    if ((errors)); then printf 'FAIL resource fixtures: %s failures\n' "$errors"; exit 1; fi
    printf 'PASS all resource report, redaction projection, health, denied, empty, and 501-pod fixtures\n'
)

# 12 GitOps collectors and deployment validation
gitops_collect() {
    local resource key
    local projection='
      {items:[.items[] | {kind,metadata:{name:.metadata.name,namespace:.metadata.namespace,
        creationTimestamp:.metadata.creationTimestamp,generation:.metadata.generation,
        labels:(.metadata.labels // {})},
        spec:{suspend:(.spec.suspend // false),url:(.spec.url // "" | sub("://[^/@]*@";"://") | sub("[?#].*$";"")),
          ref:.spec.ref,path:.spec.path,interval:.spec.interval,sourceRef:.spec.sourceRef,
          releaseName:.spec.releaseName,targetNamespace:.spec.targetNamespace,
          chart:{spec:{chart:.spec.chart.spec.chart,version:.spec.chart.spec.version,sourceRef:.spec.chart.spec.sourceRef}}},
        status:{observedGeneration:.status.observedGeneration,conditions:(.status.conditions // []),
          artifact:{revision:.status.artifact.revision},lastAppliedRevision:.status.lastAppliedRevision,
          lastAttemptedRevision:.status.lastAttemptedRevision,lastHandledReconcileAt:.status.lastHandledReconcileAt,
          lastAttemptedReleaseAction:.status.lastAttemptedReleaseAction,failures:.status.failures,
          installFailures:.status.installFailures,upgradeFailures:.status.upgradeFailures,
          inventory:{entries:(.status.inventory.entries // [])},history:[.status.history[]? | {name,namespace,version,status,chartName,chartVersion}]}}]}'
    for resource in gitrepositories.source.toolkit.fluxcd.io kustomizations.kustomize.toolkit.fluxcd.io helmrepositories.source.toolkit.fluxcd.io helmreleases.helm.toolkit.fluxcd.io; do
        key="flux_${resource%%.*}"
        collect_json "$key" 15 ns "$resource" "$projection" 'NAME:.metadata.name,READY:.status.conditions[?(@.type=="Ready")].status,SUSPENDED:.spec.suspend,GENERATION:.metadata.generation,OBSERVED:.status.observedGeneration' || :
    done
}

gitops_report() {
    gitops_collect
    local key file report_rc=0 collection_rc
    printf 'GITOPS / FLUX | context=%s namespace=%s\n' "$SENTINEL_CONTEXT" "$SENTINEL_NAMESPACE"
    printf 'SOURCE Kubernetes Flux APIs; TTL 15s. Readiness and revision evidence; desired manifests are not diffed.\n'
    for key in flux_gitrepositories flux_kustomizations flux_helmrepositories flux_helmreleases; do
        printf '\n%s | status=%s | cache age=%ss\n' "${key#flux_}" "$(cache_status "$key")" "$(cache_age "$key")"
        file="$(cache_file "$key")"
        if ! has jq || [[ ! -s "$file" ]]; then
            [[ -s "$CACHE_DIR/$key.txt" ]] && cat "$CACHE_DIR/$key.txt"
            continue
        fi
        jq -r '
          def ready: ([.status.conditions[]? | select(.type=="Ready")][0] // {});
          def gen: (.status.observedGeneration // ready.observedGeneration);
          def state:
            if .spec.suspend then "WARN SUSPENDED"
            elif any(.status.conditions[]?; .type=="Stalled" and .status=="True") then "FAIL RECONCILIATION_FAILED"
            elif any(.status.conditions[]?; .type=="Reconciling" and .status=="True") then "WARN RECONCILIATION_PENDING"
            elif ready.status=="False" then (if .kind=="HelmRelease" then "FAIL HELM_FAILURE" else "FAIL RECONCILIATION_FAILED" end)
            elif gen == null then "UNKNOWN OBSERVED_GENERATION"
            elif .metadata.generation!=gen then "WARN GENERATION_DRIFT / RECONCILIATION_PENDING"
            elif ready.status=="True" then "OK NO_DRIFT_EVIDENCE"
            else "UNKNOWN DRIFT_NOT_VERIFIABLE" end;
          "TOTAL \(.items|length) | READY \([.items[]|select(ready.status=="True")]|length) | SUSPENDED \([.items[]|select(.spec.suspend)]|length) | FAILED \([.items[]|select(ready.status=="False")]|length)",
          (.items[] | "\n\(.kind)/\(.metadata.name) [\(state)]",
            "  Ready=\(ready.status // "UNKNOWN") suspend=\(.spec.suspend) generation=\(.metadata.generation // "UNKNOWN") observed=\(gen // "UNKNOWN")",
            "  Created=\(.metadata.creationTimestamp // "UNKNOWN") transition=\(ready.lastTransitionTime // "UNKNOWN") handledReconcile=\(.status.lastHandledReconcileAt // "UNKNOWN")",
            (if .spec.url!="" then "  URL=\(.spec.url) branch/tag=\(.spec.ref.branch // .spec.ref.tag // .spec.ref.semver // .spec.ref.commit // "default")" else empty end),
            (if .spec.sourceRef!=null then "  Source=\(.spec.sourceRef.kind)/\(.spec.sourceRef.name) namespace=\(.spec.sourceRef.namespace // .metadata.namespace) path=\(.spec.path // "-") interval=\(.spec.interval // "-")" else empty end),
            (if .kind=="HelmRelease" then "  Chart=\(.spec.chart.spec.chart // "UNKNOWN") requestedVersion=\(.spec.chart.spec.version // "UNKNOWN") installedVersion=\(.status.history[0].chartVersion // "UNKNOWN") releaseRevision=\(.status.history[0].version // "UNKNOWN")" else empty end),
            "  Artifact=\(.status.artifact.revision // "-") applied=\(.status.lastAppliedRevision // "-") attempted=\(.status.lastAttemptedRevision // "-")",
            "  Reason=\(ready.reason // "UNKNOWN") message=\(ready.message // "-")")' "$file"
        if jq -e 'any(.items[]; .spec.suspend!=true and any(.status.conditions[]?; (.type=="Ready" and .status=="False") or (.type=="Stalled" and .status=="True")))' "$file" >/dev/null 2>&1; then report_rc=1; fi
    done
    gitops_revision_report
    gitops_certificate_collection_rc flux_gitrepositories flux_kustomizations flux_helmrepositories flux_helmreleases; collection_rc=$?
    ((collection_rc>report_rc)) && report_rc="$collection_rc"
    return "$report_rc"
}

gitops_certificate_collection_rc() {
    local key result=0 state
    for key in "$@"; do
        state="$(cache_status "$key")"
        case "$state" in
            AUTH_ERROR|API_TIMEOUT|NETWORK_ERROR) result=3 ;;
            RBAC_DENIED|PARSE_ERROR|COMMAND_MISSING|UNKNOWN) ((result<2)) && result=2 ;;
        esac
    done
    return "$result"
}

gitops_revision_report() {
    local source="$CACHE_DIR/flux_gitrepositories.json" target="$CACHE_DIR/flux_kustomizations.json"
    has jq && [[ -s "$source" && -s "$target" ]] || return 0
    printf '\nSOURCE / APPLIED REVISION COMPARISON (namespace-local observed relationships)\n'
    jq -r --slurpfile src "$source" '
      .items[] | select(.spec.sourceRef.kind=="GitRepository") | . as $k |
      [$src[0].items[] | select(.metadata.name==$k.spec.sourceRef.name and .metadata.namespace==($k.spec.sourceRef.namespace // $k.metadata.namespace))][0] as $s |
      "Kustomization/\(.metadata.name) -> GitRepository/\(.spec.sourceRef.name): " +
      (if $s==null then "DRIFT_NOT_VERIFIABLE (source outside visible scope or unavailable)"
       elif $s.status.artifact.revision==null or .status.lastAppliedRevision==null then "UNKNOWN (revision unavailable)"
       elif $s.status.artifact.revision==.status.lastAppliedRevision then "NO_DRIFT_EVIDENCE (revision matches)"
       else "REVISION_DRIFT / POTENTIAL_DRIFT (source revision differs from applied; reconciliation may be pending)" end)' "$target"
}

helm_list_project() {
    helm_ns list --all --output json | jq '[.[] | {name,namespace,revision,updated,status,chart,app_version}]'
}

helm_status_project() {
    helm_ns status "$1" --output json | jq '{name,namespace,version,info:{status:.info.status,
      first_deployed:.info.first_deployed,last_deployed:.info.last_deployed,deleted:.info.deleted,
      description:.info.description},chart:{name:.chart.metadata.name,version:.chart.metadata.version,appVersion:.chart.metadata.appVersion}}'
}

helm_history_project() {
    helm_ns history "$1" --max 50 --output json | jq '[.[] | {revision,updated,status,chart,app_version,description}]'
}

helm_secret_metadata() {
    kctl_ns get secrets -l owner=helm -o 'go-template={{range .items}}{{.metadata.name}}{{"\t"}}{{.type}}{{"\t"}}{{index .metadata.labels "name"}}{{"\t"}}{{index .metadata.labels "status"}}{{"\t"}}{{index .metadata.labels "version"}}{{"\t"}}{{.metadata.creationTimestamp}}{{"\n"}}{{end}}'
}

helm_report() {
    printf 'HELM | context=%s namespace=%s | TTL 15s\n' "$SENTINEL_CONTEXT" "$SENTINEL_NAMESPACE"
    if has helm && has jq; then
        collect_text helm 15 helm_list_project || :
        printf 'SOURCE helm list | status=%s | cache age=%ss\n' "$(cache_status helm)" "$(cache_age helm)"
        if [[ -s "$CACHE_DIR/helm.txt" ]]; then
            jq -r '"NAME\tREVISION\tSTATUS\tCHART\tAPP VERSION\tUPDATED",(.[]|[.name,.revision,.status,.chart,.app_version,.updated]|@tsv)' "$CACHE_DIR/helm.txt" 2>/dev/null || cat "$CACHE_DIR/helm.txt"
        fi
    else
        printf 'Helm CLI=%s jq=%s; using release Secret metadata only.\n' "$(has helm && printf AVAILABLE || printf COMMAND_MISSING)" "$(has jq && printf AVAILABLE || printf COMMAND_MISSING)"
        collect_text helm_metadata 15 helm_secret_metadata || :
        printf 'SOURCE Kubernetes Secret metadata | status=%s | cache age=%ss\n' "$(cache_status helm_metadata)" "$(cache_age helm_metadata)"
        printf 'SECRET\tTYPE\tRELEASE\tSTATUS\tREVISION\tCREATED\n'
        [[ -s "$CACHE_DIR/helm_metadata.txt" ]] && cat "$CACHE_DIR/helm_metadata.txt"
    fi
}

helm_detail_report() {
    local release="$1" key="${1//./_}"
    [[ "$release" =~ ^[a-z0-9][a-z0-9.-]*$ ]] || { printf 'INVALID release name\n'; return 2; }
    has helm && has jq || { printf 'UNAVAILABLE: helm and jq are needed for safe detailed projection.\n'; return 0; }
    collect_text "helm_status_$key" 15 helm_status_project "$release" || :
    collect_text "helm_history_$key" 15 helm_history_project "$release" || :
    printf 'HELM STATUS | %s | %s\n' "$release" "$(cache_status "helm_status_$key")"
    [[ -s "$CACHE_DIR/helm_status_$key.txt" ]] && cat "$CACHE_DIR/helm_status_$key.txt"
    printf '\nHELM HISTORY | %s | %s\n' "$release" "$(cache_status "helm_history_$key")"
    [[ -s "$CACHE_DIR/helm_history_$key.txt" ]] && cat "$CACHE_DIR/helm_history_$key.txt"
    printf '\nRelease values, manifests, hooks and notes are excluded.\n'
}

deployment_chain_report() {
    local selected="${1:-}"
    gitops_collect
    collect_pods
    collect_workloads
    printf 'DEPLOYMENT VALIDATION | namespace=%s | SOURCE cached API metadata/status\n' "$SENTINEL_NAMESPACE"
    has jq || { printf 'DEGRADED: jq required for relationship analysis.\n'; return 0; }
    local pods workloads hrs kus
    pods="$(json_cache_path pods)"; workloads="$(json_cache_path workloads)"
    hrs="$(json_cache_path flux_helmreleases)"; kus="$(json_cache_path flux_kustomizations)"
    jq -r --arg selected "$selected" --arg ns "$SENTINEL_NAMESPACE" --slurpfile work "$workloads" --slurpfile hr "$hrs" --slurpfile ks "$kus" '
      def owner: ([.metadata.ownerReferences[]? | select(.controller==true)][0] // .metadata.ownerReferences[0]);
      .items[] | . as $pod | owner as $own |
      ([$work[0].items[] | select(.kind==$own.kind and .metadata.name==$own.name)][0]) as $direct |
      (if $own.kind=="ReplicaSet" and $direct!=null then $direct|owner else $own end) as $top |
      ([$work[0].items[] | select(.kind==$top.kind and .metadata.name==$top.name)][0] // $direct) as $w |
      select($selected=="" or .metadata.name==$selected or $top.name==$selected or (($top.kind // "")+"/"+($top.name // ""))==$selected) |
      ($w.metadata.annotations["meta.helm.sh/release-name"] // $w.metadata.labels["app.kubernetes.io/instance"]) as $release |
      ([$hr[0].items[] | select((.status.history[0].name // .spec.releaseName // (if .spec.targetNamespace!=null then .spec.targetNamespace+"-"+.metadata.name else .metadata.name end))==$release and (.spec.targetNamespace // .metadata.namespace)==$ns)][0]) as $h |
      ($w.metadata.labels["kustomize.toolkit.fluxcd.io/name"] // $h.metadata.labels["kustomize.toolkit.fluxcd.io/name"]) as $kn |
      ($w.metadata.labels["kustomize.toolkit.fluxcd.io/namespace"] // $h.metadata.labels["kustomize.toolkit.fluxcd.io/namespace"] // $ns) as $kns |
      ([$ks[0].items[] | select(.metadata.name==$kn and .metadata.namespace==$kns)][0]) as $k |
      "\nPod/\(.metadata.name) -> \($own.kind // "UNKNOWN")/\($own.name // "UNKNOWN") -> \($top.kind // "UNKNOWN")/\($top.name // "UNKNOWN")",
      "  Workload desired=\($w.spec.replicas // $w.status.desiredNumberScheduled // "UNKNOWN") available=\($w.status.availableReplicas // $w.status.numberAvailable // "UNKNOWN") generation=\($w.metadata.generation // "UNKNOWN") observed=\($w.status.observedGeneration // "UNKNOWN")",
      "  HelmRelease=\($h.metadata.name // "RELATIONSHIP_NOT_VERIFIED") releaseLabel=\($release // "-")",
      "  Kustomization=\($k.metadata.name // "RELATIONSHIP_NOT_VERIFIED") source=\($k.spec.sourceRef.kind // "UNKNOWN")/\($k.spec.sourceRef.name // "UNKNOWN") applied=\($k.status.lastAppliedRevision // "UNKNOWN")",
      (.spec.containers[] as $c |
       ([$pod.status.containerStatuses[]? | select(.name==$c.name)][0]) as $s |
       ([$w.spec.template.spec.containers[]? | select(.name==$c.name)][0].image) as $template |
       "  Container/\($c.name) declared=\($c.image) runtime=\($s.imageID // "UNKNOWN") ready=\($s.ready // false)",
       "    Image evidence: " +
       (if $template!=null and $template!=$c.image then "IMAGE_VARIANCE (workload template and pod differ; rollout may be active)"
        elif ($c.image|contains("@sha256:")) and (($s.imageID // "")|contains("sha256:")) then
          (if ($c.image|split("@")[-1])==($s.imageID|split("@")[-1]|sub("^docker-pullable://";"")|sub("^containerd://";"")) then "NO_DRIFT_EVIDENCE (digest matches)" else "RUNTIME_VARIANCE (digest differs; platform/index digest resolution NOT VERIFIED)" end)
        elif ($c.image|contains("@")) then "DRIFT_NOT_VERIFIABLE (runtime digest unavailable)"
        else "MUTABLE_TAG / DRIFT_NOT_VERIFIABLE (tag-to-digest desired mapping unavailable)" end))' "$pods"
    printf '\nRelationships use owner references and controller/release labels. Labels alone do not prove desired-state equality.\n'
}

gitops_menu() {
    local choice release
    while :; do
        printf '\nGITOPS: Flux APIs, namespace locked, 15s cache; status evidence does not establish manifest drift.\n'
        choose 'GitOps' 'Flux overview and revisions' 'Helm releases' 'Helm release status/history' 'Deployment validation chain' 'Back'
        choice="$REPLY"
        case "$choice" in
            'Flux overview and revisions') capture_report 'GitOps' gitops_report; view_file "$CURRENT_REPORT" 'GitOps' ;;
            'Helm releases') capture_report 'Helm' helm_report; view_file "$CURRENT_REPORT" 'Helm' ;;
            'Helm release status/history')
                has jq && has helm || { printf 'UNAVAILABLE: helm and jq required.\n'; continue; }
                collect_text helm 15 helm_list_project || :
                local -a releases=()
                mapfile -t releases < <(jq -r '.[].name' "$CACHE_DIR/helm.txt" 2>/dev/null)
                ((${#releases[@]})) || { printf 'No selectable releases (%s).\n' "$(cache_status helm)"; continue; }
                choose 'Release' "${releases[@]}" 'Back'; release="$REPLY"
                [[ "$release" == Back || -z "$release" ]] && continue
                capture_report 'Helm release' helm_detail_report "$release"; view_file "$CURRENT_REPORT" 'Helm release' ;;
            'Deployment validation chain') capture_report 'Deployment chain' deployment_chain_report; view_file "$CURRENT_REPORT" 'Deployment chain' ;;
            *) return ;;
        esac
    done
}

gitops_findings() {
    has jq || { findings_add UNKNOWN GITOPS namespace 'jq unavailable; GitOps conditions not analyzed' 'Dependency detection'; return; }
    local key file severity resource issue
    for key in flux_gitrepositories flux_kustomizations flux_helmrepositories flux_helmreleases; do
        file="$(cache_file "$key")"
        if [[ ! -s "$file" ]]; then
            findings_add UNKNOWN GITOPS "${key#flux_}" "$(cache_status "$key")" 'Flux API collector'; continue
        fi
        while IFS=$'\t' read -r severity resource issue; do
            [[ -n "$severity" ]] && findings_add "$severity" GITOPS "$resource" "$issue" 'Observed Flux conditions/generation'
        done < <(jq -r '.items[] | . as $o | ([.status.conditions[]? | select(.type=="Ready")][0] // {}) as $r |
          if .spec.suspend then ["WARN",(.kind+"/"+.metadata.name),"Reconciliation suspended"]
          elif any(.status.conditions[]?;.type=="Reconciling" and .status=="True") then ["WARN",(.kind+"/"+.metadata.name),"RECONCILIATION_PENDING"]
          elif $r.status=="False" or any(.status.conditions[]?;.type=="Stalled" and .status=="True") then ["FAIL",(.kind+"/"+.metadata.name),("Reconciliation failed: "+($r.reason // "Stalled"))]
          elif (.status.observedGeneration // $r.observedGeneration)==null then ["UNKNOWN",(.kind+"/"+.metadata.name),"Observed generation unavailable"]
          elif .metadata.generation!=(.status.observedGeneration // $r.observedGeneration) then ["WARN",(.kind+"/"+.metadata.name),"GENERATION_DRIFT / reconciliation pending"]
          elif $r.status=="True" then ["OK",(.kind+"/"+.metadata.name),"Ready with observed generation; no drift evidence"]
          else ["UNKNOWN",(.kind+"/"+.metadata.name),"Ready condition unavailable"] end | @tsv' "$file")
    done
    if [[ -s "$CACHE_DIR/helm.txt" ]]; then
        while IFS=$'\t' read -r resource issue; do
            [[ -n "$resource" ]] && findings_add FAIL HELM "$resource" "Release status: $issue" 'helm list status'
        done < <(jq -r '.[] | select(.status=="failed") | [.name,.status]|@tsv' "$CACHE_DIR/helm.txt" 2>/dev/null)
    fi
}

# 13 Certificate collectors and bounded TLS auditing
certificate_epoch() {
    local value="$1" result
    result="$(date -u -d "$value" +%s 2>/dev/null)" && { printf '%s\n' "$result"; return; }
    result="$(LC_ALL=C date -j -u -f '%b %e %T %Y %Z' "$value" +%s 2>/dev/null)" && { printf '%s\n' "$result"; return; }
    result="$(date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$value" +%s 2>/dev/null)" && { printf '%s\n' "$result"; return; }
    return 1
}

certificate_validity() {
    local before="$1" after="$2" now begin end remain
    CERT_DAYS=UNKNOWN; CERT_STATE=PARSE_ERROR
    now="$(date +%s)" || return
    begin="$(certificate_epoch "$before")" || return
    end="$(certificate_epoch "$after")" || return
    [[ "$now" =~ ^[0-9]+$ && "$begin" =~ ^-?[0-9]+$ && "$end" =~ ^-?[0-9]+$ ]] || return
    remain=$((end-now)); CERT_DAYS=$((remain/86400))
    if ((begin>now)); then CERT_STATE=NOT_YET_VALID
    elif ((remain<=0)); then CERT_STATE=EXPIRED
    elif ((remain<=CERT_CRIT_DAYS*86400)); then CERT_STATE=CRITICAL
    elif ((remain<=CERT_WARN_DAYS*86400)); then CERT_STATE=WARN
    else CERT_STATE=OK; fi
}

cert_self_tests() (
    CERT_WARN_DAYS=90 CERT_CRIT_DAYS=30
    [[ "$(certificate_epoch '2000-01-01T00:00:00Z')" == 946684800 ]] || return 1
    certificate_validity '2000-01-01T00:00:00Z' '2001-01-01T00:00:00Z'
    [[ "$CERT_STATE" == EXPIRED && "$CERT_DAYS" == -* ]] || return 1
    certificate_validity invalid invalid
    [[ "$CERT_STATE" == PARSE_ERROR && "$CERT_DAYS" == UNKNOWN ]] || return 1
    tls_valid_target 'example.invalid' 443 || return 1
    tls_valid_target '::1' 443 || return 1
    ! tls_valid_target '--context=escape' 443 || return 1
    ! tls_valid_target 'example.invalid' 65536 || return 1
    ! tls_valid_target 'example.invalid;id' 443 || return 1
    local cert_fixture_status=RBAC_DENIED
    cache_status() { printf '%s\n' "$cert_fixture_status"; }
    gitops_certificate_collection_rc fixture; [[ $? == 2 ]] || return 1
    cert_fixture_status=AUTH_ERROR
    gitops_certificate_collection_rc fixture; [[ $? == 3 ]] || return 1
    cert_fixture_status=EMPTY_RESULT
    gitops_certificate_collection_rc fixture; [[ $? == 0 ]] || return 1
    cert_fixture_status=COMMAND_MISSING
    gitops_certificate_collection_rc fixture; [[ $? == 2 ]] || return 1
)

gitops_certificate_self_tests() (
    # All collectors below are isolated mocks. No cluster, remote Git, network,
    # private key file or production credential is used by these fixtures.
    has jq || { printf 'SKIP GitOps JSON fixtures: jq unavailable\n'; return 0; }
    local fixture_dir
    fixture_dir="$(mktemp -d "$RUN_DIR/gitops-cert-fixtures.XXXXXXXX")" || return 1
    trap 'rm -rf -- "$fixture_dir"' EXIT
    local CACHE_DIR="$fixture_dir" SENTINEL_CONTEXT=fixture SENTINEL_NAMESPACE=fixture
    local CERT_WARN_DAYS=90 CERT_CRIT_DAYS=30 FORCE_REFRESH=0
    cache_status() { printf 'OK\n'; }
    cache_age() { printf '0\n'; }
    cache_file() { printf '%s/%s.json\n' "$CACHE_DIR" "$1"; }
    json_cache_path() {
        if [[ -s "$CACHE_DIR/$1.json" ]]; then printf '%s/%s.json\n' "$CACHE_DIR" "$1"
        else printf '%s/empty.json\n' "$CACHE_DIR"; fi
    }
    collect_json() { printf '%s\n' "$fixture" | jq "$5" > "$CACHE_DIR/$1.json"; }
    collect_pods() { :; }; collect_workloads() { :; }
    findings_add() { printf '%s|%s|%s|%s|%s\n' "$@"; }
    printf '{"items":[]}\n' > "$CACHE_DIR/empty.json"
    local fixture='{"items":[{"kind":"GitRepository","metadata":{"name":"source","namespace":"fixture","generation":2},"spec":{"url":"https://test-user:test-password@example.invalid/repo.git?token=fixture-only"},"status":{"observedGeneration":2,"artifact":{"revision":"main@sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"conditions":[{"type":"Ready","status":"True","observedGeneration":2}]}}]}'
    gitops_report > "$fixture_dir/gitops.txt" || return 1
    grep -q 'OK NO_DRIFT_EVIDENCE' "$fixture_dir/gitops.txt" || return 1
    ! grep -q 'test-password\|fixture-only' "$CACHE_DIR/flux_gitrepositories.json" || return 1
    jq '.items[0].metadata.generation=3' "$CACHE_DIR/flux_gitrepositories.json" > "$CACHE_DIR/change.json" || return 1
    mv -- "$CACHE_DIR/change.json" "$CACHE_DIR/flux_gitrepositories.json"
    gitops_findings > "$fixture_dir/findings.txt" || return 1
    grep -q 'GENERATION_DRIFT' "$fixture_dir/findings.txt" || return 1
    cat > "$CACHE_DIR/pods.json" <<'PODS_FIXTURE'
{"items":[{"metadata":{"name":"pod","namespace":"fixture","ownerReferences":[{"kind":"ReplicaSet","name":"rs","controller":true}]},"spec":{"containers":[{"name":"api","image":"example.invalid/image@sha256:abc","volumeMounts":[{"name":"cert","mountPath":"/cert"}]}],"volumes":[{"name":"cert","secret":{"secretName":"fixture-tls"}}]},"status":{"containerStatuses":[{"name":"api","ready":true,"imageID":"example.invalid/image@sha256:abc"}]}}]}
PODS_FIXTURE
    cat > "$CACHE_DIR/workloads.json" <<'WORKLOADS_FIXTURE'
{"items":[{"kind":"ReplicaSet","metadata":{"name":"rs","ownerReferences":[{"kind":"Deployment","name":"api","controller":true}]}},{"kind":"Deployment","metadata":{"name":"api","labels":{},"annotations":{},"generation":1},"spec":{"replicas":1,"template":{"spec":{"containers":[{"name":"api","image":"example.invalid/image@sha256:abc"}]}}},"status":{"availableReplicas":1,"observedGeneration":1}}]}
WORKLOADS_FIXTURE
    deployment_chain_report > "$fixture_dir/chain.txt" || return 1
    grep -q 'NO_DRIFT_EVIDENCE (digest matches)' "$fixture_dir/chain.txt" || return 1
    cert_mounts_report > "$fixture_dir/mounts.txt" || return 1
    grep -q 'CONFIGURED' "$fixture_dir/mounts.txt" || return 1
    cert_self_tests || return 1
    if has openssl; then
        local pem cert_fixture_b64
        pem="$(openssl req -x509 -newkey rsa:2048 -nodes -subj '/CN=sentinel-self-test.invalid' -days 10 -keyout /dev/null 2>/dev/null)" || return 1
        certificate_chain_metadata fixture fixture "$pem" > "$fixture_dir/certificate.txt" || return 1
        grep -q '\[CRITICAL\]' "$fixture_dir/certificate.txt" || return 1
        ! grep -q 'BEGIN.*KEY\|BEGIN CERTIFICATE' "$fixture_dir/certificate.txt" || return 1
        cert_fixture_b64="$(printf '%s\n' "$pem" | openssl base64 -A)" || return 1
        kctl_ns() { printf 'fixture\t%s\n' "$cert_fixture_b64"; }
        tls_secret_metadata_collect > "$fixture_dir/secret-certificate.txt" || return 1
        grep -q '\[CRITICAL\]' "$fixture_dir/secret-certificate.txt" || return 1
        ! grep -q 'BEGIN.*KEY\|BEGIN CERTIFICATE' "$fixture_dir/secret-certificate.txt" || return 1
        unset pem cert_fixture_b64
    else printf 'SKIP X.509 parsing fixture: openssl unavailable\n'; fi
    if declare -F dev_flux_source_wait >/dev/null; then
        local MODE=dev-flux-verify DEV_COMMIT_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        local DEV_FLUX_WAIT=1 DEV_FLUX_SELECTED_SOURCE=source DEV_FLUX_SELECTED_NAMESPACE=fixture API_TIMEOUT=1
        local DEV_FLUX_JSON DEV_FLUX_DEPENDENTS_OK
        dev_flux_query() { DEV_FLUX_JSON="$fixture"; }
        dev_flux_source_wait > "$fixture_dir/source-pass.txt" || return 1
        grep -q 'FLUX_SOURCE_SYNCHRONIZED' "$fixture_dir/source-pass.txt" || return 1
        fixture="$(printf '%s\n' "$fixture" | jq '.items[0].metadata.generation=3')" || return 1
        if dev_flux_source_wait > "$fixture_dir/source-generation.txt"; then return 1; fi
        grep -q 'TIMEOUT' "$fixture_dir/source-generation.txt" || return 1
        fixture="$(printf '%s\n' "$fixture" | jq '.items[0].metadata.generation=2 | .items[0].status.artifact.revision="main@sha1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"')" || return 1
        if dev_flux_source_wait > "$fixture_dir/source-revision.txt"; then return 1; fi
        grep -q 'TIMEOUT' "$fixture_dir/source-revision.txt" || return 1
        local ks='{"items":[{"kind":"Kustomization","metadata":{"name":"apps","namespace":"fixture","generation":1},"spec":{"sourceRef":{"kind":"GitRepository","name":"source"},"suspend":false},"status":{"observedGeneration":1,"lastAppliedRevision":"main@sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","conditions":[{"type":"Ready","status":"True"}],"inventory":{"entries":[{"id":"fixture_api_helm.toolkit.fluxcd.io_HelmRelease","v":"v2"}]}}}]}'
        local hr='{"items":[{"kind":"HelmRelease","metadata":{"name":"api","namespace":"fixture","generation":1},"spec":{"suspend":false},"status":{"observedGeneration":1,"conditions":[{"type":"Ready","status":"True"},{"type":"Released","status":"True"}]}},{"kind":"HelmRelease","metadata":{"name":"unrelated","namespace":"fixture","generation":1},"spec":{"suspend":false},"status":{"observedGeneration":1,"conditions":[{"type":"Ready","status":"False"}]}}]}'
        dev_flux_query() { case "$1" in kustomizations.*) DEV_FLUX_JSON="$ks" ;; helmreleases.*) DEV_FLUX_JSON="$hr" ;; esac; }
        dev_flux_dependents_once > "$fixture_dir/dependents.txt" || return 1
        [[ "$DEV_FLUX_DEPENDENTS_OK" == 1 ]] || return 1
        grep -q 'HelmRelease/fixture/api' "$fixture_dir/dependents.txt" || return 1
        ! grep -q 'unrelated' "$fixture_dir/dependents.txt" || return 1
        hr="$(printf '%s\n' "$hr" | jq '.items[0].status.conditions[0].status="False"')" || return 1
        dev_flux_dependents_once > "$fixture_dir/dependents-failed.txt" || return 1
        [[ "$DEV_FLUX_DEPENDENTS_OK" == 0 ]] || return 1
        MODE=dashboard
        if dev_flux_reconcile_guarded >/dev/null 2>&1; then return 1; fi
    fi
)

certificate_pem_metadata() {
    local name="$1" source="$2" pem="$3" metadata line before='' after='' sans
    metadata="$(printf '%s\n' "$pem" | openssl x509 -noout -subject -issuer -serial -dates -fingerprint -sha256 2>/dev/null)" || {
        printf '[PARSE_ERROR] %s | source=%s | invalid or absent X.509 certificate\n' "$name" "$source"; return 1;
    }
    while IFS= read -r line; do
        case "$line" in notBefore=*) before="${line#*=}" ;; notAfter=*) after="${line#*=}" ;; esac
    done <<< "$metadata"
    certificate_validity "$before" "$after"
    printf '[%s] %s | namespace=%s | source=%s | daysLeft=%s\n' "$CERT_STATE" "$name" "$SENTINEL_NAMESPACE" "$source" "$CERT_DAYS"
    printf '%s\n' "$metadata"
    sans="$(printf '%s\n' "$pem" | openssl x509 -noout -ext subjectAltName 2>/dev/null)" || sans='SAN: UNAVAILABLE with this OpenSSL version'
    printf '%s\n\n' "$sans"
}

certificate_decode() {
    printf '%s' "$1" | openssl base64 -d -A
}

certificate_chain_metadata() {
    local name="$1" source="$2" chain="$3" line block='' inside=0 count=0
    while IFS= read -r line; do
        line="${line%$'\r'}"
        if [[ "$line" == '-----BEGIN CERTIFICATE-----' ]]; then inside=1; block=''; fi
        if ((inside)); then block+="$line"$'\n'; fi
        if [[ "$line" == '-----END CERTIFICATE-----' && "$inside" == 1 ]]; then
            ((count+=1))
            certificate_pem_metadata "$name" "$source certificate#$count" "$block" || :
            inside=0; block=''
        fi
    done <<< "$chain"
    if ((count==0 || inside)); then printf '[PARSE_ERROR] %s | source=%s | missing/incomplete PEM certificate\n' "$name" "$source"; fi
}

secret_metadata_collect() {
    kctl_ns get secrets -o 'go-template={{range .items}}{{.metadata.name}}{{"\t"}}{{.type}}{{"\t"}}{{.metadata.creationTimestamp}}{{"\t"}}{{len .data}}{{"\t"}}{{range $key,$value := .data}}{{$key}}{{" "}}{{end}}{{"\n"}}{{end}}'
}

tls_secret_metadata_collect() {
    local raw name encoded pem rc
    has openssl || { printf 'COMMAND_MISSING: openssl; certificate parsing unavailable.\n'; return 127; }
    raw="$(kctl_ns get secrets --field-selector type=kubernetes.io/tls -o 'go-template={{range .items}}{{.metadata.name}}{{"\t"}}{{index .data "tls.crt"}}{{"\n"}}{{end}}')"; rc=$?
    ((rc==0)) || return "$rc"
    [[ -n "$raw" ]] || { printf 'EMPTY_RESULT: no TLS Secrets in selected namespace.\n'; return 0; }
    while IFS=$'\t' read -r name encoded; do
        [[ -n "$name" ]] || continue
        pem="$(certificate_decode "$encoded" 2>/dev/null)" || { printf '[PARSE_ERROR] %s | certificate base64 decode failed\n' "$name"; continue; }
        certificate_chain_metadata "$name" 'Secret/tls.crt' "$pem"
        unset pem encoded
    done <<< "$raw"
    unset raw
}

cert_manager_collect() {
    local resource scope key
    local projection='{items:[.items[] | {kind,metadata:{name:.metadata.name,namespace:.metadata.namespace,creationTimestamp:.metadata.creationTimestamp,generation:.metadata.generation},spec:{secretName:.spec.secretName,issuerRef:.spec.issuerRef,dnsNames:.spec.dnsNames,duration:.spec.duration,renewBefore:.spec.renewBefore},status:{notBefore:.status.notBefore,notAfter:.status.notAfter,renewalTime:.status.renewalTime,revision:.status.revision,failureTime:.status.failureTime,conditions:(.status.conditions // [])}}]}'
    for resource in certificates.cert-manager.io certificaterequests.cert-manager.io issuers.cert-manager.io clusterissuers.cert-manager.io; do
        scope=ns; [[ "$resource" == clusterissuers.* ]] && scope=cluster
        key="cert_${resource%%.*}"
        collect_json "$key" 60 "$scope" "$resource" "$projection" 'NAME:.metadata.name,READY:.status.conditions[?(@.type=="Ready")].status,SECRET:.spec.secretName,NOTAFTER:.status.notAfter' || :
    done
}

cert_ingress_collect() {
    collect_json cert_ingresses 60 ns ingresses.networking.k8s.io '{items:[.items[]|{metadata:{name:.metadata.name,namespace:.metadata.namespace},spec:{tls:(.spec.tls // []),rules:[.spec.rules[]?|{host}]}}]}' 'NAME:.metadata.name,HOSTS:.spec.tls[*].hosts,SECRETS:.spec.tls[*].secretName' || :
}

cert_mounts_report() {
    collect_pods
    printf 'SECRET MOUNT REFERENCES | SOURCE Pod specifications | namespace=%s | cache age=%ss\n' "$SENTINEL_NAMESPACE" "$(cache_age pods)"
    printf 'CONFIGURED means a Pod spec reference; container filesystem contents are NOT VERIFIED.\n'
    has jq || { printf 'UNAVAILABLE: jq required for volume relationship analysis.\n'; return 0; }
    local file; file="$(json_cache_path pods)"
    printf 'SECRET\tPOD\tVOLUME\tCONTAINER\tMOUNT PATH\tSUBPATH\tSTATUS\n'
    jq -r '.items[] as $p | $p.spec.volumes[]? as $v |
      ([$v.secret.secretName, $v.projected.sources[]?.secret.name] | .[] | select(.!=null)) as $secret |
      ($p.spec.containers[]?, $p.spec.initContainers[]?, $p.spec.ephemeralContainers[]?) as $c |
      $c.volumeMounts[]? | select(.name==$v.name) |
      [$secret,$p.metadata.name,$v.name,$c.name,.mountPath,(.subPath // "-"),"CONFIGURED; secret type/certificate presence may be unknown"]|@tsv' "$file"
}

certificate_relationships_report() {
    cert_ingress_collect
    printf '\nINGRESS -> TLS SECRET -> CERTIFICATE -> ISSUER\n'
    has jq || { [[ -f "$CACHE_DIR/cert_ingresses.txt" ]] && cat "$CACHE_DIR/cert_ingresses.txt"; return 0; }
    local ingress certs; ingress="$(json_cache_path cert_ingresses)"; certs="$(json_cache_path cert_certificates)"
    jq -r --slurpfile cert "$certs" '.items[] as $i | $i.spec.tls[]? as $tls |
      [$cert[0].items[] | select(.spec.secretName==$tls.secretName)] as $matches |
      "Ingress/\($i.metadata.name) hosts=\($tls.hosts // [] | join(",")) -> Secret/\($tls.secretName // "UNKNOWN") -> " +
      (if ($matches|length)==0 then "Certificate/UNKNOWN -> Issuer/UNKNOWN"
       else ($matches | map("Certificate/"+.metadata.name+" -> "+(.spec.issuerRef.kind // "Issuer")+"/"+(.spec.issuerRef.name // "UNKNOWN")) | join("; ")) end)' "$ingress"
}

certificates_report() {
    local key file name before after condition report_rc=0 collection_rc
    printf 'CERTIFICATES | namespace=%s | TTL 60s | WARN <=%sd CRITICAL <=%sd\n' "$SENTINEL_NAMESPACE" "$CERT_WARN_DAYS" "$CERT_CRIT_DAYS"
    printf 'SOURCE cert-manager status and parsed TLS Secret certificate chains. Raw certificate/key values are not exported.\n'
    cert_manager_collect
    for key in cert_certificates cert_certificaterequests cert_issuers cert_clusterissuers; do
        printf '\n%s | %s | cache age=%ss\n' "${key#cert_}" "$(cache_status "$key")" "$(cache_age "$key")"
        file="$(cache_file "$key")"
        if has jq && [[ -s "$file" ]]; then
            jq -r '.items[] | "\(.kind)/\(.metadata.name) secret=\(.spec.secretName // "-") issuer=\(.spec.issuerRef.kind // "Issuer")/\(.spec.issuerRef.name // "-") renewal=\(.status.renewalTime // "UNKNOWN")",(.status.conditions[]? | "  \(.type)=\(.status) reason=\(.reason // "-") message=\(.message // "-")")' "$file"
            if [[ "$key" == cert_certificates ]]; then
                while IFS=$'\t' read -r name before after; do
                    [[ -n "$name" ]] || continue
                    certificate_validity "$before" "$after"
                    printf '[%s] Certificate/%s daysLeft=%s notBefore=%s notAfter=%s\n' "$CERT_STATE" "$name" "$CERT_DAYS" "$before" "$after"
                    case "$CERT_STATE" in EXPIRED|NOT_YET_VALID) report_rc=1 ;; esac
                done < <(jq -r '.items[] | [.metadata.name,(.status.notBefore // "UNKNOWN"),(.status.notAfter // "UNKNOWN")]|@tsv' "$file")
            fi
        elif [[ -s "$CACHE_DIR/$key.txt" ]]; then cat "$CACHE_DIR/$key.txt"; fi
    done
    collect_text secret_metadata 60 secret_metadata_collect || :
    printf '\nSECRET METADATA | %s | cache age=%ss\nNAME\tTYPE\tCREATED\tKEY COUNT\tKEY NAMES\n' "$(cache_status secret_metadata)" "$(cache_age secret_metadata)"
    [[ -s "$CACHE_DIR/secret_metadata.txt" ]] && cat "$CACHE_DIR/secret_metadata.txt"
    collect_text tls_certificates 60 tls_secret_metadata_collect || :
    printf '\nTLS CERTIFICATE METADATA | %s | cache age=%ss\n' "$(cache_status tls_certificates)" "$(cache_age tls_certificates)"
    [[ -s "$CACHE_DIR/tls_certificates.txt" ]] && cat "$CACHE_DIR/tls_certificates.txt"
    certificate_relationships_report
    cert_mounts_report
    if [[ -s "$CACHE_DIR/tls_certificates.txt" ]] && grep -Eq '^\[(EXPIRED|NOT_YET_VALID)\]' "$CACHE_DIR/tls_certificates.txt"; then report_rc=1; fi
    gitops_certificate_collection_rc cert_certificates cert_certificaterequests cert_issuers cert_clusterissuers secret_metadata tls_certificates cert_ingresses pods; collection_rc=$?
    ((collection_rc>report_rc)) && report_rc="$collection_rc"
    return "$report_rc"
}

certificates_findings() {
    local name before after severity line state
    if has jq && [[ -s "$CACHE_DIR/cert_certificates.json" ]]; then
        while IFS=$'\t' read -r name before after; do
            [[ -n "$name" ]] || continue
            certificate_validity "$before" "$after"
            case "$CERT_STATE" in EXPIRED|NOT_YET_VALID) severity=FAIL ;; CRITICAL|WARN) severity=WARN ;; OK) severity=OK ;; *) severity=UNKNOWN ;; esac
            findings_add "$severity" CERTIFICATE "Certificate/$name" "$CERT_STATE daysLeft=$CERT_DAYS" 'cert-manager notBefore/notAfter'
        done < <(jq -r '.items[]|[.metadata.name,(.status.notBefore // "UNKNOWN"),(.status.notAfter // "UNKNOWN")]|@tsv' "$CACHE_DIR/cert_certificates.json")
        while IFS=$'\t' read -r name state; do
            [[ -n "$name" ]] && findings_add WARN CERTIFICATE "Certificate/$name" "Ready=False: $state" 'cert-manager Ready condition'
        done < <(jq -r '.items[] | .metadata.name as $n | .status.conditions[]? | select(.type=="Ready" and .status=="False") | [$n,(.reason // "UNKNOWN")]|@tsv' "$CACHE_DIR/cert_certificates.json")
    fi
    if [[ -s "$CACHE_DIR/tls_certificates.txt" ]]; then
        while IFS= read -r line; do
            [[ "$line" == \[*\]* ]] || continue
            state="${line%%]*}"; state="${state#[}"
            name="${line#*] }"; name="${name%% |*}"
            case "$state" in EXPIRED|NOT_YET_VALID) severity=FAIL ;; CRITICAL|WARN) severity=WARN ;; OK) severity=OK ;; *) severity=UNKNOWN ;; esac
            findings_add "$severity" CERTIFICATE "Secret/$name" "$line" 'X.509 TLS certificate metadata'
        done < "$CACHE_DIR/tls_certificates.txt"
    else findings_add UNKNOWN CERTIFICATE 'TLS secrets' "$(cache_status tls_certificates)" 'Certificate collector'; fi
}

webhook_certificate_collect() {
    local resource raw name encoded pem rc
    resource="$1"
    raw="$(kctl_cluster get "$resource" -o 'go-template={{range .items}}{{$config := .metadata.name}}{{range .webhooks}}{{$config}}{{"/"}}{{.name}}{{"\t"}}{{.clientConfig.caBundle}}{{"\n"}}{{end}}{{end}}')"; rc=$?
    ((rc==0)) || return "$rc"
    [[ -n "$raw" ]] || { printf 'EMPTY_RESULT: no webhook CA bundles.\n'; return 0; }
    while IFS=$'\t' read -r name encoded; do
        [[ -n "$encoded" && "$encoded" != '<no value>' ]] || { printf '[UNKNOWN] %s: no explicit CA bundle\n' "$name"; continue; }
        pem="$(certificate_decode "$encoded" 2>/dev/null)" || { printf '[PARSE_ERROR] %s\n' "$name"; continue; }
        certificate_chain_metadata "$name" "$resource CA bundle" "$pem"
        unset pem encoded
    done <<< "$raw"
    unset raw
}

webhook_certificates_report() {
    local resource key
    has openssl || { printf 'COMMAND_MISSING: openssl\n'; return 0; }
    printf 'WEBHOOK CA CERTIFICATES | cluster scope | each PEM certificate in CA bundles is inspected.\n'
    printf 'A CA bundle is trust configuration; it does not reveal the serving endpoint certificate.\n'
    for resource in validatingwebhookconfigurations.admissionregistration.k8s.io mutatingwebhookconfigurations.admissionregistration.k8s.io; do
        key="cert_${resource%%.*}"
        collect_text "$key" 60 webhook_certificate_collect "$resource" || :
        printf '\n%s | %s | cache age=%ss\n' "$resource" "$(cache_status "$key")" "$(cache_age "$key")"
        [[ -s "$CACHE_DIR/$key.txt" ]] && cat "$CACHE_DIR/$key.txt"
    done
}

filesystem_certificate_report() {
    local path="$1" pem
    has openssl || { printf 'COMMAND_MISSING: openssl\n'; return 0; }
    [[ -f "$path" && -r "$path" && ! -L "$path" ]] || { printf 'UNAVAILABLE: select a readable regular certificate file (no symlinks).\n'; return 2; }
    case "$path" in *.crt|*.cer|*.pem) ;; *) printf 'UNSUPPORTED: use a .crt, .cer or .pem certificate.\n'; return 2 ;; esac
    if grep -q 'PRIVATE KEY' "$path"; then printf 'REFUSED: file contains private key material.\n'; return 2; fi
    pem="$(openssl x509 -in "$path" -outform PEM 2>/dev/null)" || pem="$(openssl x509 -inform DER -in "$path" -outform PEM 2>/dev/null)" || { printf 'PARSE_ERROR: not an X.509 PEM/DER certificate.\n'; return 2; }
    certificate_pem_metadata "${path##*/}" 'Explicitly selected filesystem certificate' "$pem"
    unset pem
}

tls_valid_target() {
    local host="$1" port="$2"
    [[ "$host" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*$ || "$host" =~ ^[[:xdigit:]:]+$ ]] || return 1
    [[ "$port" =~ ^[0-9]{1,5}$ ]] && ((10#$port>0 && 10#$port<=65535))
}

tls_report() {
    local host="$1" port="${2:-443}" target help output rc pem protocol label check flag local_support summary report_rc=0
    tls_valid_target "$host" "$port" || { printf 'INVALID target: provide DNS name/IP and port 1..65535.\n'; return 2; }
    printf 'TLS AUDIT | host=%s port=%s | SOURCE direct network handshake | per-probe timeout=%ss\n' "$host" "$port" "$TLS_TIMEOUT"
    printf 'Observed from this workstation; results can differ from Pod network paths.\n'
    if [[ "$host" == *:* || "$host" =~ ^[0-9.]+$ ]]; then printf 'DNS: N/A (IP target)\n'
    elif has getent; then
        output="$(run_bounded "$TLS_TIMEOUT" getent ahosts "$host" 2>&1)"; rc=$?
        if ((rc==0)) && [[ -n "$output" ]]; then printf 'DNS: RESOLVED\n%s\n' "$output"
        elif ((rc==124 || rc==137 || rc==143)); then printf 'DNS: API_TIMEOUT\n'; report_rc=3
        else printf 'DNS: RESOLUTION_FAILED\n'; fi
    else printf 'DNS: UNAVAILABLE (getent absent; TLS connection will resolve through OpenSSL)\n'; fi
    output="$(run_bounded "$TLS_TIMEOUT" bash -c 'exec 3<>"/dev/tcp/$1/$2"' sentinel-tcp "$host" "$port" 2>&1)"; rc=$?
    if ((rc==0)); then printf 'TCP: CONNECTED\n'
    elif ((rc==124 || rc==137 || rc==143)); then printf 'TCP: TIMEOUT\n'; report_rc=3
    else printf 'TCP: CONNECTION_FAILED_OR_LOCAL_UNAVAILABLE\n'; report_rc=1; fi
    has openssl || { printf 'TLS: COMMAND_MISSING (openssl)\n'; return 2; }
    target="$host:$port"; [[ "$host" == *:* ]] && target="[$host]:$port"
    help="$(openssl s_client -help 2>&1)"
    local -a args=(openssl s_client -connect "$target" -servername "$host" -showcerts)
    [[ "$help" == *-verify_return_error* ]] && args+=(-verify_return_error)
    if [[ "$host" == *:* || "$host" =~ ^[0-9.]+$ ]]; then
        if [[ "$help" == *-verify_ip* ]]; then args+=(-verify_ip "$host"); else printf 'HOSTNAME VERIFICATION: UNAVAILABLE in local OpenSSL\n'; fi
    elif [[ "$help" == *-verify_hostname* ]]; then args+=(-verify_hostname "$host")
    else printf 'HOSTNAME VERIFICATION: UNAVAILABLE in local OpenSSL\n'; fi
    output="$(run_bounded "$TLS_TIMEOUT" "${args[@]}" </dev/null 2>&1)"; rc=$?
    if ((rc==124 || rc==137 || rc==143)); then printf 'TLS HANDSHAKE: TIMEOUT\n'; report_rc=3
    elif ((rc==0)) && [[ "$output" == *'BEGIN CERTIFICATE'* ]]; then printf 'TLS HANDSHAKE: COMPLETED\n'
    else printf 'TLS HANDSHAKE: FAILED / CERTIFICATE_VERIFICATION_OR_NETWORK_ERROR (exit=%s)\n' "$rc"; ((report_rc<1)) && report_rc=1; fi
    printf '%s\n' "$output" | awk '/^[[:space:]]*(Protocol[[:space:]]*:|Cipher[[:space:]]*:|Cipher is |Verification:|Verify return code:|New,|Server Temp Key:|verify error:|Verification error:)/ {print}'
    pem="$(printf '%s\n' "$output" | awk '/-----BEGIN CERTIFICATE-----/{p=1} p{print} /-----END CERTIFICATE-----/{exit}')"
    [[ -n "$pem" ]] && certificate_pem_metadata "$host:$port" 'Remote TLS leaf' "$pem"
    unset output pem
    printf '\nPROTOCOL PROBES (independent actual handshakes; certificate trust assessed above)\n'
    for protocol in tls1 tls1_1 tls1_2 tls1_3; do
        case "$protocol" in tls1) label='TLS 1.0' ;; tls1_1) label='TLS 1.1' ;; tls1_2) label='TLS 1.2' ;; tls1_3) label='TLS 1.3' ;; esac
        if [[ "$help" != *"-$protocol "* && "$help" != *"-$protocol"$'\n'* ]]; then printf '%-8s LOCAL_UNAVAILABLE\n' "$label"; continue; fi
        output="$(run_bounded "$TLS_TIMEOUT" openssl s_client -connect "$target" -servername "$host" "-$protocol" </dev/null 2>&1)"; rc=$?
        summary="$(printf '%s\n' "$output" | awk '/Cipher is / && !/NONE/ {print} /Cipher[[:space:]]*:/ && !/0000|NONE/ {print}')"
        if ((rc==124 || rc==137 || rc==143)); then check=TIMEOUT
        elif [[ "$output" == *'no protocols available'* || "$output" == *'no ciphers available'* || "$output" == *'no suitable signature algorithm'* || "$output" == *'unknown option'* || "$output" == *'Unknown option'* ]]; then check=LOCAL_UNAVAILABLE
        elif [[ -n "$summary" && "$output" == *'BEGIN CERTIFICATE'* ]]; then check=SUPPORTED
        elif [[ "$output" == *'alert protocol version'* ]]; then check=REJECTED
        else check='NOT_VERIFIED (handshake failed; remote rejection not established)'; fi
        printf '%-8s %s\n' "$label" "$check"
        unset output
    done
    return "$report_rc"
}

tls_menu() {
    local host port choice
    printf '\nTLS: direct DNS/TCP/TLS probes, bounded per attempt; results apply to this workstation.\n'
    choose 'TLS target' 'Discovered ingress host' 'Enter host and port' 'Back'; choice="$REPLY"
    case "$choice" in
        'Discovered ingress host')
            cert_ingress_collect
            has jq || { printf 'UNAVAILABLE: jq required to select discovered host.\n'; return; }
            local -a hosts=()
            mapfile -t hosts < <(jq -r '[.items[]|(.spec.tls[]?.hosts[]?,.spec.rules[]?.host)|select(.!=null and .!="" and (startswith("*.")|not))]|unique[]' "$(json_cache_path cert_ingresses)")
            ((${#hosts[@]})) || { printf 'No concrete ingress hosts discovered.\n'; return; }
            choose 'Host' "${hosts[@]}" 'Back'; host="$REPLY"
            [[ "$host" == Back || -z "$host" ]] && return
            port=443 ;;
        'Enter host and port') prompt 'DNS host or IP (no URL scheme)'; host="$REPLY"; prompt 'Port [443]'; port="${REPLY:-443}" ;;
        *) return ;;
    esac
    capture_report 'TLS audit' tls_report "$host" "$port"; view_file "$CURRENT_REPORT" 'TLS audit'
}

certificates_menu() {
    local choice path warning critical
    while :; do
        printf '\nCERTIFICATES: namespace inventory/relationships; optional cluster CA and direct endpoint checks.\n'
        choose 'Certificates' 'Certificate inventory' 'Mounted secret relationships' 'TLS endpoint audit' 'Webhook CA certificates' 'Selected filesystem certificate' 'Expiry thresholds' 'Back'
        choice="$REPLY"
        case "$choice" in
            'Certificate inventory') capture_report 'Certificates' certificates_report; view_file "$CURRENT_REPORT" 'Certificates' ;;
            'Mounted secret relationships') capture_report 'Certificate mounts' cert_mounts_report; view_file "$CURRENT_REPORT" 'Certificate mounts' ;;
            'TLS endpoint audit') tls_menu ;;
            'Webhook CA certificates') capture_report 'Webhook CA certificates' webhook_certificates_report; view_file "$CURRENT_REPORT" 'Webhook CA certificates' ;;
            'Selected filesystem certificate') prompt 'Explicit certificate file (.crt/.cer/.pem; metadata only)'; path="$REPLY"; [[ -n "$path" ]] || continue; capture_report 'Filesystem certificate' filesystem_certificate_report "$path"; view_file "$CURRENT_REPORT" 'Filesystem certificate' ;;
            'Expiry thresholds')
                prompt 'Warning days [90]'; warning="${REPLY:-90}"; prompt 'Critical days [30]'; critical="${REPLY:-30}"
                if [[ "$warning" =~ ^[0-9]{1,5}$ && "$critical" =~ ^[0-9]{1,5}$ ]] && ((10#$warning>=10#$critical && 10#$critical>0)); then
                    CERT_WARN_DAYS=$((10#$warning)); CERT_CRIT_DAYS=$((10#$critical)); FORCE_REFRESH=1
                else printf 'INVALID: warning must be >= critical and critical >0.\n'; fi ;;
            *) return ;;
        esac
    done
}

# 14 Splunk Engine: catalog generation never requires a Splunk connection.
declare -a SP_CATEGORY=() SP_TERMS=() SP_DESCRIPTION=() SP_QUERY=()
declare -a SP_STATUS=() SP_COUNT=() SP_VALIDATED=() SP_NOTES=() SP_FIELDS=()
declare -A SP_MAP=() SP_VALUE=()
SP_INITIALIZED=0 SP_SIGNATURE='' SP_DISCOVERY_SCOPE='' SP_DISCOVERED_AT='' SP_KUBE_SCOPE=''
SP_GENERATION_STATUS=GENERATED_UNVALIDATED SP_GENERATION_DETAIL=''
SP_RESPONSE='' SP_REQUEST_STATUS='' SP_REQUEST_DETAIL='' SP_HTTP=''

splunk_init() {
    # Remove the inherited export attribute; children never inherit this token.
    export -n SPLUNK_TOKEN 2>/dev/null || :
    [[ $SP_INITIALIZED == 1 ]] && return 0
    SP_CATEGORY=( '' 'Authentication events' 'Authorization failures' 'Kubernetes changes'
      'Configuration changes' 'Deployment events' 'Pod failures' 'Container failures'
      'Kubernetes warnings' 'Flux failures' 'Helm failures' 'Certificate events'
      'TLS failures' 'Secret metadata events' 'RBAC events' 'Network failures'
      'Kafka failures' 'SNMP/alarm events' 'Syslog/log-transformer failures'
      'Application errors' 'Audit events' 'Security events' 'Resource pressure/OOM'
      'Storage/PVC failures' )
    SP_TERMS=( ''
      '("authentication" OR "login" OR "OIDC" OR "unauthenticated")'
      '("forbidden" OR "unauthorized" OR "access denied" OR "permission denied")'
      '("kubernetes" AND ("create" OR "update" OR "patch" OR "delete"))'
      '("configuration" OR "configmap" OR "configuration changed")'
      '("deployment" OR "rollout" OR "ReplicaSet")'
      '("CrashLoopBackOff" OR "ImagePullBackOff" OR "FailedScheduling" OR "Evicted")'
      '("container" AND ("failed" OR "terminated" OR "restart" OR "OOMKilled"))'
      '("Warning" AND ("kubernetes" OR "kubelet" OR "pod"))'
      '(("flux" OR "kustomize-controller" OR "source-controller") AND ("error" OR "failed"))'
      '(("helm" OR "helm-controller" OR "HelmRelease") AND ("failed" OR "error"))'
      '("certificate" OR "cert-manager" OR "CertificateRequest" OR "x509")'
      '("TLS handshake" OR "certificate verify failed" OR "unknown authority" OR "SSL error")'
      '("secret" AND ("created" OR "updated" OR "deleted" OR "metadata"))'
      '("RBAC" OR "RoleBinding" OR "ClusterRoleBinding" OR "ClusterRole")'
      '("connection refused" OR "connection timed out" OR "DNS" OR "NetworkPolicy")'
      '("kafka" AND ("error" OR "failed" OR "timeout" OR "under-replicated"))'
      '("SNMP" OR "trap" OR "alarm raised" OR "alarm cleared")'
      '(("syslog" OR "log-transformer" OR "log transformer") AND ("failed" OR "dropped" OR "error"))'
      '("exception" OR "fatal" OR "application error" OR "unhandled")'
      '("audit" OR "auditID" OR "AuditEvent")'
      '("security" OR "intrusion" OR "suspicious" OR "policy violation")'
      '("OOMKilled" OR "out of memory" OR "MemoryPressure" OR "DiskPressure" OR "Insufficient cpu")'
      '("FailedMount" OR "FailedAttachVolume" OR "FailedBinding" OR "PVC" OR "volume error")' )
    local i
    for ((i=1; i<=23; i++)); do
        SP_DESCRIPTION[i]='Keyword triage search; matches require investigation and do not establish root cause or audit coverage.'
        SP_STATUS[i]=GENERATED_UNVALIDATED SP_COUNT[i]='UNKNOWN' SP_VALIDATED[i]='NEVER'
    done
    SP_INITIALIZED=1
}

splunk_quote() {
    local value=$1
    value=${value//\\/\\\\}; value=${value//\"/\\\"}
    value=${value//$'\r'/ }; value=${value//$'\n'/ }; value=${value//$'\t'/ }
    printf '"%s"' "$value"
}

splunk_scope_signature() {
    printf '%s\034%s\034%s' "${SPLUNK_URL:-}" "${SPLUNK_INDEX:-}" "${SPLUNK_SOURCETYPE:-}"
}

splunk_field_safe() {
    local field=$1 lower=${1,,}
    [[ $field =~ ^[a-zA-Z_][a-zA-Z0-9_.:-]*$ ]] || return 1
    case $lower in *password*|*passwd*|*token*|*secret*|*private*key*|*authorization*|*credential*|*api_key*|*apikey*) return 1;; esac
}

splunk_has_field() {
    local field
    for field in "${SP_FIELDS[@]}"; do [[ $field == "$1" ]] && return 0; done
    return 1
}

splunk_base() {
    printf 'search'
    [[ -n ${SPLUNK_INDEX:-} ]] && printf ' index=%s' "$(splunk_quote "$SPLUNK_INDEX")"
    [[ -n ${SPLUNK_SOURCETYPE:-} ]] && printf ' sourcetype=%s' "$(splunk_quote "$SPLUNK_SOURCETYPE")"
    printf ' earliest=-15m latest=now'
}

splunk_catalog_inputs() {
    local role field value
    SP_GENERATION_STATUS=GENERATED_UNVALIDATED SP_GENERATION_DETAIL=''
    if [[ -n ${SPLUNK_INDEX:-} && ! $SPLUNK_INDEX =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$ ]]; then
        SP_GENERATION_STATUS=INVALID SP_GENERATION_DETAIL='Index must be an explicit name without wildcards or SPL operators'; return 1
    fi
    if [[ -n ${SPLUNK_SOURCETYPE:-} && ! $SPLUNK_SOURCETYPE =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.:/-]*$ ]]; then
        SP_GENERATION_STATUS=INVALID SP_GENERATION_DETAIL='Sourcetype must be an explicit name without wildcards or SPL operators'; return 1
    fi
    for role in "${!SP_MAP[@]}"; do
        field=${SP_MAP[$role]} value=${SP_VALUE[$role]:-}
        if ! splunk_field_safe "$field" || ! splunk_has_field "$field"; then
            SP_GENERATION_STATUS=FIELD_NOT_FOUND SP_GENERATION_DETAIL='A mapped field is not a safe member of the observed field set'; return 1
        fi
        if [[ ${#value} -gt 2048 || $value == *[$'\001'-$'\037'$'\177']* ]]; then
            SP_GENERATION_STATUS=INVALID SP_GENERATION_DETAIL='Filter values must contain at most 2048 characters and no control characters'; return 1
        fi
    done
}

splunk_generate() {
    splunk_init
    local i role base signature maptext='' required='' scope sig note
    scope=$(splunk_scope_signature)
    if [[ -n $SP_DISCOVERY_SCOPE && $SP_DISCOVERY_SCOPE != "$scope" ]]; then
        SP_FIELDS=(); SP_MAP=(); SP_VALUE=(); SP_DISCOVERY_SCOPE=''; SP_DISCOVERED_AT=''
    fi
    if [[ -n $SP_KUBE_SCOPE && $SP_KUBE_SCOPE != "${SENTINEL_CONTEXT:-}|${SENTINEL_NAMESPACE:-}" ]]; then
        # A scope switch invalidates semantic filter values, even when the
        # same Splunk source still exposes the previously discovered fields.
        SP_MAP=(); SP_VALUE=()
    fi
    SP_KUBE_SCOPE="${SENTINEL_CONTEXT:-}|${SENTINEL_NAMESPACE:-}"
    if ! splunk_catalog_inputs; then
        for ((i=1; i<=23; i++)); do
            SP_QUERY[i]='' SP_STATUS[i]=$SP_GENERATION_STATUS SP_COUNT[i]=UNKNOWN SP_VALIDATED[i]=NEVER SP_NOTES[i]=$SP_GENERATION_DETAIL
        done
        SP_REQUIRED_FIELDS=NONE SP_SIGNATURE=''
        return 1
    fi
    base=$(splunk_base)
    for role in cluster namespace pod container node host application severity message; do
        if [[ -n ${SP_MAP[$role]:-} && -n ${SP_VALUE[$role]:-} ]]; then
            # where equality treats values literally and is case-sensitive;
            # search field=value would interpret a user-entered * as wildcard.
            maptext+="${maptext:+ AND }'${SP_MAP[$role]}'=$(splunk_quote "${SP_VALUE[$role]}")"
            required+="${required:+,}${SP_MAP[$role]}"
        fi
    done
    signature="$scope|${SENTINEL_CONTEXT:-}|${SENTINEL_NAMESPACE:-}|$maptext"
    if [[ $SP_SIGNATURE != "$signature" ]]; then
        for ((i=1; i<=23; i++)); do
            SP_STATUS[i]=GENERATED_UNVALIDATED SP_COUNT[i]='UNKNOWN' SP_VALIDATED[i]='NEVER'
        done
        SP_SIGNATURE=$signature
    fi
    note='Keyword triage only; event fields and coverage are not assumed. Time window: last 15 minutes. Mapped values use exact case-sensitive comparisons; wildcard characters are literal.'
    [[ -z ${SPLUNK_INDEX:-} ]] && note+=' Index unspecified; offline query uses Splunk permitted defaults; connected searches require an explicit index.'
    if [[ -z ${SP_MAP[namespace]:-} || ${SP_VALUE[namespace]:-} != "${SENTINEL_NAMESPACE:-}" ]]; then
        note+=' Namespace scope UNVERIFIED: no observed namespace field mapped to the selected namespace.'
    else
        note+=' Namespace filter uses an observed field; field semantics are user-selected.'
    fi
    SP_REQUIRED_FIELDS=${required:-NONE}
    for ((i=1; i<=23; i++)); do
        SP_QUERY[i]="$base ${SP_TERMS[i]}${maptext:+ | where $maptext}"
        if [[ ${SP_STATUS[i]} == GENERATED_UNVALIDATED ]]; then SP_NOTES[i]=$note; fi
    done
}

splunk_connection_check() {
    SP_REQUEST_STATUS=SPLUNK_UNAVAILABLE SP_REQUEST_DETAIL='NOT_CONFIGURED'
    has curl || { SP_REQUEST_DETAIL='COMMAND_MISSING: curl'; return 1; }
    has jq || { SP_REQUEST_DETAIL='COMMAND_MISSING: jq; offline generation remains available'; return 1; }
    [[ -n ${SPLUNK_URL:-} && -n ${SPLUNK_TOKEN:-} && -n ${SPLUNK_INDEX:-} ]] || return 1
    # A management origin/base path only: no URL credentials, queries or fragments.
    [[ $SPLUNK_URL =~ ^https://([a-zA-Z0-9.-]+|\[[a-fA-F0-9:]+\])(:[0-9]{1,5})?(/[a-zA-Z0-9._~-]*)*$ ]] || {
        SP_REQUEST_DETAIL='INVALID: supply an HTTPS management URL without credentials, query or fragment'; return 1;
    }
    [[ $SPLUNK_INDEX =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$ ]] || {
        SP_REQUEST_DETAIL='INVALID: index must be an explicit index name, without wildcard'; return 1;
    }
    [[ -z ${SPLUNK_SOURCETYPE:-} || $SPLUNK_SOURCETYPE =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.:/-]*$ ]] || {
        SP_REQUEST_DETAIL='INVALID: sourcetype contains unsupported characters'; return 1;
    }
    [[ $SPLUNK_TOKEN != *[$'\001'-$'\037'$'\177']* ]] || {
        SP_REQUEST_DETAIL='INVALID: token contains a control character'; return 1;
    }
    SP_REQUEST_STATUS=OK SP_REQUEST_DETAIL='HTTPS certificate verification enabled'
}

splunk_request() {
    # This is a fixed, read-only search endpoint. The token is sent on stdin,
    # never as an argument, environment of a child process, or a temporary file.
    local search=$1 payload token_config rc limit=${SPLUNK_TIMEOUT:-20}
    SP_RESPONSE='' SP_HTTP=''
    splunk_init
    splunk_connection_check || return 1
    [[ $limit =~ ^[0-9]+$ && $limit -ge 1 && $limit -le 300 ]] || limit=20
    token_config=${SPLUNK_TOKEN//\\/\\\\}; token_config=${token_config//\"/\\\"}
    payload=$(printf 'header = "Authorization: Bearer %s"\n' "$token_config" |
      run_bounded "$((limit+2))" curl -q --config - --silent --show-error --globoff \
        --proto '=https' --proto-redir '=https' --max-redirs 0 --connect-timeout 5 \
        --max-time "$limit" --max-filesize 2097152 --request POST \
        --data-urlencode "search=$search" --data-urlencode 'output_mode=json' \
        --data-urlencode 'preview=false' \
        --data-urlencode 'auto_cancel=30' --write-out $'\nSENTINEL_HTTP:%{http_code}' \
        "${SPLUNK_URL%/}/services/search/v2/jobs/export" 2>/dev/null)
    rc=$?; token_config=''
    SP_HTTP=${payload##*$'\nSENTINEL_HTTP:'}
    SP_RESPONSE=${payload%$'\nSENTINEL_HTTP:'*}
    if ((rc != 0)); then
        SP_REQUEST_STATUS=SPLUNK_UNAVAILABLE
        case $rc in
          28|124|137) SP_REQUEST_DETAIL='API_TIMEOUT: no complete result was accepted';;
          60|51) SP_REQUEST_DETAIL='TLS_ERROR: server certificate verification failed';;
          63) SP_REQUEST_DETAIL='OUTPUT_LIMIT: response exceeded 2 MiB';;
          *) SP_REQUEST_DETAIL="NETWORK_ERROR: curl/transport exit $rc";;
        esac
        SP_RESPONSE=''; return 1
    fi
    case $SP_HTTP in
      200) ;;
      401) SP_REQUEST_DETAIL='AUTH_ERROR: HTTP 401'; SP_REQUEST_STATUS=SPLUNK_UNAVAILABLE; SP_RESPONSE=''; return 1;;
      403) SP_REQUEST_DETAIL='RBAC_DENIED: HTTP 403'; SP_REQUEST_STATUS=SPLUNK_UNAVAILABLE; SP_RESPONSE=''; return 1;;
      400|422) SP_REQUEST_DETAIL="Search rejected: HTTP $SP_HTTP"; SP_REQUEST_STATUS=INVALID; SP_RESPONSE=''; return 1;;
      *) SP_REQUEST_DETAIL="HTTP $SP_HTTP: no completed search result"; SP_REQUEST_STATUS=SPLUNK_UNAVAILABLE; SP_RESPONSE=''; return 1;;
    esac
    # Never consider an HTTP 200 alone sufficient. Reject malformed JSON and
    # both top-level and streamed messages, including partial-result warnings.
    if ! printf '%s' "$SP_RESPONSE" | jq -e -s 'length > 0 and all(.[]; type == "object")' >/dev/null 2>&1; then
        SP_REQUEST_STATUS=INVALID SP_REQUEST_DETAIL='PARSE_ERROR: response is not a JSON result stream'; SP_RESPONSE=''; return 1
    fi
    if ! printf '%s' "$SP_RESPONSE" | jq -e -s '
        def harmless_message:
          type == "object" and (.text|type) == "string" and
          (.type|type) == "string" and ((.type|ascii_upcase) == "INFO" or (.type|ascii_upcase) == "DEBUG");
        all(.[];
          (has("error") or has("errors") | not) and
          ((has("messages")|not) or ((.messages|type) == "array" and all(.messages[]; harmless_message))) and
          ((has("text") or has("type") | not) or harmless_message) and
          (has("result") or has("messages") or has("text")))
      ' >/dev/null 2>&1; then
        SP_REQUEST_STATUS=INVALID SP_REQUEST_DETAIL='Server returned an error, warning, or malformed message envelope; complete search coverage is not verified'; SP_RESPONSE=''; return 1
    fi
    if ! printf '%s' "$SP_RESPONSE" | jq -e -s '
        [ .[] | select(.result? != null) ] as $r |
        ($r|length) > 0 and all($r[]; .preview == false and (.result|type) == "object") and
        ($r[-1].lastrow == true) and all($r[0:-1][]; .lastrow != true)
      ' >/dev/null 2>&1; then
        SP_REQUEST_STATUS=INVALID SP_REQUEST_DETAIL='Incomplete, preview-only, or unrecognized export; final result marker required'; SP_RESPONSE=''; return 1
    fi
    SP_REQUEST_STATUS=OK SP_REQUEST_DETAIL='Completed JSON export, no error/warning messages'
}

splunk_discover() {
    splunk_generate || { printf '%s: %s\n' "$SP_GENERATION_STATUS" "$SP_GENERATION_DETAIL"; return 1; }
    local field list rc query
    query="$(splunk_base) | head 500 | fieldsummary maxvals=1 | fields field | head 500"
    printf 'Discovering field names from at most 500 events in the last 15 minutes...\n'
    if ! splunk_request "$query"; then
        printf '%s: %s\n' "$SP_REQUEST_STATUS" "$SP_REQUEST_DETAIL"
        return 1
    fi
    list=$(printf '%s' "$SP_RESPONSE" | jq -r -s '[.[] | .result.field? | select(type == "string")] | unique[]' 2>/dev/null)
    rc=$?; SP_RESPONSE=''
    ((rc == 0)) || { printf 'PARSE_ERROR: discovery fields unavailable\n'; return 1; }
    SP_FIELDS=(); SP_MAP=(); SP_VALUE=()
    while IFS= read -r field; do
        splunk_field_safe "$field" && SP_FIELDS+=("$field")
    done <<< "$list"
    SP_DISCOVERY_SCOPE=$(splunk_scope_signature)
    SP_DISCOVERED_AT=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    printf 'Observed selectable fields: %s. Sample coverage only; absent fields are not proven absent from the index.\n' "${#SP_FIELDS[@]}"
    printf 'Sensitive field names and names outside the safe identifier grammar are excluded.\n'
    ((${#SP_FIELDS[@]})) && printf '  %s\n' "${SP_FIELDS[@]}"
}

splunk_map_fields() {
    local role selection field
    ((${#SP_FIELDS[@]})) || { printf 'FIELD_NOT_FOUND: run field discovery first.\n'; return 1; }
    choose 'Map observed field to semantic role' cluster namespace pod container node host application severity message || return
    role=$REPLY
    [[ $role =~ ^[0-9]+$ ]] && {
        local -a roles=(cluster namespace pod container node host application severity message)
        role=${roles[$((role-1))]:-}
    }
    case $role in cluster|namespace|pod|container|node|host|application|severity|message) ;; *) return 1;; esac
    choose 'Choose an observed field' "${SP_FIELDS[@]}" || return
    field=$REPLY
    [[ $field =~ ^[0-9]+$ ]] && field=${SP_FIELDS[$((field-1))]:-}
    splunk_has_field "$field" || { printf 'FIELD_NOT_FOUND\n'; return 1; }
    local value
    if [[ $role == namespace ]]; then
        value=${SENTINEL_NAMESPACE:-}
    else
        prompt "Value for $role (blank leaves the filter unset)" || return
        value=$REPLY
    fi
    [[ ${#value} -le 2048 && $value != *[$'\001'-$'\037'$'\177']* ]] || {
        printf 'INVALID: filter values must be short single-line strings without control characters.\n'; return 1;
    }
    SP_MAP[$role]=$field SP_VALUE[$role]=$value
    SP_SIGNATURE=''
    splunk_generate
    printf 'Mapped %s to observed field %s.\n' "$role" "$field"
}

splunk_validate() {
    local i=$1 role count rc
    splunk_generate || return 1
    [[ $i =~ ^[0-9]+$ && $i -ge 1 && $i -le 23 ]] || return 2
    SP_COUNT[i]=UNKNOWN SP_VALIDATED[i]=NEVER
    for role in "${!SP_MAP[@]}"; do
        if ! splunk_has_field "${SP_MAP[$role]}"; then
            SP_STATUS[i]=FIELD_NOT_FOUND SP_NOTES[i]="Mapped $role field is not in the observed field set"
            return 1
        fi
    done
    if ! splunk_request "${SP_QUERY[i]} | stats count"; then
        SP_STATUS[i]=$SP_REQUEST_STATUS SP_NOTES[i]=$SP_REQUEST_DETAIL
        return 1
    fi
    count=$(printf '%s' "$SP_RESPONSE" | jq -e -r -s '
      [.[] | select(.result? != null) | .result] as $r |
      if ($r|length) == 1 and ($r[0].count|type) == "string" and ($r[0].count|test("^(0|[1-9][0-9]*)$"))
      then $r[0].count else error("count result missing or ambiguous") end' 2>/dev/null)
    rc=$?; SP_RESPONSE=''
    if ((rc != 0)); then
        SP_STATUS[i]=INVALID SP_NOTES[i]='PARSE_ERROR: exactly one non-negative count result is required'
        return 1
    fi
    SP_COUNT[i]=$count SP_VALIDATED[i]=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    if [[ $count == 0 ]]; then SP_STATUS[i]=NO_MATCH; else SP_STATUS[i]=VALIDATED; fi
    SP_NOTES[i]='Observed completed search count for the displayed query and last 15 minutes; keyword matches do not prove coverage or cause.'
    return 0
}

splunk_report() {
    splunk_generate
    local i selected=${1:-all}
    printf 'SPLUNK AUDIT QUERY CATALOG\nCONTEXT %s  NAMESPACE %s\n' "${SENTINEL_CONTEXT:-UNSELECTED}" "${SENTINEL_NAMESPACE:-UNSELECTED}"
    printf 'SOURCE locally generated SPL; last discovery %s; validation is per query\n' "${SP_DISCOVERED_AT:-NEVER}"
    printf 'INDEX %s  SOURCETYPE %s\n' "${SPLUNK_INDEX:-UNSPECIFIED}" "${SPLUNK_SOURCETYPE:-UNSPECIFIED}"
    printf 'No field semantics, event coverage or source matches are inferred.\n'
    for ((i=1; i<=23; i++)); do
        [[ $selected == all || $selected == "$i" ]] || continue
        printf '\nID AUD-K8S-%03d\nCATEGORY %s\nSTATUS %s\n' "$i" "${SP_CATEGORY[i]}" "${SP_STATUS[i]}"
        printf 'QUERY\n%s\nREQUIRED_FIELDS %s\nMATCHES %s\nVALIDATED %s\nNOTES %s\n' \
          "${SP_QUERY[i]}" "$SP_REQUIRED_FIELDS" "${SP_COUNT[i]}" "${SP_VALIDATED[i]}" "${SP_NOTES[i]}"
    done
}

splunk_csv_cell() {
    local value=$1
    value=${value//\"/\"\"}
    printf '"%s"' "$value"
}

splunk_catalog_csv() {
    local i cell first id
    splunk_generate
    printf 'ID,CATEGORY,DESCRIPTION,SPL,REQUIRED_FIELDS,VALIDATION_STATUS,MATCH_COUNT,LAST_VALIDATED,NOTES\n'
    for ((i=1; i<=23; i++)); do
        printf -v id 'AUD-K8S-%03d' "$i"
        first=1
        for cell in "$id" "${SP_CATEGORY[i]}" "${SP_DESCRIPTION[i]}" "${SP_QUERY[i]}" "$SP_REQUIRED_FIELDS" \
          "${SP_STATUS[i]}" "${SP_COUNT[i]}" "${SP_VALIDATED[i]}" "${SP_NOTES[i]}"; do
            ((first)) || printf ','
            splunk_csv_cell "$cell"; first=0
        done
        printf '\n'
    done
}

splunk_export() {
    # Accept a basename only; arbitrary filesystem paths are deliberately absent.
    local name=${1:-splunk-catalog-$(date -u '+%Y%m%dT%H%M%SZ').csv} path
    [[ $name =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*\.csv$ ]] || { printf 'INVALID: export name must be a CSV basename.\n'; return 2; }
    path="$OUTPUT_DIR/$name"
    [[ ! -e $path && ! -L $path ]] || { printf 'Export already exists: %s\n' "$name"; return 1; }
    (set -o noclobber; splunk_catalog_csv | redact > "$path") || return 1
    printf 'EXPORTED %s\n' "$path"
}

splunk_configure() {
    prompt 'Splunk HTTPS management URL (blank keeps current)' || return
    [[ -z $REPLY ]] || SPLUNK_URL=$REPLY
    prompt 'Splunk index (blank keeps current)' || return
    [[ -z $REPLY ]] || SPLUNK_INDEX=$REPLY
    prompt 'Splunk sourcetype (blank leaves unchanged; - clears)' || return
    if [[ $REPLY == - ]]; then SPLUNK_SOURCETYPE=''; elif [[ -n $REPLY ]]; then SPLUNK_SOURCETYPE=$REPLY; fi
    if [[ -t 0 ]]; then
        printf 'Splunk token (silent; blank keeps current): '
        local entered=''
        IFS= read -r -s entered || { printf '\n'; return 1; }
        printf '\n'
        [[ -z $entered ]] || SPLUNK_TOKEN=$entered
        entered=''; export -n SPLUNK_TOKEN 2>/dev/null || :
    fi
    SP_SIGNATURE=''; splunk_generate
}

splunk_diagnostics() {
    splunk_init
    if splunk_connection_check; then
        printf 'SPLUNK CONFIGURED_UNTESTED; HTTPS verification enabled; token held only in memory\n'
    else
        printf 'SPLUNK %s: %s\n' "$SP_REQUEST_STATUS" "$SP_REQUEST_DETAIL"
    fi
    printf 'Offline catalog AVAILABLE (23 categories); connected operations are on demand.\n'
}

splunk_menu() {
    local action selected
    while :; do
        printf '\nSPLUNK AUDIT\n[1] Generate Queries Only  [2] Discover Fields  [3] Validate Generated Query\n'
        printf '[4] Audit Query Catalog  [5] Export SPL Catalog  [6] Configuration  [7] Map Fields\n[8] Help  [0] Back\n'
        prompt 'Selection' || return
        action=$REPLY
        case $action in
          1|4) capture_report 'Splunk Audit Catalog' splunk_report; view_file "$CURRENT_REPORT" 'Splunk Audit Catalog';;
          2) splunk_discover;;
          3)
            splunk_generate
            choose 'Select catalog query to validate' "${SP_CATEGORY[@]:1}" || continue
            selected=$REPLY
            if [[ ! $selected =~ ^[0-9]+$ ]]; then
                local i
                for ((i=1; i<=23; i++)); do [[ ${SP_CATEGORY[i]} == "$selected" ]] && { selected=$i; break; }; done
            fi
            splunk_validate "$selected"
            capture_report 'Splunk Query Validation' splunk_report "$selected"
            view_file "$CURRENT_REPORT" 'Splunk Query Validation';;
          5) splunk_export;;
          6) splunk_configure;;
          7) splunk_map_fields;;
          8) printf '%s\n' 'Purpose: generate 23 keyword triage searches; optional count-only validation.' \
             'Source: user-selected Splunk index/sourcetype; fields come from a bounded observed sample.' \
             'Scope: namespace filtering requires a discovered field mapping; otherwise scope is UNVERIFIED.' \
             'Refresh: manual only; queries search the last 15 minutes, discovery samples 500 events.' \
             'Limitations: keyword matches do not prove cause or coverage; TLS verification cannot be disabled.' \
             'Validation requires a completed export with a numeric count; errors and previews are never VALIDATED.';;
          0|q) return;;
          *) printf 'Choose a listed number.\n';;
        esac
    done
}

# Isolated response fixtures replace only the transport, never contact Splunk,
# and assert that the credential remains absent from process arguments and env.
splunk_self_tests() (
    has jq || { printf 'SKIP: jq unavailable for Splunk response fixtures\n'; return 77; }
    SP_INITIALIZED=0 SP_SIGNATURE='' SP_DISCOVERY_SCOPE=''
    SP_FIELDS=() SP_MAP=() SP_VALUE=()
    SENTINEL_CONTEXT=fixture-context SENTINEL_NAMESPACE=fixture-namespace
    SPLUNK_URL=https://splunk.example.invalid:8089 SPLUNK_INDEX=fixture_index SPLUNK_SOURCETYPE=fixture_type
    SPLUNK_TOKEN='fixture-secret-"quoted"-\token'
    export SPLUNK_TOKEN
    local fixture_body='{"preview":false,"result":{"count":"7"},"lastrow":true}'
    local fixture_http=200 fixture_rc=0 fixture_category
    DEV_TEST_TOTAL=0 DEV_TEST_PASSED=0 DEV_TEST_FAILED=0
    run_bounded() { shift; "$@"; }
    curl() {
        local argument line
        for argument in "$@"; do
            [[ $argument != *fixture-secret* && $argument != --insecure && $argument != --location ]] || return 99
            [[ $argument != exec_mode=* ]] || return 99
        done
        [[ -z $(printenv SPLUNK_TOKEN) ]] || return 99
        IFS= read -r line
        [[ $line == 'header = "Authorization: Bearer '* ]] || return 99
        printf '%s\nSENTINEL_HTTP:%s' "$fixture_body" "$fixture_http"
        return "$fixture_rc"
    }
    splunk_validate 1
    dev_test_equal SPLUNK_COMPLETED_COUNT VALIDATED "${SP_STATUS[1]}"
    dev_test_equal SPLUNK_COUNT_VALUE 7 "${SP_COUNT[1]}"
    fixture_body='{"preview":false,"result":{"count":"0"},"lastrow":true}'
    splunk_validate 1
    dev_test_equal SPLUNK_ZERO_COUNT NO_MATCH "${SP_STATUS[1]}"
    for fixture_body in '{"messages":[{"type":"ERROR","text":"bad query"}]}' \
      '{"preview":false,"result":{"count":"4"},"lastrow":true,"messages":[{"type":"WARN","text":"partial"}]}' \
      '{"preview":true,"result":{"count":"4"},"lastrow":true}' \
      '{"preview":false,"result":{"count":"4"}}' \
      '{"preview":false,"result":{"count":"invalid"},"lastrow":true}' \
      '{"preview":false,"result":{"count":7},"lastrow":true}' \
      '{"preview":false,"result":{"count":"00"},"lastrow":true}' \
      '{"preview":false,"result":{"count":"7"},"lastrow":true,"messages":"ERROR"}' \
      '{"preview":false,"result":{"count":"7"},"lastrow":true,"messages":["ERROR"]}' \
      '{"preview":false,"result":{"count":"7"},"lastrow":true,"messages":[{"type":123,"text":"malformed"}]}' \
      '{"preview":false,"result":{"count":"7"},"lastrow":true,"messages":null}' \
      '{"preview":false,"result":{"count":"4"},"lastrow":true' \
      $'{"preview":false,"result":{"count":"4"},"lastrow":true}\n{"preview":false,"result":{"count":"2"},"lastrow":true}'; do
        splunk_validate 1
        dev_test_equal SPLUNK_REJECT_INVALID INVALID "${SP_STATUS[1]}"
    done
    fixture_body='{"preview":false,"result":{"count":"7"},"lastrow":true}'
    fixture_http=400
    splunk_validate 1
    dev_test_equal SPLUNK_HTTP_BAD_REQUEST INVALID "${SP_STATUS[1]}"
    fixture_http=403
    splunk_validate 1
    dev_test_equal SPLUNK_HTTP_FORBIDDEN SPLUNK_UNAVAILABLE "${SP_STATUS[1]}"
    fixture_http=302
    splunk_validate 1
    dev_test_equal SPLUNK_REDIRECT_REFUSED SPLUNK_UNAVAILABLE "${SP_STATUS[1]}"
    fixture_http=401
    splunk_validate 1
    dev_test_equal SPLUNK_AUTH SPLUNK_UNAVAILABLE "${SP_STATUS[1]}"
    fixture_http=200 fixture_rc=28
    splunk_validate 1
    dev_test_equal SPLUNK_TIMEOUT SPLUNK_UNAVAILABLE "${SP_STATUS[1]}"
    fixture_rc=0
    SPLUNK_TOKEN=$'unsafe\nheader = evil'
    splunk_validate 1
    dev_test_equal SPLUNK_HEADER_INJECTION SPLUNK_UNAVAILABLE "${SP_STATUS[1]}"
    SPLUNK_TOKEN=fixture-secret SPLUNK_URL=https://fixture-secret@splunk.example.invalid
    splunk_validate 1
    dev_test_equal SPLUNK_URL_CREDENTIALS SPLUNK_UNAVAILABLE "${SP_STATUS[1]}"
    SPLUNK_URL=https://splunk.example.invalid
    SP_FIELDS=(observed.namespace)
    SP_MAP[namespace]=observed.namespace SP_VALUE[namespace]=fixture-namespace
    SP_DISCOVERY_SCOPE=$(splunk_scope_signature)
    splunk_generate
    dev_test_equal SPLUNK_OBSERVED_MAPPING 1 "$( [[ ${SP_QUERY[1]} == *observed.namespace* ]] && printf 1 || printf 0 )"
    dev_test_equal SPLUNK_EXACT_NAMESPACE_FILTER 1 "$( [[ ${SP_QUERY[1]} == *" | where 'observed.namespace'=\"fixture-namespace\"" ]] && printf 1 || printf 0 )"
    SP_FIELDS+=(observed.pod)
    SP_MAP[pod]=observed.pod SP_VALUE[pod]='literal*pod'
    splunk_generate
    dev_test_equal SPLUNK_WILDCARD_IS_LITERAL 1 "$( [[ ${SP_QUERY[1]} == *"'observed.pod'=\"literal*pod\"" ]] && printf 1 || printf 0 )"
    SP_VALUE[pod]='x" OR 1=1 | stats count `untrusted`'
    splunk_generate
    dev_test_equal SPLUNK_VALUE_QUOTE_ESCAPED 1 "$( [[ ${SP_QUERY[1]} == *"'observed.pod'=\"x\\\" OR 1=1 | stats count \`untrusted\`\"" ]] && printf 1 || printf 0 )"
    SP_VALUE[pod]=$'line1\nline2'
    splunk_generate
    dev_test_equal SPLUNK_CONTROL_VALUE_REJECT INVALID "${SP_STATUS[1]}"
    SP_VALUE[pod]=somepod
    SP_MAP[pod]=missing.field SP_VALUE[pod]=somepod
    splunk_validate 1
    dev_test_equal SPLUNK_ABSENT_FIELD FIELD_NOT_FOUND "${SP_STATUS[1]}"
    SP_MAP[pod]=observed.pod
    SENTINEL_NAMESPACE=next-namespace
    splunk_generate
    dev_test_equal SPLUNK_SCOPE_SWITCH_RESETS_MAP 0 "${#SP_MAP[@]}"
    SP_MAP=() SP_VALUE=()
    SPLUNK_URL='' SPLUNK_INDEX='' SPLUNK_SOURCETYPE=''
    splunk_generate
    dev_test_equal SPLUNK_OFFLINE_STATUS GENERATED_UNVALIDATED "${SP_STATUS[1]}"
    dev_test_equal SPLUNK_CATEGORY_COUNT 23 "$(( ${#SP_CATEGORY[@]} - 1 ))"
    dev_test_equal SPLUNK_CSV_ROWS 24 "$(splunk_catalog_csv | wc -l)"
    dev_test_equal SPLUNK_CSV_QUOTING '"a,""b"""' "$(splunk_csv_cell 'a,"b"')"
    for ((fixture_category=1; fixture_category<=23; fixture_category++)); do
        dev_test_equal "SPLUNK_OFFLINE_CATEGORY_$fixture_category" GENERATED_UNVALIDATED "${SP_STATUS[fixture_category]}"
    done
    SPLUNK_INDEX='*'
    splunk_generate
    dev_test_equal SPLUNK_INDEX_WILDCARD_REJECT INVALID "${SP_STATUS[1]}"
    dev_test_equal SPLUNK_INVALID_HAS_NO_QUERY '' "${SP_QUERY[1]}"
    SPLUNK_INDEX=fixture_index SPLUNK_SOURCETYPE='" OR index=*'
    splunk_generate
    dev_test_equal SPLUNK_SOURCETYPE_INJECTION_REJECT INVALID "${SP_STATUS[1]}"
    printf 'SPLUNK FIXTURES %s/%s PASS\n' "$DEV_TEST_PASSED" "$DEV_TEST_TOTAL"
    ((DEV_TEST_FAILED == 0))
)

# 19 Isolated developer workflow. Normal dashboard execution never calls these
# entry points. WSL is a development gate, not a production runtime dependency.
: "${DEV_GIT_REMOTE:=${SNTL_GIT_REMOTE:-}}" "${DEV_GIT_BRANCH:=${SNTL_GIT_BRANCH:-}}"
: "${DEV_MESSAGE:=}" "${DEV_WITH_SMOKE:=0}" "${DEV_ALLOW_PROTECTED_BRANCH:=0}"
: "${DEV_FLUX_SOURCE:=${SNTL_FLUX_GITREPOSITORY:-}}" "${DEV_FLUX_NAMESPACE:=${SNTL_FLUX_NAMESPACE:-}}"
: "${DEV_FLUX_WAIT:=${SNTL_FLUX_WAIT:-120}}" "${DEV_FLUX_RECONCILE:=0}" "${DEV_REQUIRE_FLUX:=0}"
: "${DEV_ALLOW_PROD_RECONCILE:=0}" "${DEV_NON_INTERACTIVE:=0}" "${DEV_COMMIT:=}" "${DEV_BUMP:=}"
DEV_SOURCE='' DEV_DIR='' DEV_REPO='' DEV_SOURCE_REL='' DEV_BRANCH='' DEV_REMOTE=''
DEV_REMOTE_URL='' DEV_REMOTE_SHA='' DEV_COMMIT_SHA='' DEV_PUSH_VERIFIED=0 DEV_TESTS_PASSED=0
DEV_LOCK_DIR='' DEV_LOCK_FD='' DEV_LOCK_OWNED=0 DEV_BACKUP='' DEV_MODIFIED_SHA='' DEV_PRIVATE_INDEX=''
DEV_TEST_TOTAL=0 DEV_TEST_PASSED=0 DEV_TEST_FAILED=0 DEV_TEST_SKIPPED=0

dev_source_path() {
    local directory
    [[ ${SOURCE_FILE##*/} == KubeOps_Sentinel.sh && -f $SOURCE_FILE && ! -L $SOURCE_FILE ]] || {
        printf '[FAIL] Source must be the regular, non-symlink KubeOps_Sentinel.sh\n' >&2; return 2;
    }
    directory=$(cd -- "$(dirname -- "$SOURCE_FILE")" && pwd -P) || return 2
    DEV_SOURCE="$directory/KubeOps_Sentinel.sh"
    DEV_DIR="$directory/.sentinel-dev"
    [[ ! -L $DEV_DIR ]] || { printf '[FAIL] .sentinel-dev is a symlink\n' >&2; return 2; }
    [[ ! -e $DEV_DIR || -d $DEV_DIR ]] || return 2
    mkdir -p -- "$DEV_DIR" || return 2
}

dev_is_wsl() {
    [[ $(uname -s 2>/dev/null) == Linux ]] || return 1
    [[ -n ${WSL_INTEROP:-} || -n ${WSL_DISTRO_NAME:-} ]] && return 0
    [[ -r /proc/version ]] && grep -qi microsoft /proc/version
}

dev_environment() {
    local version path failed=0
    if dev_is_wsl; then printf '[PASS] WSL Linux environment\n'
    else printf '[FAIL] Development validation requires native Linux inside WSL\n'; failed=1; fi
    if ((BASH_VERSINFO[0] > 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] >= 4))); then
        printf '[PASS] Bash >= 4.4\n'
    else printf '[FAIL] Bash >= 4.4 required\n'; failed=1; fi
    path=$(command -v kubectl 2>/dev/null)
    case ${path,,} in *.exe|/mnt/?/*)
        printf '[FAIL] Windows kubectl detected; select a Linux kubectl: %s\n' "$path"; failed=1;;
      '') printf '[WARN] kubectl not installed; live tests unavailable\n';;
      *) printf '[PASS] Linux kubectl executable: %s\n' "$path";;
    esac
    return "$failed"
}

dev_sha256() {
    local result
    if has sha256sum; then result=$(sha256sum -- "$1") || return
    elif has shasum; then result=$(shasum -a 256 -- "$1") || return
    elif has openssl; then result=$(openssl dgst -sha256 "$1") || return; result=${result##* }
    else printf 'SHA256_UNAVAILABLE\n' >&2; return 1; fi
    result=${result%% *}
    [[ $result =~ ^[a-fA-F0-9]{64}$ ]] || return 1
    printf '%s\n' "${result,,}"
}

dev_stream_sha256() {
    local result
    if has sha256sum; then result=$(sha256sum) || return
    elif has shasum; then result=$(shasum -a 256) || return
    elif has openssl; then result=$(openssl dgst -sha256) || return; result=${result##* }
    else return 1; fi
    result=${result%% *}
    [[ $result =~ ^[a-fA-F0-9]{64}$ ]] || return 1
    printf '%s\n' "${result,,}"
}

dev_git_url_normalize() {
    local value=$1 authority path host
    value=${value%%\?*}; value=${value%%\#*}
    if [[ $value == *://* ]]; then
        value=${value#*://}; authority=${value%%/*}; path=${value#*/}
        [[ $path != "$value" ]] || return 1
        authority=${authority##*@}; host=$authority
        [[ $host == *:22 ]] && host=${host%:22}
    elif [[ $value == *@*:* ]]; then
        value=${value#*@}; host=${value%%:*}; path=${value#*:}
    else return 1; fi
    path=${path#/}; path=${path%/}; path=${path%.git}
    [[ -n $host && -n $path && $host != *[$'\n\r\t ']* && $path != *[$'\n\r\t ']* ]] || return 1
    printf '%s/%s\n' "${host,,}" "$path"
}

dev_git_discover() {
    dev_source_path || return
    has git || { printf '[FAIL] git not installed\n' >&2; return 2; }
    DEV_REPO=$(git -C "${DEV_SOURCE%/*}" rev-parse --show-toplevel 2>/dev/null) || {
        printf '[FAIL] Source is not in a Git repository\n' >&2; return 2;
    }
    DEV_REPO=$(cd -- "$DEV_REPO" && pwd -P) || return
    [[ $DEV_SOURCE == "$DEV_REPO/"* ]] || return 2
    DEV_SOURCE_REL=${DEV_SOURCE#"$DEV_REPO/"}
    DEV_BRANCH=$(git -C "$DEV_REPO" symbolic-ref --quiet --short HEAD 2>/dev/null) || {
        printf '[FAIL] Detached HEAD: select a branch before publication\n' >&2; return 2;
    }
    [[ -z $DEV_GIT_BRANCH || $DEV_GIT_BRANCH == "$DEV_BRANCH" ]] || {
        printf '[FAIL] --git-branch must match the checked-out branch; automatic checkout is disabled\n' >&2; return 2;
    }
    git -C "$DEV_REPO" check-ref-format --branch "$DEV_BRANCH" >/dev/null 2>&1 || return 2
    DEV_COMMIT_SHA=$(git -C "$DEV_REPO" rev-parse --verify HEAD 2>/dev/null) || DEV_COMMIT_SHA=''
    local remote found=0 fetch_url fetch_identity push_identity
    local -a remotes=()
    while IFS= read -r remote; do [[ -n $remote ]] && remotes+=("$remote"); done < <(git -C "$DEV_REPO" remote)
    DEV_REMOTE=$DEV_GIT_REMOTE
    if [[ -z $DEV_REMOTE ]]; then
        for remote in "${remotes[@]}"; do [[ $remote == origin ]] && DEV_REMOTE=origin; done
        if [[ -z $DEV_REMOTE && ${#remotes[@]} == 1 ]]; then DEV_REMOTE=${remotes[0]}; fi
    fi
    if [[ -z $DEV_REMOTE ]]; then
        printf '[WARN] Git remote NOT_CONFIGURED or ambiguous; use --git-remote NAME\n' >&2
        DEV_REMOTE_URL=''; return 0
    fi
    [[ $DEV_REMOTE =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$ ]] || return 2
    for remote in "${remotes[@]}"; do [[ $remote == "$DEV_REMOTE" ]] && found=1; done
    ((found)) || { printf '[FAIL] Requested remote does not exist\n' >&2; return 2; }
    DEV_REMOTE_URL=$(git -C "$DEV_REPO" remote get-url --push "$DEV_REMOTE" 2>/dev/null) || return 2
    [[ $(git -C "$DEV_REPO" remote get-url --push --all "$DEV_REMOTE" | wc -l) -eq 1 ]] || {
        printf '[FAIL] Multiple push URLs require manual publication\n' >&2; return 2;
    }
    fetch_url=$(git -C "$DEV_REPO" remote get-url "$DEV_REMOTE" 2>/dev/null) || return 2
    fetch_identity=$(dev_git_url_normalize "$fetch_url") || fetch_identity=$fetch_url
    push_identity=$(dev_git_url_normalize "$DEV_REMOTE_URL") || push_identity=$DEV_REMOTE_URL
    [[ $fetch_identity == "$push_identity" ]] || {
        printf '[FAIL] Remote fetch and push repositories differ; automated SHA verification requires the same repository\n' >&2; return 2;
    }
}

dev_git_error_class() {
    local message=${1,,}
    case $message in
      *'protected branch'*|*gh006*|*gh013*) printf 'PROTECTED_BRANCH';;
      *'repository not found'*|*'does not appear to be a git repository'*) printf 'REMOTE_NOT_FOUND';;
      *'authentication failed'*|*'could not read username'*|*'terminal prompts disabled'*|*'could not read password'*) printf 'AUTH_REQUIRED';;
      *'permission denied'*|*'access denied'*|*'write access'*|*'403'*) printf 'PERMISSION_DENIED';;
      *'could not resolve'*|*'connection'*|*'timed out'*|*'network'*) printf 'NETWORK_ERROR';;
      *'non-fast-forward'*|*'fetch first'*) printf 'NON_FAST_FORWARD';;
      *) printf 'UNKNOWN';;
    esac
}

dev_git_network() {
    local result rc
    result=$(GIT_TERMINAL_PROMPT=0 GCM_INTERACTIVE=never run_bounded 60 git -C "$DEV_REPO" "$@" 2>&1)
    rc=$?
    if ((rc)); then
        if ((rc == 124 || rc == 137)); then printf '[FAIL] Git NETWORK_ERROR: bounded operation timed out\n' >&2
        else printf '[FAIL] Git %s\n' "$(dev_git_error_class "$result")" >&2; fi
        return "$rc"
    fi
    # Only the caller that needs a ref listing sees successful output; the
    # transport's failure text is never logged because it may contain a token.
    printf '%s\n' "$result" | redact
}

dev_git_remote_head() {
    local listing sha ref
    DEV_REMOTE_SHA=''
    [[ -n $DEV_REMOTE ]] || { printf '[FAIL] Git remote NOT_CONFIGURED\n' >&2; return 2; }
    listing=$(dev_git_network ls-remote --heads "$DEV_REMOTE" "refs/heads/$DEV_BRANCH") || return
    while IFS=$'\t' read -r sha ref; do
        if [[ $ref == "refs/heads/$DEV_BRANCH" && $sha =~ ^[a-fA-F0-9]{40}([a-fA-F0-9]{24})?$ ]]; then DEV_REMOTE_SHA=${sha,,}; fi
    done <<< "$listing"
}

dev_info() {
    dev_source_path || return
    local tool path state count
    printf 'KUBEOPS SENTINEL :: DEVELOPMENT ENVIRONMENT\n'
    printf 'OS %s\nKERNEL %s\nBASH %s\nPWD %s\nSOURCE %s\n' "$(uname -s)" "$(uname -r)" "$BASH_VERSION" "$PWD" "$DEV_SOURCE"
    if dev_is_wsl; then printf 'WSL YES\n'; else printf 'WSL NO\n'; fi
    printf 'WSL DISTRIBUTION %s\n' "${WSL_DISTRO_NAME:-UNKNOWN}"
    if [[ -n ${VSCODE_IPC_HOOK_CLI:-} || ${TERM_PROGRAM:-} == vscode ]]; then printf 'VS CODE SESSION DETECTED (WSL transport inferred only when WSL=YES)\n'
    else printf 'VS CODE WSL UNKNOWN\n'; fi
    for tool in bash git kubectl shellcheck flux helm jq openssl sha256sum; do
        path=$(command -v "$tool" 2>/dev/null)
        printf '%-15s %s\n' "$tool" "${path:-NOT INSTALLED}"
    done
    printf 'KUBECONFIG MODE %s\n' "$KUBECONFIG_MODE"
    [[ $KUBECONFIG_MODE == EXPLICIT ]] && printf 'KUBECONFIG %s\n' "${KUBECONFIG:-}"
    if dev_git_discover; then
        printf 'REPOSITORY %s\nBRANCH %s\nREMOTE %s\nREMOTE URL %s\nHEAD %s\n' "$DEV_REPO" "$DEV_BRANCH" "${DEV_REMOTE:-NONE}" "$(sanitize_url "$DEV_REMOTE_URL")" "${DEV_COMMIT_SHA:-UNBORN}"
        if [[ -n $(git -C "$DEV_REPO" status --porcelain --untracked-files=normal) ]]; then printf 'UNCOMMITTED CHANGES YES\n'; else printf 'UNCOMMITTED CHANGES NO\n'; fi
    fi
    dev_source_integrity
    if has kubectl && [[ $(command -v kubectl) != *.exe ]]; then
        count=$(run_bounded "$API_TIMEOUT" kubectl config get-contexts -o name 2>/dev/null | awk 'NF{n++} END{print n+0}')
        printf 'CONTEXTS %s\n' "${count:-UNKNOWN}"
        printf 'CURRENT CONTEXT '
        run_bounded "$API_TIMEOUT" kubectl config current-context 2>/dev/null | redact
    fi
    if [[ -n $SENTINEL_CONTEXT && -n $SENTINEL_NAMESPACE ]] && dev_is_wsl; then
        dev_smoke
    else printf 'AUTHENTICATION / API / FLUX NOT_TESTED: supply explicit test context and namespace for live preflight\n'; fi
}

dev_source_integrity() {
    local first failed=0
    IFS= read -r first < "$DEV_SOURCE"
    if [[ $first == '#!/usr/bin/env bash' ]]; then printf '[PASS] Shebang\n'
    else printf '[FAIL] Shebang must be #!/usr/bin/env bash\n'; failed=1; fi
    if LC_ALL=C grep -q $'\r' "$DEV_SOURCE"; then printf '[FAIL] LINE ENDINGS: carriage returns found; LF is required\n'; failed=1
    else printf '[PASS] LF line endings\n'; fi
    if [[ -x $DEV_SOURCE ]]; then printf '[PASS] Executable permission\n'
    else printf '[FAIL] Executable permission missing\n'; failed=1; fi
    if LC_ALL=C grep -Eq '^(<<<<<<< |=======|>>>>>>> )' "$DEV_SOURCE"; then
        printf '[FAIL] Merge conflict markers in source\n'; failed=1
    fi
    has file && file -- "$DEV_SOURCE"
    return "$failed"
}

dev_static_safety() {
    # A conservative textual check, not a shell parser or a security proof.
    # Data in quoted strings can be flagged; comments are excluded. The only
    # allowed reconcile command is guarded in dev_flux_reconcile_guarded.
    local failed=0 matches forbidden tokenword
    forbidden='(^|[;&|[:space:]])e''val([[:space:]]|$)|kubectl[[:space:]]+(delete|patch|apply|edit|replace|scale)|kubectl[[:space:]]+rollout[[:space:]]+restart|helm[[:space:]]+(upgrade|uninstall)|flux[[:space:]]+(suspend|resume|bootstrap)'
    matches=$(awk '!/^[[:space:]]*#/' "$DEV_SOURCE" | grep -En "$forbidden")
    if [[ -n $matches ]]; then
        printf '[FAIL] STATIC SECURITY CHECK: forbidden command pattern detected\n'; failed=1
    else printf '[PASS] STATIC SECURITY CHECK: forbidden command patterns absent\n'; fi
    tokenword='(echo|printf)[[:space:]].*\$(TOKEN|PASSWORD|SPLUNK_TOKEN)([^[:alnum:]_]|$)|cat[[:space:]].*\.kube/config'
    if awk '!/^[[:space:]]*#/' "$DEV_SOURCE" | grep -Eq "$tokenword"; then
        printf '[FAIL] STATIC SECURITY CHECK: obvious credential printing pattern\n'; failed=1
    else printf '[PASS] STATIC SECURITY CHECK: obvious credential printing patterns absent\n'; fi
    if ! grep -Fq 'set -o pipefail' "$DEV_SOURCE"; then printf '[FAIL] pipefail absent\n'; failed=1; fi
    local function
    for function in kctl_ns kctl_cluster scope_args_safe redact cache_fresh bootstrap_scope resources_report health_report gitops_report certificates_report splunk_report capture_report view_file; do
        if ! declare -F "$function" >/dev/null; then printf '[FAIL] Function reference: %s\n' "$function"; failed=1; fi
    done
    if ((failed == 0)); then printf '[PASS] Required function references\n'; fi
    printf '[INFO] Static pattern checks do not constitute comprehensive security certification\n'
    return "$failed"
}

dev_test_equal() {
    local id=$1 expected=$2 actual=$3
    ((DEV_TEST_TOTAL+=1))
    if [[ $actual == "$expected" ]]; then ((DEV_TEST_PASSED+=1)); printf '%-40s PASS\n' "$id"
    else ((DEV_TEST_FAILED+=1)); printf '%-40s FAIL\n' "$id"; fi
}

dev_test_status() {
    local id=$1 expected=$2 rc
    shift 2
    "$@" >/dev/null 2>&1; rc=$?
    dev_test_equal "$id" "$expected" "$rc"
}

dev_duration() {
    local seconds=$1
    [[ $seconds =~ ^[0-9]+$ ]] || { printf 'UNKNOWN'; return 1; }
    printf '%dd %02dh %02dm %02ds' "$((seconds/86400))" "$((seconds/3600%24))" "$((seconds/60%60))" "$((seconds%60))"
}

dev_cache_fixture() (
    local saved_dir
    saved_dir=$(mktemp -d "$RUN_DIR/unit-cache.XXXXXX") || exit 1
    CACHE_DIR=$saved_dir FORCE_REFRESH=0
    printf 'OK\n' > "$CACHE_DIR/fixture.status"
    printf '95\n' > "$CACHE_DIR/fixture.time"
    now_epoch() { printf '100\n'; }
    cache_fresh fixture 6 || exit 1
    cache_fresh fixture 5 && exit 1
    FORCE_REFRESH=1
    cache_fresh fixture 100 && exit 1
    rm -f -- "$CACHE_DIR/fixture.status" "$CACHE_DIR/fixture.time"
    rmdir -- "$CACHE_DIR"
)

dev_self_test() {
    DEV_TEST_TOTAL=0 DEV_TEST_PASSED=0 DEV_TEST_FAILED=0 DEV_TEST_SKIPPED=0
    local fixture actual role
    printf 'DETERMINISTIC SELF TESTS (no Kubernetes or network access)\n'
    dev_test_equal ERROR_AUTH AUTH_ERROR "$(classify_error 1 'Unauthorized')"
    dev_test_equal ERROR_RBAC RBAC_DENIED "$(classify_error 1 'Forbidden: cannot list pods')"
    dev_test_equal ERROR_TIMEOUT API_TIMEOUT "$(classify_error 124 '')"
    dev_test_equal ERROR_NETWORK NETWORK_ERROR "$(classify_error 1 'connection refused')"
    dev_test_equal ERROR_NETWORK_URL_TIMEOUT NETWORK_ERROR "$(classify_error 1 'Get https://example.invalid/api?timeout=10s: connect: connection refused')"
    dev_test_equal ERROR_MISSING COMMAND_MISSING "$(classify_error 127 '')"
    dev_test_equal ERROR_EMPTY_SUCCESS OK "$(classify_error 0 '')"
    dev_test_equal ERROR_PARSE PARSE_ERROR "$(classify_error 1 'cannot unmarshal object')"
    for fixture in '-n' '-nevil' '--namespace=evil' '--context=evil' '--kubeconfig=evil' '-A' '--all-namespaces' '--token=fixture' '--server=fixture'; do
        dev_test_status "SCOPE_REJECT_${fixture%%=*}" 2 scope_args_safe "$fixture"
    done
    dev_test_status SCOPE_ALLOW_NORMAL 0 scope_args_safe get pods -o json
    dev_test_status RESOURCE_REJECT_ARBITRARY 2 allowed_resource ns arbitrary
    dev_test_status RESOURCE_ALLOW_PODS 0 allowed_resource ns pods
    dev_test_equal REDACTION_AUTH_SCHEME '[REDACTED]' "$(printf 'Bearer fixture-hidden\n' | redact)"
    dev_test_equal REDACTION_PASSWORD '[REDACTED]' "$(printf 'password=fixture-hidden\n' | redact)"
    dev_test_equal REDACTION_APIKEY '[REDACTED]' "$(printf 'api_key=fixture-hidden\n' | redact)"
    dev_test_equal REDACTION_AUTHORIZATION '[REDACTED]' "$(printf 'Authorization: fixture-hidden\n' | redact)"
    dev_test_equal REDACTION_PRIVATE_KEY '[REDACTED PRIVATE KEY]' "$(printf '%s\n' '-----BEGIN PRIVATE KEY-----' 'fixture-hidden' '-----END PRIVATE KEY-----' | redact)"
    dev_test_equal URL_SANITIZE 'https://[REDACTED]@example.invalid/repo' "$(sanitize_url 'https://fixture-hidden@example.invalid/repo?token=fixture-hidden')"
    dev_test_equal GIT_URL_HTTPS 'example.invalid/team/repo' "$(dev_git_url_normalize 'https://fixture-hidden@EXAMPLE.invalid/team/repo.git')"
    dev_test_equal GIT_URL_SSH 'example.invalid/team/repo' "$(dev_git_url_normalize 'ssh://git@example.invalid/team/repo.git')"
    dev_test_equal GIT_URL_SCP 'example.invalid/team/repo' "$(dev_git_url_normalize 'git@example.invalid:team/repo.git')"
    dev_test_equal TABLE_TRUNCATION 'abcd~' "$(truncate_text abcdefgh 5)"
    dev_test_equal TABLE_UNCHANGED abc "$(truncate_text abc 5)"
    dev_test_equal DURATION_FORMAT '1d 01h 01m 01s' "$(dev_duration 90061)"
    actual=$(COLUMNS=80 LINES=24 TERM=dumb terminal_size; printf '%s' "$UI_COLS")
    dev_test_equal TERMINAL_WIDTH_80 80 "$actual"
    actual=$(COLUMNS=160 LINES=40 TERM=dumb terminal_size; printf '%s' "$UI_COLS")
    dev_test_equal TERMINAL_WIDTH_160 160 "$actual"
    dev_test_status CACHE_TTL_BOUNDARY 0 dev_cache_fixture
    dev_test_status FIELD_REJECT_SECRET 1 splunk_field_safe client_secret
    dev_test_status FIELD_REJECT_TOKEN 1 splunk_field_safe access_token
    dev_test_status FIELD_ALLOW_OBSERVED_NAME 0 splunk_field_safe kubernetes.namespace_name
    dev_test_equal CSV_QUOTE '"a,""b"""' "$(splunk_csv_cell 'a,"b"')"
    dev_test_equal GIT_AUTH_CLASS AUTH_REQUIRED "$(dev_git_error_class 'fatal: could not read Username: terminal prompts disabled')"
    dev_test_equal GIT_PROTECTED_CLASS PROTECTED_BRANCH "$(dev_git_error_class 'remote: GH006: Protected branch update failed')"
    if ! has jq; then
        printf '%-40s SKIP (jq not installed)\n' RESOURCE_QUANTITY_FIXTURES
        ((DEV_TEST_SKIPPED+=1))
    elif declare -F resource_self_tests >/dev/null; then
        dev_test_status RESOURCE_QUANTITY_FIXTURES 0 resource_self_tests
    else printf '%-40s FAIL\n' RESOURCE_QUANTITY_FIXTURES; ((DEV_TEST_TOTAL+=1,DEV_TEST_FAILED+=1)); fi
    if declare -F cert_self_tests >/dev/null; then
        dev_test_status CERTIFICATE_DATE_FIXTURES 0 cert_self_tests
    else printf '%-40s FAIL\n' CERTIFICATE_DATE_FIXTURES; ((DEV_TEST_TOTAL+=1,DEV_TEST_FAILED+=1)); fi
    if has jq; then
        dev_test_status CORE_BOOTSTRAP_CACHE_FIXTURES 0 core_integration_tests
        dev_test_status SPLUNK_RESPONSE_FIXTURES_20 0 splunk_self_tests
        dev_test_status RESOURCE_REPORT_FIXTURES 0 resource_integration_tests
        dev_test_status GITOPS_CERTIFICATE_FIXTURES 0 gitops_certificate_self_tests
    else
        printf '%-40s SKIP (jq not installed)\n' CORE_BOOTSTRAP_CACHE_FIXTURES SPLUNK_RESPONSE_FIXTURES_20 RESOURCE_REPORT_FIXTURES GITOPS_CERTIFICATE_FIXTURES
        ((DEV_TEST_SKIPPED+=4))
    fi
    if has git; then dev_test_status PUBLICATION_SAFETY_FIXTURES_12 0 developer_publish_self_tests
    else printf '%-40s SKIP (git not installed)\n' PUBLICATION_SAFETY_FIXTURES_12; ((DEV_TEST_SKIPPED+=1)); fi
    dev_test_status UI_AND_PROCESS_CLEANUP_FIXTURES 0 ui_process_self_tests
    printf 'TOTAL CHECKS/GROUPS %d  PASS %d  FAIL %d  SKIP %d\n' "$DEV_TEST_TOTAL" "$DEV_TEST_PASSED" "$DEV_TEST_FAILED" "$DEV_TEST_SKIPPED"
    ((DEV_TEST_FAILED == 0))
}

dev_client_preflight() {
    local path context status=0
    path=$(command -v kubectl 2>/dev/null)
    if [[ -z $path ]]; then printf '[SKIP] Kubernetes client preflight: kubectl not installed\n'; return 0; fi
    [[ ${path,,} != *.exe && $path != /mnt/?/* ]] || { printf '[FAIL] Windows Kubernetes client\n'; return 1; }
    printf 'KUBECTL %s\n' "$path"
    if run_bounded "$API_TIMEOUT" kubectl version --client -o yaml 2>&1 | redact; then printf '[PASS] Kubernetes client version\n'
    else printf '[FAIL] Kubernetes client version\n'; status=1; fi
    printf 'KUBECONFIG MODE %s\n' "$KUBECONFIG_MODE"
    [[ $KUBECONFIG_MODE == EXPLICIT ]] && printf 'KUBECONFIG %s\n' "${KUBECONFIG:-}"
    if run_bounded "$API_TIMEOUT" kubectl config get-contexts -o name 2>&1 | redact; then printf '[PASS] Kubeconfig context discovery\n'
    else printf '[WARN] Kubeconfig context discovery unavailable; required live smoke will fail separately\n'; fi
    context=$(run_bounded "$API_TIMEOUT" kubectl config current-context 2>/dev/null) || context=UNSET
    printf 'CURRENT KUBECTL CONTEXT %s\n' "$context" | redact
    return "$status"
}

dev_validate_body() {
    local failed=0 rc hash_start hash_end
    dev_source_path || return
    hash_start=$(dev_sha256 "$DEV_SOURCE") || return 1
    printf 'KUBEOPS SENTINEL :: DEVELOPMENT VALIDATION\n'
    dev_environment || failed=1
    dev_source_integrity || failed=1
    if bash -n "$DEV_SOURCE"; then printf '[PASS] Bash syntax\n'
    else printf '[FAIL] Bash syntax\n'; return 1; fi
    if has shellcheck; then
        shellcheck "$DEV_SOURCE"; rc=$?
        if ((rc == 0)); then printf '[PASS] ShellCheck\n'
        elif shellcheck --severity=error "$DEV_SOURCE" >/dev/null 2>&1; then printf '[WARN] ShellCheck warnings above\n'
        else printf '[FAIL] ShellCheck errors\n'; failed=1; fi
    else printf '[SKIP] ShellCheck not installed\n'; fi
    dev_static_safety || failed=1
    # Re-execute the on-disk source so editor saves cannot cause old in-memory
    # functions to be tested while a different source file is committed.
    if bash "$DEV_SOURCE" --dev-self-test --output "$OUTPUT_DIR"; then printf '[PASS] Embedded self tests\n'
    else printf '[FAIL] Embedded self tests\n'; failed=1; fi
    dev_client_preflight || failed=1
    if [[ $DEV_WITH_SMOKE == 1 ]]; then
        if dev_smoke; then printf '[PASS] Required live smoke\n'; else printf '[FAIL] Required live smoke\n'; failed=1; fi
    else printf '[SKIP] Optional live smoke (enable --with-smoke)\n'; fi
    if dev_git_discover; then
        if git -C "$DEV_REPO" diff --check -- "$DEV_SOURCE_REL" && git -C "$DEV_REPO" diff --cached --check -- "$DEV_SOURCE_REL"; then
            printf '[PASS] Git diff whitespace checks\n'
        else printf '[FAIL] Git diff whitespace checks\n'; failed=1; fi
        if ! git -C "$DEV_REPO" check-ignore -q -- "$DEV_DIR"; then
            printf '[WARN] .sentinel-dev is not ignored; it is never staged by this workflow\n'
        fi
    else printf '[FAIL] Git readiness\n'; failed=1; fi
    hash_end=$(dev_sha256 "$DEV_SOURCE") || failed=1
    if [[ $hash_start != "$hash_end" ]]; then printf '[FAIL] SOURCE CHANGED DURING VALIDATION\n'; failed=1; fi
    if ((failed)); then printf 'VALIDATION RESULT FAIL\n'; return 1; fi
    DEV_TESTS_PASSED=1
    printf 'VALIDATION RESULT PASS\n'
}

dev_validate() {
    dev_source_path || return
    local logfile
    logfile=$(mktemp "$DEV_DIR/validation.XXXXXXXX.log") || return
    dev_validate_body 2>&1 | redact | tee "$logfile"
    local rc=${PIPESTATUS[0]}
    ((rc == 0)) && DEV_TESTS_PASSED=1
    printf 'VALIDATION LOG %s\n' "$logfile"
    return "$rc"
}

dev_smoke() {
    dev_environment || return
    [[ -n $SENTINEL_CONTEXT ]] || SENTINEL_CONTEXT=${SNTL_DEV_CONTEXT:-}
    [[ -n $SENTINEL_NAMESPACE ]] || SENTINEL_NAMESPACE=${SNTL_DEV_NAMESPACE:-}
    [[ -n $SENTINEL_CONTEXT && -n $SENTINEL_NAMESPACE ]] || {
        printf '[FAIL] Read-only smoke requires explicit --context and --namespace, or SNTL_DEV_* values\n'; return 2;
    }
    has kubectl || { printf '[FAIL] Smoke requires Linux kubectl\n'; return 2; }
    printf 'READ-ONLY SMOKE context=%s namespace=%s\n' "$SENTINEL_CONTEXT" "$SENTINEL_NAMESPACE" | redact
    if [[ $SCOPE_READY != 1 ]]; then bootstrap_scope || return; fi
    local resource raw rc status failed=0
    for resource in pods deployments services endpointslices.discovery.k8s.io persistentvolumeclaims events; do
        raw=$(kctl_ns get "$resource" -o 'jsonpath={.metadata.resourceVersion}' 2>&1); rc=$?
        status=$(classify_error "$rc" "$raw")
        if ((rc == 0)); then printf '[PASS] %s list\n' "$resource"
        elif [[ $status == RBAC_DENIED && $resource != pods ]]; then printf '[SKIP] %s RBAC_DENIED\n' "$resource"
        elif [[ $status == RESOURCE_NOT_FOUND && $resource == endpointslices.discovery.k8s.io ]]; then printf '[SKIP] EndpointSlice API unavailable\n'
        else printf '[FAIL] %s %s\n' "$resource" "$status"; failed=1; fi
    done
    collect_pods >/dev/null; collect_workloads >/dev/null; collect_metrics >/dev/null
    printf 'RESOURCE COLLECTOR %s\nMETRICS %s\n' "$(cache_status pods)" "$(cache_status metrics)"
    case $(cache_status pods) in OK|EMPTY_RESULT) ;; *) failed=1;; esac
    capture_report 'Developer Resource Smoke' resources_report; rc=$?
    ((rc==0)) || { printf '[FAIL] Resource report exit %s\n' "$rc"; failed=1; }
    printf 'RESOURCE REPORT %s\n' "$CURRENT_REPORT"
    capture_report 'Developer Health Smoke' health_report; rc=$?
    ((rc==0 || rc==1)) || { printf '[FAIL] Health collection exit %s\n' "$rc"; failed=1; }
    printf 'HEALTH REPORT %s (operational findings are reported separately from collector validity)\n' "$CURRENT_REPORT"
    capture_report 'Developer GitOps Smoke' gitops_report
    printf 'GITOPS REPORT %s\n' "$CURRENT_REPORT"
    capture_report 'Developer Certificate Smoke' certificates_report
    printf 'CERTIFICATE REPORT %s\n' "$CURRENT_REPORT"
    printf 'AUTH %s API %s NAMESPACE %s\n' "$AUTH_STATUS" "$API_STATUS" "$SENTINEL_NAMESPACE"
    if ((failed)); then printf 'SMOKE RESULT FAIL\n'; return 1; fi
    printf 'SMOKE RESULT PASS (optional API/RBAC gaps remain explicitly classified)\n'
}

dev_git_status() {
    dev_git_discover || return
    local upstream ahead=UNKNOWN behind=UNKNOWN state path staged=0 modified=0 untracked=0
    upstream=$(git -C "$DEV_REPO" rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null) || upstream=NONE
    if [[ $upstream != NONE ]]; then
        read -r ahead behind < <(git -C "$DEV_REPO" rev-list --left-right --count "HEAD...$upstream")
    fi
    while IFS= read -r -d '' state; do
        case ${state:0:2} in '??') ((untracked+=1));;
          *) [[ ${state:0:1} != ' ' ]] && ((staged+=1)); [[ ${state:1:1} != ' ' ]] && ((modified+=1));;
        esac
        [[ ${state:0:2} == *R* || ${state:0:2} == *C* ]] && IFS= read -r -d '' path
    done < <(git -C "$DEV_REPO" status --porcelain=v1 -z --untracked-files=normal)
    printf 'REPOSITORY %s\nBRANCH %s\nREMOTE %s\nURL %s\nUPSTREAM %s\nLOCAL HEAD %s\n' \
      "$DEV_REPO" "$DEV_BRANCH" "${DEV_REMOTE:-NONE}" "$(sanitize_url "$DEV_REMOTE_URL")" "$upstream" "${DEV_COMMIT_SHA:-UNBORN}"
    printf 'AHEAD %s BEHIND %s (cached upstream; no automatic pull/rebase)\nMODIFIED %s STAGED %s UNTRACKED %s\n' "$ahead" "$behind" "$modified" "$staged" "$untracked"
    if [[ -n $DEV_REMOTE ]]; then
        if dev_git_remote_head; then printf 'REMOTE HEAD %s\n' "${DEV_REMOTE_SHA:-BRANCH_NOT_FOUND}"
        else printf 'REMOTE HEAD UNAVAILABLE\n'; fi
    fi
}

dev_git_diff() {
    dev_git_discover || return
    local failed=0
    git -C "$DEV_REPO" --no-pager diff --no-ext-diff --no-textconv -- "$DEV_SOURCE_REL" | redact
    git -C "$DEV_REPO" --no-pager diff --cached --no-ext-diff --no-textconv -- "$DEV_SOURCE_REL" | redact
    git -C "$DEV_REPO" diff --check -- "$DEV_SOURCE_REL" || failed=1
    git -C "$DEV_REPO" diff --cached --check -- "$DEV_SOURCE_REL" || failed=1
    dev_source_integrity || failed=1
    return "$failed"
}

dev_lock() {
    dev_source_path || return
    if has flock; then
        [[ ! -L $DEV_DIR/release.lock ]] || return 1
        exec {DEV_LOCK_FD}> "$DEV_DIR/release.lock" || return
        flock -n "$DEV_LOCK_FD" || { printf '[FAIL] ANOTHER RELEASE PIPELINE IS RUNNING\n'; return 1; }
        DEV_LOCK_OWNED=1
    else
        DEV_LOCK_DIR="$DEV_DIR/release.lock.d"
        # Directory creation is atomic. A stale fallback lock is kept for
        # explicit inspection; automatically guessing PID reuse is unsafe.
        mkdir -- "$DEV_LOCK_DIR" 2>/dev/null || {
            printf '[FAIL] ANOTHER RELEASE PIPELINE IS RUNNING or stale lock needs inspection: %s\n' "$DEV_LOCK_DIR"; return 1;
        }
        DEV_LOCK_OWNED=1
        printf '%s\n' "$BASHPID" > "$DEV_LOCK_DIR/pid"
    fi
}

dev_cleanup() {
    if [[ -n $DEV_PRIVATE_INDEX && $DEV_PRIVATE_INDEX == "$DEV_DIR"/tested-index.* && ! -L $DEV_PRIVATE_INDEX ]]; then
        rm -f -- "$DEV_PRIVATE_INDEX" "$DEV_PRIVATE_INDEX.lock"
        DEV_PRIVATE_INDEX=''
    fi
    if [[ $DEV_LOCK_OWNED == 1 ]]; then
        if [[ -n $DEV_LOCK_FD ]]; then
            flock -u "$DEV_LOCK_FD" 2>/dev/null || :
            exec {DEV_LOCK_FD}>&- 2>/dev/null || :
        elif [[ -n $DEV_LOCK_DIR && $DEV_LOCK_DIR == "$DEV_DIR/release.lock.d" && -d $DEV_LOCK_DIR && ! -L $DEV_LOCK_DIR ]]; then
            rm -f -- "$DEV_LOCK_DIR/pid"; rmdir -- "$DEV_LOCK_DIR" 2>/dev/null || :
        fi
    fi
    DEV_LOCK_OWNED=0 DEV_LOCK_FD='' DEV_LOCK_DIR=''
}

dev_git_only_source_staged() {
    local path
    while IFS= read -r -d '' path; do
        [[ $path == "$DEV_SOURCE_REL" ]] || {
            printf '[FAIL] Unrelated staged changes detected; leave them staged and publish Sentinel separately\n'; return 1;
        }
    done < <(git -C "$DEV_REPO" diff --cached --name-only -z)
}

dev_publish_locked() {
    local tested_sha current_sha staged_sha committed_sha pre_head new_head path unexpected=0
    dev_git_discover || return
    [[ -n $DEV_REMOTE ]] || { printf '[FAIL] Publishing needs an unambiguous configured remote\n'; return 2; }
    case $DEV_BRANCH in main|master|production|prod|release|release/*)
        [[ $DEV_ALLOW_PROTECTED_BRANCH == 1 ]] || {
            printf '[FAIL] PROTECTED_BRANCH: direct push requires --allow-protected-branch\n'; return 2;
        };;
    esac
    git -C "$DEV_REPO" var GIT_AUTHOR_IDENT >/dev/null 2>&1 && git -C "$DEV_REPO" var GIT_COMMITTER_IDENT >/dev/null 2>&1 || {
        printf '[FAIL] Configure Git user.name and user.email yourself; no Git configuration was changed\n'; return 2;
    }
    dev_git_only_source_staged || return
    while IFS= read -r -d '' path; do
        [[ $path == "$DEV_SOURCE_REL" ]] || unexpected=1
    done < <(git -C "$DEV_REPO" ls-files --modified --others --exclude-standard -z)
    ((unexpected)) && printf '[WARN] Unrelated repository changes detected; only Sentinel can be staged\n'
    [[ -n $DEV_BUMP ]] && { dev_bump_version "$DEV_BUMP" || return; }
    tested_sha=$(dev_sha256 "$DEV_SOURCE") || return
    if ! dev_validate; then dev_restore_backup; return 1; fi
    current_sha=$(dev_sha256 "$DEV_SOURCE") || return
    [[ $current_sha == "$tested_sha" ]] || { printf '[FAIL] SOURCE CHANGED AFTER VALIDATION\n'; return 1; }
    DEV_TESTS_PASSED=1
    dev_git_remote_head || return
    if [[ -n $DEV_REMOTE_SHA ]]; then
        # Fetch only the selected branch into FETCH_HEAD; no merge, checkout,
        # rebase, tags or automatic branch switch is performed.
        dev_git_network fetch --no-tags "$DEV_REMOTE" "refs/heads/$DEV_BRANCH" >/dev/null || return
        [[ -n $DEV_COMMIT_SHA ]] && git -C "$DEV_REPO" merge-base --is-ancestor "$DEV_REMOTE_SHA" "$DEV_COMMIT_SHA" || {
            printf '[FAIL] Local branch is BEHIND or DIVERGED; resolve it manually before publishing\n'; return 1;
        }
    fi
    dev_git_only_source_staged || return
    git -C "$DEV_REPO" diff --check -- "$DEV_SOURCE_REL" || return
    [[ $(dev_sha256 "$DEV_SOURCE") == "$tested_sha" ]] || { printf '[FAIL] SOURCE CHANGED AFTER VALIDATION\n'; return 1; }
    git -C "$DEV_REPO" add -- "$DEV_SOURCE_REL" || return
    git -C "$DEV_REPO" update-index --chmod=+x -- "$DEV_SOURCE_REL" || return
    dev_git_only_source_staged || return
    git -C "$DEV_REPO" diff --cached --check -- "$DEV_SOURCE_REL" || return
    staged_sha=$(git -C "$DEV_REPO" show ":$DEV_SOURCE_REL" | dev_stream_sha256) || return
    [[ $staged_sha == "$tested_sha" ]] || { printf '[FAIL] Staged blob differs from validated bytes (check Git clean filters / line endings)\n'; return 1; }
    [[ $(dev_sha256 "$DEV_SOURCE") == "$tested_sha" ]] || { printf '[FAIL] SOURCE CHANGED AFTER VALIDATION\n'; return 1; }
    pre_head=$(git -C "$DEV_REPO" rev-parse --verify HEAD 2>/dev/null) || pre_head=''
    if git -C "$DEV_REPO" diff --cached --quiet -- "$DEV_SOURCE_REL"; then
        printf 'NO CHANGES TO COMMIT\n'
    else
        local message=${DEV_MESSAGE:-chore(sentinel): update KubeOps Sentinel $APP_VERSION}
        [[ $message != *[$'\r\n']* && ${#message} -le 500 ]] || { printf '[FAIL] Commit message must be a single line of at most 500 characters\n'; return 2; }
        # This fully validated automated path disables external hooks for this
        # single command to prevent a hook from replacing the tested staged
        # snapshot. Existing repository/global hook configuration is unchanged.
        # A private copy prevents another Git process from replacing the
        # verified index between this check and the commit operation.
        local index_path
        index_path=$(git -C "$DEV_REPO" rev-parse --git-path index) || return
        [[ $index_path == /* ]] || index_path="$DEV_REPO/$index_path"
        DEV_PRIVATE_INDEX=$(mktemp "$DEV_DIR/tested-index.XXXXXXXX") || return
        cp -- "$index_path" "$DEV_PRIVATE_INDEX" || return
        staged_sha=$(GIT_INDEX_FILE="$DEV_PRIVATE_INDEX" git -C "$DEV_REPO" show ":$DEV_SOURCE_REL" | dev_stream_sha256) || return
        [[ $staged_sha == "$tested_sha" ]] || { printf '[FAIL] Source index changed before commit\n'; return 1; }
        while IFS= read -r -d '' path; do
            [[ $path == "$DEV_SOURCE_REL" ]] || { printf '[FAIL] Unrelated index change raced publication; commit blocked\n'; return 1; }
        done < <(GIT_INDEX_FILE="$DEV_PRIVATE_INDEX" git -C "$DEV_REPO" diff --cached --name-only -z)
        if ! GIT_INDEX_FILE="$DEV_PRIVATE_INDEX" GIT_TERMINAL_PROMPT=0 run_bounded 60 git -C "$DEV_REPO" -c core.hooksPath=/dev/null commit -m "$message"; then
            printf '[FAIL] Commit failed; push was not attempted\n'; return 1
        fi
        rm -f -- "$DEV_PRIVATE_INDEX"; DEV_PRIVATE_INDEX=''
    fi
    new_head=$(git -C "$DEV_REPO" rev-parse --verify HEAD) || return
    committed_sha=$(git -C "$DEV_REPO" show "$new_head:$DEV_SOURCE_REL" | dev_stream_sha256) || return
    [[ $committed_sha == "$tested_sha" ]] || { printf '[FAIL] Committed blob differs from validated bytes; push blocked\n'; return 1; }
    if [[ -n $pre_head && $new_head != "$pre_head" ]]; then
        while IFS= read -r -d '' path; do
            [[ $path == "$DEV_SOURCE_REL" ]] || { printf '[FAIL] Commit changed unrelated paths; push blocked\n'; return 1; }
        done < <(git -C "$DEV_REPO" diff-tree --no-commit-id --name-only -r -z "$new_head")
    fi
    [[ $(git -C "$DEV_REPO" symbolic-ref --quiet --short HEAD) == "$DEV_BRANCH" ]] || { printf '[FAIL] Branch changed during publication\n'; return 1; }
    # A full refspec targets exactly the existing branch. No force option.
    if ! dev_git_network push --set-upstream "$DEV_REMOTE" "HEAD:refs/heads/$DEV_BRANCH"; then return 1; fi
    dev_git_remote_head || return
    [[ $DEV_REMOTE_SHA == "$new_head" && $(git -C "$DEV_REPO" rev-parse HEAD) == "$new_head" ]] || {
        printf '[FAIL] PUSH VERIFICATION: local and observed remote SHA do not match\n'; return 1;
    }
    local tracking
    tracking=$(git -C "$DEV_REPO" rev-parse --verify "refs/remotes/$DEV_REMOTE/$DEV_BRANCH" 2>/dev/null) || tracking=UNKNOWN
    printf 'PUSH VERIFIED MATCH\nCOMMIT %s\nBRANCH %s\nREMOTE %s\nREMOTE HEAD %s\nTRACKING SHA %s\nTIMESTAMP %s\n' \
      "$new_head" "$DEV_BRANCH" "$DEV_REMOTE" "$DEV_REMOTE_SHA" "$tracking" "$(timestamp)"
    DEV_BACKUP='' DEV_MODIFIED_SHA=''
}

dev_publish() {
    dev_source_path || return
    local logfile rc
    logfile=$(mktemp "$DEV_DIR/publish.XXXXXXXX.log") || return
    (
        dev_lock || exit
        trap dev_cleanup EXIT
        dev_publish_locked
    ) 2>&1 | redact | tee "$logfile"
    rc=${PIPESTATUS[0]}
    printf 'PUBLISH LOG %s\n' "$logfile"
    ((rc == 0)) || return "$rc"
    dev_git_discover || return
    dev_git_remote_head || return
    [[ -n $DEV_COMMIT_SHA && $DEV_COMMIT_SHA == "$DEV_REMOTE_SHA" ]] || return 1
    DEV_PUSH_VERIFIED=1 DEV_TESTS_PASSED=1
}

dev_release() {
    DEV_WITH_SMOKE=1
    [[ -n $SENTINEL_CONTEXT ]] || SENTINEL_CONTEXT=${SNTL_DEV_CONTEXT:-}
    [[ -n $SENTINEL_NAMESPACE ]] || SENTINEL_NAMESPACE=${SNTL_DEV_NAMESPACE:-}
    printf 'KUBEOPS SENTINEL :: DEV RELEASE PIPELINE\nSOURCE -> QUALITY -> READ-ONLY KUBERNETES -> GIT -> PUSH -> FLUX\n'
    if ! dev_publish; then printf 'RELEASE RESULT FAIL (publication gate)\n'; return 1; fi
    local flux_result=0 version
    dev_flux_verify || flux_result=$?
    version=$(awk -F'"' '/^APP_VERSION="[0-9]+\.[0-9]+\.[0-9]+"$/{print $2; exit}' "$DEV_SOURCE")
    printf 'APPLICATION %s\nVERSION %s\nBRANCH %s\nCOMMIT %s\nREMOTE %s\nPUSH MATCH\n' \
      "$APP_NAME" "${version:-UNKNOWN}" "$DEV_BRANCH" "$DEV_COMMIT_SHA" "$(sanitize_url "$DEV_REMOTE_URL")"
    printf 'TEST CONTEXT %s\nTEST NAMESPACE %s\nSELF TESTS PASS\nSMOKE TESTS PASS\nFLUX VERIFICATION EXIT %s\nTIMESTAMP %s\n' \
      "$SENTINEL_CONTEXT" "$SENTINEL_NAMESPACE" "$flux_result" "$(timestamp)"
    if [[ $DEV_REQUIRE_FLUX == 1 && $flux_result != 0 ]]; then
        printf 'RELEASE RESULT FAIL: required Flux verification failed after verified push\n'; return 1;
    fi
    ((flux_result)) && printf '[WARN] Flux post-push verification incomplete; no script deployment is inferred\n'
    printf 'RELEASE SUCCESS\n'
}

dev_watch() {
    dev_source_path || return
    dev_environment || return
    local previous='' current stable last_smoke=0 now child_rc
    local -a args
    printf 'WATCHING ONLY %s; Ctrl+C exits. Saves validate; publishing remains an explicit command.\n' "$DEV_SOURCE"
    while :; do
        current=$(dev_sha256 "$DEV_SOURCE") || { sleep 1; continue; }
        if [[ $current != "$previous" ]]; then
            # Require one quiet second, including atomic editor replacements.
            sleep 1
            stable=$(dev_sha256 "$DEV_SOURCE") || continue
            [[ $current == "$stable" ]] || continue
            previous=$stable
            printf '[%s] Change detected\n' "$(timestamp)"
            args=(--dev-validate --output "$OUTPUT_DIR")
            [[ -n $SENTINEL_CONTEXT ]] && args+=(--context "$SENTINEL_CONTEXT")
            [[ -n $SENTINEL_NAMESPACE ]] && args+=(--namespace "$SENTINEL_NAMESPACE")
            now=$(now_epoch)
            if [[ $DEV_WITH_SMOKE == 1 ]] && ((now-last_smoke >= 30)); then args+=(--with-smoke); last_smoke=$now; fi
            bash "$DEV_SOURCE" "${args[@]}"; child_rc=$?
            if ((child_rc == 0)); then printf 'SOURCE HEALTHY\n'; else printf 'SOURCE VALIDATION FAILED\n'; fi
            # Recheck immediately after validation: a save during it is dirty.
            continue
        fi
        if has inotifywait; then
            inotifywait -q -t 2 -e close_write,move_self,delete_self,attrib -- "$DEV_SOURCE" >/dev/null 2>&1 || :
        else sleep 1; fi
    done
}

dev_make_backup() {
    DEV_BACKUP=$(mktemp "$DEV_DIR/source-backup.XXXXXXXX") || return
    cp -p -- "$DEV_SOURCE" "$DEV_BACKUP" || return
}

dev_restore_backup() {
    [[ -n $DEV_BACKUP && -f $DEV_BACKUP && ! -L $DEV_BACKUP ]] || return 0
    if [[ $(dev_sha256 "$DEV_SOURCE") == "$DEV_MODIFIED_SHA" ]]; then
        cp -p -- "$DEV_BACKUP" "$DEV_SOURCE" || return
        printf '[INFO] Restored source snapshot after failed validation\n'
    else printf '[WARN] Source changed after automatic edit; backup retained for manual restoration: %s\n' "$DEV_BACKUP"; fi
    DEV_BACKUP='' DEV_MODIFIED_SHA=''
}

dev_bump_version() {
    local part=$1 version major minor patch temp
    dev_source_path || return
    [[ $part == patch || $part == minor || $part == major ]] || return 2
    version=$(awk -F'"' '/^APP_VERSION="[0-9]+\.[0-9]+\.[0-9]+"$/{print $2}' "$DEV_SOURCE")
    [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { printf '[FAIL] Version assignment is not a unique semantic version\n'; return 2; }
    IFS=. read -r major minor patch <<< "$version"
    case $part in patch) patch=$((10#$patch+1));; minor) minor=$((10#$minor+1)); patch=0;; major) major=$((10#$major+1)); minor=0; patch=0;; esac
    dev_make_backup || return
    temp=$(mktemp "$DEV_DIR/version.XXXXXXXX") || return
    awk -v v="$major.$minor.$patch" '/^APP_VERSION="[0-9]+\.[0-9]+\.[0-9]+"$/ {$0="APP_VERSION=\"" v "\""} {print}' "$DEV_SOURCE" > "$temp" || return
    cat -- "$temp" > "$DEV_SOURCE" || return
    rm -f -- "$temp"
    DEV_MODIFIED_SHA=$(dev_sha256 "$DEV_SOURCE") || return
    printf 'VERSION %s -> %s.%s.%s; validation will run before staging\n' "$version" "$major" "$minor" "$patch"
}

dev_fix_line_endings() {
    dev_source_path || return
    local temp original
    dev_make_backup || return
    temp=$(mktemp "$DEV_DIR/lf.XXXXXXXX") || return
    sed 's/\r$//' "$DEV_SOURCE" > "$temp" || return
    bash -n "$temp" || { printf '[FAIL] LF repair would leave invalid Bash; source unchanged\n'; return 1; }
    cat -- "$temp" > "$DEV_SOURCE" || return
    rm -f -- "$temp"
    printf 'LF repair complete: only %s was modified; snapshot %s\n' "$DEV_SOURCE" "$DEV_BACKUP"
    DEV_BACKUP=''
}

dev_fix_permissions() {
    dev_source_path || return
    chmod +x -- "$DEV_SOURCE" || return
    printf 'Executable permission restored for %s\n' "$DEV_SOURCE"
}

dev_install_hook() {
    dev_git_discover || return
    local hook configured
    configured=$(git -C "$DEV_REPO" config --get core.hooksPath) || configured=''
    [[ -z $configured ]] || { printf 'Existing core.hooksPath configuration: hook installation skipped\n'; return 1; }
    hook=$(git -C "$DEV_REPO" rev-parse --git-path hooks/pre-commit) || return
    [[ $hook == /* ]] || hook="$DEV_REPO/$hook"
    [[ ! -e $hook && ! -L $hook ]] || { printf 'EXISTING HOOK DETECTED; left untouched\n'; return 0; }
    [[ -d ${hook%/*} && ! -L ${hook%/*} ]] || return 1
    # %q is Bash quoting of a fixed source-relative path, never shell evaluation.
    (set -o noclobber
      { printf '#!/usr/bin/env bash\nset -o pipefail\n'
        printf 'repo=$(git rev-parse --show-toplevel) || exit 1\ncd -- "$repo" || exit 1\n'
        printf 'exec bash %q --dev-validate\n' "$DEV_SOURCE_REL"
      } > "$hook") || return
    chmod +x -- "$hook" || return
    printf 'INSTALLED LOCAL PRE-COMMIT HOOK %s\n' "$hook"
}

# All Git operations in these tests are confined to a mktemp repository and a
# local bare remote under RUN_DIR. No existing Git identity/config is changed.
developer_publish_self_tests() (
    has git || { printf 'SKIP: git unavailable for local publication fixtures\n'; return 77; }
    local fixture before
    fixture=$(mktemp -d "$RUN_DIR/publish-fixture.XXXXXXXX") || return
    trap dev_cleanup EXIT
    git init --bare "$fixture/remote.git" >/dev/null 2>&1 || return
    git init -b feature/fixture "$fixture/work" >/dev/null 2>&1 || return
    git -C "$fixture/work" config user.name 'Sentinel Fixture'
    git -C "$fixture/work" config user.email fixture@example.invalid
    git -C "$fixture/work" config commit.gpgsign false
    git -C "$fixture/work" config core.autocrlf false
    git -C "$fixture/work" remote add origin "$fixture/remote.git"
    SOURCE_FILE="$fixture/work/KubeOps_Sentinel.sh"
    printf '#!/usr/bin/env bash\nprintf "fixture\\n"\n' > "$SOURCE_FILE"
    chmod +x "$SOURCE_FILE"
    DEV_GIT_REMOTE=origin DEV_GIT_BRANCH='' DEV_MESSAGE='test: source-only fixture'
    DEV_ALLOW_PROTECTED_BRANCH=0 DEV_BUMP='' DEV_PRIVATE_INDEX=''
    DEV_LOCK_FD='' DEV_LOCK_DIR='' DEV_LOCK_OWNED=0
    DEV_TEST_TOTAL=0 DEV_TEST_PASSED=0 DEV_TEST_FAILED=0
    dev_validate() { DEV_TESTS_PASSED=1; return 0; }
    dev_publish_locked > "$fixture/publish.log" 2>&1
    dev_test_equal PUBLISH_LOCAL_SUCCESS 0 "$?"
    dev_git_discover
    dev_git_remote_head
    dev_test_equal PUBLISH_REMOTE_SHA "$DEV_COMMIT_SHA" "$DEV_REMOTE_SHA"
    dev_test_equal PUBLISH_SINGLE_FILE KubeOps_Sentinel.sh "$(git -C "$fixture/work" ls-tree --name-only HEAD)"
    printf 'unrelated\n' > "$fixture/work/unrelated.txt"
    git -C "$fixture/work" add -- unrelated.txt
    dev_publish_locked > "$fixture/staged.log" 2>&1
    dev_test_equal PUBLISH_REFUSE_UNRELATED_STAGE 1 "$?"
    dev_test_equal PUBLISH_PRESERVE_UNRELATED unrelated.txt "$(git -C "$fixture/work" diff --cached --name-only)"
    git -C "$fixture/work" reset -q HEAD -- unrelated.txt
    before=$(git -C "$fixture/work" rev-parse HEAD)
    dev_validate() { printf '# changed during validation\n' >> "$DEV_SOURCE"; return 0; }
    dev_publish_locked > "$fixture/race.log" 2>&1
    dev_test_equal PUBLISH_REFUSE_SOURCE_RACE 1 "$?"
    dev_test_equal PUBLISH_NO_COMMIT_ON_RACE "$before" "$(git -C "$fixture/work" rev-parse HEAD)"
    dev_validate() { return 1; }
    dev_publish_locked > "$fixture/validation.log" 2>&1
    dev_test_equal PUBLISH_REFUSE_FAILED_VALIDATE 1 "$?"
    dev_test_equal PUBLISH_NO_COMMIT_ON_FAILURE "$before" "$(git -C "$fixture/work" rev-parse HEAD)"
    dev_validate() { return 0; }
    git -C "$fixture/work" branch -m main
    dev_publish_locked > "$fixture/protected.log" 2>&1
    dev_test_equal PUBLISH_REFUSE_PROTECTED 2 "$?"
    git -C "$fixture/work" branch -m feature/fixture
    dev_lock
    dev_test_equal PUBLISH_ACQUIRE_LOCK 0 "$?"
    (DEV_LOCK_OWNED=0; dev_lock) > "$fixture/lock.log" 2>&1
    dev_test_equal PUBLISH_REFUSE_SECOND_LOCK 1 "$?"
    dev_cleanup
    printf 'PUBLICATION FIXTURES %s/%s PASS\n' "$DEV_TEST_PASSED" "$DEV_TEST_TOTAL"
    ((DEV_TEST_FAILED == 0))
)

# 21 Developer post-push Flux verification. This is isolated from dashboard wrappers.
dev_flux_mode_allowed() {
    [[ ${MODE:-} == dev-release || ${MODE:-} == dev-flux-verify ]]
}

dev_flux_query() {
    local resource="$1" namespace="$2" name="${3:-}" raw error rc
    DEV_FLUX_JSON='{"items":[]}'
    DEV_FLUX_ERROR=UNKNOWN
    dev_flux_mode_allowed || return 2
    case "$resource" in gitrepositories.source.toolkit.fluxcd.io|ocirepositories.source.toolkit.fluxcd.io|kustomizations.kustomize.toolkit.fluxcd.io|helmreleases.helm.toolkit.fluxcd.io) ;; *) return 2 ;; esac
    [[ "$namespace" == '*' || "$namespace" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 2
    [[ -z "$name" || "$name" =~ ^[a-z0-9][a-z0-9.-]*$ ]] || return 2
    [[ -n ${SENTINEL_CONTEXT:-} ]] || return 2
    has kubectl && has jq || { DEV_FLUX_ERROR=COMMAND_MISSING; return 1; }
    local -a args=(kubectl --context "$SENTINEL_CONTEXT" --request-timeout "${API_TIMEOUT}s" --cache-dir "$RUN_DIR/kubectl-cache" get "$resource")
    [[ -n "$name" ]] && args+=("$name")
    if [[ "$namespace" == '*' ]]; then args+=(--all-namespaces); else args+=(-n "$namespace"); fi
    args+=(-o json)
    error="$(mktemp "$RUN_DIR/dev-flux-error.XXXXXX")" || return 1
    raw="$(capture_command "$error" run_bounded "$API_TIMEOUT" "${args[@]}")"; rc=$?
    if ((rc!=0)); then
        DEV_FLUX_ERROR="$(classify_error "$rc" "$(cat "$error")")"
        rm -f -- "$error"
        return 1
    fi
    rm -f -- "$error"
    printf '%s\n' "$raw" | jq -e 'type=="object" and ((.items|type=="array") or (.metadata|type=="object"))' >/dev/null 2>&1 || {
        DEV_FLUX_ERROR=PARSE_ERROR; return 1;
    }
    DEV_FLUX_JSON="$(printf '%s\n' "$raw" | jq '
      (if .items!=null then . else {items:[.]} end) |
      {items:[.items[]|{kind,metadata:{name:.metadata.name,namespace:.metadata.namespace,generation:.metadata.generation,
       labels:{"kustomize.toolkit.fluxcd.io/name":.metadata.labels["kustomize.toolkit.fluxcd.io/name"],"kustomize.toolkit.fluxcd.io/namespace":.metadata.labels["kustomize.toolkit.fluxcd.io/namespace"]}},
       spec:{url:(.spec.url // "" | sub("://[^/@]*@";"://")|sub("[?#].*$";"")),suspend:(.spec.suspend // false),sourceRef:.spec.sourceRef,ref:.spec.ref,path:.spec.path},
       status:{artifact:{revision:.status.artifact.revision},conditions:(.status.conditions // []),
       observedGeneration:.status.observedGeneration,lastAppliedRevision:.status.lastAppliedRevision,
       lastAttemptedRevision:.status.lastAttemptedRevision,failures:.status.failures,installFailures:.status.installFailures,
       upgradeFailures:.status.upgradeFailures,inventory:{entries:(.status.inventory.entries // [])}}}]}' | json_sanitize)" || { DEV_FLUX_ERROR=PARSE_ERROR; return 1; }
    unset raw
    DEV_FLUX_ERROR=OK
}

dev_flux_discover() {
    local normalized name namespace url logical records='' fallback all_json='{"items":[]}' started now reads=0 discovery_error=UNKNOWN
    local -a matches=() namespaces=()
    normalized="$(dev_git_url_normalize "$DEV_REMOTE_URL")" || return 2
    printf 'GIT REMOTE %s\nPUSHED SHA %s\n' "$normalized" "$DEV_COMMIT_SHA"
    DEV_FLUX_DISCOVERY_SCOPE='*'
    if dev_flux_query gitrepositories.source.toolkit.fluxcd.io '*'; then all_json="$DEV_FLUX_JSON"; reads=1
    else
        discovery_error="$DEV_FLUX_ERROR"
        printf 'Flux cluster discovery: %s; trying accessible namespaces.\n' "$DEV_FLUX_ERROR"
        DEV_FLUX_DISCOVERY_SCOPE=partial
        namespaces+=("${DEV_FLUX_NAMESPACE:-$SENTINEL_NAMESPACE}")
        [[ "$SENTINEL_NAMESPACE" != "${namespaces[0]}" ]] && namespaces+=("$SENTINEL_NAMESPACE")
        fallback="$(kctl_cluster get namespaces -o 'jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)" || fallback=''
        while IFS= read -r namespace; do
            [[ -n "$namespace" ]] || continue
            [[ " ${namespaces[*]} " == *" $namespace "* ]] || namespaces+=("$namespace")
        done <<< "$fallback"
        started="$(date +%s)"
        for namespace in "${namespaces[@]}"; do
            now="$(date +%s)"
            ((now-started<60)) || { printf 'Namespace discovery budget reached; coverage PARTIAL. Use --flux-namespace to narrow.\n'; break; }
            if dev_flux_query gitrepositories.source.toolkit.fluxcd.io "$namespace"; then
                ((reads+=1))
                all_json="$(printf '%s\n%s\n' "$all_json" "$DEV_FLUX_JSON" | jq -s '{items:([.[].items[]]|unique_by([.metadata.namespace,.metadata.name]))}')"
            else discovery_error="$DEV_FLUX_ERROR"
            fi
        done
    fi
    if ((reads==0)); then
        printf 'FLUX DISCOVERY: %s (no successful resource reads; absence cannot be established).\n' "$discovery_error"
        [[ "$discovery_error" == RESOURCE_NOT_FOUND ]] && return 4
        return 1
    fi
    while IFS=$'\t' read -r namespace name url; do
        [[ -n "$name" ]] || continue
        [[ -z ${DEV_FLUX_SOURCE:-} || "$name" == "$DEV_FLUX_SOURCE" ]] || continue
        [[ -z ${DEV_FLUX_NAMESPACE:-} || "$namespace" == "$DEV_FLUX_NAMESPACE" ]] || continue
        logical="$(dev_git_url_normalize "$url")" || continue
        [[ "$logical" == "$normalized" ]] && matches+=("$namespace/$name")
    done < <(printf '%s\n' "$all_json" | jq -r '.items[]|[.metadata.namespace,.metadata.name,.spec.url]|@tsv')
    if ((${#matches[@]}==0)); then
        printf 'FLUX SOURCE MATCH: NOT FOUND / NOT CONFIGURED within accessible scope.\n'
        return 4
    elif ((${#matches[@]}==1)); then records="${matches[0]}"
    elif [[ ${DEV_NON_INTERACTIVE:-0} == 1 || ! -t 0 ]]; then
        printf 'Multiple matching Flux sources; set --flux-source and --flux-namespace.\n'
        printf '%s\n' "${matches[@]}"
        return 2
    else
        choose 'Select Flux GitRepository' "${matches[@]}" || return 2
        records="$REPLY"
    fi
    DEV_FLUX_SELECTED_NAMESPACE="${records%%/*}"
    DEV_FLUX_SELECTED_SOURCE="${records#*/}"
    printf 'FLUX SOURCE %s/%s | context=%s | discovery=%s\n' "$DEV_FLUX_SELECTED_NAMESPACE" "$DEV_FLUX_SELECTED_SOURCE" "$SENTINEL_CONTEXT" "$DEV_FLUX_DISCOVERY_SCOPE"
    # OCI sources may carry artifact digests, which are not necessarily Git SHAs.
    if dev_flux_query ocirepositories.source.toolkit.fluxcd.io "$DEV_FLUX_SELECTED_NAMESPACE"; then
        printf '%s\n' "$DEV_FLUX_JSON" | jq -r '.items[]|"OCIRepository/\(.metadata.name) artifact=\(.status.artifact.revision // "UNKNOWN") Git-commit linkage=NOT_VERIFIED"'
    else printf 'OCIRepository visibility: %s\n' "$DEV_FLUX_ERROR"; fi
}

dev_flux_revision_sha() {
    local revision="$1" sha
    sha="${revision##*:}"
    [[ "$sha" =~ ^[0-9a-fA-F]{40}$ || "$sha" =~ ^[0-9a-fA-F]{64}$ ]] || return 1
    printf '%s\n' "${sha,,}"
}

dev_flux_source_wait() {
    local budget="${DEV_FLUX_WAIT:-120}" start now remaining revision observed ready matched pause
    local configured_timeout="$API_TIMEOUT"
    start="$(date +%s)"
    while :; do
        now="$(date +%s)"; remaining=$((budget-(now-start)))
        ((remaining>0)) || { printf 'FLUX SOURCE: TIMEOUT after %ss; pushed commit not verified ready.\n' "$budget"; return 1; }
        local API_TIMEOUT="$configured_timeout"
        ((API_TIMEOUT>remaining)) && API_TIMEOUT="$remaining"
        if dev_flux_query gitrepositories.source.toolkit.fluxcd.io "$DEV_FLUX_SELECTED_NAMESPACE" "$DEV_FLUX_SELECTED_SOURCE"; then
            revision="$(printf '%s\n' "$DEV_FLUX_JSON" | jq -r '.items[0].status.artifact.revision // "UNKNOWN"')"
            ready="$(printf '%s\n' "$DEV_FLUX_JSON" | jq -r '([.items[0].status.conditions[]?|select(.type=="Ready")][0].status) // "UNKNOWN"')"
            matched="$(dev_flux_revision_sha "$revision")" || matched=UNKNOWN
            printf 'Waiting for Flux revision: elapsed=%ss Ready=%s artifact=%s\n' "$((now-start))" "$ready" "$revision"
            if [[ "$matched" == "${DEV_COMMIT_SHA,,}" ]] && printf '%s\n' "$DEV_FLUX_JSON" | jq -e '
                .items[0] | ([.status.conditions[]?|select(.type=="Ready")][0] // {}) as $r |
                $r.status=="True" and .spec.suspend!=true and
                (.status.observedGeneration // $r.observedGeneration)==.metadata.generation and
                (any(.status.conditions[]?;(.type=="Stalled" or .type=="Reconciling") and .status=="True")|not)' >/dev/null; then
                printf 'FLUX_SOURCE_SYNCHRONIZED | exact pushed SHA, Ready=True, generation observed\n'; return 0
            fi
        else
            printf 'FLUX SOURCE: %s\n' "$DEV_FLUX_ERROR"
            case "$DEV_FLUX_ERROR" in AUTH_ERROR|RBAC_DENIED|RESOURCE_NOT_FOUND|COMMAND_MISSING) return 1 ;; esac
        fi
        now="$(date +%s)"; pause=$((budget-(now-start))); ((pause>5)) && pause=5
        ((pause>0)) && sleep "$pause"
    done
}

dev_flux_dependents_once() {
    local kjson hjson scope ks_status hr_status count bad
    DEV_FLUX_DEPENDENTS_OK=0
    scope='*'
    if dev_flux_query kustomizations.kustomize.toolkit.fluxcd.io '*'; then kjson="$DEV_FLUX_JSON"
    elif dev_flux_query kustomizations.kustomize.toolkit.fluxcd.io "$DEV_FLUX_SELECTED_NAMESPACE"; then
        kjson="$DEV_FLUX_JSON"; scope="$DEV_FLUX_SELECTED_NAMESPACE"
        printf 'Kustomization coverage PARTIAL: source namespace only. Cross-namespace dependents NOT VERIFIED.\n'
    else printf 'KUSTOMIZATIONS: %s\n' "$DEV_FLUX_ERROR"; return 1; fi
    kjson="$(printf '%s\n' "$kjson" | jq --arg n "$DEV_FLUX_SELECTED_SOURCE" --arg ns "$DEV_FLUX_SELECTED_NAMESPACE" '{items:[.items[]|select(.spec.sourceRef.kind=="GitRepository" and .spec.sourceRef.name==$n and (.spec.sourceRef.namespace // .metadata.namespace)==$ns)]}')"
    count="$(printf '%s\n' "$kjson" | jq '.items|length')"
    if ((count==0)); then
        printf 'KUSTOMIZATIONS: none linked in visible scope. Script deployment: NOT VERIFIED.\n'
        [[ "$scope" == '*' ]] && DEV_FLUX_DEPENDENTS_OK=1
        return 0
    fi
    ks_status="$(printf '%s\n' "$kjson" | jq -r --arg sha "${DEV_COMMIT_SHA,,}" '
      .items[] | ([.status.conditions[]?|select(.type=="Ready")][0] // {}) as $r |
      "Kustomization/\(.metadata.namespace)/\(.metadata.name) Ready=\($r.status // "UNKNOWN") suspended=\(.spec.suspend) generation=\(.metadata.generation) observed=\(.status.observedGeneration // $r.observedGeneration // "UNKNOWN") applied=\(.status.lastAppliedRevision // "UNKNOWN") attempted=\(.status.lastAttemptedRevision // "UNKNOWN")",
      (.status.conditions[]?|"  \(.type)=\(.status) reason=\(.reason // "-") message=\(.message // "-")")')"
    printf '%s\n' "$ks_status"
    bad="$(printf '%s\n' "$kjson" | jq --arg sha "${DEV_COMMIT_SHA,,}" '[.items[]|
      ([.status.conditions[]?|select(.type=="Ready")][0] // {}) as $r |
      select($r.status!="True" or .spec.suspend or .metadata.generation!=(.status.observedGeneration // $r.observedGeneration) or
      ((.status.lastAppliedRevision // "" | split(":")[-1]|ascii_downcase)!=$sha) or
      any(.status.conditions[]?;(.type=="Stalled" or .type=="Reconciling") and .status=="True"))]|length')"
    if dev_flux_query helmreleases.helm.toolkit.fluxcd.io '*'; then hjson="$DEV_FLUX_JSON"
    elif dev_flux_query helmreleases.helm.toolkit.fluxcd.io "$DEV_FLUX_SELECTED_NAMESPACE"; then
        hjson="$DEV_FLUX_JSON"; scope="$DEV_FLUX_SELECTED_NAMESPACE"
        printf 'HelmRelease coverage PARTIAL: source namespace only.\n'
    elif [[ "$DEV_FLUX_ERROR" == RESOURCE_NOT_FOUND ]]; then hjson='{"items":[]}'
    else printf 'HELMRELEASES: %s\n' "$DEV_FLUX_ERROR"; return 1; fi
    # Inventory IDs are namespace_name_group_kind; the version is a separate field.
    hjson="$(printf '%s\n%s\n' "$kjson" "$hjson" | jq -s '
      .[0].items as $ks | {items:[.[1].items[] | . as $h |
       select(any($ks[]; . as $k |
        any(.status.inventory.entries[]?; .id==($h.metadata.namespace+"_"+$h.metadata.name+"_helm.toolkit.fluxcd.io_HelmRelease")) or
        ($h.metadata.labels["kustomize.toolkit.fluxcd.io/name"]==$k.metadata.name and $h.metadata.labels["kustomize.toolkit.fluxcd.io/namespace"]==$k.metadata.namespace)))]}')"
    printf '%s\n' "$hjson" | jq -r '
      if (.items|length)==0 then "HELMRELEASES: no downstream relationship established" else
      .items[] | ([.status.conditions[]?|select(.type=="Ready")][0] // {}) as $r |
      "HelmRelease/\(.metadata.namespace)/\(.metadata.name) Ready=\($r.status // "UNKNOWN") suspended=\(.spec.suspend) observed=\(.status.observedGeneration // $r.observedGeneration // "UNKNOWN") generation=\(.metadata.generation) attemptedRevision=\(.status.lastAttemptedRevision // "UNKNOWN") failures=\(.status.failures // "UNKNOWN") installFailures=\(.status.installFailures // "UNKNOWN") upgradeFailures=\(.status.upgradeFailures // "UNKNOWN")",
      (.status.conditions[]?|"  \(.type)=\(.status) reason=\(.reason // "-") message=\(.message // "-")") end'
    hr_status="$(printf '%s\n' "$hjson" | jq '[.items[]|([.status.conditions[]?|select(.type=="Ready")][0] // {}) as $r |
      select($r.status!="True" or .spec.suspend or .metadata.generation!=(.status.observedGeneration // $r.observedGeneration) or
      any(.status.conditions[]?;(.type=="Stalled" or .type=="Reconciling") and .status=="True") or
      any(.status.conditions[]?;.type=="Released" and .status=="False"))]|length')"
    if ((bad==0 && hr_status==0)) && [[ "$scope" == '*' ]]; then DEV_FLUX_DEPENDENTS_OK=1; fi
    printf 'Relationships establish controller association; whether this commit changed a Helm release is NOT VERIFIED.\n'
}

dev_flux_dependents_wait() {
    local start now remaining pause budget="${DEV_FLUX_WAIT:-120}" configured_timeout="$API_TIMEOUT"
    start="$(date +%s)"
    while :; do
        now="$(date +%s)"; remaining=$((budget-(now-start)))
        ((remaining>0)) || { printf 'DEPENDENTS: TIMEOUT / readiness or coverage incomplete.\n'; return 1; }
        local API_TIMEOUT="$configured_timeout"
        # A pass performs up to four reads, including namespace fallbacks.
        ((API_TIMEOUT>remaining/4)) && API_TIMEOUT=$((remaining/4))
        ((API_TIMEOUT>0)) || API_TIMEOUT=1
        dev_flux_dependents_once || :
        [[ "$DEV_FLUX_DEPENDENTS_OK" == 1 ]] && return 0
        now="$(date +%s)"; pause=$((budget-(now-start))); ((pause>5)) && pause=5
        ((pause>0)) && sleep "$pause"
    done
}

dev_flux_reconcile_guarded() {
    # Deliberate developer-only mutation exception. Dashboard wrappers remain read-only.
    dev_flux_mode_allowed || return 2
    [[ ${DEV_FLUX_RECONCILE:-0} == 1 && ${DEV_PUSH_VERIFIED:-0} == 1 && ${DEV_TESTS_PASSED:-0} == 1 ]] || {
        printf 'RECONCILE REFUSED: explicit request, passed tests and verified pushed commit are required.\n'; return 2;
    }
    [[ -n ${DEV_FLUX_SELECTED_SOURCE:-} && -n ${DEV_FLUX_SELECTED_NAMESPACE:-} ]] || return 2
    # Context names are not security controls. Every unclassified context uses the
    # production guard; no environment is inferred safe from a dev/test substring.
    [[ ${DEV_ALLOW_PROD_RECONCILE:-0} == 1 ]] || {
        printf 'RECONCILE REFUSED: context classification is unverified. Explicit --allow-prod-reconcile is required.\n'; return 2;
    }
    if [[ ${DEV_NON_INTERACTIVE:-0} != 1 ]]; then
        prompt "Reconcile $SENTINEL_CONTEXT $DEV_FLUX_SELECTED_NAMESPACE/$DEV_FLUX_SELECTED_SOURCE? Type RECONCILE:" || return 2
        [[ "$REPLY" == RECONCILE ]] || { printf 'Reconcile cancelled.\n'; return 2; }
    fi
    has flux || { printf 'RECONCILE UNAVAILABLE: flux CLI is absent; no mutation fallback is used.\n'; return 2; }
    printf 'Explicit developer reconcile: context=%s source=%s/%s\n' "$SENTINEL_CONTEXT" "$DEV_FLUX_SELECTED_NAMESPACE" "$DEV_FLUX_SELECTED_SOURCE"
    run_bounded "${DEV_FLUX_WAIT:-120}" command flux --context "$SENTINEL_CONTEXT" -n "$DEV_FLUX_SELECTED_NAMESPACE" --timeout "${DEV_FLUX_WAIT:-120}s" reconcile source git "$DEV_FLUX_SELECTED_SOURCE" 2>&1 | redact
}

dev_flux_verify() {
    local requested_sha="${DEV_COMMIT:-${COMMIT_SHA:-${DEV_COMMIT_SHA:-}}}" rc
    dev_flux_mode_allowed || { printf 'Flux verification is available only in explicit developer modes.\n'; return 2; }
    has jq || { printf 'FLUX: COMMAND_MISSING (jq).\n'; return 1; }
    printf '\nFLUX POST-PUSH VERIFICATION\n'
    if [[ ${DEV_PUSH_VERIFIED:-0} != 1 ]]; then
        dev_git_discover || return
        dev_git_remote_head || return
        [[ -n "$requested_sha" ]] || requested_sha="$(git -C "$DEV_REPO" rev-parse HEAD)"
        [[ "$requested_sha" =~ ^[0-9a-fA-F]{40}$ || "$requested_sha" =~ ^[0-9a-fA-F]{64}$ ]] || { printf 'Full commit SHA required.\n'; return 2; }
        [[ "${requested_sha,,}" == "${DEV_REMOTE_SHA,,}" ]] || { printf 'PUSH NOT VERIFIED: commit is not the exact remote branch head.\n'; return 1; }
        DEV_COMMIT_SHA="${requested_sha,,}"; DEV_PUSH_VERIFIED=1
    fi
    if [[ ${DEV_FLUX_RECONCILE:-0} == 1 && ${DEV_TESTS_PASSED:-0} != 1 ]]; then
        dev_validate || return
        dev_smoke || return
        DEV_TESTS_PASSED=1
    fi
    [[ -n ${SENTINEL_CONTEXT:-} && -n ${SENTINEL_NAMESPACE:-} ]] || { printf 'Flux verification requires explicit context and namespace.\n'; return 2; }
    dev_flux_discover; rc=$?
    if ((rc!=0)); then
        if ((rc==4)) && [[ ${DEV_REQUIRE_FLUX:-0} != 1 && ${DEV_FLUX_RECONCILE:-0} != 1 ]]; then
            printf 'RESULT: FLUX_NOT_CONFIGURED (optional verification skipped; source not found).\n'; return 0
        fi
        return "$rc"
    fi
    # Give normal controller polling the entire configured budget before mutation.
    if ! dev_flux_source_wait; then
        if [[ ${DEV_FLUX_RECONCILE:-0} == 1 ]]; then
            dev_flux_reconcile_guarded || return
            dev_flux_source_wait || return
        else return 1; fi
    fi
    dev_flux_dependents_wait || return
    printf 'RESULT: PASS | source revision and visible linked controllers verified.\n'
    printf 'Script deployment by Flux: NOT VERIFIED; observing a Git revision does not establish runtime script execution.\n'
}

# 15 Shared output, exports and evidence
declare -a REPORT_HISTORY=()
capture_report() {
    local title=$1 text rc path
    shift
    path=$(mktemp "$RUN_DIR/report.XXXXXXXX") || return 2
    text=$("$@" 2>&1); rc=$?
    { printf '%s | %s\nContext: %s | Namespace: %s\n' "$title" "$(timestamp)" "$SENTINEL_CONTEXT" "$SENTINEL_NAMESPACE"; printf '%s\n' "$text"; } | redact > "$path"
    CURRENT_REPORT=$path CURRENT_TITLE=$title
    REPORT_HISTORY+=("$path")
    if ((${#REPORT_HISTORY[@]}>50)); then
        rm -f -- "${REPORT_HISTORY[0]}"
        REPORT_HISTORY=("${REPORT_HISTORY[@]:1}")
    fi
    log_audit "report=$title exit=$rc"
    return "$rc"
}
export_file() {
    local file=$1 label=${2:-report} format=${3:-txt} path line text
    [[ -f $file && $file == "$RUN_DIR/"* ]] || { printf 'Export source unavailable\n'; return 2; }
    case $format in txt|csv|json) ;; *) return 2;; esac
    path=$(mktemp "$OUTPUT_DIR/$(safe_id "$label")-$(date -u +%Y%m%dT%H%M%SZ).XXXXXX.$format") || return 2
    case $format in
        txt) redact < "$file" > "$path";;
        csv) printf 'LINE,TEXT\n' > "$path"; local i=0
            while IFS= read -r line || [[ -n $line ]]; do
                ((i+=1)); text=${line//\"/\"\"}; printf '%s,"%s"\n' "$i" "$text"
            done < <(redact < "$file") >> "$path";;
        json)
            if has jq; then
                redact < "$file" | jq -Rs --arg title "$label" --arg context "$SENTINEL_CONTEXT" --arg namespace "$SENTINEL_NAMESPACE" --arg collected "$(timestamp)" '{title:$title,context:$context,namespace:$namespace,collected:$collected,lines:split("\n")}' > "$path"
                jq -e . "$path" >/dev/null || { rm -f "$path"; return 2; }
            else rm -f "$path"; printf 'UNAVAILABLE: JSON export requires jq\n'; return 2; fi;;
    esac
    printf 'EXPORTED %s\n' "$path"
    log_audit "export=$path status=OK"
}
format_table() {
    local width=${1:-$UI_COLS}
    if ! has awk; then
        local line
        while IFS= read -r line; do truncate_text "${line//$'\t'/ }" "$((width-1))"; printf '\n'; done
        return
    fi
    awk -F '\t' -v w="$((width-1))" '
    function clip(s,n) {return length(s)>n ? substr(s,1,n-1) "~" : s}
    NF<2 { print clip($0,w); next }
    NF>=20 {
      if(w<100) line=sprintf("%-24s %-5s %-14s %4s %9s %12s",clip($1,24),clip($2,5),clip($3,14),clip($4,4),clip($6,9),clip($9,12))
      else if(w<140) line=sprintf("%-28s %-5s %-15s %4s %9s %9s %12s %12s",clip($1,28),clip($2,5),clip($3,15),clip($4,4),clip($6,9),clip($7,9),clip($9,12),clip($10,12))
      else line=sprintf("%-36s %-5s %-18s %5s %9s %9s %9s %12s %12s %12s %-18s",clip($1,36),clip($2,5),clip($3,18),clip($4,5),clip($6,9),clip($7,9),clip($8,9),clip($9,12),clip($10,12),clip($11,12),clip($16,18))
      print clip(line,w); next
    }
    {
      # Name first, then high priority left-hand columns; full data stays in report.
      first=(w>=150?40:(w>=110?32:25)); rest=12; max=1+int((w-first)/(rest+1))
      line=sprintf("%-*s",first,clip($1,first)); n=NF<max?NF:max
      for(i=2;i<=n;i++) line=line " " sprintf("%-*s",rest,clip($i,rest))
      print clip(line,w)
    }'
}
view_file() {
    local file=$1 title=${2:-'Full Output'} page=0 page_size key search='' i start count line
    local -a all=() shown=()
    [[ -f $file ]] || return 1
    CURRENT_REPORT=$file CURRENT_TITLE=$title
    if (( ! INTERACTIVE )); then redact < "$file"; return; fi
    terminal_size; page_size=$((UI_ROWS-7))
    # Wrap instead of discarding overflow: every character is reachable in pager.
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line//$'\t'/  }
        while ((${#line}>UI_COLS-1)); do all+=("${line:0:UI_COLS-1}"); line=${line:UI_COLS-1}; done
        all+=("$line")
    done < <(redact < "$file")
    shown=("${all[@]}")
    while :; do
        count=${#shown[@]}; start=$((page*page_size))
        printf '\n%s | page %d/%d | %s\n' "$title" "$((page+1))" "$(((count+page_size-1)/page_size))" "$search"
        rule
        for ((i=start;i<start+page_size && i<count;i++)); do printf '%s\n' "${shown[i]}"; done
        printf '[n] next [p] prev [g/G] first/last [/] search [e] export [q] back\n'
        prompt 'Viewer:' || break; key=$REPLY
        case $key in
            n) ((start+page_size<count)) && ((page+=1));;
            p) ((page>0)) && ((page-=1));;
            g) page=0;; G) page=$(((count>0?count-1:0)/page_size));;
            /) prompt 'Search (literal, empty resets):' || continue; search=$REPLY; shown=(); page=0
               for line in "${all[@]}"; do [[ ${line,,} == *"${search,,}"* ]] && shown+=("$line"); done;;
            e) choose 'Export format' TXT CSV JSON || continue; export_file "$file" "$title" "${REPLY,,}";;
            q|0) break;;
        esac
    done
}
show_report() { local title=$1; shift; capture_report "$title" "$@"; view_file "$CURRENT_REPORT" "$title"; }
global_search() {
    local term file line count=0
    prompt 'Search all cached reports (literal):' || return
    term=$REPLY
    local out; out=$(mktemp "$RUN_DIR/search.XXXXXXXX") || return
    for file in "$CACHE_DIR"/*.txt "$CACHE_DIR"/*.json "$RUN_DIR"/report.*; do
        [[ -f $file ]] || continue
        while IFS= read -r line; do
            if [[ ${line,,} == *"${term,,}"* ]]; then printf '%s: %s\n' "${file##*/}" "$line" >> "$out"; ((count+=1)); fi
        done < "$file"
    done
    printf '\nMatches: %s (sanitized cache projections only)\n' "$count" >> "$out"
    view_file "$out" 'Global search'
}
output_center() {
    local action file
    local -a files=()
    while choose 'FULL OUTPUT / LOG CENTER' 'Full current report' 'Raw sanitized cache' Summary Search 'Application audit log' 'Pod logs' Export; do
        action=$REPLY
        case $action in
            'Full current report') [[ -f $CURRENT_REPORT ]] && view_file "$CURRENT_REPORT" "$CURRENT_TITLE";;
            'Raw sanitized cache')
                files=()
                for file in "$CACHE_DIR"/*.json "$CACHE_DIR"/*.txt; do [[ -f $file ]] && files+=("$file"); done
                choose 'Select a cached safe projection (raw credentials are never retained)' "${files[@]}" && view_file "$REPLY" 'Raw sanitized projection';;
            Summary) show_report Summary summary_report;;
            Search) global_search;;
            'Application audit log') view_file "$RUN_DIR/application.log" 'Application audit';;
            'Pod logs') logs_capture; [[ -f $CURRENT_REPORT ]] && view_file "$CURRENT_REPORT" 'Pod logs';;
            Export) export_center;;
        esac
    done
}
evidence_metadata() {
    local category=$1 status=$2
    scope_report
    printf 'Collector category: %s\nCollector status: %s\n\n' "$category" "$status"
}
evidence_section() {
    local directory=$1 filename=$2 category=$3 text rc status
    shift 3
    text=$("$@" 2>&1); rc=$?
    status=COMPLETED_WITH_PER_COLLECTOR_STATUS
    ((rc==0)) || status="PARTIAL_EXIT_$rc"
    { evidence_metadata "$category" "$status"; printf '%s\n' "$text"; } | redact > "$directory/$filename"
    printf '%s\t%s\n' "$filename" "$status" >> "$directory/collection.tsv"
}
evidence_manifest() {
    local directory=$1 file
    if has sha256sum; then
        (cd -- "$directory" || exit; for file in *.txt *.csv *.tsv 15_LOGS/*.txt; do [[ -f $file ]] && sha256sum -- "$file"; done) > "$directory/MANIFEST.sha256"
        printf 'Evidence integrity manifest generated: YES\n'
    else printf 'Evidence integrity manifest: UNAVAILABLE (sha256sum not installed)\n'; fi
}
logs_capture() {
    local destination=${1:-$RUN_DIR} pod=${2:-} container tail=500 since=1h previous=0 file text rc
    local -a containers=() args=()
    [[ -n $pod ]] || { select_pod || return 2; pod=$SELECTED_POD; }
    collect_pods
    if has jq && [[ -f $CACHE_DIR/pods.json ]]; then
        mapfile -t containers < <(jq -r --arg p "$pod" '.items[]|select(.metadata.name==$p)|(.spec.containers[],.spec.initContainers[]?,.spec.ephemeralContainers[]?)|.name' "$CACHE_DIR/pods.json")
    else printf 'UNAVAILABLE: jq required for discovered container selection\n'; return 2; fi
    choose "Container in $pod" "${containers[@]}" || return 2; container=$REPLY
    choose 'Log stream' current previous || return 2
    [[ $REPLY == previous ]] && previous=1
    prompt 'Tail lines [500], or type FULL LOG (may be large; transfer remains time bounded):' || return 2
    if [[ $REPLY == 'FULL LOG' ]]; then tail=-1
    elif [[ -n $REPLY ]]; then [[ $REPLY =~ ^[1-9][0-9]{0,6}$ ]] || return 2; tail=$REPLY; fi
    prompt 'Since duration [1h; e.g. 30m, 2h, 24h; FULL for no time limit]:' || return 2
    [[ -n $REPLY ]] && since=$REPLY
    [[ $since == FULL || $since =~ ^[1-9][0-9]{0,5}(s|m|h)$ ]] || return 2
    args=(logs "$pod" -c "$container" "--tail=$tail" --timestamps=true)
    [[ $since != FULL ]] && args+=("--since=$since")
    ((previous)) && args+=(--previous=true)
    [[ $destination == "$RUN_DIR" || $destination == "$OUTPUT_DIR/"* ]] || return 2
    file=$(mktemp "$destination/$(safe_id "$pod-$container").XXXXXXXX.txt") || return 2
    # Stream straight through redaction: unlimited logs never accumulate in memory.
    evidence_metadata 'pod logs' "REQUESTED tail=$tail since=$since previous=$previous" > "$file"
    kctl_ns "${args[@]}" 2>&1 | redact >> "$file"; rc=${PIPESTATUS[0]}
    printf '\nCollector exit: %s; status: %s\n' "$rc" "$(classify_error "$rc" "$(tail -n 3 "$file")")" >> "$file"
    printf 'Log evidence: %s\n' "$file"
    CURRENT_REPORT=$file CURRENT_TITLE='Redacted pod logs'
    log_audit "logs pod=$pod container=$container exit=$rc"
    return "$rc"
}
executive_report() {
    printf 'EXECUTIVE SUMMARY\n'
    scope_report
    printf '\nCollection time: %s\nGitOps: %s\nCertificate capability: %s\nMetrics: %s\n' "$(timestamp)" "$GITOPS_STATUS" "$CERT_STATUS" "$METRICS_STATUS"
    printf 'Evidence completeness: see collection.tsv and per-source statuses; denied/unavailable sources are unknown.\n'
    health_report
}
evidence_create() {
    local id=$1 mode=${2:-9} directory selected=${SELECTED_POD:-} saved_force=$FORCE_REFRESH
    id=$(safe_id "$id")
    directory=$(mktemp -d "$OUTPUT_DIR/${id}_$(date -u +%Y%m%d_%H%M%S)_XXXXXX") || return 2
    mkdir -- "$directory/15_LOGS" || return 2
    printf 'FILE\tCOLLECTION_STATUS\n' > "$directory/collection.tsv"
    printf 'Collecting evidence in %s\n' "$directory" >&2
    # Each collector reuses one fresh cache snapshot across the bundle.
    FORCE_REFRESH=0
    evidence_section "$directory" 01_SESSION_SCOPE.txt session scope_report
    evidence_section "$directory" 02_API_AUTH_RBAC.txt diagnostics diagnostics_report
    case $mode in 1|2|3|9)
        evidence_section "$directory" 03_PODS.txt pods resources_report
        evidence_section "$directory" 04_WORKLOADS.txt workloads workloads_report
        if [[ $mode == 3 && -n $selected ]]; then evidence_section "$directory" 03_SELECTED_POD.txt "pod/$selected" inspector_report "$selected"; fi;; esac
    case $mode in 2|4|9) evidence_section "$directory" 05_SERVICES_ENDPOINTS.txt network network_report; evidence_section "$directory" 06_STORAGE.txt storage storage_report;; esac
    case $mode in 1|2|3|8|9)
        evidence_section "$directory" 07_EVENTS.txt events events_report all
        events_report csv | redact > "$directory/16_TIMELINE.csv"
        evidence_section "$directory" 16_TIMELINE_METADATA.txt timeline evidence_metadata 'event CSV' 'see event collector status';; esac
    case $mode in 1|2|3|7|9)
        evidence_section "$directory" 08_RESOURCE_USAGE.txt resources resources_report
        evidence_section "$directory" 09_NODES.txt nodes nodes_report
        evidence_section "$directory" 14_IMAGES.txt images images_report;; esac
    case $mode in 2|5|9) evidence_section "$directory" 10_HELM.txt helm helm_report; evidence_section "$directory" 11_FLUX.txt gitops gitops_report;; esac
    case $mode in 2|6|9)
        evidence_section "$directory" 12_CERTIFICATES.txt certificates certificates_report
        evidence_section "$directory" 13_TLS.txt tls certificate_relationships_report;; esac
    if ((INTERACTIVE)) && [[ $mode == 3 || $mode == 9 ]]; then
        prompt 'Capture selected, bounded pod logs? [y/N]:' && [[ $REPLY == y || $REPLY == Y ]] && logs_capture "$directory/15_LOGS" "$selected"
    fi
    evidence_section "$directory" 00_EXECUTIVE_SUMMARY.txt executive executive_report
    evidence_section "$directory" 17_FINDINGS.txt findings cat "$RUN_DIR/findings.tsv"
    {
        evidence_metadata bundle COMPLETE_WITH_SOURCE_STATUS
        printf 'Read 00_EXECUTIVE_SUMMARY.txt and collection.tsv first. All scope is locked to the selected context/namespace.\n'
        printf 'Node/storage cluster metadata may be included where permitted. Reservations remain namespace scoped.\n'
        printf 'Logs are opt-in, bounded and redacted. No Secret payloads, kubeconfig credentials, or private keys are exported.\n'
        printf 'Certificate sections contain parsed metadata only. TLS connections are run only on explicit target selection.\n'
        printf 'Redaction removes recognized credential patterns; restrict access to operational evidence.\n'
        printf 'Validate integrity from this directory with: sha256sum -c MANIFEST.sha256\n'
        printf 'Snapshots and API lists are collected sequentially; this is not an atomic cluster snapshot.\n'
    } | redact > "$directory/README.txt"
    evidence_manifest "$directory"
    FORCE_REFRESH=$saved_force
    log_audit "evidence=$directory mode=$mode status=COMPLETE"
    printf 'Evidence bundle: %s\n' "$directory"
}
evidence_menu() {
    local selection id
    choose 'INCIDENT EVIDENCE COLLECTOR' 'Quick Evidence' 'Full Namespace Evidence' 'Pod/Workload Evidence' 'Network/Service Evidence' 'GitOps Evidence' 'Certificate/TLS Evidence' 'Resource/Capacity Evidence' 'Event Timeline' 'Complete Incident Bundle' || return
    case $REPLY in Quick*) selection=1;; Full*) selection=2;; Pod*) selection=3;; Network*) selection=4;; GitOps*) selection=5;; Certificate*) selection=6;; Resource*) selection=7;; Event*) selection=8;; Complete*) selection=9;; esac
    prompt 'Incident / Change ID:' || return; id=$REPLY
    [[ $selection != 3 ]] || select_pod || return
    evidence_create "$id" "$selection"
    prompt 'Enter to return:' || :
}
snapshot_create() {
    local target part key
    target=$(mktemp "$OUTPUT_DIR/snapshot-$(date -u +%Y%m%dT%H%M%SZ).XXXXXXXX.txt") || return 2
    {
        scope_report
        printf '\nSnapshot counts, resource states, images and allocation\n'
        summary_report; resources_report; images_report; network_report; storage_report
        gitops_report; helm_report; certificates_report; events_report warnings
    } | redact > "$target"
    printf 'Snapshot: %s\n' "$target"
    log_audit "snapshot=$target"
}
snapshot_compare() {
    local before after file
    local -a snapshots=()
    for file in "$OUTPUT_DIR"/snapshot-*.txt; do [[ -f $file && ! -L $file ]] && snapshots+=("$file"); done
    ((${#snapshots[@]}>1)) || { printf 'Create at least two snapshots first.\n'; return; }
    choose 'BEFORE snapshot' "${snapshots[@]}" || return; before=$REPLY
    choose 'AFTER snapshot' "${snapshots[@]}" || return; after=$REPLY
    if has diff; then show_report 'BEFORE / AFTER / CHANGE (exact resource lines; timestamps also differ)' diff -u -- "$before" "$after"
    else printf 'UNAVAILABLE: diff not installed\n'; fi
}
export_center() {
    local selected
    choose 'EXPORT & EVIDENCE CENTER' 'Current complete report' 'Health report' 'Resource snapshot' 'GitOps snapshot' 'Certificate inventory' 'Splunk catalog' 'Incident evidence' 'Create snapshot' 'Compare snapshots' || return
    selected=$REPLY
    case $selected in
        'Current complete report') [[ -f $CURRENT_REPORT ]] || { printf 'No report yet\n'; return; };;
        'Health report') capture_report Health health_report;;
        'Resource snapshot') capture_report Resources resources_report;;
        'GitOps snapshot') capture_report GitOps gitops_report;;
        'Certificate inventory') capture_report Certificates certificates_report;;
        'Splunk catalog') splunk_export; return;;
        'Incident evidence') evidence_menu; return;;
        'Create snapshot') snapshot_create; return;;
        'Compare snapshots') snapshot_compare; return;;
    esac
    choose 'Export format' TXT CSV JSON || return
    export_file "$CURRENT_REPORT" "$CURRENT_TITLE" "${REPLY,,}"
}

# 17 Stable terminal painting. The frame/menu is drawn once per screen; only
# changed rows in the dynamic region are replaced between refreshes.
declare -a UI_PREVIOUS=()
ui_enter() {
    if [[ -t 1 && ${TERM:-dumb} != dumb ]]; then printf '\033[?1049h\033[?25l'; UI_ACTIVE=1; fi
    terminal_size
}
ui_leave() {
    if ((UI_ACTIVE)); then printf '\033[0m\033[?25h\033[?1049l'; UI_ACTIVE=0; fi
    UI_PREVIOUS=()
}
paint_line() {
    local row=$1 line=$2 color=$C_CYAN
    line=$(truncate_text "$line" "$((UI_COLS-1))")
    if [[ ${UI_PREVIOUS[$row]:-__unset__} != "$line" ]]; then
        case $line in
            *FAIL*|*EXPIRED*|*CRITICAL*|*CrashLoopBackOff*|*AUTH_ERROR*) color=$C_RED;;
            *WARN*|*UNKNOWN*|*UNAVAILABLE*|*RBAC_DENIED*|*Pending*) color=$C_YELLOW;;
            *'[OK]'*|*PASS*|*AUTHENTICATED*) color=$C_GREEN;;
        esac
        ((row==1)) && color=$C_BLUE
        if ((UI_ACTIVE)); then printf '\033[%s;1H\033[2K%s%s%s' "$row" "$color" "$line" "$C_RESET"; else printf '%s\n' "$line"; fi
        UI_PREVIOUS[$row]=$line
    fi
}
paint_frame() {
    local title=$1 footer=$2
    paint_line 1 "$APP_NAME :: $title :: READ-ONLY :: v$APP_VERSION"
    paint_line 2 "CONTEXT $SENTINEL_CONTEXT | NAMESPACE $SENTINEL_NAMESPACE"
    paint_line "$UI_ROWS" "$footer"
}
paint_report() {
    local file=$1 line row=5
    paint_line 3 "AUTH $AUTH_STATUS | API $API_STATUS | METRICS $(cache_status metrics) | REFRESH ${REFRESH}s | $(timestamp)"
    paint_line 4 "SOURCE cached Kubernetes APIs | Pods age $(cache_age pods)s | / filter | full output preserves hidden columns"
    while IFS= read -r line; do
        ((row<UI_ROWS)) || break
        paint_line "$row" "$line"; ((row+=1))
    done < <(format_table "$UI_COLS" < "$file")
    while ((row<UI_ROWS)); do paint_line "$row" ''; ((row+=1)); done
    ((UI_ACTIVE)) && printf '\033[%s;1H' "$UI_ROWS"
}
filter_sort_report() {
    local source=$1 destination=$2
    # The resource engine receives SORT_BY/FILTER; this generic view additionally
    # supports literal matches in every projected report without API requests.
    if [[ -z $FILTER ]]; then cat -- "$source" > "$destination"
    elif has grep; then
        printf '%s\n' "FILTER regex: $FILTER" > "$destination"
        grep -E -- "$FILTER" "$source" >> "$destination"; local rc=$?
        ((rc==2)) && printf 'PARSE_ERROR: invalid regular expression\n' >> "$destination"
    else printf 'UNAVAILABLE: regex filtering requires grep\n' > "$destination"; fi
}
live_resources() {
    local key paused=0 repaint=1 filtered width=$UI_COLS
    local -a intervals=(0 2 5 10 15 30 60)
    filtered=$(mktemp "$RUN_DIR/live.XXXXXXXX") || return
    ui_enter
    paint_frame 'LIVE RESOURCE TRACKER' '[p] pause [r] refresh [+/-] interval [/] filter [s] sort [i] inspect [e] export [f] full [q] back'
    while :; do
        terminal_size
        if [[ $width != "$UI_COLS" ]]; then width=$UI_COLS; UI_PREVIOUS=(); paint_frame 'LIVE RESOURCE TRACKER' '[p] pause [r] refresh [+/-] rate [/] filter [s] sort [i] inspect [e] export [f] full [q] back'; fi
        if ((repaint)); then
            RESOURCE_FILTER=$FILTER RESOURCE_SORT=$SORT_BY
            capture_report 'Live Resources' resources_report
            cat -- "$CURRENT_REPORT" > "$filtered"
            paint_report "$filtered"
            FORCE_REFRESH=0 repaint=0
        fi
        key=
        if ((paused || REFRESH==0)); then IFS= read -r -s -n 1 key || break
        elif ! IFS= read -r -s -n 1 -t "$REFRESH" key; then
            [[ -t 0 ]] || break
            repaint=1; continue
        fi
        case $key in
            q|0) break;;
            p) paused=$((1-paused)); paint_line 4 "PAUSED=$paused | Pods cache age $(cache_age pods)s";;
            r) FORCE_REFRESH=1 repaint=1;;
            +) case $REFRESH in 0|60) REFRESH=30;;30) REFRESH=15;;15) REFRESH=10;;10) REFRESH=5;;5|2) REFRESH=2;;esac; repaint=1;;
            -) case $REFRESH in 2) REFRESH=5;;5) REFRESH=10;;10) REFRESH=15;;15) REFRESH=30;;30) REFRESH=60;;60|0) REFRESH=0;;esac; repaint=1;;
            /) ui_leave; prompt 'Filter [regex; empty clears]:' && FILTER=$REPLY; ui_enter; repaint=1;;
            s) ui_leave; choose 'Sort by' name cpu memory restarts age status node && SORT_BY=$REPLY; ui_enter; repaint=1;;
            f) ui_leave; view_file "$CURRENT_REPORT" 'Full resource output'; ui_enter; repaint=1;;
            e) ui_leave; export_file "$CURRENT_REPORT" resources txt; prompt 'Enter:' || :; ui_enter; repaint=1;;
            i) ui_leave; component_triage; ui_enter; repaint=1;;
        esac
        paint_frame 'LIVE RESOURCE TRACKER' '[p] pause [r] refresh [+/-] interval [/] filter [s] sort [i] inspect [e] export [f] full [q] back'
    done
    ui_leave
}
component_triage() {
    local action
    select_pod || return
    while choose "TRIAGE: $SELECTED_POD" Inspect Events Resources Containers Images Services Storage GitOps Certificates Logs Evidence; do
        action=$REPLY
        case $action in
            Inspect) show_report 'Pod inspector' inspector_report "$SELECTED_POD";;
            Events) show_report 'Related events and relationships' inspector_report "$SELECTED_POD";;
            Resources|Containers) show_report 'Container resources' containers_report "$SELECTED_POD";;
            Images) show_report 'Runtime images' images_report;;
            Services) show_report 'Service relationships' inspector_report "$SELECTED_POD";;
            Storage) show_report 'Storage' storage_report;;
            GitOps) show_report 'Deployment validation' deployment_chain_report "$SELECTED_POD";;
            Certificates) show_report 'Certificate references' cert_mounts_report;;
            Logs) logs_capture "$RUN_DIR" "$SELECTED_POD"; [[ -f $CURRENT_REPORT ]] && view_file "$CURRENT_REPORT" 'Logs';;
            Evidence) prompt 'Incident / Change ID:' && evidence_create "$REPLY" 3;;
        esac
    done
}
module_help() {
    cat <<'HELP'
OPERATIONS HELP
Scope: every namespaced read is locked to the displayed context and namespace.
Sources: Kubernetes resource APIs; metrics.k8s.io; Flux/cert-manager when installed.
Refresh: pods/metrics 5s, events 10s, Flux/Helm 15s, certificates 60s, discovery 300s.
Live keys: p pause, r force, +/- rate, / regex filter, s sort, i triage, e export, f full.
Tables hide lower-priority columns at narrow widths. Full output wraps and pages all data.
Readiness counts observed OK/WARN/FAIL/UNKNOWN findings; it is not a health percentage.
Missing permissions, API errors and missing metrics are explicit, never interpreted as zero.
GitOps: generation/revision differences can be reconciliation lag. Desired manifests are
not downloaded; runtime variance is not proof of Git desired-state drift.
Certificates: only public certificate metadata is parsed; mount configuration does not
prove that a file exists in a running container. TLS probes are explicit and bounded.
Splunk: offline keywords are GENERATED_UNVALIDATED. Fields must be discovered before use.
Evidence: local private sanitized projections, opt-in bounded logs, SHA256 when installed.
Snapshots are sequential observations, not a transactionally consistent cluster state.
Node requests/limits represent this namespace only; total node reservations are unknown.
No application mode runs arbitrary shell commands or arbitrary kubectl arguments.
HELP
}
dashboard_report() {
    summary_report | { local line number=0; while IFS= read -r line; do ((number+=1)); ((number<=8)) && printf '%s\n' "$line"; done; }
    printf '\nLIVE OPERATIONS                         FORENSICS & ASSURANCE\n'
    printf '[ 1] Live Resource Tracker              [ 7] Incident Evidence\n'
    printf '[ 2] Pod / Container Inspector          [ 8] Event Timeline\n'
    printf '[ 3] Node / Pool Capacity               [ 9] Certificate / TLS\n'
    printf '[ 4] Workload Health                    [10] Splunk Audit Queries\n'
    printf '[ 5] Network / Services                 [11] Export / Snapshots\n'
    printf '[ 6] Health / Readiness                 [12] GitOps Drift\n'
    printf '[13] Full Output / Logs                 [14] Change Scope\n'
    printf '[15] Dependency / RBAC diagnostics      [16] Help\n'
    printf '[/] Global search                      [ 0] Secure exit\n'
}
dashboard() {
    local selection last_report='' rc=0
    ui_enter
    while :; do
        paint_frame 'LIVE KUBERNETES OPERATIONS' 'Select a number + Enter | / Search | 0 Exit'
        capture_report Dashboard dashboard_report
        paint_report "$CURRENT_REPORT"
        [[ -n $last_report ]] && CURRENT_REPORT=$last_report
        selection=
        if ((UI_ACTIVE)); then printf '\033[%s;1H\033[2KSelect [0-16, /]: \033[?25h' "$UI_ROWS"; fi
        if ((REFRESH>0)); then
            IFS= read -r -t "$REFRESH" selection; rc=$?
            if ((rc>128)); then continue; elif ((rc!=0)); then break; fi
        else IFS= read -r selection || break; fi
        ui_leave
        log_audit "menu=$selection"
        case $selection in
            0|q) break;;
            1) live_resources;; 2) component_triage;;
            3) show_report 'Node capacity' nodes_report;;
            4) show_report 'Workload health' workloads_report;;
            5) show_report 'Network / Service relationships' network_report;;
            6) show_report 'Health / Readiness' health_report;;
            7) evidence_menu;; 8) show_report 'Event Timeline' events_report all;;
            9) certificates_menu;; 10) splunk_menu;; 11) export_center;; 12) gitops_menu;;
            13) output_center;;
            14) SENTINEL_CONTEXT= SENTINEL_NAMESPACE= SCOPE_READY=0
                # Clear cached scope before selecting; never combine different scopes.
                rm -f -- "$CACHE_DIR"/*.json "$CACHE_DIR"/*.txt "$CACHE_DIR"/*.status "$CACHE_DIR"/*.time "$CACHE_DIR"/*.error
                bootstrap_scope || { rc=$?; break; };;
            15) show_report Diagnostics diagnostics_report;; 16|h|help) show_report Help module_help;;
            /) global_search;;
        esac
        last_report=$CURRENT_REPORT
        ui_enter
    done
    ui_leave
    return "$rc"
}

# 19 CLI. Developer controls are deliberately absent from the operations menu.
ui_process_self_tests() (
    local width line result=0 dir first second marker child child_runtime rc tries=0
    dir=$(mktemp -d "$RUN_DIR/ui-fixtures.XXXXXXXX") || return 1
    UI_ACTIVE=1 UI_PREVIOUS=() UI_COLS=80
    C_RESET= C_CYAN= C_RED= C_GREEN= C_YELLOW= C_BLUE=
    paint_line 3 'stable row' > "$dir/frame"
    first=$(wc -c < "$dir/frame")
    paint_line 3 'stable row' >> "$dir/frame"
    second=$(wc -c < "$dir/frame")
    [[ $first == "$second" ]] || return 1
    ! grep -Fq $'\033[2J' "$dir/frame" || return 1
    for width in 80 100 120 160; do
        printf 'fixture-pod\t1/1\tRunning\t0\t1d\t125m\t250m\t500m\t32 MiB\t64 MiB\t128 MiB\t50%%\t25%%\t50%%\t25%%\tnode\tip\towner\tapp\timage\n' | format_table "$width" > "$dir/table"
        while IFS= read -r line; do ((${#line}<width)) || return 1; done < "$dir/table"
        grep -q '125m' "$dir/table" && grep -q '32 MiB' "$dir/table" || return 1
    done
    INTERACTIVE=0 UI_ACTIVE=0
    printf '%0250d END_OF_FULL_OUTPUT\n' 0 > "$dir/full"
    view_file "$dir/full" Fixture > "$dir/view"
    grep -q END_OF_FULL_OUTPUT "$dir/view" || return 1
    run_bounded 1 sleep 5 >/dev/null 2>&1; rc=$?
    [[ $rc == 124 || $rc == 143 ]] || return 1
    ((${#ACTIVE_PIDS[@]}==0)) || return 1
    has() { [[ $1 != timeout ]] && command -v "$1" >/dev/null 2>&1; }
    run_bounded 1 sleep 5 >/dev/null 2>&1; rc=$?
    [[ $rc == 143 ]] || return 1
    ((${#ACTIVE_PIDS[@]}==0)) || return 1
    # Verify real TERM cleanup in a fresh Bash process using the same executable.
    marker=$(mktemp "$RUN_DIR/signal-fixture.XXXXXXXX") || return 1
    bash -c 'source "$1"; OUTPUT_DIR=$2; MODE=dev-self-test; init_runtime || exit; printf "%s\n" "$RUN_DIR" > "$3"; run_bounded 20 sleep 20' sentinel-cleanup "$SOURCE_FILE" "$OUTPUT_DIR" "$marker" </dev/null >/dev/null 2>&1 &
    child=$!
    while [[ ! -s $marker ]] && ((tries<50)); do sleep 0.05; ((tries+=1)); done
    [[ -s $marker ]] || { kill_tree "$child"; wait "$child" 2>/dev/null; return 1; }
    IFS= read -r child_runtime < "$marker"
    kill -TERM "$child" 2>/dev/null || return 1
    wait "$child" 2>/dev/null; rc=$?
    [[ $rc == 143 && ! -d $child_runtime ]] || return 1
    printf 'PASS stable rendering at 80/100/120/160 columns, complete viewer, command deadline and TERM cleanup\n'
)

DEV_GIT_REMOTE=${SNTL_GIT_REMOTE:-} DEV_GIT_BRANCH=${SNTL_GIT_BRANCH:-}
DEV_MESSAGE= DEV_WITH_SMOKE=0 DEV_ALLOW_PROTECTED_BRANCH=0 DEV_FLUX_RECONCILE=0
DEV_REQUIRE_FLUX=0 DEV_FLUX_SOURCE=${SNTL_FLUX_GITREPOSITORY:-}
DEV_FLUX_NAMESPACE=${SNTL_FLUX_NAMESPACE:-} DEV_FLUX_WAIT=${SNTL_FLUX_WAIT:-120}
DEV_ALLOW_PROD_RECONCILE=0 DEV_NON_INTERACTIVE=0 DEV_COMMIT= DEV_BUMP=
COMMIT_SHA= DEV_PUSH_VERIFIED=0
usage() {
    cat <<'HELP'
KubeOps Sentinel -- read-only Kubernetes operations in one Bash executable
Usage: ./KubeOps_Sentinel.sh [options]
  --kubeconfig PATH       Explicit kubeconfig (existing environment otherwise preserved)
  --context NAME         Lock Kubernetes context; never changes current-context
  --namespace NAME       Lock namespace (required for noninteractive cluster commands)
  --refresh 0|2|5|10|15|30|60   Seconds; 0 = manual (default 5)
  --health | --resources | --gitops | --certificates | --evidence ID
  --output DIR           Local working-directory descendant for private runtime/export files
  --api-timeout SECONDS  --log-timeout SECONDS --tls-timeout SECONDS
  --cert-warn-days DAYS  --cert-critical-days DAYS
  --cpu-warn PCT --cpu-critical PCT --mem-warn PCT --mem-critical PCT
  --no-color --version --help --help-dev
Environment: SNTL_CONTEXT, SNTL_NAMESPACE, SNTL_REFRESH, SNTL_OUTPUT_DIR,
             SPLUNK_URL, SPLUNK_INDEX, SPLUNK_SOURCETYPE, SPLUNK_TOKEN (never persisted).
Exit: 0 no operational FAIL; 1 observed operational FAIL; 2 usage/configuration;
      3 authentication/API failure. UNKNOWN is reported, not counted as healthy.
TXT/CSV exports preserve full report lines. JSON report exports require optional jq.
HELP
}
usage_dev() {
    cat <<'HELP'
DEVELOPER COMMANDS -- native Linux / WSL, independent of the production menu
  --dev-info                  Environment/tool/source/Git diagnostics
  --dev-validate              Syntax, source integrity, static safety, self-tests, Git checks
  --dev-self-test             Deterministic embedded tests; no Kubernetes connection
  --dev-smoke                 Read-only Kubernetes integration checks
  --dev-watch [--with-smoke]  Debounced save-and-test; never publishes
  --dev-git-status | --dev-git-diff
  --dev-publish --message TEXT    Validate, exact-file commit, safe push
  --dev-release --message TEXT    Validate, smoke, publish, observe Flux
  --dev-flux-verify [--commit SHA] Verify exact pushed SHA and related Flux readiness
  --dev-fix-line-endings | --dev-fix-permissions | --dev-install-hook
  --git-remote NAME --git-branch NAME --allow-protected-branch
  --with-smoke --require-flux --flux-source NAME --flux-namespace NAME --flux-wait SECONDS
  --flux-reconcile --allow-prod-reconcile --non-interactive --bump patch|minor|major
Reconciliation is a separate explicit developer exception after verified push and tests.
Unknown context classification is treated conservatively for reconcile authorization.
No force-push, automatic merge/rebase, Git credential storage or configuration edits.
Environment: SNTL_DEV_CONTEXT, SNTL_DEV_NAMESPACE, SNTL_GIT_REMOTE, SNTL_GIT_BRANCH,
             SNTL_FLUX_NAMESPACE, SNTL_FLUX_GITREPOSITORY, SNTL_FLUX_WAIT.
HELP
}
cli_need_value() { (($#>=2)) && [[ -n $2 ]] || { printf 'Missing value for %s\n' "$1" >&2; return 2; }; }
parse_cli() {
    local mode_set=0 opt
    while (($#)); do
        opt=$1
        case $opt in
            --help|-h) usage; return 10;; --help-dev) usage_dev; return 10;;
            --version) printf '%s %s (%s)\n' "$APP_NAME" "$APP_VERSION" "$APP_BUILD"; return 10;;
            --no-color) NO_COLOR_FLAG=1;;
            --health|--resources|--gitops|--certificates|--dev-info|--dev-validate|--dev-self-test|--dev-smoke|--dev-watch|--dev-git-status|--dev-git-diff|--dev-publish|--dev-flux-verify|--dev-release|--dev-fix-line-endings|--dev-fix-permissions|--dev-install-hook)
                ((mode_set==0)) || { printf 'Select exactly one command mode\n' >&2; return 2; }; MODE=${opt#--}; mode_set=1;;
            --evidence) cli_need_value "$@" || return; ((mode_set==0)) || return 2; MODE=evidence EVIDENCE_ID=$2 mode_set=1; shift;;
            --kubeconfig) cli_need_value "$@" || return; export KUBECONFIG=$2; KUBECONFIG_MODE=EXPLICIT; shift;;
            --context) cli_need_value "$@" || return; SENTINEL_CONTEXT=$2; shift;;
            --namespace) cli_need_value "$@" || return; SENTINEL_NAMESPACE=$2; shift;;
            --output) cli_need_value "$@" || return; OUTPUT_DIR=$2; shift;;
            --refresh) cli_need_value "$@" || return; REFRESH=$2; shift;;
            --api-timeout|--log-timeout|--tls-timeout|--cert-warn-days|--cert-critical-days|--cpu-warn|--cpu-critical|--mem-warn|--mem-critical|--flux-wait)
                cli_need_value "$@" || return; [[ $2 =~ ^[1-9][0-9]{0,4}$ ]] || return 2
                case $opt in --api-timeout) API_TIMEOUT=$2;;--log-timeout) LOG_TIMEOUT=$2;;--tls-timeout) TLS_TIMEOUT=$2;;--cert-warn-days) CERT_WARN_DAYS=$2;;--cert-critical-days) CERT_CRIT_DAYS=$2;;--cpu-warn) CPU_WARN=$2;;--cpu-critical) CPU_CRIT=$2;;--mem-warn) MEM_WARN=$2;;--mem-critical) MEM_CRIT=$2;;--flux-wait) DEV_FLUX_WAIT=$2;;esac; shift;;
            --message|--git-remote|--git-branch|--flux-source|--flux-namespace|--commit|--bump)
                cli_need_value "$@" || return
                case $opt in --message) DEV_MESSAGE=$2;;--git-remote) DEV_GIT_REMOTE=$2;;--git-branch) DEV_GIT_BRANCH=$2;;--flux-source) DEV_FLUX_SOURCE=$2;;--flux-namespace) DEV_FLUX_NAMESPACE=$2;;--commit) DEV_COMMIT=$2;;--bump) DEV_BUMP=$2;;esac; shift;;
            --allow-protected-branch) DEV_ALLOW_PROTECTED_BRANCH=1;;--with-smoke) DEV_WITH_SMOKE=1;;
            --flux-reconcile) DEV_FLUX_RECONCILE=1;;--require-flux) DEV_REQUIRE_FLUX=1;;
            --allow-prod-reconcile) DEV_ALLOW_PROD_RECONCILE=1;;--non-interactive) DEV_NON_INTERACTIVE=1;;
            *) printf 'Unknown option: %s\n' "$opt" >&2; return 2;;
        esac
        shift
    done
    case $REFRESH in 0|2|5|10|15|30|60) ;;*) printf 'Invalid refresh interval\n' >&2; return 2;;esac
    ((CERT_CRIT_DAYS<=CERT_WARN_DAYS && CPU_WARN<CPU_CRIT && MEM_WARN<MEM_CRIT && CPU_CRIT<=100 && MEM_CRIT<=100)) || return 2
    if [[ $MODE == dev-* ]]; then
        [[ -n $SENTINEL_CONTEXT ]] || SENTINEL_CONTEXT=${SNTL_DEV_CONTEXT:-}
        [[ -n $SENTINEL_NAMESPACE ]] || SENTINEL_NAMESPACE=${SNTL_DEV_NAMESPACE:-}
    elif ((DEV_WITH_SMOKE || DEV_FLUX_RECONCILE || DEV_REQUIRE_FLUX || DEV_ALLOW_PROD_RECONCILE)); then printf 'Developer options require a developer command\n' >&2; return 2; fi
    if ((DEV_FLUX_RECONCILE)) && [[ $MODE != dev-release && $MODE != dev-flux-verify ]]; then printf 'Reconciliation only permitted in explicit developer release/verify modes\n' >&2; return 2; fi
    [[ -z $DEV_BUMP || $DEV_BUMP == patch || $DEV_BUMP == minor || $DEV_BUMP == major ]] || return 2
    [[ -z $DEV_COMMIT || $DEV_COMMIT =~ ^[a-fA-F0-9]{40}$ || $DEV_COMMIT =~ ^[a-fA-F0-9]{64}$ ]] || return 2
    [[ $DEV_FLUX_WAIT =~ ^[1-9][0-9]{0,4}$ ]] || return 2
    [[ -z $DEV_FLUX_NAMESPACE || $DEV_FLUX_NAMESPACE =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || return 2
    [[ -z $DEV_FLUX_SOURCE || $DEV_FLUX_SOURCE =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] || return 2
    [[ $DEV_GIT_REMOTE != -* && $DEV_GIT_BRANCH != -* ]] || return 2
    return 0
}
main() {
    if ((BASH_VERSINFO[0]<4 || (BASH_VERSINFO[0]==4 && BASH_VERSINFO[1]<4))); then printf 'Bash 4.4+ required\n' >&2; return 2; fi
    local rc command_fn
    parse_cli "$@"; rc=$?
    ((rc==10)) && return 0
    ((rc==0)) || return "$rc"
    dependency_detect
    for command_fn in mktemp mkdir rm cat; do has "$command_fn" || { printf 'Required core UNIX utility missing: %s\n' "$command_fn" >&2; return 2; }; done
    color_init; terminal_size
    SOURCE_FILE=$(cd -- "$(dirname -- "$SOURCE_FILE")" && printf '%s/%s' "$(pwd -P)" "${SOURCE_FILE##*/}") || return 2
    init_runtime || return
    if [[ $MODE == dev-* ]]; then
        command_fn=${MODE//-/_}
        declare -F "$command_fn" >/dev/null || { printf 'Unknown developer command\n' >&2; return 2; }
        "$command_fn"; return $?
    fi
    if [[ $MODE == dashboard && $INTERACTIVE == 0 ]]; then printf 'Dashboard needs a terminal; use --health or --resources for noninteractive output.\n' >&2; return 2; fi
    bootstrap_scope || return
    case $MODE in
        dashboard) dashboard;;
        resources) capture_report Resources resources_report; rc=$?; cat "$CURRENT_REPORT"; return "$rc";;
        health) capture_report Health health_report; rc=$?; cat "$CURRENT_REPORT"; return "$rc";;
        gitops) capture_report GitOps gitops_report; rc=$?; cat "$CURRENT_REPORT"; return "$rc";;
        certificates) capture_report Certificates certificates_report; rc=$?; cat "$CURRENT_REPORT"; return "$rc";;
        evidence) evidence_create "$EVIDENCE_ID" 9;;
    esac
}

# Sourcing defines testable functions but never runs a dashboard or touches a cluster.
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; exit $?; fi