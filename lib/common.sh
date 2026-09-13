#!/usr/bin/env bash
# lib/common.sh
#
# Shared helpers used by every module: logging, timestamped backups,
# idempotent file edits, and a dry-run-aware command runner.
#
# This file is sourced, not executed. It expects the following variables
# to already be set by bin/harden.sh: LOG_FILE, BACKUP_DIR, DRY_RUN.

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

# log LEVEL "message"
log() {
    local level="$1"; shift
    local message="$*"
    local elapsed
    elapsed=$(( $(date +%s) - HARDEN_START_TIME ))
    printf '[%02d:%02d] %-5s %s\n' \
        "$(( elapsed / 60 ))" "$(( elapsed % 60 ))" "$level" "$message" \
        | tee -a "$LOG_FILE"
}

log_info()  { log "INFO"  "$@"; }
log_warn()  { log "WARN"  "$@"; }
log_error() { log "ERROR" "$@"; }
log_ok()    { log "OK"    "$@"; }

# ---------------------------------------------------------------------------
# Command execution wrapper
# ---------------------------------------------------------------------------
# run "human readable description" cmd arg1 arg2 ...
#
# Centralizing every state-changing command through `run` gives us one
# place to add dry-run support, consistent logging, and error handling
# instead of scattering `|| true` and ad-hoc echo statements everywhere.
#
# `run` always returns 0. The orchestrator runs dozens of independent
# steps across unrelated subsystems (packages, firewall, PAM, sysctl...);
# a single missing package or a service that is already stopped should be
# logged and skipped, not allowed to abort every step after it under
# `set -e`. Failures are never swallowed silently -- they are always
# written to the log as WARN -- but they cannot halt the run. No call
# site in this project depends on `run`'s exit status for control flow;
# if you add one that must, check the log instead of branching on `run`.
run() {
    local description="$1"; shift
    if [ "${DRY_RUN:-0}" = "1" ]; then
        # Join args with plain spaces regardless of the caller's IFS
        # (bin/harden.sh sets IFS=$'\n\t' globally for safe word-splitting
        # elsewhere, which would otherwise make "$*" join with newlines).
        local cmd_str
        cmd_str="$(printf '%s ' "$@")"
        log_info "DRY-RUN: $description -- would execute: ${cmd_str% }"
        return 0
    fi
    if "$@"; then
        log_ok "$description"
    else
        local cmd_str
        cmd_str="$(printf '%s ' "$@")"
        log_warn "$description (command failed: ${cmd_str% })"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------

# backup_file /path/to/file
# Copies a file into $BACKUP_DIR with a timestamp suffix if it exists.
# Safe to call multiple times; never overwrites a previous backup.
backup_file() {
    local src="$1"
    if [ ! -e "$src" ]; then
        log_warn "backup skipped, not found: $src"
        return 0
    fi
    if [ "${DRY_RUN:-0}" = "1" ]; then
        log_info "DRY-RUN: would back up $src"
        return 0
    fi
    local stamp dest
    stamp=$(date +"%Y%m%d_%H%M%S")
    dest="$BACKUP_DIR/$(basename "$src").${stamp}.bak"
    if cp -a -- "$src" "$dest" 2>/dev/null; then
        log_ok "backed up $src -> $dest"
    else
        log_warn "failed to back up $src"
    fi
}

# ---------------------------------------------------------------------------
# Idempotent file edits
# ---------------------------------------------------------------------------

# ensure_line_in_file "exact line" /path/to/file
# Appends a line only if it is not already present, so the module can be
# re-run safely (a core requirement for anything that runs during a live
# competition image where re-runs are common).
ensure_line_in_file() {
    local line="$1" file="$2"
    if [ "${DRY_RUN:-0}" = "1" ]; then
        log_info "DRY-RUN: would ensure line in $file: $line"
        return 0
    fi
    mkdir -p -- "$(dirname "$file")"
    touch -- "$file"
    if grep -Fxq -- "$line" "$file" 2>/dev/null; then
        log_info "already present in $file: $line"
    else
        echo "$line" >> "$file"
        log_ok "appended to $file: $line"
    fi
}

# ensure_block_in_file "UNIQUE-MARKER" /path/to/file <<'EOF'
# ...block...
# EOF
# Appends a heredoc block guarded by a marker comment so re-running the
# script does not duplicate the block.
ensure_block_in_file() {
    local marker="$1" file="$2"
    if grep -Fq -- "$marker" "$file" 2>/dev/null; then
        log_info "block already present in $file ($marker)"
        cat >/dev/null # drain stdin so callers can always pipe a heredoc
        return 0
    fi
    if [ "${DRY_RUN:-0}" = "1" ]; then
        log_info "DRY-RUN: would append block to $file ($marker)"
        cat >/dev/null
        return 0
    fi
    mkdir -p -- "$(dirname "$file")"
    touch -- "$file"
    {
        printf '\n# --- %s ---\n' "$marker"
        cat
    } >> "$file"
    log_ok "appended block to $file ($marker)"
}

# safe_chmod MODE PATH -- only touches the path if it exists
safe_chmod() {
    local mode="$1" path="$2"
    if [ ! -e "$path" ]; then
        log_info "chmod skipped, not found: $path"
        return 0
    fi
    run "chmod $mode $path" chmod "$mode" "$path"
}

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

# confirm "question" "default(yes|no)" -> returns 0 for yes, 1 for no
# Falls back to the default on EOF (e.g. stdin redirected from /dev/null)
# instead of aborting the whole run under `set -e`.
confirm() {
    local question="$1" default="${2:-no}" answer
    local hint="y/N"
    if [ "$default" = "yes" ]; then hint="Y/n"; fi
    read -r -p "$question [$hint]: " answer || answer=""
    answer="${answer:-$default}"
    case "$answer" in
        y|Y|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Environment checks
# ---------------------------------------------------------------------------

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root (e.g. sudo ./bin/harden.sh)." >&2
        exit 1
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        printf '%s %s\n' "${NAME:-Unknown}" "${VERSION_ID:-Unknown}"
    elif command -v lsb_release >/dev/null 2>&1; then
        lsb_release -d -r 2>/dev/null
    else
        echo "Unknown OS"
    fi
}
