#!/usr/bin/env bash
# bin/harden.sh
#
# Orchestrates the hardening modules in lib/. Designed for Debian/Ubuntu
# family systems (developed and tested against Ubuntu 20.04/22.04 and
# Linux Mint, the images most commonly used in CyberPatriot's Linux
# division).
#
# Usage:
#   sudo ./bin/harden.sh                     interactive mode
#   sudo ./bin/harden.sh --config my.env      load answers from a file
#   sudo ./bin/harden.sh --dry-run            log intended actions, change nothing
#   sudo ./bin/harden.sh --auto-approve       skip per-package purge prompts
#
# See examples/config.env.example for the full list of variables an env
# file can set, and docs/security-controls.md for the reasoning and
# standards references behind each module.

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
HARDEN_START_TIME=$(date +%s)
export HARDEN_START_TIME # consumed by log() in lib/common.sh

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
DRY_RUN=0
AUTO_APPROVE=0
CONFIG_FILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --auto-approve) AUTO_APPROVE=1 ;;
        --config) shift; CONFIG_FILE="${1:-}" ;;
        -h|--help)
            grep '^#' "${BASH_SOURCE[0]}" | sed 's/^#//; s/^ //'
            exit 0
            ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
    shift
done
export DRY_RUN AUTO_APPROVE

# ---------------------------------------------------------------------------
# Output locations
# ---------------------------------------------------------------------------
STATE_DIR="${HARDEN_STATE_DIR:-$HOME/hardening-run}"
LOG_FILE="$STATE_DIR/harden.log"
BACKUP_DIR="$STATE_DIR/backups"
ARTIFACT_DIR="$STATE_DIR/baseline"

mkdir -p "$BACKUP_DIR" "$ARTIFACT_DIR"
: > "$LOG_FILE"
chmod 700 "$STATE_DIR" "$BACKUP_DIR" "$ARTIFACT_DIR"
chmod 600 "$LOG_FILE"

# ---------------------------------------------------------------------------
# Load library modules
# ---------------------------------------------------------------------------
# shellcheck source=../lib/common.sh
source "$REPO_ROOT/lib/common.sh"
# shellcheck source=../lib/packages.sh
source "$REPO_ROOT/lib/packages.sh"
# shellcheck source=../lib/users.sh
source "$REPO_ROOT/lib/users.sh"
# shellcheck source=../lib/ssh.sh
source "$REPO_ROOT/lib/ssh.sh"
# shellcheck source=../lib/services.sh
source "$REPO_ROOT/lib/services.sh"
# shellcheck source=../lib/firewall.sh
source "$REPO_ROOT/lib/firewall.sh"
# shellcheck source=../lib/kernel.sh
source "$REPO_ROOT/lib/kernel.sh"
# shellcheck source=../lib/pam.sh
source "$REPO_ROOT/lib/pam.sh"
# shellcheck source=../lib/filesystem.sh
source "$REPO_ROOT/lib/filesystem.sh"
# shellcheck source=../lib/monitoring.sh
source "$REPO_ROOT/lib/monitoring.sh"
# shellcheck source=../lib/forensics.sh
source "$REPO_ROOT/lib/forensics.sh"

require_root

if [ -n "$CONFIG_FILE" ]; then
    [ -f "$CONFIG_FILE" ] || { echo "Config file not found: $CONFIG_FILE" >&2; exit 1; }
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
    log_info "loaded configuration from $CONFIG_FILE"
fi

# ---------------------------------------------------------------------------
# Service role questions (skipped for any variable already set by --config)
# ---------------------------------------------------------------------------
ask_yn() {
    local var="$1" question="$2" default="$3"
    if [ -n "${!var:-}" ]; then
        return 0
    fi
    if confirm "$question" "$default"; then
        printf -v "$var" 'yes'
    else
        printf -v "$var" 'no'
    fi
}

log_info "=== $(basename "$0") starting on $(detect_os) ==="
if [ "$DRY_RUN" = "1" ]; then
    log_info "DRY-RUN MODE: no changes will be made"
fi
log_info "Competition note: this machine's network connectivity to your scoring"
log_info "engine/router is not something this script can verify. Confirm you"
log_info "still have connectivity after the firewall step before walking away."

ask_yn WANT_SAMBA    "Does this machine need Samba?"        "no"
ask_yn WANT_FTP      "Does this machine need FTP?"          "no"
ask_yn WANT_SSH      "Does this machine need SSH?"          "yes"
ask_yn WANT_TELNET   "Does this machine need Telnet?"       "no"
ask_yn WANT_MAIL     "Does this machine need Mail?"         "no"
ask_yn WANT_PRINTING "Does this machine need Printing?"     "no"
ask_yn WANT_MYSQL    "Does this machine need MySQL?"        "no"
ask_yn WANT_HTTP     "Will this machine be a Web Server?"   "no"
ask_yn WANT_DNS      "Does this machine need DNS?"          "no"
ask_yn ALLOW_MEDIA_FILES "Does this machine's policy allow media files?" "yes"

WANT_SSH=${WANT_SSH:-yes}

# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------
backup_files=(
    /etc/passwd /etc/group /etc/shadow /etc/sudoers
    /etc/ssh/sshd_config /etc/sysctl.conf
    /etc/pam.d/common-auth /etc/pam.d/common-password
    /etc/login.defs /etc/hosts /etc/rc.local
)
log_info "=== Backing up critical configuration files ==="
for f in "${backup_files[@]}"; do backup_file "$f"; done

packages_update_system
packages_remove_offensive_tools
packages_remove_games

firewall_set_defaults
ssh_configure
services_configure_samba
services_configure_ftp
services_configure_telnet
services_configure_mail
services_configure_printing
services_configure_mysql
services_configure_http
services_configure_dns
firewall_status

users_review_existing
users_create_new
users_find_hidden_root
users_find_empty_passwords

kernel_harden_sysctl
kernel_disable_ipv6_if_requested
kernel_login_defs
pam_configure_password_quality
pam_configure_lockout

filesystem_harden_permissions
filesystem_secure_cron
filesystem_secure_rc_local
filesystem_login_banner
filesystem_disable_removable_media
filesystem_remove_media_files
filesystem_scan_for_anomalies

monitoring_install_tools
monitoring_update_signatures
monitoring_run_baseline_scan

forensics_collect_baseline

log_info "=== Hardening run complete ==="
log_info "Log:       $LOG_FILE"
log_info "Backups:   $BACKUP_DIR"
log_info "Baseline:  $ARTIFACT_DIR"
log_info "Review the log for any WARN entries before considering the system ready."

if confirm "Reboot now to apply all changes?" "no"; then
    run "reboot system" shutdown -r now
fi
