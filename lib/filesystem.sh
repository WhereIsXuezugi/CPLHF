#!/usr/bin/env bash
# lib/filesystem.sh
#
# File permissions, startup script hygiene, cron/at restriction, and
# read-only reconnaissance of the filesystem for common misconfigurations
# (SUID/SGID binaries, world-writable files, unowned files). This module
# never deletes anything outside of an operator-confirmed media sweep --
# everything else is reported to a log for manual review.
#
# References:
#   - CIS Ubuntu Linux Benchmark section 6.1 "System File Permissions"
#   - NIST SP 800-53 Rev. 5, AC-6 (Least Privilege), CM-6 (Configuration
#     Settings)

filesystem_harden_permissions() {
    log_info "=== Hardening core file permissions ==="
    safe_chmod 640 /etc/shadow
    safe_chmod 644 /etc/passwd
    safe_chmod 644 /etc/group
    safe_chmod 644 /etc/apt/sources.list

    for home_dir in /home/*; do
        [ -d "$home_dir" ] || continue
        safe_chmod 750 "$home_dir"
        if [ -f "$home_dir/.bash_history" ]; then
            safe_chmod 600 "$home_dir/.bash_history"
        fi
    done
    safe_chmod 700 /root
    if [ -f /root/.bash_history ]; then
        safe_chmod 600 /root/.bash_history
    fi
}

filesystem_secure_cron() {
    log_info "=== Restricting cron/at to root ==="
    if [ "${DRY_RUN:-0}" != "1" ]; then
        printf 'root\n' > /etc/cron.allow
        printf 'root\n' > /etc/at.allow
    fi
    safe_chmod 600 /etc/cron.allow
    safe_chmod 600 /etc/at.allow
}

filesystem_secure_rc_local() {
    log_info "=== Resetting /etc/rc.local to a minimal, auditable state ==="
    backup_file /etc/rc.local
    if [ "${DRY_RUN:-0}" != "1" ]; then
        cat > /etc/rc.local <<'EOF'
#!/bin/sh -e
# Intentionally minimal. Review docs/security-controls.md before adding
# anything here -- rc.local runs as root at boot with no logging by default.
exit 0
EOF
        chmod +x /etc/rc.local
    fi
}

filesystem_login_banner() {
    log_info "=== Installing legal login banners ==="
    local banner="Unauthorized access to this system is prohibited. All activity is logged and monitored."
    if [ "${DRY_RUN:-0}" != "1" ]; then
        printf '%s\n' "$banner" > /etc/issue
        printf '%s\n' "$banner" > /etc/issue.net
    fi
    log_ok "wrote /etc/issue and /etc/issue.net"
}

# Blocks USB mass storage / FireWire / Thunderbolt at the module level.
# This maps to physical-access controls (CIS 1.1.23-1.1.24) and is most
# relevant on lab machines where removable media is a documented risk.
filesystem_disable_removable_media() {
    [ "${DISABLE_REMOVABLE_MEDIA:-no}" = "yes" ] || return 0
    log_info "=== Disabling removable-media kernel modules ==="
    ensure_line_in_file "install usb-storage /bin/true" /etc/modprobe.d/disable-usb-storage.conf
    ensure_line_in_file "install firewire-core /bin/true" /etc/modprobe.d/disable-firewire.conf
    ensure_line_in_file "install thunderbolt /bin/true" /etc/modprobe.d/disable-thunderbolt.conf
}

# Deletes common media file types under /home, but only after an explicit,
# typed confirmation -- this is a destructive, irreversible action so it
# gets a higher bar than the yes/no confirm() helper used elsewhere.
filesystem_remove_media_files() {
    if [ "$ALLOW_MEDIA_FILES" = "yes" ]; then
        return 0
    fi
    log_info "=== Media files are disallowed by policy for this build ==="
    echo "Type DELETE to permanently remove media files under /home, or press Enter to skip:"
    read -r confirm_media || confirm_media=""
    if [ "$confirm_media" != "DELETE" ]; then
        log_info "media file removal skipped by operator"
        return 0
    fi
    local patterns=(
        "*.mp3" "*.wav" "*.flac" "*.m4a" "*.ogg"
        "*.mp4" "*.avi" "*.mov" "*.mkv" "*.flv"
        "*.jpg" "*.jpeg" "*.png" "*.gif" "*.bmp"
    )
    local find_args=()
    for p in "${patterns[@]}"; do
        find_args+=(-iname "$p" -o)
    done
    unset 'find_args[${#find_args[@]}-1]' # drop trailing -o

    if [ "${DRY_RUN:-0}" = "1" ]; then
        log_info "DRY-RUN: would delete matching media files under /home"
        return 0
    fi
    find /home -xdev -type f \( "${find_args[@]}" \) -print -delete >> "$LOG_FILE" 2>/dev/null
    log_ok "removed media files under /home (see $LOG_FILE for the list)"
}

# Read-only reconnaissance -- results go to $ARTIFACT_DIR for manual triage,
# nothing here modifies the system.
filesystem_scan_for_anomalies() {
    log_info "=== Scanning for SUID/SGID, world-writable, and unowned files ==="
    if [ "${DRY_RUN:-0}" = "1" ]; then
        log_info "DRY-RUN: would write scan results to $ARTIFACT_DIR"
        return 0
    fi
    find / -xdev -type f -perm /6000 > "$ARTIFACT_DIR/suid_sgid_files.txt" 2>/dev/null
    find / -xdev -type f -perm -o+w > "$ARTIFACT_DIR/world_writable_files.txt" 2>/dev/null
    find / -xdev \( -nouser -o -nogroup \) > "$ARTIFACT_DIR/unowned_files.txt" 2>/dev/null
    find / -xdev -type f -name "*.php" > "$ARTIFACT_DIR/php_files.txt" 2>/dev/null
    log_ok "scan results written to $ARTIFACT_DIR"
}
