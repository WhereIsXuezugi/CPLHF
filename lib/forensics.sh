#!/usr/bin/env bash
# lib/forensics.sh
#
# Captures a point-in-time system baseline (users, processes, listening
# ports, installed packages, firewall state) so a later run -- or a human
# reviewer -- can diff behavior over time. Purely read-only.

forensics_collect_baseline() {
    log_info "=== Collecting system baseline for later comparison ==="
    if [ "${DRY_RUN:-0}" = "1" ]; then
        log_info "DRY-RUN: would write baseline artifacts to $ARTIFACT_DIR"
        return 0
    fi

    {
        uname -a
        echo "---"
        cat /etc/os-release 2>/dev/null
    } > "$ARTIFACT_DIR/system_info.txt"

    getent passwd > "$ARTIFACT_DIR/all_users.txt"
    getent group  > "$ARTIFACT_DIR/all_groups.txt"
    lastlog       > "$ARTIFACT_DIR/last_logins.txt" 2>/dev/null || true
    ps aux        > "$ARTIFACT_DIR/processes.txt"

    systemctl list-unit-files --type=service > "$ARTIFACT_DIR/services.txt" 2>/dev/null || true
    ss -tuln > "$ARTIFACT_DIR/listening_ports.txt" 2>/dev/null || true

    dpkg -l > "$ARTIFACT_DIR/installed_packages.txt" 2>/dev/null || true
    apt-mark showmanual > "$ARTIFACT_DIR/manually_installed_packages.txt" 2>/dev/null || true

    ufw status verbose > "$ARTIFACT_DIR/ufw_status.txt" 2>/dev/null || true
    if [ -f /etc/ssh/sshd_config ]; then
        cp /etc/ssh/sshd_config "$ARTIFACT_DIR/sshd_config.snapshot"
    fi

    log_ok "baseline written to $ARTIFACT_DIR"
}
