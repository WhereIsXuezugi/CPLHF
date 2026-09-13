#!/usr/bin/env bash
# lib/monitoring.sh
#
# Installs and enables host-based detection tooling: fail2ban for
# brute-force protection, auditd for kernel-level audit logging, and
# rkhunter/chkrootkit for rootkit/anomaly scanning.
#
# References:
#   - fail2ban: https://github.com/fail2ban/fail2ban
#   - Linux Audit (auditd): https://github.com/linux-audit/audit-userspace
#   - rkhunter: https://rkhunter.sourceforge.net/
#   - chkrootkit: https://www.chkrootkit.org/
#   - Lynis (recommended as a follow-up audit, not run automatically here):
#     https://github.com/CISOfy/lynis
#   - NIST SP 800-53 Rev. 5, SI-4 (System Monitoring), AU-2 (Event Logging)

monitoring_install_tools() {
    log_info "=== Installing intrusion detection and audit tooling ==="
    run "install fail2ban" apt-get -y install fail2ban
    run "install auditd" apt-get -y install auditd
    run "install rkhunter" apt-get -y install rkhunter
    run "install chkrootkit" apt-get -y install chkrootkit

    run "enable fail2ban" systemctl enable --now fail2ban
    run "enable auditd" systemctl enable --now auditd

    # ClamAV is a full antivirus engine with a multi-hundred-megabyte
    # signature database. Installing and updating it can take longer than
    # every other step in this script combined on a slow connection, which
    # is a bad trade during a timed round unless your scoring checklist
    # specifically calls for it. Opt in with INSTALL_CLAMAV=yes.
    if [ "${INSTALL_CLAMAV:-no}" = "yes" ]; then
        run "install clamav" apt-get -y install clamav
    else
        log_info "skipping ClamAV install (set INSTALL_CLAMAV=yes to enable)"
    fi
}

monitoring_update_signatures() {
    log_info "=== Updating detection signatures ==="
    if command -v freshclam >/dev/null 2>&1; then
        run "update ClamAV signatures" freshclam
    fi
    if command -v rkhunter >/dev/null 2>&1; then
        run "update rkhunter signatures" rkhunter --update
    fi
}

# Runs quick, non-interactive scans and appends results to the main log.
# These are advisory: a hit here means "go look at this", not "the script
# already fixed it", because automated remediation of rootkit findings is
# unsafe to do unattended. Skipped by default -- rkhunter's filesystem
# properties check alone can run several minutes -- since it does not
# change system state and can always be run later with time to spare.
# Opt in with RUN_BASELINE_SCAN=yes.
monitoring_run_baseline_scan() {
    if [ "${RUN_BASELINE_SCAN:-no}" != "yes" ]; then
        log_info "skipping rkhunter/chkrootkit baseline scan (set RUN_BASELINE_SCAN=yes to enable)"
        return 0
    fi
    log_info "=== Running baseline rootkit/anomaly scan (advisory only) ==="
    if [ "${DRY_RUN:-0}" = "1" ]; then
        log_info "DRY-RUN: would run rkhunter --check and chkrootkit"
        return 0
    fi
    if command -v rkhunter >/dev/null 2>&1; then
        rkhunter --check --sk --rwo >> "$LOG_FILE" 2>&1 || true
    fi
    if command -v chkrootkit >/dev/null 2>&1; then
        chkrootkit >> "$LOG_FILE" 2>&1 || true
    fi
    log_ok "baseline scan complete; review $LOG_FILE for findings"
}
