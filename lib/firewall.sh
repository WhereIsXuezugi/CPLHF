#!/usr/bin/env bash
# lib/firewall.sh
#
# Establishes a default-deny inbound posture with UFW, then lets each
# service module (lib/services.sh, lib/ssh.sh) open the specific ports it
# needs. This module only sets defaults and blocks a couple of ports
# commonly abused in the competition threat model (e.g. 1337).
#
# Reference: CIS Ubuntu Linux Benchmark section 4 "Firewall Configuration";
# NIST SP 800-53 Rev. 5 SC-7 (Boundary Protection).

firewall_set_defaults() {
    log_info "=== Firewall: applying default-deny posture ==="
    log_info "If this image reports to a scoring engine or monitoring agent"
    log_info "over the network, confirm its traffic survives this step --"
    log_info "outbound stays open by default, but review $ARTIFACT_DIR/listening_ports.txt"
    log_info "from a prior run if you are unsure what is actually listening."
    run "install ufw" apt-get -y install ufw
    run "default deny incoming" ufw default deny incoming
    run "default allow outgoing" ufw default allow outgoing
    run "deny known backdoor port 1337" ufw deny 1337
    run "enable ufw" ufw --force enable
}

firewall_status() {
    if [ "${DRY_RUN:-0}" = "1" ]; then
        log_info "DRY-RUN: would print ufw status"
        return 0
    fi
    ufw status verbose | tee -a "$LOG_FILE"
}
