#!/usr/bin/env bash
# lib/kernel.sh
#
# Kernel and network-stack hardening via sysctl. Values are drawn from the
# CIS Ubuntu Linux Benchmark section 3 "Network Configuration" and the
# kernel self-protection guidance in the Linux Kernel Security documentation
# (https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html).

kernel_harden_sysctl() {
    log_info "=== Applying kernel and network sysctl hardening ==="
    backup_file /etc/sysctl.conf

    ensure_block_in_file "HARDENING-SYSCTL" /etc/sysctl.conf <<'EOF'
# --- Network hardening ---
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.tcp_synack_retries=2

# --- Kernel self-protection ---
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.yama.ptrace_scope=1
kernel.randomize_va_space=2
fs.suid_dumpable=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.protected_fifos=2
fs.protected_regular=2
EOF

    run "reload sysctl" sysctl -p
}

# IPv6 disablement is optional: many networks (including some CyberPatriot
# images) rely on it, so this is only applied when explicitly requested.
kernel_disable_ipv6_if_requested() {
    [ "${DISABLE_IPV6:-no}" = "yes" ] || return 0
    ensure_block_in_file "HARDENING-DISABLE-IPV6" /etc/sysctl.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
EOF
    run "reload sysctl (ipv6)" sysctl -p
}
