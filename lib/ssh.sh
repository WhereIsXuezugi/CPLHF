#!/usr/bin/env bash
# lib/ssh.sh
#
# SSH is either removed entirely or hardened to current best practice
# (key-based auth, modern ciphers, no root login).
#
# References:
#   - CIS Ubuntu Linux Benchmark, section 5.1 "Configure SSH Server"
#   - Mozilla OpenSSH modern configuration guidelines
#     (https://infosec.mozilla.org/guidelines/openssh)
#   - NIST SP 800-53 Rev. 5, AC-17 (Remote Access), IA-2 (Identification
#     and Authentication)

ssh_configure() {
    if [ "$WANT_SSH" != "yes" ]; then
        log_info "=== SSH not required: removing ==="
        run "deny ssh in firewall" ufw deny ssh
        run "purge openssh-server" apt-get -y purge openssh-server
        return 0
    fi

    log_info "=== SSH required: installing and hardening ==="
    run "install openssh-server" apt-get -y install openssh-server
    run "allow ssh in firewall" ufw allow ssh
    backup_file /etc/ssh/sshd_config

    # Password auth defaults to ON. This is a deliberate, competition-tested
    # choice, not an oversight: disabling it before your team has actually
    # provisioned SSH keys turns a hardening step into a self-inflicted
    # lockout. Set SSH_PASSWORD_AUTH=no in your config file once keys are
    # in place if you want the stricter, keys-only posture.
    local password_auth="${SSH_PASSWORD_AUTH:-yes}"

    if [ "${DRY_RUN:-0}" != "1" ]; then
        cat > /etc/ssh/sshd_config <<EOF
# Managed by lib/ssh.sh -- see docs/security-controls.md for rationale.
Protocol 2
Port 22

PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 2

PubkeyAuthentication yes
PasswordAuthentication ${password_auth}
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2

LogLevel VERBOSE
SyslogFacility AUTH
EOF
        log_ok "wrote hardened /etc/ssh/sshd_config (PasswordAuthentication ${password_auth})"
    else
        log_info "DRY-RUN: would write hardened /etc/ssh/sshd_config (PasswordAuthentication ${password_auth})"
    fi

    # Restrict logins to an explicit allow-list if the operator supplied one.
    if [ -n "${SSH_ALLOWED_USERS:-}" ] && [ "${DRY_RUN:-0}" != "1" ]; then
        sed -i '/^AllowUsers/d' /etc/ssh/sshd_config
        printf 'AllowUsers %s\n' "$SSH_ALLOWED_USERS" >> /etc/ssh/sshd_config
        log_ok "restricted SSH logins to: $SSH_ALLOWED_USERS"
    fi

    if [ "${DRY_RUN:-0}" != "1" ] && command -v sshd >/dev/null 2>&1; then
        if sshd -t; then
            run "restart sshd" systemctl restart ssh
        else
            log_error "sshd_config failed validation (sshd -t); leaving service untouched. Inspect /etc/ssh/sshd_config."
        fi
    fi
}
