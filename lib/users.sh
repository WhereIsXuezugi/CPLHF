#!/usr/bin/env bash
# lib/users.sh
#
# Interactive account review: privilege assignment, password policy,
# and detection of anomalies (hidden UID 0 accounts, empty passwords).
#
# References:
#   - CIS Ubuntu Linux Benchmark, section 5 "Access, Authentication and
#     Authorization" and section 6.2 "User and Group Settings"
#   - NIST SP 800-53 Rev. 5, IA-5 (Authenticator Management), AC-6 (Least
#     Privilege) (https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)

# The competition-standard placeholder password. This exists because
# CyberPatriot images are scored by an automated checker that expects
# accounts to have a policy-compliant password, not because a shared
# static password is good practice on a real production system.
#
# CHANGE THIS before using the script outside of a training environment,
# or override it with the HARDEN_DEFAULT_PASSWORD environment variable.
DEFAULT_PASSWORD="${HARDEN_DEFAULT_PASSWORD:-ChangeMe!2024}"

_apply_password_policy() {
    local user="$1"
    # Max age 90 days, min age 1 day, warn 7 days before expiry.
    # Matches CIS recommendations 5.4.1.1-5.4.1.4.
    run "set password aging for $user" chage --maxdays 90 --mindays 1 --warndays 7 "$user"
}

# Sets a password non-interactively via chpasswd rather than piping into
# `passwd`. `passwd` expects to read its confirmation prompt from a TTY on
# some PAM configurations and can hang instead of failing cleanly when run
# from a script -- exactly the kind of stall you cannot afford with a
# competition clock running. chpasswd has no such ambiguity.
_set_password() {
    local user="$1" pass="$2"
    printf '%s:%s\n' "$user" "$pass" | run "set password for $user" chpasswd
}

users_review_existing() {
    log_info "=== User account review ==="
    echo "Enter existing account names to review (space separated), or press Enter to skip:"
    read -r -a review_users || true

    for user in "${review_users[@]:-}"; do
        if [ -z "$user" ]; then continue; fi
        if ! id "$user" &>/dev/null; then
            log_warn "user not found: $user"
            continue
        fi

        if confirm "Delete user '$user'?" "no"; then
            if [ "$user" = "${SUDO_USER:-}" ] || [ "$user" = "$(whoami)" ]; then
                log_warn "refusing to delete the current operator account ($user)"
            else
                run "delete user $user" userdel -r "$user"
            fi
            continue
        fi

        if confirm "Should '$user' have administrator rights?" "no"; then
            run "grant admin groups to $user" usermod -aG sudo,adm,lpadmin "$user"
        else
            for grp in sudo adm lpadmin sambashare; do
                if getent group "$grp" >/dev/null 2>&1; then
                    gpasswd -d "$user" "$grp" >/dev/null 2>&1 || true
                fi
            done
            log_ok "ensured $user is a standard (non-admin) user"
        fi

        if confirm "Set a custom password for '$user'?" "no"; then
            read -r -s -p "New password for $user: " user_pass || user_pass=""; echo
            _set_password "$user" "$user_pass"
        else
            _set_password "$user" "$DEFAULT_PASSWORD"
        fi

        _apply_password_policy "$user"
    done
}

users_create_new() {
    if ! confirm "Create any new user accounts?" "no"; then
        return 0
    fi
    echo "Enter new account names (space separated):"
    read -r -a new_users || true
    for user in "${new_users[@]:-}"; do
        if [ -z "$user" ]; then continue; fi
        if id "$user" &>/dev/null; then
            log_warn "user already exists, skipping creation: $user"
            continue
        fi
        run "create user $user" adduser --gecos "" --disabled-password "$user"
        _set_password "$user" "$DEFAULT_PASSWORD"
        _apply_password_policy "$user"
    done
}

# Detects accounts other than 'root' that share UID 0. A second UID-0
# account is a classic backdoor technique, so we flag it loudly and
# disable it rather than silently deleting a possibly-legitimate account.
users_find_hidden_root() {
    log_info "=== Scanning for hidden UID 0 accounts ==="
    local hidden
    hidden=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd || true)
    if [ -z "$hidden" ]; then
        log_ok "no hidden UID 0 accounts found"
        return 0
    fi
    log_warn "hidden UID 0 accounts found: $hidden"
    while read -r acct; do
        if [ -z "$acct" ]; then continue; fi
        run "lock hidden root account $acct" passwd -l "$acct"
        log_warn "review /etc/passwd manually and remove $acct if it is not authorized"
    done <<< "$hidden"
}

# Locks any account with an empty password field in /etc/shadow.
users_find_empty_passwords() {
    log_info "=== Scanning for accounts with empty passwords ==="
    local empty
    empty=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null || true)
    if [ -z "$empty" ]; then
        log_ok "no accounts with empty passwords found"
        return 0
    fi
    log_warn "accounts with empty passwords: $empty"
    while read -r acct; do
        if [ -z "$acct" ]; then continue; fi
        run "lock empty-password account $acct" passwd -l "$acct"
    done <<< "$empty"
}
