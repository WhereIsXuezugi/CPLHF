#!/usr/bin/env bash
# lib/pam.sh
#
# Password quality, history, and account lockout via PAM. Configuration is
# appended to the pam-auth-update managed stack rather than replacing it
# outright, which avoids breaking distro-specific modules that later
# `apt` upgrades may add.
#
# References:
#   - CIS Ubuntu Linux Benchmark section 5.3 "Configure PAM"
#   - NIST SP 800-53 Rev. 5, IA-5(1) (Password-Based Authentication)

pam_configure_password_quality() {
    log_info "=== Configuring PAM password quality and history ==="
    run "install libpam-pwquality" apt-get -y install libpam-pwquality
    backup_file /etc/pam.d/common-password

    if [ "${DRY_RUN:-0}" = "1" ]; then
        log_info "DRY-RUN: would ensure pam_pwquality/pam_pwhistory lines in common-password"
        return 0
    fi

    # retry=3, 12-char minimum, at least 3 character classes different
    # from the previous password, one of each character class required.
    #
    # Recent Ubuntu releases ship a minimal, unconfigured pam_pwquality.so
    # line in common-password by default (just "retry=3", no length or
    # complexity requirements). A plain "does this line already exist"
    # check would treat that stub as "already hardened" and never
    # strengthen it, so a pre-existing line is replaced in place with our
    # full policy rather than being left alone or duplicated.
    local pwquality_line='password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1'
    if grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
        sed -i "\\|pam_pwquality.so|c\\${pwquality_line}" /etc/pam.d/common-password
        log_ok "replaced existing pam_pwquality.so line with the hardened policy"
    else
        sed -i "/pam_unix.so/i ${pwquality_line}" /etc/pam.d/common-password
        log_ok "added pam_pwquality policy"
    fi

    local pwhistory_line='password requisite pam_pwhistory.so use_authtok remember=5'
    if grep -q "pam_pwhistory.so" /etc/pam.d/common-password; then
        sed -i "\\|pam_pwhistory.so|c\\${pwhistory_line}" /etc/pam.d/common-password
        log_ok "replaced existing pam_pwhistory.so line with the hardened policy"
    else
        sed -i "/pam_unix.so/i ${pwhistory_line}" /etc/pam.d/common-password
        log_ok "added pam_pwhistory policy (remember=5)"
    fi
}

pam_configure_lockout() {
    log_info "=== Configuring account lockout on repeated auth failures ==="
    backup_file /etc/pam.d/common-auth
    ensure_line_in_file \
        "auth required pam_faillock.so preauth silent deny=5 unlock_time=1800" \
        /etc/pam.d/common-auth
}

kernel_login_defs() {
    log_info "=== Applying login.defs password aging defaults ==="
    backup_file /etc/login.defs
    if [ "${DRY_RUN:-0}" = "1" ]; then
        log_info "DRY-RUN: would edit /etc/login.defs"
        return 0
    fi
    sed -i 's/^\s*PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/'  /etc/login.defs
    sed -i 's/^\s*PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/'   /etc/login.defs
    sed -i 's/^\s*PASS_WARN_AGE.*/PASS_WARN_AGE\t7/'   /etc/login.defs
    log_ok "updated PASS_MAX_DAYS / PASS_MIN_DAYS / PASS_WARN_AGE"
}
