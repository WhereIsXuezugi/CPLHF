#!/usr/bin/env bash
# lib/packages.sh
#
# System update and package hygiene.
#
# References:
#   - CIS Ubuntu Linux Benchmark, section 1 "Initial Setup" and section 3
#     "Service Uninstallation" (https://www.cisecurity.org/benchmark/ubuntu_linux)
#   - NIST SP 800-53 Rev. 5, SI-2 (Flaw Remediation), CM-7 (Least Functionality)
#     (https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)

# Packages that provide offensive-security or exploitation capability with
# essentially no legitimate reason to be on a general-purpose competition
# image. These are purged automatically (still logged, never silent).
readonly ALWAYS_REMOVE_PACKAGES=(
    john john-data hydra hydra-gtk aircrack-ng ophcrack ophcrack-cli
    fcrackzip lcrack pdfcrack pyrit rarcrack sipcrack irpas logkeys
    medusa truecrack cryptcat
)

# Dual-use packages: legitimate for network administration, but also
# common attacker tooling, and occasionally required by a specific
# competition image's stated role (e.g. a box whose job is to monitor
# traffic). These are only purged after an explicit per-package
# confirmation (or with --auto-approve), so the script never silently
# breaks a machine's actual job.
readonly REVIEW_BEFORE_REMOVE_PACKAGES=(
    nmap zenmap wireshark tcpdump nikto
    netcat netcat-openbsd netcat-traditional ncat pnetcat socat sbd
)

# Remote-access and legacy protocol daemons that are rarely required on a
# hardened workstation/server and are frequently flagged by CyberPatriot
# scoring images when present without justification.
readonly LEGACY_SERVICE_PACKAGES=(
    tightvncserver x11vnc vnc4server vncsnapshot
    nfs-kernel-server nfs-common portmap rpcbind autofs
    xinetd openbsd-inetd inetutils-telnetd telnetd
    snmp
)

readonly GAME_PACKAGES=(
    aisleriot gnome-mahjongg gnome-mines gnome-sudoku
    gnome-chess supertux supertuxkart
)

packages_update_system() {
    log_info "=== Package management: updating system ==="
    export DEBIAN_FRONTEND=noninteractive
    run "refresh package lists" apt-get update -y
    run "upgrade installed packages" apt-get -y upgrade
    run "fix broken dependencies" apt-get -y install -f
    run "remove orphaned packages" apt-get -y autoremove --purge
    run "clean package cache" apt-get -y autoclean

    # Unattended-upgrades keeps the box patched between competition rounds.
    # NIST SP 800-53 SI-2(5) recommends automated flaw remediation.
    if [ "${DRY_RUN:-0}" != "1" ]; then
        cat > /etc/apt/apt.conf.d/10periodic <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
        log_ok "configured unattended-upgrades (10periodic)"
    else
        log_info "DRY-RUN: would write /etc/apt/apt.conf.d/10periodic"
    fi
}

# Remove a list of packages, but only after confirming with the operator
# unless AUTO_APPROVE=1 is set. Interactive confirmation matters here: a
# server build might legitimately need nmap or netcat for its role, so we
# never purge silently.
_purge_if_present() {
    local pkg="$1"
    if ! dpkg-query -W -f='${Status}\n' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        return 0
    fi
    if [ "${AUTO_APPROVE:-0}" = "1" ] || confirm "Package '$pkg' is installed and is commonly flagged as a risk. Purge it?" "yes"; then
        run "purge $pkg" apt-get -y purge "$pkg"
    else
        log_info "kept $pkg at operator's request"
    fi
}

# Purges a package without prompting -- used only for the
# ALWAYS_REMOVE_PACKAGES list, where there is no realistic scenario in
# which a competition image legitimately needs the tool.
_purge_silently_if_present() {
    local pkg="$1"
    if dpkg-query -W -f='${Status}\n' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        run "purge $pkg" apt-get -y purge "$pkg"
    fi
}

packages_remove_offensive_tools() {
    log_info "=== Removing unambiguous offensive-security tooling ==="
    for pkg in "${ALWAYS_REMOVE_PACKAGES[@]}"; do
        _purge_silently_if_present "$pkg"
    done

    log_info "=== Reviewing legacy services ==="
    for pkg in "${LEGACY_SERVICE_PACKAGES[@]}"; do
        _purge_if_present "$pkg"
    done

    log_info "=== Reviewing dual-use network tools (nmap, wireshark, netcat, ...) ==="
    log_info "These are legitimate admin tools that are also common attacker tools;"
    log_info "keep them only if this machine's stated role actually needs them."
    for pkg in "${REVIEW_BEFORE_REMOVE_PACKAGES[@]}"; do
        _purge_if_present "$pkg"
    done
}

packages_remove_games() {
    log_info "=== Removing bundled desktop games ==="
    for pkg in "${GAME_PACKAGES[@]}"; do
        if dpkg-query -W -f='${Status}\n' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
            run "purge $pkg" apt-get -y purge "$pkg"
        fi
    done
}
