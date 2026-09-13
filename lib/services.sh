#!/usr/bin/env bash
# lib/services.sh
#
# Every optional network service follows the same pattern: if the machine's
# role does not require it, purge the package and deny the port; if it does,
# install it, allow the port, and apply a minimal hardening pass. Driven by
# the WANT_* variables set in bin/harden.sh (interactively or from an env
# file -- see examples/config.env.example).
#
# Reference: CIS Ubuntu Linux Benchmark section 2 "Services" -- "Ensure
# only approved services are enabled" and NIST SP 800-53 CM-7(1) (Least
# Functionality: Periodic Review).

services_configure_samba() {
    if [ "$WANT_SAMBA" != "yes" ]; then
        run "deny samba ports" ufw deny netbios-ns
        run "purge samba" apt-get -y purge samba samba-common samba-common-bin
        return 0
    fi
    run "allow samba ports" ufw allow netbios-ns
    run "allow samba data port" ufw allow microsoft-ds
    run "install samba" apt-get -y install samba
    backup_file /etc/samba/smb.conf
    log_info "samba installed; review /etc/samba/smb.conf shares manually before use"
}

services_configure_ftp() {
    if [ "$WANT_FTP" != "yes" ]; then
        run "deny ftp ports" ufw deny ftp
        run "purge vsftpd" apt-get -y purge vsftpd
        return 0
    fi
    run "allow ftp ports" ufw allow ftp
    run "install vsftpd" apt-get -y install vsftpd
    backup_file /etc/vsftpd.conf
    ensure_line_in_file "anonymous_enable=NO" /etc/vsftpd.conf
    ensure_line_in_file "ssl_enable=YES" /etc/vsftpd.conf
    run "restart vsftpd" systemctl restart vsftpd
}

services_configure_telnet() {
    if [ "$WANT_TELNET" != "yes" ]; then
        run "deny telnet port" ufw deny telnet
        run "purge telnet daemon" apt-get -y purge telnetd inetutils-telnetd
        return 0
    fi
    log_warn "Telnet transmits credentials in cleartext. Allowing it should require an explicit competition/scoring requirement."
    run "allow telnet port" ufw allow telnet
}

services_configure_mail() {
    if [ "$WANT_MAIL" != "yes" ]; then
        run "deny mail ports" ufw deny smtp
        run "deny imap/pop ports" ufw deny imap
        return 0
    fi
    run "allow smtp" ufw allow smtp
    run "allow imaps" ufw allow imaps
    run "allow pop3s" ufw allow pop3s
}

services_configure_printing() {
    if [ "$WANT_PRINTING" != "yes" ]; then
        run "deny printing ports" ufw deny ipp
        return 0
    fi
    run "allow printing ports" ufw allow ipp
}

services_configure_mysql() {
    if [ "$WANT_MYSQL" != "yes" ]; then
        run "deny mysql port" ufw deny mysql
        run "purge mysql-server" apt-get -y purge mysql-server mariadb-server
        return 0
    fi
    run "allow mysql port" ufw allow mysql
    run "install mysql-server" apt-get -y install mysql-server
    backup_file /etc/mysql/my.cnf
    if [ -f /etc/mysql/my.cnf ] && [ "${DRY_RUN:-0}" != "1" ]; then
        if grep -q "^bind-address" /etc/mysql/my.cnf; then
            sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/my.cnf
        else
            echo "bind-address = 127.0.0.1" >> /etc/mysql/my.cnf
        fi
        log_ok "bound MySQL to localhost only"
    fi
    run "restart mysql" systemctl restart mysql
}

services_configure_http() {
    if [ "$WANT_HTTP" != "yes" ]; then
        run "deny http" ufw deny http
        run "deny https" ufw deny https
        run "purge apache2" apt-get -y purge apache2
        return 0
    fi
    run "allow http" ufw allow http
    run "allow https" ufw allow https
    run "install apache2" apt-get -y install apache2
    backup_file /etc/apache2/apache2.conf
    ensure_line_in_file "ServerTokens Prod" /etc/apache2/apache2.conf
    ensure_line_in_file "ServerSignature Off" /etc/apache2/apache2.conf
    ensure_block_in_file "HARDENING-DENY-ROOT-DIR" /etc/apache2/apache2.conf <<'EOF'
<Directory />
    AllowOverride None
    Require all denied
</Directory>
EOF
    run "restart apache2" systemctl restart apache2
}

services_configure_dns() {
    if [ "$WANT_DNS" != "yes" ]; then
        run "deny dns port" ufw deny domain
        run "purge bind9" apt-get -y purge bind9
        return 0
    fi
    run "allow dns port" ufw allow domain
}
