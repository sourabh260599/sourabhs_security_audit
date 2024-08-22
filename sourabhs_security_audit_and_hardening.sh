#!/bin/bash

# Configuration
LOG_FILE="/var/log/sourabhs_security_audit.log"
EMAIL_RECIPIENT="souravlondhe007@gmail.com"
EXCLUDED_DIRS="/proc /sys /dev /run /mnt"

# Helper function for logging
log() {
    echo "$1" | tee -a "$LOG_FILE"
}

# User and Group Audits
user_and_group_audits() {
    log "User and Group Audits:"
    
    log "Listing all users:"
    cut -d: -f1 /etc/passwd | tee -a "$LOG_FILE"
    
    log "Listing all groups:"
    cut -d: -f1 /etc/group | tee -a "$LOG_FILE"
    
    log "Users with UID 0:"
    awk -F: '$3 == 0 {print $1}' /etc/passwd | tee -a "$LOG_FILE"
    
    log "Users without passwords:"
    awk -F: '($2 == "" || $2 == "*") {print $1}' /etc/shadow | tee -a "$LOG_FILE"
}

# File and Directory Permissions
file_and_directory_permissions() {
    log "File and Directory Permissions:"
    
    log "World-writable files and directories:"
    find / -xdev \( -type f -o -type d \) -perm -002 -print 2>/dev/null | tee -a "$LOG_FILE"
    
    log ".ssh directory permissions:"
    find / -type d -name ".ssh" -exec ls -ld {} \; 2>/dev/null | tee -a "$LOG_FILE"
    
    log "Files with SUID or SGID bits set:"
    find / -perm /6000 -type f -exec ls -l {} \; 2>/dev/null | tee -a "$LOG_FILE"
}

# Service Audits
service_audits() {
    log "Service Audits:"
    
    log "Running services:"
    systemctl list-units --type=service --state=running | tee -a "$LOG_FILE"
    
    log "Checking sshd service:"
    systemctl status sshd | tee -a "$LOG_FILE"
    
    log "Checking iptables service:"
    systemctl status netfilter-persistent | tee -a "$LOG_FILE"
    
    log "Services listening on non-standard ports:"
    ss -tuln | grep -vE '(:22|:80|:443)' | tee -a "$LOG_FILE"
}

# Firewall and Network Security
firewall_and_network_security() {
    log "Firewall and Network Security:"
    
    log "Firewall status:"
    ufw status verbose | tee -a "$LOG_FILE"
    
    log "Open ports:"
    ss -tuln | tee -a "$LOG_FILE"
    
    log "IP forwarding status:"
    sysctl net.ipv4.ip_forward | tee -a "$LOG_FILE"
}

# IP and Network Configuration Checks
ip_and_network_configuration() {
    log "IP and Network Configuration Checks:"
    
    log "IP addresses and types:"
    ip addr show | grep inet | tee -a "$LOG_FILE"
}

# Security Updates and Patching
security_updates_and_patching() {
    log "Security Updates and Patching:"
    
    log "Checking for security updates:"
    apt list --upgradable | tee -a "$LOG_FILE"
    
    log "Configuring unattended-upgrades..."
    apt install -y unattended-upgrades
    dpkg-reconfigure --priority=low unattended-upgrades | tee -a "$LOG_FILE"
}

# Log Monitoring
log_monitoring() {
    log "Log Monitoring:"
    
    log "Recent SSH login attempts:"
    grep "Failed password" /var/log/auth.log | tee -a "$LOG_FILE"
}

# Server Hardening Steps
server_hardening_steps() {
    log "Server Hardening Steps:"
    
    log "Implementing SSH key-based authentication..."
    sed -i 's/^PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    systemctl restart sshd
    
    log "Disabling IPv6..."
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p
    
    log "Setting GRUB password..."
    # Implementation required for your specific GRUB configuration
    
    log "Configuring iptables rules..."
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables-save > /etc/iptables/rules.v4
}

# Reporting and Alerting
reporting_and_alerting() {
    log "Reporting and Alerting:"
    
    log "Generating summary report..."
    # Implementation for summary report generation
    
    log "Sending email alerts..."
    echo "Critical issue found" | mail -s "Security Alert" "$EMAIL_RECIPIENT"
}

# Main Script Execution
main() {
    log "Starting Sourabh's security audit and hardening process..."
    
    user_and_group_audits
    file_and_directory_permissions
    service_audits
    firewall_and_network_security
    ip_and_network_configuration
    security_updates_and_patching
    log_monitoring
    server_hardening_steps
    reporting_and_alerting
    
    log "Sourabh's security audit and hardening process completed."
}

main
