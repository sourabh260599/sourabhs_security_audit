# Sourabh's Security Audit and Hardening Script

## Overview

`Sourabh's Security Audit and Hardening Script` is designed to automate security audits and hardening for Linux servers. It performs various security checks, validates configurations, and applies hardening measures to ensure server security.

## Features

- **User and Group Audits**: List all users and groups, check for root users, and identify users without passwords.
- **File and Directory Permissions**: Detect world-writable files and directories, check `.ssh` directory permissions, and identify files with SUID/SGID bits.
- **Service Audits**: List running services, verify critical services, and check for non-standard ports.
- **Firewall and Network Security**: Check firewall status, open ports, and IP forwarding.
- **IP and Network Configuration**: Identify public vs. private IP addresses and ensure sensitive services are secured.
- **Security Updates and Patching**: Check for available updates and configure automatic updates.
- **Log Monitoring**: Review logs for suspicious entries.
- **Server Hardening**: Implement SSH key-based authentication, disable IPv6, and configure iptables.
- **Reporting and Alerting**: Generate reports and send alerts for critical issues.

## Audit Findings

### User and Group Audits

- **Users with UID 0:** `root`
- **Users without passwords:** `root`, `daemon`, `bin`, etc.

### File and Directory Permissions

- **World-writable files and directories:** `/init`, `/tmp`, `/var/tmp`, etc.
- **`.ssh` Directory Permissions:** Ensure `.ssh` directory and its contents have appropriate permissions.


## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/yourusername/yourrepository.git
