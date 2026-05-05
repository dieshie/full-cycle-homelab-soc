# HomeLab for SOC & Detection Practice

I built this lab to understand how attacks look in SIEM and practice detection engineering. No cloud, no automation - just manual setup to learn the fundamentals.

## What's inside

Three VMs in VMware Internal Network, isolated from host:

| Machine | IP | Role |
|---------|-----|------|
| Server (Fedora) | 192.168.190.137 | FreeIPA domain controller + Wazuh (server, indexer, dashboard) |
| Client (Fedora) | 192.168.190.136 | Domain user workstation + Wazuh agent |
| Kali Linux | 192.168.190.133 | Attacker machine |

All machines are in the same /24 subnet by design - this simplifies setup and lets me focus on SIEM detection rather than network segmentation. For a production environment, the attacker would be placed in an external network behind a firewall.

### Network Topology

![Network topology](https://github.com/user-attachments/assets/082a1d52-3ff0-4c11-9ffa-792ea3b1114d)

## Setup

### FreeIPA - Linux Domain Controller

I chose FreeIPA because it's essentially Active Directory for Linux: centralized authentication (LDAP + Kerberos), single sign-on, and host-based access control - all open source. It provides the enterprise-grade authentication layer that generates meaningful logs for SIEM analysis.

FreeIPA server installed on Fedora. Created two domain users (`diamond` and `cliff`) for testing:

![FreeIPA users in web UI](https://github.com/user-attachments/assets/2c3dffea-d3ac-4156-8741-360d445608d8)

Client joined to the domain, user `diamond@lab.local` can log in:

![Domain user login on client](https://github.com/user-attachments/assets/03084b33-7fa1-43d9-96eb-f32854d1082d)

### Wazuh - SIEM & XDR

Wazuh deployed on the server (all-in-one: manager, indexer, dashboard). Below is the baseline state before any attacks - clean dashboard, no alerts:

![Wazuh baseline before attacks](https://github.com/user-attachments/assets/3ad55ae6-2345-48be-976d-622f8afc00ac)

**Issues I ran into during Wazuh setup:**

**1. Minimal hardware check.** Fedora is not in Wazuh's officially supported OS list. The installer fails the pre-flight check. Fixed by running the installer with the `-i` flag to ignore the hardware check.

**2. Log collection not working initially.** Wazuh was not collecting authentication events. The agent configuration needed an explicit localfile entry to monitor `/var/log/secure`. After adding the `<localfile>` block with `syslog` format pointing to `/var/log/secure` and restarting the agent, SSH login events started appearing on the dashboard.

**3. Filebeat was not running.** After a reboot, alerts stopped appearing. The `filebeat` service (which ships logs from Wazuh Manager to Indexer) was installed but inactive. Starting and enabling it with `systemctl` fixed the issue.

## Attack Simulation

### SSH Brute Force with Medusa

Ran a dictionary attack against the client using Medusa with a custom wordlist. The list included both existing and non-existing usernames:

![Medusa brute force attack](https://github.com/user-attachments/assets/cb1c37bd-16a0-4514-9e97-a3f49506acda)

**Detection result in Wazuh:** Rule **5720** - `sshd: Multiple authentication failures`. Knowing rule IDs is useful for quick filtering in investigations.

![Wazuh alert for multiple auth failures](https://github.com/user-attachments/assets/b8f07a15-4c55-4b3d-9738-18edfddd611b)

### Nmap Reconnaissance

Ran port scanning and NSE brute-force scripts from Kali:

![Nmap NSE scan](https://github.com/user-attachments/assets/e05ab038-517e-457e-93c0-99e8ca931089)

**Detection result in Wazuh:** 22 alerts within 8 minutes. These triggered three different rules:

| Rule ID | Description |
|---------|-------------|
| 5712 | SSHD: Brute force trying to get access — non-existent user |
| 5763 | SSHD: Brute force trying to get access — authentication failed |
| 5551 | PAM: Multiple failed logins in a small period of time |

![Wazuh alerts after Nmap scan](https://github.com/user-attachments/assets/3f1afe86-cc5c-490a-98d7-11327f936971)

### MITRE ATT&CK Mapping

Wazuh automatically maps alerts to MITRE ATT&CK techniques:

![MITRE ATT&CK mapping](https://github.com/user-attachments/assets/ef59d5fe-7aa2-435a-a65c-d0c7bf137ea8)

**Techniques identified:**

- **T1110** — Brute Force
- **T1078** — Valid Accounts (when successful login follows brute force)

This correlation is valuable for incident response — you immediately know the adversary's playbook.

### Successful Login Detection

A single successful login generates a low-severity alert (Rule **5715** - `sshd: authentication success`). By itself, it's not suspicious:

![Successful login — low severity](https://github.com/user-attachments/assets/3a5442c2-3ffa-47db-a2e5-1f5cccb223f2)

**However,** when a successful login occurs during a brute-force attack, Wazuh correlates it differently. I added the correct password for `diamond` to the wordlist and re-ran the attack. The result:

![Successful login following brute force — high severity](https://github.com/user-attachments/assets/02ffd5f9-4b64-4453-8994-aab6c16d4130)

Rule **40112** fired: `Multiple authentication failures followed by a success`. This is high severity — the system correctly identified that a brute-force attack resulted in a compromise.

**Key takeaway:** Context matters. A successful login alone means nothing. A successful login surrounded by 20 failures means credential compromise.

## How It Works (Data Flow)

Client auth log (`/var/log/secure`) → Wazuh Agent → Wazuh Manager (analysisd) → Filebeat → Wazuh Indexer → Dashboard

1. SSH daemon writes to `/var/log/secure`
2. Wazuh Agent reads the file (configured via `localfile`)
3. Agent sends events to Wazuh Manager on port 1514
4. Manager's `analysisd` matches events against rules
5. Filebeat ships alerts from Manager to Indexer (port 9200)
6. Dashboard queries Indexer and displays alerts

## Detection Use Cases

### Use Case 1: SSH Brute Force Detection

| Field | Value |
|-------|-------|
| **Event Source** | `/var/log/secure` (client) |
| **Rule IDs** | 5712, 5763, 5551 → correlated to 5720 |
| **Detection Logic** | More than 5 failed authentications from single source IP within 2 minutes |
| **Severity** | Medium (Level 8-10) |
| **MITRE Technique** | T1110 — Brute Force |

**Query to find brute-force attempts:** filter by `rule.id: 5712 OR 5763 OR 5551` and `agent.name: client.lab.local`

### Use Case 2: Successful Credential Compromise

| Field | Value |
|-------|-------|
| **Event Source** | `/var/log/secure` (client) |
| **Rule IDs** | 40112 |
| **Detection Logic** | Multiple failed authentications followed by a success from same source IP |
| **Severity** | High (Level 12+) |
| **MITRE Technique** | T1078 — Valid Accounts |

**Response steps:**

1. Verify source IP — is it expected?
2. Check what account was compromised
3. Force password reset for that account
4. Review that user's recent activity for lateral movement


## Lessons Learned

- **DNS is critical for FreeIPA.** The server hostname must resolve to a real IP (not 127.0.0.1). Kerberos breaks otherwise.
- **Wazuh is a HIDS, not a NIDS.** It monitors host logs. Network-level attacks like port scans are only detected indirectly — through application logs (SSH failures) or firewall logs. For full network visibility, Suricata or Zeek would need to be added.
- **Correlation is everything.** A single failed login is noise. Multiple failures from one IP is suspicious. Multiple failures followed by a success is an incident. Understanding this progression is the core of detection engineering.
- **Know your rule IDs.** During an investigation, filtering by rule ID (5712, 5551, 40112) is much faster than searching raw logs.


## Future Improvements

- [ ] Add Suricata IDS for network-level detection (port scans, C2 traffic)
- [ ] Implement Active Response — automatic IP blocking on brute-force detection
- [ ] Add external network segment for realistic perimeter (attacker outside, firewall between zones)
- [ ] Create custom correlation rules in Wazuh
- [ ] Integrate TheHive or DFIR-IRIS for case management
