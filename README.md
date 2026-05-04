## HomeLab for SOC & Detection Practice
I built this lab to understand how attacks look in SIEM and practice detection engineering. No cloud, no automation - just manual setup.

## What's inside
Three VMs in VirtualBox Internal Network, isolated from host:

| Machine | IP | Role |
|---------|-----|------|
| Server (Fedora) | 192.168.190.10 | FreeIPA domain controller + Wazuh (server, indexer, dashboard) |
| Client (Fedora) | 192.168.190.20 | Domain user workstation + Wazuh agent |
| Kali Linux | 192.168.190.30 | Attacker machine |

All machines are in the same /24 subnet by design - this simplifies setup and lets me focus on SIEM detection rather than network complexity.
<img width="990" height="579" alt="image" src="https://github.com/user-attachments/assets/082a1d52-3ff0-4c11-9ffa-792ea3b1114d" />
