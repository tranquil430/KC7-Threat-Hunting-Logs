# WhiskerMania Incident Report

### Executive Summary

The Whiskers & Wonders nonprofit organization was targeted by a sophisticated cyberattack beginning on June 2, 2025, originating from a targeted credential phishing campaign masquerading as internal HR communications. The threat actors successfully compromised three employee workstations, subsequently establishing persistent Command and Control (C2) using encrypted HTTPS beaconing to external attacker-controlled infrastructure. The primary objective of this "Payment Shadow Campaign" appears to be establishing a foothold within the accounts of personnel possessing direct access to the critical Donation Portal, posing a severe risk of financial diversion and data exfiltration if left unchecked.

### Attack Chain & Advanced Queries

**Phase 1: Reconnaissance & Initial Access**
The adversary initiated the attack by registering a lookalike domain, `whiskersandwonders-hr.com`, to impersonate the organization's Human Resources department. On June 2, 2025, at exactly 4:00:00 PM, targeted spear-phishing emails bearing the high-urgency subject line `[EXTERNAL] Important: Employee Benefits Update Required` were sent to three specific employees: Alex Rivera (Development Officer), Jessica Huang (Adoption Coordinator), and David Okonkwo (Adoption Coordinator). The targeting of these specific roles indicates the attackers were specifically seeking initial access to users with elevated privileges or direct involvement with the organization's financial and donation systems.

**Phase 2: Execution & Command and Control (Beaconing)**
Approximately seven hours after the phishing emails were delivered, the compromised workstations began exhibiting signs of malware execution and Command and Control (C2) communication. Starting at 11:52:31 PM on June 2, the victim machines (residing in the `10.10.16.x` workstation VLAN) began issuing DNS queries for `update-cdn-service.xyz`. The malware utilized the `.xyz` top-level domain to blend in with generic infrastructure traffic.

Once resolved, the compromised endpoints established outbound TCP connections to the attacker IP `185.174.137.42` over Port 443 (HTTPS). By routing C2 traffic through encrypted web protocols, the adversary successfully bypassed standard port-blocking firewalls. Proxy event logs revealed that the malware was executing automated "beaconing" by routinely requesting the URI paths `/api/v1/status` and `/api/v1/config`—a technique designed to mimic legitimate API traffic while fetching attacker commands and configuration updates. This persistence mechanism remained active for approximately four days across the three compromised hosts.

**Advanced Threat Hunting Queries**

During the investigation, cross-table joins were utilized to correlate network telemetry directly with organizational identity data to determine the operational impact of the compromised internal IP addresses.

```kusto
DnsEvents
| where query_name contains "update-cdn-service.xyz"
| distinct client_ip
| join kind=inner (
    Employees 
    | project ip_addr, name, username, role
  ) on $left.client_ip == $right.ip_addr
| project name, username, role

```

*Query Explanation:* This query effectively maps raw network IOCs to human identities. It first filters the `DnsEvents` table to isolate the distinct internal IP addresses that queried the malicious C2 domain. It then uses an `inner join` to correlate those compromised IP addresses (`client_ip`) with the `ip_addr` column in the `Employees` directory table. Finally, it projects the human-readable names and job roles, immediately informing incident responders that critical staff (Development Officers and Adoption Coordinators) were compromised.

```kusto
let c2_domain = "update-cdn-service.xyz";
let compromised_ips = DnsEvents
| where query_name contains c2_domain
| distinct client_ip;
DnsEvents
| where client_ip in (compromised_ips)
| where query_name contains c2_domain
| summarize
    first_beacon = min(timestamp),
    last_beacon = max(timestamp),
    total_queries = count()
  by client_ip

```

*Query Explanation:* This query establishes the exact timeline and volume of the C2 beaconing per compromised host. It utilizes `let` statements to declare the malicious domain and dynamically generate an array of compromised IP addresses. By passing these IPs into the `summarize` operator, the query calculates the absolute start (`min(timestamp)`) and end (`max(timestamp)`) of the infection window, as well as the aggregate check-in count, allowing analysts to quantify the persistence duration.

### Remediation Recommendations

* **Implement Network & DNS Sinkholing:** Immediately add the malicious domain (`update-cdn-service.xyz`) to the organization's internal DNS sinkhole/blocklist to severe the hostname resolution capability of the malware. Concurrently, block outbound traffic to the IP address `185.174.137.42` at the perimeter firewall.
* **Configure Web Proxy Pattern Blocking:** Update the secure web gateway (SWG) or proxy server to explicitly drop and alert on HTTP/HTTPS requests originating from internal workstations that match the regular expression pattern `^/api/v\d+/(status|config)$` when directed toward `.xyz` domains.
* **Enhance Email Gateway Defenses & Isolate Hosts:** Configure the corporate email gateway to quarantine or reject inbound mail from newly registered lookalike domains (e.g., `whiskersandwonders-hr.com`). Immediately isolate the three compromised workstations (`10.10.16.14`, `10.10.16.7`, `10.10.16.24`) from the network, perform a full forensic image, and force a global credential reset for the impacted users prior to reimaging the machines.

### MITRE ATT&CK Mapping

| Tactic | Technique ID & Name | Description of Action |
| --- | --- | --- |
| Reconnaissance | T1583.001: Acquire Infrastructure: Domains | Adversary registered lookalike domain `whiskersandwonders-hr.com` and C2 domain `update-cdn-service.xyz`. |
| Initial Access | T1566.002: Phishing: Spearphishing Link | Sent targeted social engineering emails impersonating HR regarding "Employee Benefits" to specific organizational roles. |
| Command and Control | T1071.001: Application Layer Protocol: Web Protocols | Established C2 communication channels using encrypted HTTPS over port 443 to bypass standard network filtering. |
| Command and Control | T1001.003: Data Obfuscation: Protocol Impersonation | Designed malware beaconing URIs (`/api/v1/status` and `/api/v1/config`) to mimic legitimate API traffic and evade proxy analysis. |
| Command and Control | T1568: Dynamic Resolution | Leveraged the Domain Name System (DNS) to resolve the C2 staging server, initiating the beaconing sequence. |
