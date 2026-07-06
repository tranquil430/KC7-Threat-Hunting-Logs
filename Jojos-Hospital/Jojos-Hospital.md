# JoJo's Hospital Incident Report

### Executive Summary

JoJo's Hospital was the victim of a multi-stage ransomware and data extortion attack orchestrated by the Lockbyte ransomware group. The initial access vector was a malvertising campaign utilizing a spoofed domain for a local restaurant, which led to the execution of Cobalt Strike payloads on hospital endpoints. After achieving lateral movement and exfiltrating highly sensitive patient records and network credentials, the threat actors deployed ransomware, encrypting over 6,400 files across 321 hostnames. The ultimate impact was severe operational disruption and the threat of a data leak involving patient Social Security Numbers if the $10,000 ransom was not paid within 72 hours.

### Attack Chain & Advanced Queries

**Phase 1: Initial Access & Reconnaissance**

The attack began around May 1, 2024, when hospital staff were targeted by a sponsored Google search advertisement masquerading as a popular local restaurant, "Raising Cane's" (`raisinkanes.com`). The malicious ad redirected 24 unique employees to attacker-controlled domains such as `nothing-to-see-here.net`. The first compromised host, `RQJQ-MACHINE`, downloaded a malicious document (`Raisin_Kane_Promo_Offer.docx`) via Chrome. Upon execution, the document dropped `cobaltstrike.exe`, which immediately established a Command and Control (C2) connection to IP `93.238.22.122` over port 50050. The attackers subsequently ran basic discovery commands like `systeminfo` to orient themselves.

**Phase 2: Lateral Movement & Credential Theft**

By mid-May, the threat actors had acquired the credentials of employee Anthony Davis, likely through dark web purchases or earlier credential harvesting. On May 14, they established a Cobalt Strike session directly on Davis's workstation (`AMFB-MACHINE`). To map the internal environment, they downloaded `advanced-ip-scanner.exe`. The attackers then compressed critical infrastructure files, including `network_diagrams.pdf` and `credentials.txt`, into a file named `important_network_info.zip` and exfiltrated it using `curl` to `nothing-to-see-here.net`. Concurrent to this, external threat actors operating from `203.0.113.1` and `203.0.113.2` actively probed the hospital's public website, specifically searching for "patient records" and methods to bypass security.

**Phase 3: Data Exfiltration & Ransomware Deployment**

The attack culminated on June 17, 2024. Operating from `AMFB-MACHINE`, the attackers downloaded a custom tool named `patient_data_exporter.exe` from `secure-health-access.com`. They systematically archived critical directories from the hospital server (`\jojos-hospital-server\important_data\`) into three archives: `patient_data_1.zip`, `patient_data_2.zip`, and `patient_data_3.zip`. These archives were exfiltrated to `secure-health-access.com` using `curl`, after which the attackers executed a deletion command to clear their tracks. Finally, they deployed the Lockbyte ransomware executable (`lockbyte_ransomer.exe`), renaming it to `spread_ransomware.exe` and hosting it on the `\\jojos-hospital.org` network share to maximize the infection radius. This resulted in the encryption of 6,420 files and the generation of the `We_Have_Your_Data_Pay_Up.txt` ransom note.

**Advanced Threat Hunting Queries**

During the investigation, we utilized cross-table correlation to track the specific lateral movement targeting Anthony Davis.

Code snippet

```
let host = Employees
| where name == "Anthony Davis"
| distinct hostname;
ProcessEvents
| where hostname in (host)
| where process_commandline contains "cobalt"
```

_Query Explanation:_ This query efficiently links identity data with endpoint telemetry. The `let` statement creates a variable that queries the `Employees` table to find the specific machine name assigned to Anthony Davis. The query then pipes that hostname into the `ProcessEvents` table, using the `in` operator to filter for any command-line executions on his machine that contain the string "cobalt" (identifying the Cobalt Strike payload).

Code snippet

```
OutboundNetworkEvents
| where url contains "raisinkanes.com"
| distinct src_ip
| count
```

_Query Explanation:_ This query was used to determine the exact scope of the initial malvertising campaign. By filtering the outbound web proxy logs for the spoofed domain and using the `distinct` operator on the source IP addresses, we successfully identified the exact number of unique hospital employees (24) who fell victim to the fake advertisement.

### Remediation Recommendations

- **Implement Strict Egress Filtering and Application Control:** Block native utilities like `curl.exe` from making outbound connections to the internet unless originating from approved administrative subnets. Implement application whitelisting to block the execution of unknown binaries (like `cobaltstrike.exe` or `advanced-ip-scanner.exe`) on standard employee workstations.
    
- **Deploy DNS Security and Ad-Blocking:** Implement enterprise-wide DNS filtering to block known malicious domains (e.g., `nothing-to-see-here.net`, newly registered domains like `raisinkanes.com`) and prevent malicious ad networks from loading on corporate browsers. This neutralizes the initial access vector at the network edge.
    
- **Enhance Ransomware Precursor Detections:** Configure EDR rules to trigger high-severity alerts when executable files are dropped to or executed from widespread administrative network shares (e.g., `\\jojos-hospital.org`). Monitor and alert on mass file modification events or the sudden creation of files with known ransomware extensions (e.g., `.encrypted`).
    

### MITRE ATT&CK Mapping

|**Tactic**|**Technique ID & Name**|**Description of Action**|
|---|---|---|
|Initial Access|T1189: Drive-by Compromise|Malvertising campaign utilizing a spoofed restaurant domain to serve malicious `.docx` and `.pdf` files.|
|Execution|T1059.003: Windows Command Shell|Utilized `cmd.exe /c del` to delete the staging archives after data exfiltration.|
|Command and Control|T1071.001: Web Protocols|C2 communication established via Cobalt Strike routing over port 50050 to an external IP.|
|Discovery|T1046: Network Service Discovery|Executed `advanced-ip-scanner.exe` to map the internal hospital network and identify core servers.|
|Exfiltration|T1567: Exfiltration Over Web Service|Exfiltrated zipped patient records and credential files using `curl` to attacker-controlled domains.|
|Impact|T1486: Data Encrypted for Impact|Deployed Lockbyte ransomware via network shares, encrypting over 6,400 files and leaving ransom notes.|
