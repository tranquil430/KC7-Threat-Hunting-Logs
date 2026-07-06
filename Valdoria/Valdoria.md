# Valdoria Incident Report

### Executive Summary

The Valdorian Times suffered a targeted cyberattack resulting in severe reputational damage and data exfiltration. The initial access vector was a highly targeted spear-phishing campaign disguised as recruitment outreach, which successfully tricked editorial staff into downloading malicious Office documents. The primary tools utilized included a custom PowerShell payload (`hacktivist_manifesto.ps1`), scheduled tasks for persistence, and `plink.exe` to establish Command and Control (C2) tunnels. The ultimate impact involved the attackers hijacking an employee's email account to publish a falsified, defamatory article about a local political candidate, followed by the exfiltration of archived internal data to an external server.

### Attack Chain & Advanced Queries

**Phase 1: Reconnaissance & Initial Access**
The adversary initiated the campaign by sending targeted spear-phishing emails to The Valdorian Times editorial staff. On January 5, 2024, Senior Editor Sonia Gose received an email from `newspaper_jobs@gmail.com` and clicked a link to `promotionrecruit.com`, downloading `Valdorian_Times_Editorial_Offer_Letter.docx`. Days later, on January 10, 2024, Editorial Intern Ronnie McLovin was targeted by `valdorias_best_recruiter@gmail.com`. She clicked a similar link hosted on `promotionrecruit.org` and downloaded `Editorial_J0b_Openings_2024.docx`. These documents acted as initial droppers for the subsequent attack phases.

**Phase 2: Execution, Persistence, & Command and Control (C2)**
Immediately upon downloading the malicious documents, a PowerShell script named `hacktivist_manifesto.ps1` was written to disk (`C:\ProgramData\hacktivist_manifesto.ps1`). The attackers established persistence by utilizing `schtasks.exe` to create a scheduled task named "Hacktivist Manifesto" that ran the script hourly using an execution policy bypass. Following this, the attackers leveraged `plink.exe` to establish remote C2 SSH tunnels to external IP addresses (`136.130.190.181` and `168.57.191.100`). The attackers authenticated via these tunnels using the username `$had0w` and the password `thruthW!llS3tUfree`, subsequently executing basic discovery commands (e.g., `whoami`) to map the environment.

**Phase 3: Actions on Objectives & Exfiltration**
Operating via hands-on-keyboard access through Ronnie McLovin's machine (`A37A-DESKTOP`), the attackers downloaded a fabricated article (`fakestory.docx`) from `hire-recruit.org` on January 31, 2024. They used command-line tools to rename and move this file to `C:\Users\romclovin\Documents\OpEdFinal_to_print.docx`. Using Ronnie's compromised email session, they sent this fraudulent article to the printing department to ensure its publication in the morning paper. Finally, the attackers utilized `7zip` to compress the victim's local files into encrypted archives (e.g., `MyStolenDataFromDocuments.7z`) using the C2 password. These archives were exfiltrated via an automated `curl` POST request to a custom endpoint at `[https://hirejob.com/exfil_processor/upload.php](https://hirejob.com/exfil_processor/upload.php)`.

**Advanced Threat Hunting Queries**
During the investigation, we utilized identity-correlated queries to track the malicious activity across different tables based on the targeted user's dynamic IP address and hostname allocations.

```kusto
let ronnie_pc = Employees
| where name == "Ronnie McLovin"
| distinct hostname;
ProcessEvents
| where hostname in (ronnie_pc)
| where process_commandline contains "plink"

```

*Query Explanation:* This KQL query effectively links organizational identity data with endpoint process telemetry. The `let` statement creates a variable that dynamically looks up Ronnie McLovin's assigned machine name from the `Employees` directory. The query then passes that array into the `ProcessEvents` table using the `in` operator, filtering specifically for the execution of the `plink` utility. This allows analysts to track malicious C2 establishment without needing to memorize dynamically assigned hostnames.

### Remediation Recommendations

* **Implement Strict Email Gateway & Phishing Defenses:** Deploy advanced email filtering to quarantine inbound messages containing links to newly registered or untrusted domains (e.g., `.org` or `.com` variations of recruitment sites). Restrict the execution of macros and embedded scripts in Microsoft Office documents downloaded from external sources.
* **Enforce Endpoint Application Control:** Utilize EDR or Group Policy to block the execution of known tunneling and exfiltration utilities (such as `plink.exe` and `curl.exe`) on standard user workstations. Furthermore, enforce strict PowerShell Execution Policies and monitor for `-ExecutionPolicy Bypass` arguments in command-line telemetry.
* **Deploy Network Segmentation and Egress Filtering:** Restrict internal workstations from establishing outbound SSH (Port 22) connections to external internet addresses. Implement web proxy policies to block unauthorized file uploads to unclassified domains (e.g., `hirejob.com`).

### MITRE ATT&CK Mapping

| Tactic | Technique ID & Name | Description of Action |
| --- | --- | --- |
| Initial Access | T1566.002: Phishing: Spearphishing Link | Sent targeted recruitment-themed emails containing malicious links to editorial staff. |
| Execution | T1059.001: Command and Scripting Interpreter: PowerShell | Executed `hacktivist_manifesto.ps1` utilizing execution policy bypasses. |
| Persistence | T1053.005: Scheduled Task/Job: Scheduled Task | Utilized `schtasks.exe` to create an hourly scheduled task to maintain execution of the PowerShell payload. |
| Command and Control | T1572: Protocol Tunneling | Leveraged `plink.exe` to establish remote SSH tunnels to attacker-controlled infrastructure. |
| Discovery | T1033: System Owner/User Discovery | Executed `whoami` commands over the C2 tunnel to verify the compromised user context. |
| Collection | T1560.001: Archive Collected Data: Archive via Utility | Utilized `7zip` to compress targeted documents and desktop files into password-protected `.7z` archives. |
| Exfiltration | T1567: Exfiltration Over Web Service | Exfiltrated the encrypted `.7z` archives via a `curl -F` POST request to a remote PHP upload portal. |
