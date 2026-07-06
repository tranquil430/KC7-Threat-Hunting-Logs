### Executive Summary

Azure Crest Hospital suffered a severe ransomware attack initiated through a highly targeted spear-phishing campaign that successfully tricked 37 employees into executing malicious `.docm` attachments. After gaining initial access, the threat actors established persistent command and control (C2) using `putty.exe` and PowerShell scripts, allowing them to pivot through the network and compromise 35 hosts. The ultimate impact was the deployment of a custom ransomware strain (appending `.scholopendra`) on the core database server, encrypting critical pediatric medical records and severely disrupting hospital operations.

### Attack Chain & Advanced Queries

**Phase 1: Reconnaissance & Initial Access**

The adversary began by conducting open-source reconnaissance, repeatedly visiting Azure Crest's public news portal to identify internal organizational changes, specifically targeting Roy Trenneman, the Database Administrator. Following this, the attackers launched a spear-phishing campaign masquerading as `emergencycarepartners.com` (using the sender `medstaffinfo@hospitalcomm.org` and reply-to `healthupdate@gmail.com`). They sent emails with urgent subjects like "_[EXTERNAL] FW: 🚑 Attention Required: Urgent Pediatric Health Procedure Update 🌈_" containing malicious Office documents (e.g., `New_Healthcare_Protocols.docm`). The first payload execution occurred on 2024-03-01T11:58:33Z, and in total, 37 employees fell victim to the phishing lures.

**Phase 2: Execution, Persistence, & Command and Control**

Upon successful document execution, web browsers (e.g., `chrome.exe` on Jerry Jones' machine) were utilized to download malicious payloads from domains such as `takeyatimecarepartners.com`. A file named `hearburn.zip` was dropped into `C:\ProgramData\Heartburn\` on compromised hosts and extracted natively using the Windows command line (`cmd.exe /c Expand-Archive...`). To establish C2 and enable lateral movement, the attackers utilized `putty.exe` to initiate SSH connections to 17 unique external IP addresses (including `93.142.203.80`) using hardcoded credentials (`have_ya_tried` / `turning_it_off_and_on_again`). They also used `curl.exe` to pull down additional remote access tools like `anydesk_automation.ps1`.

**Phase 3: Discovery & Ransomware Deployment**

Having mapped the network, the threat actors zeroed in on `SUPER-DB-SERVER-9000`, the workstation belonging to the DBA, Roy Trenneman. A specialized reconnaissance executable named `dbhunter.exe` was dropped into the Temp folder to aggressively scan for `.db` extensions. Once the medical databases were located, the threat actor executed the ransomware payload using the password `mommawemadeit`. Critical files, such as `medical_inventories.db`, were encrypted with the `.scholopendra` extension, and the system wallpaper was modified to `ItWentWrong.jpg` to notify the victim of the compromise.

**Advanced Threat Hunting Queries**

During the investigation, we utilized cross-table correlation to track the outbound footprint of specific targeted user groups.

Code snippet

```
let mary_ips = Employees
| where name has "Mary"
| distinct ip_addr;
OutboundNetworkEvents
| where src_ip in (mary_ips)
| distinct url
| count
```

_Query Explanation:_ This KQL query effectively links identity data with network telemetry. The `let` statement creates a temporary variable containing only the distinct IP addresses of employees named "Mary" from the `Employees` table. The query then filters the `OutboundNetworkEvents` table by checking if the source IP matches any in our variable array using the `in` operator, ultimately counting the distinct malicious or benign URLs visited by this specific cohort.

### Remediation Recommendations

- **Implement Strict Email Gateway & Macro Policies:** Enforce DMARC, DKIM, and SPF validation to prevent external senders from spoofing legitimate domains. Furthermore, utilize Group Policy (GPO) to globally disable the execution of macros in Microsoft Office files downloaded from the internet (Mark-of-the-Web).
    
- **Enforce Network Segmentation & Egress Filtering:** Standard employee workstations should not be permitted to initiate outbound SSH (Port 22) connections to external internet addresses. Implement strict firewall egress rules to block unauthorized remote administration protocols and tools (like AnyDesk or Putty) from communicating outside the local network unless originating from an approved IT jump server.
    
- **Deploy and Tune Endpoint Detection and Response (EDR):** Ensure EDR agents are deployed on all endpoints, particularly critical infrastructure like database servers. Create custom behavioral alerts to detect anomalous child processes, such as `cmd.exe` extracting archives in `C:\ProgramData\`, or unauthorized binaries (like `dbhunter.exe`) executing from the `Temp` directory.
    

### MITRE ATT&CK Mapping

|**Tactic**|**Technique ID & Name**|**Description of Action**|
|---|---|---|
|Reconnaissance|T1592 Gather Victim Host Information|Threat actor visited Azure Crest's news site 37 times to map out internal personnel changes and target the new Database Administrator.|
|Initial Access|T1566.001 Phishing: Spearphishing Attachment|Adversary sent targeted emails with malicious `.docm` attachments (e.g., `New_Healthcare_Protocols.docm`) to 40 hospital employees.|
|Execution|T1059.003 Command and Scripting Interpreter: Windows Command Shell|Used native `cmd.exe` to execute `Expand-Archive` and unpack the `hearburn.zip` payload.|
|Command and Control|T1105 Ingress Tool Transfer|Utilized `curl.exe` to download `anydesk_automation.ps1` and leveraged `putty.exe` to establish SSH tunnels to external IP addresses.|
|Discovery|T1083 File and Directory Discovery|Deployed a custom tool (`dbhunter.exe`) on the database server to specifically locate `.db` files for encryption.|
|Impact|T1486 Data Encrypted for Impact|Encrypted medical databases with the `.scholopendra` extension and altered the host's desktop wallpaper to `ItWentWrong.jpg`.|
### Executive Summary

Azure Crest Hospital suffered a ransomware incident resulting in the encryption of database records with a `.scholopendra` extension. The threat actor gained initial access via a spearphishing campaign spoofing medical staff updates, leading users to download a malicious `.docm` file. Post-compromise activity included lateral movement using `putty.exe` and the deployment of the `dbhunter.exe` tool to target pediatric medical databases.

### Attack Chain & Advanced Queries

**1. Initial Access:** The attacker targeted 40 employees with a fake pediatric health update. 
**2. Execution & Lateral Movement:** The macro dropped `hearburn.zip`, expanded it via PowerShell, and the attacker used `putty.exe` to SSH across 35 compromised computers.

**Query: Correlating Affected Users to Authentication Events**

```
let staff = Employees
| where name has "Mary"
| distinct username;
AuthenticationEvents
| where username in (staff)
| count
```

### Remediation Recommendations

- **SIEM Detection:** Configure Wazuh to alert on instances of `putty.exe` executing with command-line arguments indicative of lateral movement
- **Endpoint Response:** Deploy Velociraptor artifacts to hunt for `.scholopendra` extensions and quarantine affected endpoints immediately.
### MITRE ATT&CK Mapping
|**Tactic**|**Technique**|**Description**|
|---|---|---|
|Initial Access|T1566.001|Spearphishing Attachment (`.docm`)|
|Lateral Movement|T1021.004|SSH (`putty.exe`)|
|Impact|T1486|Data Encrypted for Impact (`.scholopendra`)|
