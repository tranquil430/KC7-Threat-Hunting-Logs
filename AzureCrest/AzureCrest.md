
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
