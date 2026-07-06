## KQL Threat Hunting Investigations
Below are detailed write-ups of my investigations into various simulated cyber attacks. Each module includes a breakdown of the attack chain, the KQL queries used to hunt the adversary, and a MITRE ATT&CK mapping of the observed techniques.

| Investigation | Scenario & Threat Actor | Core Techniques Investigated | Write-up |
| :--- | :--- | :--- | :--- |
| **AzureCrest** | Ransomware deployment via malicious `.docm` macros | Spearphishing, Reconnaissance, Data Encrypted for Impact | [View Case](./AzureCrest/) |
| **Castle & Sand** | Targeted phishing campaign and extortion | Watering Hole Attack, Credential Dumping | [View Case](./Castle-and-Sand/) |
| **CloutHaus** | Social Engineering & Account Takeover | OSINT, MFA Bypass, BEC, Exfiltration | [View Case](./CloutHaus/) |
| **Jojo's Hospital** | Initial access via purchased credentials & Ransomware | Cobalt Strike, Data Exfiltration, Network Discovery | [View Case](./Jojos-Hospital/) |
| **WhiskerMania** | C2 Beaconing & Network Traffic Analysis | Protocol Tunneling, Port Analysis, C2 Infrastructure | [View Case](./WhiskerMania/) |
| **Valdoria** | Insider Threat vs. External Compromise | Hands-on-keyboard (plink), Scheduled Tasks | [View Case](./Valdoria/) |
| **Solvi Systems** | Web Application Exploitation (XSS) | Web Reconnaissance, Persistence, Discovery | [View Case](./Solvi-Systems/) |
| **Owl Records** | Executive Account Hijacking | Log Analysis, Authentication Bypas
