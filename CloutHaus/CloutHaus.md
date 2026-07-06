### Executive Summary

CloutHaus contracted influencer partner Afomiya Storm was the victim of a sophisticated business email compromise (BEC) and social media account takeover campaign. The initial access vector was a highly targeted spear-phishing email masquerading as a collaboration opportunity from the luxury fashion house "Dior," which lured the victim into entering her corporate credentials into a credential harvesting portal hosted on `super-brand-offer.com`. The primary tools used by the adversary involved strategic Open Source Intelligence (OSINT) gathering, malicious domain infrastructures, and automated email forwarding rules. The ultimate impact of the incident resulted in the compromise and hijacking of her corporate mailbox (`afomiya_storm@clouthaus.com`), the takeover of her personal Instagram account to perpetrate financial fraud, and the illicit exfiltration of highly sensitive personal documentation including tax summaries, banking routing details, and a passport scan.

### Attack Chain & Advanced Queries

**Phase 1: Reconnaissance & Social Engineering (OSINT)**

The adversary initiated the attack by aggressively harvesting publicly available personal details from Afomiya Storm's digital footprint. The threat actor actively scraped her Instagram Stories during a public Q&A session, tricking her into answering common account recovery security questions (such as entering the security answer "Kidus"). This information was promptly weaponized in a failed attempt to bypass multi-factor authentication (MFA) on her personal Gmail account. Simultaneously, inbound web server logs indicate that the adversary actively queried the `clouthaus.com` platform to profiling the influencer, searching for indicators such as her home address, location data extracted from stories, transaction history via Venmo, and mapping a physical lure centered around a fraudulent "birthday party" invitation.

**Phase 2: Initial Access & Credential Harvesting**

On April 3, 2025, the threat actor shifted tactics to direct spear-phishing, targeting her professional CloutHaus email. At 11:20:00 UTC, the victim received and interacted with an email bearing the subject line `[EXTERNAL] Exclusive Partnership Opportunity with Dior` sent from the spoofed domain `collabs@dior-partners.com`. The message included a hyperlink routing to a cloned brand portal at `[https://super-brand-offer.com/login](https://super-brand-offer.com/login)`. The victim entered her corporate credentials (`afstorm`), which were immediately captured by the adversary. PassiveDNS telemetry reveals that the hosting infrastructure located at `198.51.100.12` acted as an adversary cluster, hosting multiple phishing domains including `super-brand-offer.com`, `dior-partners.com`, and `influencer-deals.net`.

**Phase 3: Compromise, Lateral Movement, & Data Exfiltration**

Exactly one hour following the phishing link click, the adversary leveraged the harvested credentials to log directly into the victim’s corporate CloutHaus mailbox from an anomalous IP address located in Jinan, Shandong, China (`182.45.67.89`). The malicious session utilized a legacy user-agent string signature indicating a Windows NT 5.2 operating system environment. Because the `Employees` data structure indicated that corporate multi-factor authentication (`mfa_enabled`) was set to `False` for her profile, the login succeeded with zero friction.

Upon establishing access, the adversary implemented malicious inbox inbox forwarding rules to establish long-term persistence. The rule silently duplicated and exfiltrated incoming corporate mail to an external threat-actor controlled drop box: `noreply@influencer-deals.net`. Through this automated exfiltration pipeline, the adversary effectively pilfered three high-value target attachments:

- `[EXTERNAL] [FORWARD] Afomiya's payment details – direct deposit form` (exfiltrating banking and routing data)
    
- `[EXTERNAL] [FORWARD] Afomiya's passport scan – confidential` (exfiltrating primary identity verification)
    
- `[EXTERNAL] [FORWARD] Re: Tax documents – year-end summary` (exfiltrating tax and income statements)
    

Concurrently, the threat actor exploited discovered password reuse habits to hijack her Instagram account, using OSINT to verify her residence details at the City Center Apartments via previous geometric apartment view uploads, and began running downstream financial investment scams targeting her online following.

**Advanced Threat Hunting Queries**

The following KQL queries were constructed during the threat hunt to identify the operational impact of the corporate identity footprint and parse the underlying malicious web server infrastructure.

Code snippet

```
// Query 1: Extracting Account Identity Context and MFA Coverage Gaps
Employees
| where name contains "Afomiya Storm"
| project username, role, mfa_enabled, ip_addr
```

_Query Explanation:_ This query targets the core organizational directory to extract the exact account profile properties of the targeted individual. By filtering explicitly on the victim's name, security personnel isolate the baseline metadata, verifying that her account lacked vital multi-factor authentication (`mfa_enabled == false`), which provided the structural opening for the subsequent geographic login anomaly.

Code snippet

```
// Query 2: Expanding Malicious Infrastructure through PassiveDNS Pivoting
PassiveDns
| where ip == "198.51.100.12" or domain has_any ("super-brand", "dior-partners", "influencer-deals")
| summarize ResolvedDomains = make_set(domain) by ip
```

_Query Explanation:_ This hunting query performs an infrastructure pivot. By focusing on the initial phishing landing domain or the underlying web hosting address discovered during outbound web traffic analysis (`198.51.100.12`), it aggregates and prints an array of all distinct malicious staging domains operating from the identical attacker-controlled network space.

### Remediation Recommendations

- **Enforce Strict Multi-Factor Authentication (MFA) Mandates:** Immediately update corporate identity provider policies to enforce phishing-resistant Multi-Factor Authentication (such as FIDO2 WebAuthn or managed push notifications) across all corporate accounts, specifically closing gaps for external or contracted talent structures (e.g., Influencer Partners) whose profiles default to unauthenticated status.
    
- **Deploy Automated Email Forwarding Alerts and Restrictions:** Implement transport rules within the corporate email gateway (e.g., Exchange Online / Google Workspace) that strictly block external automatic email forwarding rules to unknown or untrusted domains. Configure SIEM/SOAR detection rules to trigger high-priority alerts whenever a new forwarding rule is introduced to an inbox from an external or geographically anomalous session.
    
- **Implement Behavioral Egress Filters and User-Agent Defenses:** Establish conditional access rules that automatically block authentication requests originating from non-compliant or legacy browser operating systems (such as Windows NT 5.2 / Internet Explorer legacy builds). Combine this with network-level tracking to block outbound traffic routing to newly observed domains (registered under 30 days old) or categorized adversary networks.
    

### MITRE ATT&CK Mapping

|**Tactic**|**Technique ID & Name**|**Description of Action**|
|---|---|---|
|Reconnaissance|T1594: Gather Victim Identity Information|Adversary leveraged Instagram Story Q&As and profile scraping to gather security answers, Venmo records, and residency profiles.|
|Initial Access|T1566.002: Phishing: Spearphishing Link|Sent a deceptive partnership lure containing a hyperlink pointing to a credential harvesting landing page.|
|Credential Access|T1539: Steal Web Credentials|Deployed a cloned login portal (`super-brand-offer.com`) to systematically harvest the user's corporate credentials.|
|Persistence|T1114.003: Email Collection: Email Forwarding Rule|Established malicious inbox auto-forwarding rules to route confidential documents directly to `noreply@influencer-deals.net`.|
|Exfiltration|T1567: Exfiltration Over Web Service|Exfiltrated extremely sensitive files including tax documents, direct deposit information, and official passport scans to external attacker infrastructure.|
