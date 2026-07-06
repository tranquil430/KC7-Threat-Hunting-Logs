# Owl Records Incident Report

### Executive Summary

Owl Records was targeted in a multi-stage account takeover campaign specifically aimed at high-value artists within the organization, primarily those in the "Rapper" role. The adversary initially attempted to manipulate the self-service password reset portal using Open Source Intelligence (OSINT) to guess security questions, before pivoting to a targeted spear-phishing campaign using a music-themed lure domain (`betterlyrics4u.com`). The ultimate impact was the successful compromise of the credentials belonging to artist Dwake Audrey, leading to an unauthorized login and full account takeover from the attacker's infrastructure.

### Attack Chain & Advanced Queries

**Phase 1: Reconnaissance & Credential Manipulation**
The adversary, operating from IP address `18.66.52.227`, began their campaign on April 10, 2024, by interacting with the Owl Records inbound web infrastructure. The attacker targeted the account of artist Dwake Audrey (`dwake_audrey@owl-records.com`) by abusing the self-service password reset functionality. Utilizing OSINT gathered on the victim, the attacker successfully injected the answers to personal security questions directly into the URL parameters, bypassing the security challenge with the answers "Washington" (mother's maiden name) and "Fluffy" (first pet's name).

**Phase 2: Spear-Phishing & Credential Harvesting**
Following the password reset tampering, the attacker launched a targeted phishing campaign prioritizing employees holding the "Rapper" role. The emails contained malicious links routing to `betterlyrics4u.com`, a domain resolving back to the attacker's IP (`18.66.52.227`). On April 15, 2024, at `12:03:12Z`, Dwake Audrey clicked the lure from their internal IP (`10.10.0.5`), connecting to the credential harvesting endpoint: `[http://betterlyrics4u.com/share/online/published/enter](http://betterlyrics4u.com/share/online/published/enter)`.

**Phase 3: Account Takeover**
Exactly one hour after the victim clicked the malicious phishing link, the adversary executed their objective. At `13:03:12Z` on April 15, 2024, the attacker successfully authenticated to the corporate network under Dwake’s username (`dwaudrey`) directly from the staging IP `18.66.52.227`.

**Advanced Threat Hunting Queries**
During the investigation, we utilized cross-table correlation to determine the adversary's targeting methodology, mapping the phishing indicators to organizational identity data.

```kusto
let _targets = Email
| where link has "betterlyrics4u.com"
| distinct recipient;
Employees
| where email_addr in (_targets)
| summarize TargetCount = count() by role

```

*Query Explanation:* This KQL query identifies the specific demographic targeted by the phishing campaign. The `let` statement creates a temporary array (`_targets`) containing all distinct email addresses that received a message containing the malicious domain. The query then filters the `Employees` directory table using the `in` operator to isolate those victims, allowing analysts to group them by job role and uncover that the adversary was specifically hunting users assigned the "Rapper" title.

### Remediation Recommendations

* **Deprecate Knowledge-Based Authentication:** Immediately disable the use of static security questions (e.g., mother's maiden name, pet names) for account recovery or password resets, as these are easily bypassed using social media OSINT. Transition to phishing-resistant Multi-Factor Authentication (MFA) or out-of-band push notifications for all identity verification.
* **Implement Conditional Access Policies:** Configure the identity provider (IdP) to block or challenge authentication attempts originating from anomalous or historically unassociated external IP addresses (such as the attacker's staging IP, `18.66.52.227`).
* **Deploy Advanced Email Threat Protection:** Implement email gateway filtering to automatically sandbox and quarantine inbound links to newly registered domains or domains categorized as suspicious/uncategorized (e.g., `betterlyrics4u.com`), particularly when sent to high-visibility public figures within the organization.

### MITRE ATT&CK Mapping

| Tactic | Technique ID & Name | Description of Action |
| --- | --- | --- |
| Reconnaissance | T1593.001: Gather Victim Identity Information: Web | Adversary gathered personal OSINT on the victim to guess security question answers (mother's maiden name and pet's name). |
| Initial Access | T1566.002: Phishing: Spearphishing Link | Sent highly targeted emails containing malicious links to `betterlyrics4u.com`, specifically hunting users in the Rapper role. |
| Credential Access | T1539: Steal Web Credentials | Utilized a spoofed portal (`[http://betterlyrics4u.com/share/online/published/enter](http://betterlyrics4u.com/share/online/published/enter)`) to harvest the victim's authentication material. |
| Initial Access | T1078: Valid Accounts | Attacker successfully logged into the victim's account (`dwaudrey`) from an external IP one hour after the phishing payload was triggered. |
