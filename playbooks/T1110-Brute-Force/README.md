# Brute Force Playbook

# T1110 - Brute Force Burst (4625)

## ATT&CK Mapping
- **Technique ID:** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)  
- **Tactic:** Credential Access  
- **Sub-techniques:** T1110.001 (Password Guessing), T1110.003 (Password Spraying)  

---

## Description
This playbook detects brute-force login attempts against Windows endpoints using **Security Event ID 4625 (failed logon)**.  
The detection logic identifies accounts experiencing **10 or more failed logons from the same source IP within a 15-minute window**.  
Such activity may indicate password spraying, credential stuffing, or brute force attacks targeting local or domain accounts.  

---

## Detection Logic

### Microsoft Sentinel (KQL)
```kql
SecurityEvent
| where EventID == 4625
| where Account !endswith "$"
| where isnotempty(IpAddress)
| summarize Failures = count(), Start = min(TimeGenerated), End = max(TimeGenerated)
        by Account, SrcIP = IpAddress, Computer
| where Failures >= 10 and (End - Start) < 15m

