# Hybrid SOC Lab: Monitoring & Detection (Splunk & Microsoft Sentinel)

![Badge](https://img.shields.io/badge/Role-Blue%20Team-blue) ![Badge](https://img.shields.io/badge/Tech-Splunk%20%7C%20Sentinel%20%7C%20Sysmon-orange) ![Badge](https://img.shields.io/badge/Language-SPL%20%7C%20KQL-green)

## 📌 Executive Summary
This project demonstrates the deployment of a **Hybrid SOC Environment** combining on-premise logging (Splunk Enterprise) and cloud-native SIEM (Microsoft Sentinel). The goal was to simulate a corporate infrastructure, ingest endpoint telemetry via **Sysmon**, and develop detection rules for common attack vectors.

**Key Achievements:**
* Deployed a Windows 10 Endpoint with **Sysmon** (SwiftOnSecurity config).
* Configured log ingestion into **Splunk** (via Universal Forwarder) and **Azure Sentinel** (via AMA Agent).
* Translated detection logic from **SPL** (Splunk) to **KQL** (Sentinel).
* Mapped detections to the **MITRE ATT&CK** framework.

---

## 🏗️ Architecture

*(Insert your diagram here or use the text below)*

The lab simulates a monitored endpoint sending telemetry to two distinct SIEM solutions to compare detection capabilities.

* **Endpoint:** Windows 10 Enterprise (VirtualBox)
* **Telemetry:** Sysmon (Event ID 1, 11, etc.) & Windows Security Logs (4624, 4625).
* **SIEM 1 (On-Prem):** Splunk Enterprise (Free License).
* **SIEM 2 (Cloud):** Microsoft Sentinel (Azure Log Analytics Workspace).

---

## 🛡️ Detection Engineering Showcase

I focused on detecting basic attack patterns using both query languages standard in the European market.

### Scenario 1: Brute Force Attempt (RDP/SMB)
**Objective:** Detect multiple failed login attempts on the endpoint.
**MITRE ATT&CK:** [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)

#### 🟣 Splunk (SPL)
```splunk
index="windows" source="WinEventLog:Security" EventCode=4625 
| stats count by Account_Name, Source_Network_Address 
| where count > 5
```

#### 🔵 Microsoft Sentinel (KQL)
```kql
SecurityEvent
| where EventID == 4625
| summarize FailureCount = count() by Account, IpAddress
| where FailureCount > 5
```

### Scenario 2: Suspicious Process Execution (Reconnaissance)
**Objective:** Detect usage of reconnaissance tools like whoami or net user.
**MITRE ATT&CK:** [T1033 - System Owner/User Discovery](https://attack.mitre.org/techniques/T1033/)

#### 🟣 Splunk (SPL)
```splunk
index="windows" source="xml:WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
| where Image like "%whoami.exe" OR Image like "%net.exe"
| table _time, User, CommandLine, ParentImage
```

#### 🔵 Microsoft Sentinel (KQL)
```kql
Event
| where Source == "Microsoft-Windows-Sysmon" and EventID == 1
| extend RenderedDescription = tostring(parse_xml(RenderedDescription).EventData.Data)
| where RenderedDescription has "whoami.exe"
| project TimeGenerated, RenderedDescription
```

#### 📊 Dashboards & Evidence

####💡 Lessons Learned & Business Impact
- Hybrid Visibility: Operating both SIEMs highlighted the importance of unified logging strategies, especially for compliance (GDPR/NIS2).

- Query Performance: KQL proved highly efficient for cloud-native data, while Splunk offered granular control over parsing local XML logs
