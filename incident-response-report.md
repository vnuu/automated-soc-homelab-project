# INCIDENT RESPONSE REPORT

**Detection and Response to Credential-Access Activity (Mimikatz) on a Windows Endpoint**

| Field | Value |
|-------|-------|
| Incident Date | 22 April 2025 |
| Severity | Medium |
| Status | Closed |
| Classification | TLP:AMBER |

---

# Table of Contents

1. Executive Summary
2. Scope of Engagement
3. Timeline of Events
4. Technical Findings
5. External Threat Intelligence
6. Indicators of Compromise (IOCs)
7. Impact Assessment
8. Recommendations
9. Conclusion
10. Appendix A – Detection Rule
11. Appendix B – Tools and Platforms Used

---

# 1. Executive Summary

On **22 April 2025**, the Security Operations Center (SOC) detected and investigated credential-dumping activity on a Windows endpoint in the monitored environment.

The activity came from the execution of **Mimikatz**. Mimikatz is a public credential-extraction tool. Threat actors often use this tool after they gain access to a system. They use the tool to obtain credentials and move to other systems.

The **Wazuh SIEM** detected the activity by using endpoint telemetry and correlation rules. Wazuh forwarded the alert to a **Shuffle** automation workflow through a webhook. The workflow extracted the SHA256 hash from the alert, submitted the hash to **VirusTotal** for threat intelligence enrichment, created a case in **TheHive**, and sent an email notification to the SOC analyst.

The SOC analyst reviewed the case and confirmed that the alert was a **true positive**. The activity matched **MITRE ATT&CK Technique T1003 (OS Credential Dumping)**.

The investigation found no evidence of credential exfiltration, lateral movement, or impact to other systems.

---

# 2. Scope of Engagement

This engagement covered one Windows 10 endpoint (**WIN10-ENDPOINT**) in an isolated lab environment.

The purpose of the engagement was to test and validate the SOC detection and response process.

The exercise simulated credential theft by using **Mimikatz**. The exercise evaluated the following components:

- Endpoint telemetry (Sysmon)
- SIEM correlation (Wazuh)
- Automation workflow (Shuffle)
- Case management (TheHive)

## In Scope

- Endpoint: WIN10-ENDPOINT (Windows 10, 64-bit)
- SIEM: Wazuh Manager and custom detection rules
- SOAR: Shuffle automation workflow
- Case Management: TheHive
- Threat Intelligence: VirusTotal API

## Out of Scope

- Production network infrastructure
- Systems outside the isolated lab environment

**Engagement Window**

22 April 2025

---

# 3. Timeline of Events

| Step | Event | Description |
|-----:|-------|-------------|
| 1 | Mimikatz executed | The user executed **mimikatz.exe** on **WIN10-ENDPOINT** to simulate credential-dumping activity. |
| 2 | Sysmon generated an event | Sysmon generated **Event ID 1 (Process Creation)** and recorded the process details. |
| 3 | Log forwarded to Wazuh | The Wazuh agent forwarded the Sysmon event to the Wazuh Manager for analysis. |
| 4 | Detection rule triggered | Wazuh matched the event against the custom detection rule (**Rule ID 100002**) and generated a security alert for **MITRE ATT&CK T1003 – OS Credential Dumping**. |
| 5 | Alert sent to Shuffle | Wazuh forwarded the alert to **Shuffle** through a webhook. |
| 6 | SHA256 hash extracted | Shuffle extracted the SHA256 hash from the alert by using a regular expression. |
| 7 | Threat intelligence enrichment | Shuffle submitted the SHA256 hash to **VirusTotal** for reputation analysis. |
| 8 | Case created | Shuffle created a new case in **TheHive** with the alert details and enrichment results. |
| 9 | Email notification sent | Shuffle sent an email notification to the SOC analyst. |
| 10 | Analyst review | The SOC analyst reviewed the alert in **TheHive**, validated the detection, and confirmed it as a **true positive**. |

---

# 4. Technical Findings

## 4.1 Detection Overview

Sysmon collected endpoint telemetry and forwarded the logs to the Wazuh Manager.

A custom detection rule (**Rule ID 100002**) detected **Mimikatz** execution. The rule inspected the `win.eventdata.originalFileName` field in Sysmon Event ID 1 (Process Creation).

<img width="1011" height="341" alt="image" src="https://github.com/user-attachments/assets/3d48cdf7-b6d7-4ef9-8876-044938e27ad5" />

The `originalFileName` field contains the internal file metadata. The field does not depend on the file name on the disk. Because of this, the rule can detect Mimikatz even if the attacker renames the executable.

---

## 4.2 MITRE ATT&CK Mapping

| ATT&CK Element | Value |
|---------------|-------|
| Tactic | Credential Access |
| Technique | T1003 – OS Credential Dumping |
| Representative Sub-technique | T1003.001 – LSASS Memory |

Mimikatz can extract plaintext passwords, password hashes, and Kerberos tickets from the LSASS process on Windows systems.

Threat actors use this technique to obtain credentials. They can then perform lateral movement or privilege escalation.

---

## 4.3 Process and Execution Details

| Field | Value |
|-------|-------|
| Host | WIN10-ENDPOINT |
| Process Name | mimikatz.exe |
| Original File Name (PE metadata) | mimikatz.exe |
| File Path | C:\Users\vnu\Downloads\mimikatz_trunk\x64\mimikatz.exe |
| User | DESKTOP-QKD4UIN\vnu |
| Command Line | C:\Users\vnu\Downloads\mimikatz_trunk\x64\mimikatz.exe |

---

## 4.4 Automated Threat Enrichment

After Wazuh generated the alert, it forwarded the alert to **Shuffle** through a webhook.

Shuffle extracted the SHA256 hash from the alert by using a regular expression.

The workflow submitted the extracted hash to the **VirusTotal API**.

VirusTotal returned file reputation information and additional metadata. Shuffle added this information to the alert before it created a case in **TheHive**.

The workflow then sent an email notification to the SOC analyst for investigation.

---

# 5. External Threat Intelligence

Shuffle extracted the SHA256 hash from the Wazuh alert and submitted the hash to the **VirusTotal API**.

VirusTotal returned reputation information for the detected file. The response included the file name, file type, SHA256 hash, and file metadata.

The workflow used this information to enrich the alert before it created a case in **TheHive**.

The additional threat intelligence helped the SOC analyst verify the alert and confirm it as a **true positive**.

## VirusTotal Summary

| Attribute | Value |
|----------|-------|
| Source | VirusTotal API |
| File Name | mimikatz.exe |
| File Type | PE32+ executable (x86-64) |
| SHA256 | 61C0810A23580CF492A6BA4F7654566108331E7A4134C968C2D6A05261B2D8A1 |
| Classification | HackTool / Credential Dumper |

---

# 6. Indicators of Compromise (IOCs)

| Indicator Type | Value |
|---------------|-------|
| File Name | mimikatz.exe |
| SHA256 Hash | 61C0810A23580CF492A6BA4F7654566108331E7A4134C968C2D6A05261B2D8A1 |
| File Path | C:\Users\vnu\Downloads\mimikatz_trunk\x64\mimikatz.exe |
| Host | WIN10-ENDPOINT |
| MITRE ATT&CK ID | T1003 (OS Credential Dumping) |
| Detection Rule | Wazuh Rule ID 100002 |

> **Note:** Handle all indicators in accordance with the **TLP:AMBER** classification. Share this information only with authorised personnel.

---

# 7. Impact Assessment

The investigation found no evidence of credential exfiltration, lateral movement, or access to additional systems.

The activity remained inside the isolated lab environment. The activity did not affect production systems.

---

# 8. Recommendations

1. Enable Credential Guard and LSA Protection (RunAsPPL) on Windows endpoints.
2. Deploy application allow-listing to block unauthorised credential-access tools.
3. Keep EDR and antivirus signatures up to date.
4. Expand detection by using behavioural detection and hash-based detection. Do not rely only on file names.
5. Perform regular purple-team exercises to validate SOC detection and response capability.

---

# 9. Conclusion

This engagement demonstrated that the SOC can detect, enrich, and respond to credential-dumping activity by using an automated SIEM, SOAR, and case management workflow.

The custom detection rule worked as expected.

The automated workflow reduced the manual work required during triage and case escalation.

The recommendations in this report will improve protection against credential-access techniques.

---

# Appendix A – Detection Rule (Wazuh Custom Rule)

```xml
<rule id="100002" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">
    (?i)mimikatz\.exe
  </field>
  <description>Mimikatz usage detected</description>
  <mitre>
    <id>T1003</id>
  </mitre>
</rule>
```

---

# Appendix B – Tools and Platforms Used

| Function | Tool / Platform |
|----------|-----------------|
| Endpoint Telemetry | Sysmon |
| SIEM | Wazuh |
| SOAR / Automation | Shuffle |
| Case Management | TheHive |
| Threat Intelligence | VirusTotal |
| Notification | Shuffle Email App |
