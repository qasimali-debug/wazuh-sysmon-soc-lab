# Enterprise SOC & SIEM Lab: Wazuh 4.9, Sysmon & MITRE ATT&CK Mapping

A fully functional, containerized Security Operations Center (SOC) lab deployed on a local workstation. This project demonstrates end-to-end telemetry ingestion, CIS Benchmark compliance auditing, and real-time MITRE ATT&CK threat detection using **Wazuh SIEM/EDR** and **Microsoft Sysmon**.

---

## Architecture Overview

\\\	ext
+-------------------------------------------------------------------------+
|                              Windows Host                               |
|                                                                         |
|  +--------------------+        +-------------------------------------+  |
|  | Microsoft Sysmon   | -----> | Wazuh Windows Agent (v4.9.0)        |  |
|  | (SwiftOnSecurity)  | Events | (EventChannel: Sysmon/Operational)  |  |
|  +--------------------+        +------------------+------------------+  |
|                                                   | Port 1514 (TCP)     |
+---------------------------------------------------|---------------------+
                                                    v
+-------------------------------------------------------------------------+
|                       Docker Stack (Linux Engine)                       |
|                                                                         |
|  +----------------------+    +--------------------+    +-------------+  |
|  | Wazuh Manager        | -> | Wazuh Indexer      | -> | Wazuh       |  |
|  | (Rules & Decoders)   |    | (OpenSearch Engine)|    | Dashboard   |  |
|  +----------------------+    +--------------------+    +-------------+  |
+-------------------------------------------------------------------------+
\\\

---

## Tech Stack & Components

- **SIEM / XDR:** Wazuh Server 4.9.0 (Manager, Indexer, Dashboard) orchestrated via Docker Compose.
- **Endpoint Telemetry:** Microsoft Sysmon v15.22 tuned with the SwiftOnSecurity configuration.
- **Log Transport:** Wazuh Agent ingesting native \Microsoft-Windows-Sysmon/Operational\ event channels.
- **Framework Mapping:** MITRE ATT&CK Enterprise Matrix (Tactics, Techniques, Sub-techniques).
- **Compliance:** CIS Microsoft Windows 11 Enterprise Benchmark (SCA Module).

---

## Lab Implementation Steps

### 1. Docker SIEM Deployment
Deploys single-node Wazuh cluster with production-grade certificate generation:
\\\ash
cd single-node
docker compose -f generate-indexing-certs.yml run --rm generator
docker compose up -d
\\\

### 2. Sysmon Kernel Telemetry Configuration
Installed Sysmon as a driver service utilizing refined process and network telemetry rules:
\\\powershell
Sysmon64.exe -accepteula -i sysmonconfig.xml
\\\

### 3. Agent Enrollment & Channel Ingestion
Registered the Windows endpoint to the containerized manager (\127.0.0.1:1514\) and configured \ossec.conf\ for channel forwarding:
\\\xml
<localfile>
  <log_format>eventchannel</log_format>
  <location>Microsoft-Windows-Sysmon/Operational</location>
</localfile>
\\\

---

## Threat Detection & Verification

### Case 1: Command & Control / File Manipulation (Rule ID: 92205)
- **Tactic:** Command and Control
- **MITRE ID:** T1105 - Ingress Tool Transfer
- **Alert Level:** 9 (High)
- **Observed Behavior:** Detection engine captured automated file drop/creation under system directories via PowerShell processes during setup automation.

### Case 2: Security Configuration Assessment (CIS Benchmark)
- **Policy Evaluated:** CIS Microsoft Windows 11 Enterprise Benchmark v1.0.0
- **Results:** Audit generated baseline score (32%) highlighting unhardened endpoint parameters.
