# 🕵️ Threat Hunt Challenge: **Signals Before the Noise, External RDP Compromise**

**Analyst:** Niccolas Sabella

**Date Completed:** April 27, 2026

**Environment Investigated:** PHTG Azure Tenant · Microsoft Defender for Endpoint

**Compromised Host:** azwks-phtg-02

**Investigation Window:** 9 December 2025 – 23 December 2025 UTC

**Tables Queried:** DeviceNetworkEvents, DeviceLogonEvents, DeviceProcessEvents, DeviceFileEvents, DeviceEvents

---

## 🧠 Scenario Overview

PHTG rolled out an internal endpoint health service called **HealthCloud** on 11 December 2025. Its footprint was unremarkable by design: scheduled PowerShell tasks, background executables, diagnostic cache directories under `C:\ProgramData\PHTG\HealthCloud\`, and periodic outbound check-ins. A day later, a member of the cloud engineering team posted to LinkedIn to celebrate the rollout. The photo showed a dev workstation with an Azure portal open, and on the screen: a VM's name, its public IP address, and enough networking detail to hand an attacker a ready-made target.

There was no incident. No alerts. No suspected compromise. Yet.

A threat hunter was tasked with reviewing the OSINT exposure, determining what was readable in that photo, and then pivoting into telemetry to answer the harder question: **did anyone act on what they saw?** The investigation that followed traced a complete external compromise, from opportunistic scanning of an internet-exposed RDP port, through a successful brute-force authentication from Uruguay, to the deployment and persistence of a **Meterpreter** payload disguised as a user's own notes file, embedded inside the HealthCloud service directory as cover.

---

## 🎯 Executive Summary

The hunt traced a full external RDP compromise kill chain. A LinkedIn post inadvertently exposed the VM name (`azwks-phtg-02`) and its public IP (`74.249.82.162`), reducing the cost of targeting to near zero. MDE telemetry confirmed the machine was hit by broad automated scanning from **173 unique public IPs** across **11 countries** on port 3389. Of 675 RDP authentication events, **646 failed** with `InvalidUserNameOrPassword`, consistent with credential-stuffing. **23 successful logins** originated from Uruguay using the `vmadminusername` account, a geographically anomalous source for a US-only organisation.

Post-access behaviour was methodical. The attacker opened a sensitive internal notes file (`notes_sarah.txt`) to accelerate their internal knowledge of the environment, then deployed a payload that cycled through three filenames (`Sarah_Chen_Notes.Txt` → `Sarah_Chen_Notes.exe.Txt` → `Sarah_Chen_Notes.exe`) as a double-extension evasion technique. Microsoft Defender detected and quarantined it three times before the attacker switched Defender to **passive mode**, neutralising real-time protection. The payload — classified as `Trojan:Win32/Meterpreter.RPZ!MTB` — then executed unimpeded, establishing a C2 channel back to **173.244.55.130:4444** in Uruguay. For persistence, the final renamed binary (`PHTG.exe`) was placed inside `C:\ProgramData\PHTG\HealthCloud\` and launched via `Launch.bat`, masquerading as part of the legitimate HealthCloud service baseline.

---

## ✅ Findings Summary

| # | Category | Finding | Answer |
|---|----------|---------|--------|
| 01 | OSINT | Exposed virtual machine name | `azwks-phtg-02` |
| 02 | OSINT | Public IP associated with the VM | `74.249.82.162` |
| 03 | OSINT | What makes the exposure actionable | Public IP visible and associated with the VM |
| 04 | OSINT | Activity type visible in the LinkedIn photo | Managing cloud infrastructure resources |
| 05 | OSINT | First telemetry source to review for scanning | Azure network / platform analytics (inbound connections) |
| 06 | Scanning | Port showing strongest automated scanning | `3389` (RDP) |
| 07 | Scanning | Total network events on that port | `194` |
| 08 | Scanning | Unique public source IPs | `173` |
| 09 | Scanning | IPs with both connection attempt and accepted connection | `57` |
| 10 | Scanning | Distinct countries in RDP connection activity | `11` |
| 11 | Auth | Total external authentication events | `693` |
| 12 | Auth | RDP-related authentication events | `675` |
| 13 | Auth | Dominant authentication outcome | `LogonFailed` (646 events) |
| 14 | Auth | Most common failure reason | `InvalidUserNameOrPassword` |
| 15 | Auth | Unique countries in RDP auth activity | `17` |
| 16 | Auth | Countries with at least one successful auth | `2` |
| 17 | Auth | Countries with successful RDP logins | `Uruguay`, `United States` |
| 18 | Geo Anomaly | Country outside PHTG's operating region | `Uruguay` |
| 19 | Geo Anomaly | Account used in anomalous successful auth | `vmadminusername` |
| 20 | Geo Anomaly | Count of successful logins from Uruguay | `23` |
| 21 | Geo Anomaly | First attacker IP (Uruguay) | `173.244.55.131` |
| 22 | Geo Anomaly | Second attacker IP (Uruguay) | `173.244.55.128` |
| 23 | Post-Access | First notable process after access | `notepad.exe` |
| 24 | Post-Access | Sensitive internal file opened | `notes_sarah.txt` |
| 25 | Payload | First executable-form filename | `Sarah_Chen_Notes.exe` |
| 26 | Payload | Double-extension evasion filename | `Sarah_Chen_Notes.exe.Txt` |
| 27 | Payload | SHA256 of the payload | `224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695` |
| 28 | Payload | Final observed filename | `PHTG.exe` |
| 29 | Payload | Malware family (MDE classification) | `Meterpreter` |
| 30 | Evasion | Why payload ran after quarantine | Defender switched to **passive mode** |
| 31 | Execution | Filename used in first execution phase | `Sarah_Chen_Notes.exe` |
| 32 | Execution | Process initiating the later execution phase | `cmd.exe` |
| 33 | Persistence | Batch file used to launch payload | `C:\ProgramData\PHTG\HealthCloud\Launch.bat` |
| 34 | C2 | Command-and-control IP | `173.244.55.130` |
| 35 | C2 | C2 geography | `Uruguay, South America` |
| 36 | C2 | C2 remote port | `4444` |
| 37 | Persistence | Legitimate service used as cover | `HealthCloud` |

---

## Finding by Finding

---

### 🖼️ 01 — Identifying the Exposed Asset

**Objective:** Anchor the investigation to a specific Azure resource before touching any telemetry.

**What to Hunt:** Review the OSINT source — the LinkedIn photo — and extract the virtual machine name visible in the Azure portal.

**Identified Evidence:**
```
User:        Sarah Chen
Host:        azwks-phtg-02
Public IP:   74.249.82.162
Internal IP: 10.0.0.152
```

**Answer:** `azwks-phtg-02`

**Why It Matters:** Every subsequent query in this investigation is scoped to this hostname. Naming the resource exactly as it appears in MDE device records eliminates any risk of querying the wrong machine. The VM name was plainly visible in the Azure portal screenshot — an attacker doing nothing more than reading a LinkedIn post would have the same starting point.

---

### 🌐 02 — Public Exposure Vector

**Objective:** Confirm the VM is directly reachable from the open internet.

**Identified Evidence:** *(From the LinkedIn photo)*
```
Public IP:  74.249.82.162
```

**Answer:** `74.249.82.162`

**Why It Matters:** A VM existing in Azure is not inherently a problem. A VM with a public IP — visible to anyone who saw the LinkedIn post — is. The public IP is the direct dial-in number for any service running on that machine. Combined with the VM name, an attacker now has both the target identity and the network address to reach it.

---

### 🎯 03 — When Context Becomes Actionable

**Objective:** Determine what specifically in the Azure portal view gives an external observer a clear path to act.

**Options:**
> A. The virtual machine is running Windows 10 Enterprise
> B. The VM size and memory configuration are displayed
> C. The VM is located in a specific cloud region
> **D. A public IP address is visible and associated with the virtual machine** ✅
> E. The VM has tags applied for management

**Answer:** `D`

**Why It Matters:** OS version, VM size, and region are contextual enrichment. A public IP is an action trigger. Any threat actor can pivot from a public IP directly to scanning and enumeration without any further research. The other details reduce effort once inside; this one opens the door.

---

### 📸 04 — OSINT Correlation

**Objective:** Characterise the type of activity visible in the LinkedIn photo to understand the scope of what was exposed.

**Options:**
> A. Writing application source code
> B. Responding to a security incident
> **C. Managing cloud infrastructure resources** ✅
> D. Monitoring system performance dashboards
> E. Reviewing internal documentation

**Answer:** `C`

**Why It Matters:** The photo shows an Azure portal session with VM networking details open — cloud infrastructure management. This context tells us the exposed information is operational and current, not historical documentation. A cloud engineering team member celebrating a rollout would have exactly the live infrastructure view that provides the most actionable intelligence to an observer.

---

### 🔍 05 — Evidence Source Selection

**Objective:** Identify the right telemetry source to determine whether the exposed public IP was scanned or probed after the LinkedIn post.

**Options:**
> A. Windows Application Event Logs
> B. Azure Active Directory sign-in logs
> C. Microsoft Defender for Endpoint device inventory
> **D. Azure network or platform analytics related to inbound connections** ✅
> E. Local browser history on the virtual machine

**Answer:** `D`

**Why It Matters:** Scanning activity hits the network layer before it touches any user-space process or authentication system. Network telemetry — specifically `DeviceNetworkEvents` — captures inbound connection attempts, including those that never progress past TCP handshake. Application logs and auth logs only record events that make it further into the stack, and browser history is irrelevant to inbound probing. Start at the perimeter.

---

### 📡 06 — Broad Scanning Indicators

**Objective:** Identify which local port on the VM shows the strongest indicator of broad, automated external scanning.

**KQL Query:**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09T00:00:00) .. datetime(2025-12-23T23:59:59))
| where DeviceName == "azwks-phtg-02" and LocalPort == "3389" and RemoteIPType == "Public"
| summarize count() by LocalPort
| sort by count_ desc
```

**Results:**
| LocalPort | count_ |
|-----------|--------|
| 3389 | 194 |

**Answer:** `3389`

**Why It Matters:** Port 3389 is the default RDP port. Its presence as the dominant inbound target, with 194 events from public IPs, confirms the VM's RDP service was both exposed and actively being probed. Automated scanners prioritise RDP on internet-facing Windows machines precisely because successful authentication grants direct interactive access to the desktop.

---

### 📊 07 — Exposure Activity Volume

**Objective:** Quantify the total number of network events targeting the exposed RDP port.

**KQL Query:** *(Same query as Finding 06)*

**Answer:** `194`

**Why It Matters:** 194 events over a 14-day window is not random noise. It reflects sustained, structured probing. This volume is consistent with automated credential-stuffing tools that maintain persistent connection queues against a target rather than a single opportunistic scanner.

---

### 🗺️ 08 — Source Diversity

**Objective:** Determine how many distinct public IP addresses were sending traffic to the exposed RDP port.

**KQL Query:**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09T00:00:00) .. datetime(2025-12-23T23:59:59))
| where DeviceName == "azwks-phtg-02" and LocalPort == "3389" and RemoteIPType == "Public"
| distinct RemoteIP
| summarize Total = dcount(RemoteIP)
```

**Results:**
| Total |
|-------|
| 173 |

**Answer:** `173`

**Why It Matters:** 173 unique source IPs indicates either a botnet-distributed attack or extensive use of proxy/VPN infrastructure. This level of source diversity is deliberately designed to bypass simple IP-based blocklists. Each IP contributes only a small share of the overall volume, making any single source appear low-priority in isolation.

---

### 🔗 09 — Connection Outcomes

**Objective:** Separate raw probes from sources that received a TCP response — a meaningfully different threat class.

**KQL Query:**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09T00:00:00) .. datetime(2025-12-23T23:59:59))
| where DeviceName == "azwks-phtg-02" and LocalPort == "3389"
| summarize Actions = make_set(ActionType) by RemoteIP
| where Actions contains "Attempt" and Actions contains "Accepted"
| project Actions, RemoteIP
| distinct RemoteIP
| count
```

**Results:**
| Count |
|-------|
| 57 |

**Answer:** `57`

**Why It Matters:** Of 173 scanning IPs, 57 achieved both a connection attempt and an accepted connection — meaning they completed the TCP handshake and reached the RDP service. These sources are not blind probers; they got a response and could progress to authentication. This is the subset that matters most for follow-on auth analysis.

---

### 🌍 10 — Countries with RDP Activity

**Objective:** Enrich the 57 IPs that achieved TCP response with geographic data to understand the global distribution of active scanners.

**KQL Query:**
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-09T00:00:00) .. datetime(2025-12-23T23:59:59))
| where DeviceName == "azwks-phtg-02" and LocalPort == "3389"
| summarize Actions = make_set(ActionType) by RemoteIP
| where Actions contains "Attempt" and Actions contains "Accepted"
| project Actions, RemoteIP
| distinct RemoteIP
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| distinct country_name
| count
```

**Results:**
| Count |
|-------|
| 11 |

**Answer:** `11`

**Why It Matters:** Scanning infrastructure distributed across 11 countries is consistent with a coordinated botnet or threat actors leveraging commercial proxy services. No single country dominates, a deliberate distribution strategy to complicate geographic blocking.

---

### 🔐 11 — Total External Auth Volume

**Objective:** Establish the full scope of externally sourced authentication events against the device.

**KQL Query:**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09T00:00:00) .. datetime(2025-12-23T23:59:59))
| where DeviceName == "azwks-phtg-02" and RemoteIPType == "Public"
| count
```

**Results:**
| Count |
|-------|
| 693 |

**Answer:** `693`

**Why It Matters:** 693 externally sourced authentication events over 14 days represents a sustained, systematic effort. This is not opportunistic scanning that stopped after a few probes. The volume reflects tooling that continuously feeds credential pairs into the target.

---

### 🖥️ 12 — RDP Auth Volume

**Objective:** Isolate authentication events specifically associated with Remote Desktop Protocol.

**KQL Query:**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09T00:00:00) .. datetime(2025-12-23T23:59:59))
| where DeviceName == "azwks-phtg-02" and RemoteIPType == "Public" 
  and LogonType in ("RemoteInteractive", "Network")
| count
```

**Results:**
| Count |
|-------|
| 675 |

**Answer:** `675`

**Why It Matters:** 675 of 693 total external auth events were RDP-type logons. The machine's attack surface was almost entirely defined by its exposed RDP port — consistent with what the LinkedIn OSINT revealed. An attacker who saw port 3389 accessible via a public IP would go directly to RDP credential stuffing.

---

### ❌ 13 — Dominant Auth Outcome

**Objective:** Determine which authentication outcome dominated the RDP logon activity.

**KQL Query:**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09T00:00:00) .. datetime(2025-12-23T23:59:59))
| where DeviceName == "azwks-phtg-02" and RemoteIPType == "Public" 
  and LogonType in ("RemoteInteractive", "Network")
| summarize count() by ActionType
```

**Results:**
| ActionType | count_ |
|------------|--------|
| LogonFailed | 646 |
| LogonSuccess | 29 |

**Answer:** `LogonFailed` — 646 events

**Why It Matters:** 646 failures against 29 successes is the classic ratio of a credential-stuffing campaign. Automated tooling exhausts credential lists with the expectation that a small percentage will succeed. The 646 failures are the cost of entry; the 29 successes are what the attacker came for.

---

### 🔑 14 — Dominant Failure Reason

**Objective:** Confirm the nature of the authentication failures to distinguish credential stuffing from other attack types.

**KQL Query:**
```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09T00:00:00) .. datetime(2025-12-23T23:59:59))
| where DeviceName == "azwks-phtg-02" and RemoteIPType == "Public" 
  and LogonType in ("RemoteInteractive", "Network")
| summarize count() by FailureReason
```

**Results:**
| FailureReason | count_ |
|---------------|--------|
| InvalidUserNameOrPassword | 637 |

**Answer:** `InvalidUserNameOrPassword`

**Why It Matters:** `InvalidUserNameOrPassword` is the definitive fingerprint of credential stuffing. The attacker was cycling through username/password pairs. This is not a single targeted account lockout attempt — it is a breadth-first attack across many credential combinations, expecting eventual success from a list of previously leaked or purchased credentials.

---

### 🗾 15 — Countries from Auth Activity

**Objective:** Establish the total geographic spread of all RDP authentication sources, both failed and successful.

**KQL Query:**
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09T00:00:00) .. datetime(2025-12-23T23:59:59))
| where DeviceName == "azwks-phtg-02" and RemoteIPType == "Public" 
  and LogonType in ("RemoteInteractive", "Network")
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| distinct country_name
| count
```

**Results:**
| Count |
|-------|
| 17 |

**Answer:** `17`

**Why It Matters:** Authentication attempts originating from 17 countries confirms the use of distributed infrastructure. A US-only organisation receiving auth traffic from 17 countries has a clear baseline violation to act on. This also establishes the geographic spread to contrast against when isolating the successful logins.

---

### ✅ 16 — Countries with Successful Auth

**Objective:** Narrow from all authentication countries to only those where at least one logon succeeded.

**KQL Query:**
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09T00:00:00) .. datetime(2025-12-23T23:59:59))
| where DeviceName == "azwks-phtg-02" and RemoteIPType == "Public" 
  and LogonType in ("RemoteInteractive", "Network")
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| distinct country_name
```

**Results:**
| country_name |
|--------------|
| Uruguay |
| United States |

**Answer:** `2`

**Why It Matters:** Of 17 countries generating authentication attempts, only 2 produced successful logins. The United States is expected for a US-based company. Uruguay is not. This single anomaly is the pivot point that separates background noise from confirmed threat actor access.

---

### 🌎 17 — Successful Countries

**Objective:** Document both countries associated with successful RDP authentication.

**Identified Activity:** *(From Finding 16)*

**Answer:** `Uruguay`, `United States`

**Why It Matters:** The United States result is consistent with legitimate administrative access and serves as a baseline. Uruguay's presence in the success column is the anomaly that drives the next phase of the investigation.

---

### 🚨 18 — Unexpected Country

**Objective:** Identify which successful authentication source falls entirely outside PHTG's operational geography.

**Context:** PHTG operates exclusively in the United States. No international workforce.

**Answer:** `Uruguay`

**Why It Matters:** Geographic anomaly is one of the clearest signals in identity-based threat hunting. PHTG has no presence, employees, or expected operational activity in Uruguay. A successful RDP logon from that country is either a compromised account accessed by a threat actor, or a VPN exit node in Uruguay — either scenario demands immediate investigation.

---

### 👤 19 — Account Used

**Objective:** Identify the specific account credential that the Uruguay-origin attacker successfully authenticated with.

**KQL Query:**
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09T00:00:00) .. datetime(2025-12-23T23:59:59))
| where DeviceName == "azwks-phtg-02" and RemoteIPType == "Public" 
  and LogonType in ("RemoteInteractive", "Network")
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "Uruguay"
| distinct AccountName
```

**Results:**
| AccountName |
|-------------|
| vmadminusername |

**Answer:** `vmadminusername`

**Why It Matters:** `vmadminusername` is a default-style administrator account name — exactly the type of credential that appears in common credential-stuffing lists targeting Azure VMs. Weak or predictable admin account names are a perennial vulnerability on cloud-hosted Windows machines with public IPs. This account should be disabled immediately and replaced with a non-guessable name behind an access policy.

---

### 🔢 20 — Uruguay Success Count

**Objective:** Quantify how many successful authentication sessions the attacker established from Uruguay.

**KQL Query:**
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09T00:00:00) .. datetime(2025-12-23T23:59:59))
| where DeviceName == "azwks-phtg-02" and RemoteIPType == "Public" 
  and LogonType in ("RemoteInteractive", "Network")
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "Uruguay" and ActionType == "LogonSuccess"
| count
```

**Results:**
| Count |
|-------|
| 23 |

**Answer:** `23`

**Why It Matters:** 23 successful logins from Uruguay confirms this was not a single exploratory session. The attacker returned repeatedly over the investigation window, establishing durable access and conducting activity across multiple sessions. This is indicative of a hands-on operator, not just an automated tool completing a one-time task.

---

### 🔎 21 — First Attacker IP from Uruguay

**Objective:** Identify the source IP associated with the earliest successful RDP authentication from Uruguay.

**KQL Query:**
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-09T00:00:00) .. datetime(2025-12-23T23:59:59))
| where DeviceName == "azwks-phtg-02" and RemoteIPType == "Public" 
  and LogonType in ("RemoteInteractive", "Network")
| where ActionType == "LogonSuccess"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| where country_name == "Uruguay" and ActionType == "LogonSuccess"
| project TimeGenerated, RemoteIP
| sort by TimeGenerated asc
```

**Results:**
| TimeGenerated | RemoteIP |
|---------------|----------|
| Dec 12, 2025 6:47:45 AM | 173.244.55.131 |

**Answer:** `173.244.55.131`

**Why It Matters:** This timestamp — 12 December 2025 at 06:47 UTC — marks the beginning of confirmed threat actor access and becomes the pivot point for all post-access telemetry analysis. All subsequent process, file, and network queries should begin from this timestamp.

---

### 🔎 22 — Second Attacker IP from Uruguay

**Objective:** Identify any additional source IPs used by the attacker from Uruguay.

**Identified Activity:** *(From Finding 21 query, reviewing all results)*

**Results:**
| TimeGenerated | RemoteIP |
|---------------|----------|
| Dec 12, 2025 2:31:56 PM | 173.244.55.128 |

**Answer:** `173.244.55.128`

**Why It Matters:** Two IPs from the same /24 subnet (`173.244.55.0/24`) strongly suggests the attacker is operating from the same network infrastructure — potentially a VPS provider or hosting block in Uruguay. The consistent subnet is a high-confidence IOC: blocking `173.244.55.0/24` at the network perimeter would cover both known attacker IPs and likely any future sessions from the same infrastructure.

---

### 📝 23 — First Notable Process

**Objective:** After the first confirmed Uruguay login, identify the earliest process that indicates deliberate operator interaction — not routine session startup noise.

**KQL Query:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-12T06:47:45) .. datetime(2025-12-14T23:59:59))
| where DeviceName == "azwks-phtg-02" and InitiatingProcessAccountName == "vmadminusername"
| where FileName !in ("msedge.exe", "explorer.exe", "OneDrive.exe", "identity_helper.exe")
| project TimeGenerated, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```

**Results:**
| TimeGenerated | FileName | ProcessCommandLine |
|---------------|----------|-------------------|
| Dec 12, 2025 2:46:07 PM | notepad.exe | `"NOTEPAD.EXE" C:\Users\vmAdminUsername\Documents\PHTG\Notes 12122025.txt` |

**Answer:** `notepad.exe`

**Why It Matters:** Notepad opening a named file is a human action. Session startup spawns `explorer.exe`, `OneDrive.exe`, browser helpers — automated noise. The moment an operator opens a specific named document, they are deliberately reading content. This is the dividing line between session initialisation and intentional reconnaissance.

---

### 🗂️ 24 — Sensitive Text File

**Objective:** Among files opened during the attacker's session, identify the one most likely to provide internal operational advantage.

**KQL Query:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-12T06:47:45) .. datetime(2025-12-14T23:59:59))
| where DeviceName == "azwks-phtg-02" and InitiatingProcessAccountName == "vmadminusername"
| where ProcessCommandLine has "NOTEPAD.EXE" and ProcessCommandLine contains "C:"
| project TimeGenerated, ProcessCommandLine
| sort by TimeGenerated asc
```

**Results:**
| TimeGenerated | ProcessCommandLine |
|---------------|-------------------|
| Dec 12, 2025 2:46:14 PM | `"NOTEPAD.EXE" C:\Users\vmAdminUsername\Documents\PHTG\notes_sarah.txt` |

**Answer:** `notes_sarah.txt`

**Why It Matters:** A file named `notes_sarah.txt` belonging to Sarah Chen — the same user whose workstation appeared in the LinkedIn photo — is likely to contain internal notes, credentials, infrastructure details, or other security-relevant content that Sarah accumulated in the course of her HealthCloud deployment work. An attacker reading this file immediately after gaining access is performing targeted intelligence gathering, not random file browsing.

---

### 💾 25 — First Executable Form

**Objective:** Track the payload file from its initial disguise as a text file through its first rename into an executable filename.

**KQL Query:**
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-12T06:47:45) .. datetime(2025-12-14T23:59:59))
| where DeviceName == "azwks-phtg-02" and ActionType == "FileRenamed"
| where FileName contains ".exe" and PreviousFileName endswith ".txt"
| project TimeGenerated, ActionType, FileName, PreviousFileName, SHA256
| sort by TimeGenerated asc
```

**Results:**
| TimeGenerated | FileName | PreviousFileName | SHA256 |
|---------------|----------|------------------|--------|
| Dec 12, 2025 3:18:38 PM | `Sarah_Chen_Notes.exe` | `Sarah_Chen_Notes.exe.Txt` | `224462ce5e...` |

**Answer:** `Sarah_Chen_Notes.exe`

**Why It Matters:** The attacker delivered the payload with a `.txt` extension to pass any superficial file-type checks, then renamed it to `.exe` before execution. The social engineering layer is layered into the filename itself — a file called `Sarah_Chen_Notes` referencing the legitimate user on the machine is designed to blend into the working environment if spotted.

---

### 🎭 26 — Double-Extension Evasion

**Objective:** Identify the intermediate filename used between arrival as `.txt` and execution as `.exe`.

**Identified Activity:** *(From Finding 25 query — reviewing the full rename chain)*

**Results:**
| TimeGenerated | FileName | PreviousFileName |
|---------------|----------|-----------------|
| Dec 12, 2025 3:14:02 PM | `Sarah_Chen_Notes.exe.Txt` | `Sarah_Chen_Notes.Txt` |

**Answer:** `Sarah_Chen_Notes.exe.Txt`

**Why It Matters:** The double-extension technique (`name.exe.Txt`) exploits Windows' default behaviour of hiding known file extensions. A user or analyst seeing `Sarah_Chen_Notes.exe.Txt` in Explorer with extension hiding enabled would see `Sarah_Chen_Notes.exe` — a file that appears to already be an executable, but Windows would treat `.Txt` as the actual extension and not execute it directly. This intermediate state was used during the period when Defender was still in active mode and quarantining the file, buying time before the AV was disabled.

---

### #️⃣ 27 — File SHA256

**Objective:** Extract the canonical file hash to use as an immutable identifier across all rename events and detection records.

**Identified Activity:** *(From Finding 25 query results)*

**Answer:** `224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695`

**Why It Matters:** Filenames lie. This hash is the true identity of the payload regardless of what it was called at any point. Every rename event, every Defender detection, and every network connection query should be cross-referenced against this SHA256 to maintain an unbroken chain of evidence across the file's lifecycle on the system.

---

### 🏁 28 — Final File Name

**Objective:** Track the payload forward through all rename events to determine its final deployed name.

**KQL Query:**
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-12T06:47:45) .. datetime(2025-12-14T23:59:59))
| where DeviceName == "azwks-phtg-02" and ActionType == "FileRenamed"
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| project TimeGenerated, FileName
| sort by TimeGenerated desc
```

**Results:**
| TimeGenerated | FileName |
|---------------|----------|
| Dec 13, 2025 11:16:22 AM | `PHTG.exe` |

**Answer:** `PHTG.exe`

**Why It Matters:** The attacker renamed the payload to `PHTG.exe` — the same company abbreviation used in the legitimate HealthCloud service directory. This is not accidental. Naming the malicious binary after the organisation's own tooling is a deliberate blend technique, designed so that any analyst scanning the file system would see `PHTG.exe` inside a `PHTG\HealthCloud\` directory and assume it belongs there.

---

### 🦠 29 — File Classification

**Objective:** Obtain Microsoft Defender's own classification of the payload from on-device telemetry.

**KQL Query:**
```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-12T06:47:45) .. datetime(2025-12-14T23:59:59))
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| distinct tostring(AdditionalFields)
```

**Results:**
```json
{
  "Description": "Defender detected active 'Trojan:Win32/Meterpreter.RPZ!MTB' in file 'Sarah_Chen_Notes.exe'"
}
```

**Answer:** `Meterpreter`

**Why It Matters:** Meterpreter is the post-exploitation payload component of the Metasploit Framework. It operates entirely in memory, supports extensible modules for credential dumping, lateral movement, and file exfiltration, and communicates over encrypted channels. Its presence on this VM confirms this is not a commodity infection — Meterpreter is the tool of a hands-on operator who intends to use the compromised machine as an interactive foothold.

---

### 🛡️ 30 — Why Did It Run?

**Objective:** Determine why the payload executed successfully after Defender quarantined it three times.

**KQL Query:**
```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-12T14:11:00) .. datetime(2025-12-12T15:00:00))
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| where AdditionalFields contains "Windows Defender Antivirus"
| project AdditionalFields
```

**Results:**
```json
{
  "ThreatName": "Trojan:Win32/Meterpreter.RPZ!MTB",
  "ReportSource": "Windows Defender Antivirus passive mode"
}
```

**Answer:** Defender switched to **passive mode**

**Why It Matters:** In passive mode, Microsoft Defender can detect and report threats but **does not block or quarantine them**. This mode is typically activated when a third-party antivirus product is installed. The attacker deliberately triggered passive mode — likely by installing a conflicting product or modifying a registry key — to neutralise the one control that was successfully preventing execution. This is a deliberate, knowledgeable AV evasion action, not accidental.

---

### ▶️ 31 — First Execution

**Objective:** Identify the filename under which the payload ran during its initial execution phase.

**KQL Query:**
```kql
DeviceEvents
| where TimeGenerated between (datetime(2025-12-12T14:11:00) .. datetime(2025-12-23T15:00:00))
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| project TimeGenerated, FileName, InitiatingProcessFileName
| sort by TimeGenerated asc
```

**Results:**
| TimeGenerated | FileName | InitiatingProcessFileName |
|---------------|----------|--------------------------|
| Dec 12, 2025 3:18:52 PM | `Sarah_Chen_Notes.exe` | `Sarah_Chen_Notes.exe` |

**Answer:** `Sarah_Chen_Notes.exe`

**Why It Matters:** The first execution was direct — the operator ran `Sarah_Chen_Notes.exe` manually from their active RDP session immediately after Defender was placed in passive mode. This is hands-on keyboard behaviour, the attacker waited for the AV suppression to take effect, then executed the payload in real time.

---

### 🔄 32 — Parent Process

**Objective:** Identify how the payload was launched during its later, persistent execution phase.

**KQL Query:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-12T14:11:00) .. datetime(2025-12-23T15:00:00))
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| project TimeGenerated, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by TimeGenerated asc
```

**Results:**
| TimeGenerated | FileName | InitiatingProcessFileName | InitiatingProcessCommandLine |
|---------------|----------|--------------------------|------------------------------|
| Dec 13, 2025 11:21:48 AM | `PHTG.exe` | `cmd.exe` | `cmd.exe /c ""C:\ProgramData\PHTG\HealthCloud\Launch.bat"` |

**Answer:** `cmd.exe`

**Why It Matters:** The shift from direct execution to `cmd.exe` launching via a `.bat` file marks the transition from initial operator activity to **persistence**. The attacker is no longer manually running the payload from an active RDP session — they have embedded it into a startup or scheduled mechanism that survives session disconnection and system reboots.

---

### 📄 33 — Batch File Wrapper

**Objective:** Extract the full path of the batch file used to launch the payload in the persistent execution phase.

**Identified Activity:** *(From Finding 32 query results)*

**Answer:** `C:\ProgramData\PHTG\HealthCloud\Launch.bat`

**Why It Matters:** Placing `Launch.bat` inside `C:\ProgramData\PHTG\HealthCloud\` is a studied evasion choice. The HealthCloud service — rolled out just one day before the intrusion began — already had legitimate scheduled tasks and executables in this directory. A SOC analyst reviewing startup tasks would see `Launch.bat` in a known internal service's directory and be predisposed to treat it as legitimate without further scrutiny.

---

### 📡 34 — C2 IP

**Objective:** Identify the external IP address the compromised host communicated with after payload execution.

**KQL Query:**
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-12T11:21:48) .. datetime(2025-12-14T15:00:00))
| where DeviceName == "azwks-phtg-02"
| where InitiatingProcessFileName in ("phtg.exe", "sarah_chen_notes.exe")
| distinct RemoteIP
```

**Results:**
| RemoteIP |
|----------|
| 173.244.55.130 |

**Answer:** `173.244.55.130`

**Why It Matters:** The C2 IP (`173.244.55.130`) sits in the same `/24` subnet as the two RDP attacker IPs (`173.244.55.128` and `173.244.55.131`). The attacker used the same infrastructure block for initial access and command-and-control — a strong indicator of a single threat actor operating a small, consolidated set of VPS nodes. Blocking `173.244.55.0/24` severs both the RDP attack path and the active C2 channel.

---

### 🗺️ 35 — C2 Geography

**Objective:** Geolocate the C2 infrastructure.

**KQL Query:**
```kql
let GeoTable =
    externaldata(network:string, geoname_id:long, continent_code:string, 
                 continent_name:string, country_iso_code:string, country_name:string)
    [@"https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv"]
    with (format="csv");
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-12T11:21:48) .. datetime(2025-12-14T15:00:00))
| where RemoteIP == "173.244.55.130"
| evaluate ipv4_lookup(GeoTable, RemoteIP, network)
| distinct country_name, continent_name, RemotePort
```

**Results:**
| country_name | continent_name | RemotePort |
|--------------|----------------|------------|
| Uruguay | South America | 4444 |

**Answer:** `Uruguay, South America`

**Why It Matters:** The C2 infrastructure is geolocated to Uruguay — the same country as the successful RDP logons. This is not coincidence. The attacker's RDP access nodes and their Meterpreter listener are on the same infrastructure in the same country, confirming a single, consolidated threat actor operation rather than a purchased access hand-off to a separate group.

---

### 🔌 36 — C2 Remote Port

**Objective:** Document the port used for the attacker's post-execution C2 communication.

**Identified Activity:** *(From Finding 35 query results)*

**Answer:** `4444`

**Why It Matters:** Port 4444 is the **default Metasploit/Meterpreter listener port**. Its use here indicates the attacker either did not change the Metasploit default configuration, or assessed that outbound traffic on port 4444 from this VM would not be monitored or blocked. This is an actionable detection: any outbound connection from a corporate endpoint to port 4444 on a public IP should be treated as a high-confidence C2 indicator and generate an immediate alert.

---

### 🏗️ 37 — Repurposed Baseline

**Objective:** Confirm which legitimate internal service the attacker used as cover for their persistence mechanism.

**KQL Query:**
```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-12-12T06:47:45) .. datetime(2025-12-14T23:59:59))
| where DeviceName == "azwks-phtg-02" and ActionType == "FileRenamed"
| where SHA256 == "224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695"
| project TimeGenerated, FileName, FolderPath
| sort by TimeGenerated desc
```

**Results:**
| TimeGenerated | FileName | FolderPath |
|---------------|----------|------------|
| Dec 13, 2025 11:16:22 AM | `PHTG.exe` | `C:\ProgramData\PHTG\HealthCloud\PHTG.exe` |

**Answer:** `HealthCloud`

**Why It Matters:** The attacker did not build persistence from scratch. They read the environment, identified HealthCloud as a newly deployed service with an established legitimate footprint, and embedded their payload inside it. `PHTG.exe` in `C:\ProgramData\PHTG\HealthCloud\` is indistinguishable at a glance from a genuine HealthCloud component. The timing is deliberate: a service launched the previous day has not yet been baselined by the security team, making anomalous additions harder to detect. This is **living off the land** applied to internal service directories rather than system binaries.

---

## 🕒 Attack Timeline

| Time (UTC) | Log Source | Event |
|---|---|---|
| Dec 11, 2025 | LinkedIn | Sarah Chen posts photo; VM name, public IP, and Azure portal details exposed |
| Dec 12, 06:47 | DeviceNetworkEvents | First successful RDP connection from `173.244.55.131` (Uruguay) — **initial access** |
| Dec 12, 14:46 | DeviceProcessEvents | Attacker opens `Notes 12122025.txt` — session start, operator interaction begins |
| Dec 12, 14:46 | DeviceProcessEvents | Attacker opens `notes_sarah.txt` — targeted internal reconnaissance |
| Dec 12, 14:11–14:17 | DeviceEvents | Defender detects and quarantines `Trojan:Win32/Meterpreter.RPZ!MTB` three times |
| Dec 12, ~14:20 | DeviceEvents | Defender switched to **passive mode** — real-time protection neutralised |
| Dec 12, 15:14 | DeviceFileEvents | Payload renamed: `Sarah_Chen_Notes.Txt` → `Sarah_Chen_Notes.exe.Txt` (double-extension evasion) |
| Dec 12, 15:18 | DeviceFileEvents | Payload renamed: `Sarah_Chen_Notes.exe.Txt` → `Sarah_Chen_Notes.exe` (executable form) |
| Dec 12, 15:18 | DeviceEvents | `Sarah_Chen_Notes.exe` executes — **first execution phase** |
| Dec 12, 15:18 | DeviceNetworkEvents | Meterpreter C2 beacon to `173.244.55.130:4444` (Uruguay) |
| Dec 13, 11:16 | DeviceFileEvents | Payload renamed to `PHTG.exe`, moved to `C:\ProgramData\PHTG\HealthCloud\` |
| Dec 13, 11:21 | DeviceProcessEvents | `cmd.exe` launches `PHTG.exe` via `Launch.bat` — **persistent execution phase begins** |

---

## ⚠️ Defensive Gaps Identified

| Gap | Detail | Recommended Fix |
|---|---|---|
| Internet-exposed RDP | Port 3389 reachable from any public IP on `azwks-phtg-02` | Remove public IP from VM; enforce access via Azure Bastion or VPN with IP allowlisting |
| Weak admin account name | `vmadminusername` is a predictable credential-stuffing target | Rename admin accounts to non-guessable identifiers; enforce account lockout policy |
| No MFA on RDP | Credential stuffing succeeded without a second factor | Require MFA for all administrative RDP access via Entra ID or third-party MFA gateway |
| Defender passive mode achievable by operator | Attacker could place Defender in passive mode without triggering an alert | Alert on Defender state changes; restrict ability to modify AV state to privileged roles only |
| No outbound port 4444 alerting | Meterpreter C2 traffic to port 4444 was not detected or blocked | Create NSG rule blocking non-standard outbound ports; alert on any outbound connection to port 4444 |
| New service directory not baselined | HealthCloud deployed one day before intrusion; its file contents were never captured as a clean baseline | Capture signed file inventories for all new service deployments on day zero; alert on unsigned executables in service directories |
| LinkedIn OSINT exposure | Infrastructure details visible in a public social media post | Implement media and communications policy prohibiting photography of operational systems; conduct periodic OSINT reviews of staff profiles |

---

## 🛡️ Indicators of Compromise (IoCs)

| Type | Value | Context |
|------|-------|---------|
| IP Address | `173.244.55.128` | Attacker RDP source IP #1 (Uruguay) |
| IP Address | `173.244.55.131` | Attacker RDP source IP #2 (Uruguay) |
| IP Address | `173.244.55.130` | Meterpreter C2 listener (Uruguay) |
| IP Range | `173.244.55.0/24` | Full attacker infrastructure subnet |
| Public IP | `74.249.82.162` | VM public IP exposed via LinkedIn OSINT |
| Hostname | `azwks-phtg-02` | Compromised Azure VM |
| Account | `vmadminusername` | Compromised local administrator account |
| SHA256 | `224462ce5e3304e3fd0875eeabc829810a894911e3d4091d4e60e67a2687e695` | Meterpreter payload hash |
| Filename | `Sarah_Chen_Notes.Txt` | Initial payload delivery name |
| Filename | `Sarah_Chen_Notes.exe.Txt` | Double-extension evasion intermediate name |
| Filename | `Sarah_Chen_Notes.exe` | First executable form / Phase 1 execution name |
| Filename | `PHTG.exe` | Final persistent payload name |
| File Path | `C:\ProgramData\PHTG\HealthCloud\PHTG.exe` | Payload persistence location |
| File Path | `C:\ProgramData\PHTG\HealthCloud\Launch.bat` | Persistence launcher |
| File Path | `C:\Users\vmAdminUsername\Documents\PHTG\notes_sarah.txt` | Sensitive internal file accessed |
| Port | `4444` | Meterpreter default C2 port |
| Malware Family | `Trojan:Win32/Meterpreter.RPZ!MTB` | MDE threat classification |

---

## 🔧 Immediate Remediation Actions

1. **Isolate `azwks-phtg-02`** via Azure Network Security Group — remove public IP and block all inbound connections immediately.
2. **Terminate all active sessions** on the VM, including any live Meterpreter sessions.
3. **Delete `PHTG.exe`** from `C:\ProgramData\PHTG\HealthCloud\` and **delete `Launch.bat`**.
4. **Review all scheduled tasks and services** on the VM for additional persistence mechanisms planted during the attacker's 23+ RDP sessions.
5. **Disable and rename `vmadminusername`** — rotate all credentials that may have been visible in `notes_sarah.txt`.
6. **Restore Defender to active mode** and run a full scan. Audit what changes were made to security configuration during the intrusion window.
7. **Block `173.244.55.0/24`** at the Azure NSG level and in any upstream firewall or SIEM block list.
8. **Block outbound port 4444** across all Azure VMs in the tenant via NSG policy.
9. **Audit the HealthCloud service directory** across all hosts where it is deployed — confirm no other machines received the same payload.
10. **Review Sarah Chen's account** for any further exposure — her notes file was accessed by the attacker; treat all credentials or internal details she had documented as compromised.
11. **Deploy Azure Bastion** or equivalent jump host for all administrative RDP access and remove direct public RDP exposure from all VMs in the tenant.
12. **Conduct a LinkedIn OSINT sweep** of all engineering and cloud team profiles for inadvertent infrastructure disclosure; implement a clear communications policy for social media.
