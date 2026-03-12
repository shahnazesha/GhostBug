# GhostBug PCAP Analysis - How Attack Detection Works

## Overview
GhostBug uses **rule-based intrusion detection** to analyze PCAP files. The system examines each network packet and matches it against a database of security rules.

---

## How Analysis Works

### Step 1: Packet Extraction
The Python script (`python/analyze_pcap.py`) uses **pyshark** to parse the PCAP file and extract from each packet:

- **Source IP** (IPv4 or IPv6)
- **Destination IP** (IPv4 or IPv6)
- **Source Port** (if TCP/UDP)
- **Destination Port** (if TCP/UDP)
- **Protocol** (TCP, UDP, ICMP, HTTP, etc.)
- **Payload Content** (raw packet data, if available)

### Step 2: Rule Matching
For each packet, the system checks it against **all enabled rules** in the `ids_rules` database table.

Each rule can match on:
- **`src_ip`** - Source IP address matches exactly
- **`dst_ip`** - Destination IP address matches exactly
- **`src_port`** - Source port number matches
- **`dst_port`** - Destination port number matches
- **`protocol`** - Protocol name matches (case-insensitive)
- **`payload_contains`** - Packet payload contains a specific string (case-insensitive)

### Step 3: Alert Generation
When a rule matches, an alert is created in `analysis_results` with:
- The rule that triggered it
- Severity level (from the rule)
- Source → Destination flow information
- Timestamp of the packet
- Protocol and port details

---

## Severity Levels Explained

**Severity is NOT automatically determined** - it's set by the **admin when creating each rule**. Here's the typical logic:

### 🔴 **CRITICAL**
High-risk indicators that suggest active compromise or immediate threat:
- **Remote Desktop Protocol (RDP)** on port 3389 - allows remote access if compromised
- **Known malicious IP addresses** - from threat intelligence feeds
- **Suspicious command & control (C2) traffic** - malware communication
- **High-value port scans** targeting critical services

**Example Rules:**
- `dst_port = 3389` → Critical (RDP exposure)
- `dst_ip = 203.0.113.50` → Critical (known malicious IP)

### 🟡 **WARNING**
Suspicious activity that may indicate reconnaissance, policy violations, or potential threats:
- **Telnet traffic** (port 23) - unencrypted, often abused
- **Cleartext passwords** in payloads - security risk
- **Unusual port activity** - may indicate scanning
- **Non-standard protocols** in sensitive contexts

**Example Rules:**
- `dst_port = 23` → Warning (Telnet is insecure)
- `payload_contains = "password"` → Warning (possible credential exposure)

### 🔵 **INFO**
Informational alerts for monitoring and compliance:
- **Normal but logged activity** - for audit trails
- **Low-risk protocol usage** - documentation purposes
- **Baseline traffic patterns** - for trend analysis

---

## Default Rules (Pre-loaded)

When you first set up GhostBug, these example rules are created:

| Rule Name | Type | Match Value | Severity | Why? |
|-----------|------|-------------|----------|------|
| Suspicious destination port 23 | `dst_port` | `23` | **Warning** | Telnet is unencrypted and often exploited |
| Critical port 3389 | `dst_port` | `3389` | **Critical** | RDP allows remote desktop access - high risk if exposed |
| Possible malware C2 IP | `dst_ip` | `203.0.113.50` | **Critical** | Matches known malicious IP address |
| Cleartext password keyword | `payload_contains` | `password` | **Warning** | Detects potential credential leakage in packets |

---

## How to Add Custom Rules

As an **admin**, go to **IDS Rules** page and create rules like:

### Example: Detect SSH brute force attempts
- **Name:** "SSH brute force detection"
- **Type:** `dst_port`
- **Match:** `22`
- **Severity:** Warning
- **Description:** "Detects SSH connection attempts"

### Example: Block specific malicious domain
- **Name:** "Block malicious domain"
- **Type:** `payload_contains`
- **Match:** `evil-domain.com`
- **Severity:** Critical

### Example: Detect SQL injection attempts
- **Name:** "SQL injection pattern"
- **Type:** `payload_contains`
- **Match:** `UNION SELECT`
- **Severity:** Critical

---

## Limitations & Future Enhancements

**Current System:**
- ✅ Simple pattern matching (exact matches)
- ✅ Rule-based signatures
- ✅ Manual severity assignment

**Not Currently Detected:**
- ❌ Behavioral anomalies (e.g., unusual traffic volume)
- ❌ Multi-packet attack patterns (requires state tracking)
- ❌ Encrypted payload analysis (TLS/SSL content)
- ❌ Automatic severity calculation based on context
- ❌ Machine learning-based detection

**Possible Future Additions:**
- Rate-based rules (e.g., "more than 100 connections per minute")
- Protocol-specific deep inspection
- Integration with threat intelligence APIs
- Anomaly detection algorithms

---

## Understanding Your Results

When you view alerts in the **Dashboard**, you'll see:
- **Rule name** - What triggered the alert
- **Severity badge** - Critical (red), Warning (yellow), Info (blue)
- **Flow** - Source IP → Destination IP : Port
- **File** - Which PCAP file contained this packet

**Remember:** Not every alert is an actual attack. Some may be:
- False positives (legitimate traffic matching a rule)
- Reconnaissance activity (scanning, probing)
- Policy violations (unauthorized services)

Always investigate alerts in context!

---

## Technical Details

**Python Script:** `python/analyze_pcap.py`
- Uses `pyshark` library (requires Wireshark/TShark installed)
- Processes packets sequentially
- Inserts alerts directly into MySQL database
- Updates upload status: `pending` → `analyzing` → `completed` (or `failed`)

**Database Tables:**
- `ids_rules` - Stores all detection rules
- `analysis_results` - Stores triggered alerts
- `pcap_uploads` - Tracks uploaded files and analysis status
