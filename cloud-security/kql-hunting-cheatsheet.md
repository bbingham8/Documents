## KQL Threat Hunting Cheat Sheet

### 🛡️ Reconnaissance & Port Scanning
In Wireshark, you look for individual SYN flags. In KQL, you look for the result of that behavior: a single source IP hitting a massive number of distinct destination ports in a tiny window, often resulting in dropped connections.

```
// Hunting for potential inbound Port Scans
CommonSecurityLog
| where TimeGenerated > ago(1h)
| where DeviceAction in ("deny", "drop", "block")
| summarize DistinctPorts = dcount(DestinationPort), TotalHits = count() by SourceIP
| where DistinctPorts > 50 or TotalHits > 500
| order by DistinctPorts desc
```

*What this does:* Aggregates firewall drops over the last hour. If a single external IP hits more than 50 unique ports or fires off more than 500 total connection attempts that got blocked, it bubbles straight to the top.

### 💥 Brute Force Access Attacks

Instead of looking for raw SSH or RDP packet sizes, KQL lets you pivot to endpoint and authentication logs to see the actual blast radius.

#### Network-Level SSH/RDP Spikes
If you are hunting purely on network connection data (e.g., Syslog or Zeek/Bro data):

```
// Broad network volume spikes on management ports
VMConnection
| where TimeGenerated > ago(2h)
| where DestinationPort in (22, 3389)
| summarize ConnectionCount = count() by SourceIp, DestinationIp, DestinationPort, bin(TimeGenerated, 5m)
| where ConnectionCount > 100
```

#### Endpoint-Level Verification (The "Did they get in?" test)
Network logs tell you they tried; authentication logs tell you if they succeeded. You can look for a high volume of failures followed by a single success from the same IP:

```
// Failed logins followed by a success (Targeting Windows RDP / Type 10)
let FailureThreshold = 10;
let SuspiciousIPs = SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4625 and LogonType == 10 // Remote Interactive (RDP)
| summarize Failures = count() by IpAddress
| where Failures >= FailureThreshold
| project IpAddress;
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID == 4624 and LogonType == 10
| where IpAddress in (SuspiciousIPs)
| project TimeGenerated, Computer, Account, IpAddress, Message
```

### ☣️ Malware & Command & Control (C2)

In Wireshark, you manually measure string lengths or look for TXT records. KQL handles string manipulation and record types natively across millions of DNS events.

#### DNS Tunneling & Long Domain Queries

```
// Hunting for DNS Exfiltration / Tunneling via long subdomains
DnsEvents
| where TimeGenerated > ago(1d)
| where QueryType == "A" or QueryType == "AAAA"
| extend DomainLength = strlen(Name)
| where DomainLength > 35
| summarize QueryCount = count() by Name, ClientIP, DomainLength
| order by DomainLength desc
```

#### Suspicious DNS TXT Record Requests
Attackers love TXT records for low-and-slow payload delivery because they slip past standard web proxies.

```
// Monitoring anomalous TXT query volumes
DnsEvents
| where TimeGenerated > ago(12h)
| where QueryType == "TXT"
| summarize TXTCount = count() by ClientIP, Name
| where TXTCount > 10 // Normal networks rarely spam TXT requests
| order by TXTCount desc
```

### 🎯 Lateral Movement (Internal Pivoting)

When an attacker moves laterally using tools like PsExec or WMI, they rely heavily on SMB (Port 445). In Wireshark, you trace the stream. In KQL, you look for a single internal asset suddenly acting as a client to numerous other internal assets.

```
// Tracking internal lateral movement via SMB
DeviceNetworkEvents
| where TimeGenerated > ago(4h)
| where RemotePort == 445
| where InitiatingProcessName in~ ("psexec.exe", "psexesvc.exe", "cmd.exe", "powershell.exe", "services.exe")
| summarize TargetCount = dcount(RemoteIP) by LocalIP, InitiatingProcessName
| where TargetCount > 3
```

### 💡 Pro-Tip for Translating Wireshark to KQL
| Investigation Concept | Wireshark Filter | KQL Equivalent (DeviceNetworkEvents) |
| :--- | :--- | :--- |
| **Isolate Host IP** | `ip.addr == 192.168.1.50` | `where LocalIP == "192.168.1.50" or RemoteIP == "192.168.1.50"` |
| **Target Specific Port** | `tcp.port == 445` | `where RemotePort == 445` |
| **Hunt for SYN Scans** | `tcp.flags.syn == 1 && tcp.flags.ack == 0` | `where NetworkProtocol == "TCP" and ActionType == "ConnectionAttempt"` |
| **Identify Failed Connections**| `tcp.flags.reset == 1` | `where ActionType == "ConnectionFailed"` |