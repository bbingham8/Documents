## Wireshark Investigation Cheat Sheet

### 🛡️ Reconnaissance & Scanning
Attackers usually knock on the doors before they kick them in. These filters help look for scanning behavior, like intense port scans or sweeping sweeps.

* **SYN Scans (Half-Open):** `tcp.flags.syn == 1 && tcp.flags.ack == 0`

	* *What to look for:* A massive volume of these from a single IP targeting multiple ports usually indicates a classic SYN port scan.

* **FIN Scans:** `tcp.flags.fin == 1 && tcp.flags.ack == 0`

	* *What to look for:* Used to sneak past stealth-detection mechanisms that look for SYN packets.

* **Xmas Scans:** `tcp.flags == 0x029` (or `tcp.flags.fin==1 && tcp.flags.psh==1 && tcp.flags.urg==1`)

	* *What to look for:* Packets with FIN, PUSH, and URG flags set all at once ("lit up like a Christmas tree").

### 💥 Brute-Force & Access Attacks
Once an adversary finds an open service, they might try to force their way in.

#### Remote Desktop (RDP) & SSH
* **High-Volume SSH Traffic:** `tcp.port == 22 && ip.len > 100`

	* *What to look for:* Repeated large packets on port 22 in a short window often signals an active brute-force attempt or data exfiltration.

* **RDP Connection Errors:** `rdp.pdu.type == 0x2 || rdp.pdu.type == 0x3`

	* *What to look for:* Frequent connection drops or routing errors can indicate automated tooling attempting to hit an RDP endpoint.

#### Web & Databases
* **SQL Injection (SQLi) Hints:** `http.request.uri contains "select" || http.request.uri contains "union" || http.request.uri contains "'"`

	* *What to look for:* Looking directly inside the URI strings for database keywords or escape characters.

* **Cross-Site Scripting (XSS) Hints:** `http.request.uri contains "<script>"`

	* *What to look for:* Attempts to inject JavaScript directly via HTTP GET requests.

### ☣️ Malware & Command & Control (C2)
After gaining a foothold, malware needs to communicate back home or move laterally.

#### DNS Anomalies
* **DNS Tunneling / Large Queries:** `dns.qry.name.len > 30 && !dns.flags.response`

	* *What to look for:* Incredibly long subdomains (e.g., `amFzb25zZWN1cml0eQ==.attacker.com`). This is a classic sign of data being smuggled out or commands being smuggled in via DNS queries.

* **TXT Record Hunting:** `dns.qry.type == 16`

	* *What to look for:* Attackers often use TXT records to pull down payloads or configurations because organizations rarely block them.

#### HTTP / Cleartext C2
* **Non-Standard Port HTTP Traffic:** `http && !tcp.port == 80 && !tcp.port == 8080`

	* *What to look for:* Web traffic executing over random, high-numbered ports—a common trick for basic C2 beacons.

* **Executable Downloads:** `http.content_type contains "application/x-msdownload" || http.request.uri contains ".exe"`

	* *What to look for:* Cleartext downloads of Windows binaries.

### 🎯 Network Anomalies & Lateral Movement
* **Rogue DHCP Servers:** `bootp.type == 2`

	* *What to look for:* DHCP replies. If you see replies coming from an IP address that isn't your authorized DHCP server, someone might be running a Man-in-the-Middle (MitM) attack.

* **ARP Spoofing / Poisoning:** `arp.duplicate-address-frame`

	* *What to look for:* Wireshark's built-in alert when it notices two different MAC addresses claiming the exact same IP address.

* **Suspicious SMB/RPC Activity:** `tcp.port == 445 && (smb || smb2)`

	* *What to look for:* Monitor this alongside specific internal IPs to trace lateral movement tools (like PsExec) moving across the network.

### 💡 Quick Investigation Tips
Isolate the Host: When you find a suspicious asset, pivot immediately by framing your view around that specific device using:
 
`ip.addr == 192.168.1.50` (or `ipv6.addr` for IPv6 environments).

To strip away normal traffic and only look at the handshakes that didn't complete properly (indicating connection failures, rejected ports, or resets), use this combo filter:
 
`tcp.flags.reset == 1 || tcp.flags.syn == 1`