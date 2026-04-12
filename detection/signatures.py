from __future__ import annotations

from typing import Literal, TypedDict


Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class PatternRule(TypedDict):
    """Fires on a single packet that matches all conditions."""
    name:       str
    type:       Literal["pattern"]
    severity:   Severity
    conditions: dict[str, object]


class RateRule(TypedDict):
    """Fires when a src_ip sends threshold+ matching packets within window_seconds."""
    name:           str
    type:           Literal["rate"]
    severity:       Severity
    conditions:     dict[str, object]
    threshold:      int
    window_seconds: int


Rule = PatternRule | RateRule


SIGNATURES: list[Rule] = [

    # ══════════════════════════════════════════════════════════════════════════
    # RECONNAISSANCE — Port & Host Scanning
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":           "Port Scan (SYN)",
        "type":           "rate",
        "severity":       "HIGH",
        "conditions": {
            # A flood of SYN-only packets to varying ports from one IP.
            # Classic nmap -sS stealth scan signature.
            "flags":    "S",
            "protocol": 6,
        },
        "threshold":      20,
        "window_seconds": 5,
    },

    {
        "name":           "Slow Port Scan",
        "type":           "rate",
        "severity":       "MEDIUM",
        "conditions": {
            # Low-and-slow SYN scan designed to evade rate-based detection.
            # Same signature as above but wider window catches patient scanners.
            "flags":    "S",
            "protocol": 6,
        },
        "threshold":      30,
        "window_seconds": 120,
    },

    {
        "name":     "Null Scan",
        "type":     "pattern",
        "severity": "HIGH",
        "conditions": {
            # TCP packet with no flags set (flags_int == 0).
            # Used to evade stateless firewalls and fingerprint OS TCP stacks.
            # RFC 793 compliant systems respond with RST; others ignore it.
            "protocol":  6,
            "flags_int": 0,
        },
    },

    {
        "name":     "XMAS Scan",
        "type":     "pattern",
        "severity": "HIGH",
        "conditions": {
            # FIN + PSH + URG all set simultaneously.
            # Scapy renders these flags as "FPU".
            # RFC 793 compliant systems respond RST; Windows ignores — used for OS detection.
            "protocol": 6,
            "flags":    "FPU",
        },
    },

    {
        "name":     "FIN Scan",
        "type":     "pattern",
        "severity": "MEDIUM",
        "conditions": {
            # Only FIN set with no ACK — invalid in any legitimate TCP session.
            # Some stateless firewalls pass FIN packets without session checking.
            "protocol": 6,
            "flags":    "F",
        },
    },

    {
        "name":           "Maimon Scan",
        "type":           "rate",
        "severity":       "MEDIUM",
        "conditions": {
            # FIN+ACK is normal in TCP teardown — a single packet is never suspicious.
            # Many FIN+ACK packets from the same IP in a short window means scanning.
            "protocol": 6,
            "flags":    "FA",
        },
        "threshold":      20,
        "window_seconds": 5,
    },

    {
        "name":           "ACK Scan",
        "type":           "rate",
        "severity":       "MEDIUM",
        "conditions": {
            # Pure ACK is sent constantly in established TCP — not suspicious alone.
            # A flood of bare ACKs from one IP probes firewall stateful rules.
            "protocol": 6,
            "flags":    "A",
        },
        "threshold":      50,
        "window_seconds": 5,
    },

    {
        "name":           "ICMP Host Sweep (Ping Sweep)",
        "type":           "rate",
        "severity":       "MEDIUM",
        "conditions": {
            # High rate of ICMP echo requests (type 8) = network host discovery.
            # Attacker is mapping which hosts are alive before targeting them.
            "protocol":  1,
            "icmp_type": 8,
        },
        "threshold":      20,
        "window_seconds": 10,
    },

    {
        "name":           "UDP Port Scan",
        "type":           "rate",
        "severity":       "MEDIUM",
        "conditions": {
            # High rate of outbound UDP from one IP = service discovery.
            # Threshold raised and window tightened to avoid false positives
            # from legitimate UDP-heavy apps (BitTorrent, VoIP, gaming).
            "protocol": 17,
        },
        "threshold":      100,
        "window_seconds": 5,
    },


    # ══════════════════════════════════════════════════════════════════════════
    # BRUTE FORCE — Credential Attacks
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":           "SSH Brute Force",
        "type":           "rate",
        "severity":       "CRITICAL",
        "conditions": {
            # Repeated SYN to port 22 from one IP = credential stuffing.
            # 10 attempts in 60 seconds far exceeds legitimate reconnection behavior.
            "dst_port": 22,
            "protocol": 6,
            "flags":    "S",
        },
        "threshold":      10,
        "window_seconds": 60,
    },

    {
        "name":           "RDP Brute Force",
        "type":           "rate",
        "severity":       "CRITICAL",
        "conditions": {
            # Repeated SYN to port 3389 (RDP) = remote desktop brute force.
            # RDP is one of the most targeted services for ransomware initial access.
            "dst_port": 3389,
            "protocol": 6,
            "flags":    "S",
        },
        "threshold":      10,
        "window_seconds": 60,
    },

    {
        "name":           "FTP Brute Force",
        "type":           "rate",
        "severity":       "HIGH",
        "conditions": {
            # Repeated SYN to port 21 (FTP control) = credential attack.
            # FTP is cleartext — even a successful login is a security event.
            "dst_port": 21,
            "protocol": 6,
            "flags":    "S",
        },
        "threshold":      10,
        "window_seconds": 60,
    },

    {
        "name":           "Telnet Brute Force",
        "type":           "rate",
        "severity":       "HIGH",
        "conditions": {
            # Repeated SYN to port 23 (Telnet) = credential attack.
            # Telnet should not exist on modern networks at all.
            "dst_port": 23,
            "protocol": 6,
            "flags":    "S",
        },
        "threshold":      5,
        "window_seconds": 30,
    },

    {
        "name":           "SMTP Auth Brute Force",
        "type":           "rate",
        "severity":       "HIGH",
        "conditions": {
            # Repeated SYN to port 587 (SMTP submission) = email credential attack.
            # Attackers gain relay access to send spam or phishing at scale.
            "dst_port": 587,
            "protocol": 6,
            "flags":    "S",
        },
        "threshold":      10,
        "window_seconds": 60,
    },

    {
        "name":           "IMAP Brute Force",
        "type":           "rate",
        "severity":       "HIGH",
        "conditions": {
            # Repeated SYN to port 143 (IMAP) or 993 (IMAPS).
            "dst_port": 143,
            "protocol": 6,
            "flags":    "S",
        },
        "threshold":      10,
        "window_seconds": 60,
    },

    {
        "name":           "POP3 Brute Force",
        "type":           "rate",
        "severity":       "HIGH",
        "conditions": {
            "dst_port": 110,
            "protocol": 6,
            "flags":    "S",
        },
        "threshold":      10,
        "window_seconds": 60,
    },

    {
        "name":           "VNC Brute Force",
        "type":           "rate",
        "severity":       "CRITICAL",
        "conditions": {
            # Repeated SYN to port 5900 (VNC) = remote desktop credential attack.
            # VNC often has weak/no authentication and provides full GUI access.
            "dst_port": 5900,
            "protocol": 6,
            "flags":    "S",
        },
        "threshold":      10,
        "window_seconds": 60,
    },

    {
        "name":           "MySQL Brute Force",
        "type":           "rate",
        "severity":       "CRITICAL",
        "conditions": {
            # Repeated SYN to port 3306 (MySQL) from external IP.
            # Database servers should never accept connections from the internet.
            "dst_port": 3306,
            "protocol": 6,
            "flags":    "S",
        },
        "threshold":      5,
        "window_seconds": 30,
    },

    {
        "name":           "PostgreSQL Brute Force",
        "type":           "rate",
        "severity":       "CRITICAL",
        "conditions": {
            "dst_port": 5432,
            "protocol": 6,
            "flags":    "S",
        },
        "threshold":      5,
        "window_seconds": 30,
    },

    {
        "name":           "MSSQL Brute Force",
        "type":           "rate",
        "severity":       "CRITICAL",
        "conditions": {
            "dst_port": 1433,
            "protocol": 6,
            "flags":    "S",
        },
        "threshold":      5,
        "window_seconds": 30,
    },


    # ══════════════════════════════════════════════════════════════════════════
    # DENIAL OF SERVICE — Flood Attacks
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":           "SYN Flood",
        "type":           "rate",
        "severity":       "CRITICAL",
        "conditions": {
            # Extremely high rate of SYN packets = TCP SYN flood DoS.
            # Exhausts server connection table with half-open connections.
            # Distinct from port scan: much higher threshold, any destination port.
            "flags":    "S",
            "protocol": 6,
        },
        "threshold":      200,
        "window_seconds": 5,
    },

    {
        "name":           "ICMP Flood",
        "type":           "rate",
        "severity":       "HIGH",
        "conditions": {
            # High rate of ICMP echo requests (type 8) from one IP = ping flood.
            # Can saturate bandwidth or exhaust target CPU with interrupt handling.
            "protocol":  1,
            "icmp_type": 8,
        },
        "threshold":      100,
        "window_seconds": 10,
    },

    {
        "name":           "UDP Flood",
        "type":           "rate",
        "severity":       "HIGH",
        "conditions": {
            # High rate of UDP from one IP = volumetric DoS or amplification setup.
            # UDP floods are commonly used in DDoS amplification (DNS, NTP, SSDP).
            "protocol": 17,
        },
        "threshold":      1000,
        "window_seconds": 10,
    },

    {
        "name":           "RST Flood",
        "type":           "rate",
        "severity":       "HIGH",
        "conditions": {
            # High rate of TCP RST packets = connection reset attack.
            # Can terminate legitimate TCP sessions and disrupt services.
            "flags":    "R",
            "protocol": 6,
        },
        "threshold":      100,
        "window_seconds": 10,
    },

    {
        "name":           "ACK Flood",
        "type":           "rate",
        "severity":       "HIGH",
        "conditions": {
            # High rate of ACK packets = ACK flood DDoS.
            # Bypasses SYN cookies since ACKs look like established session traffic.
            "flags":    "A",
            "protocol": 6,
        },
        "threshold":      500,
        "window_seconds": 10,
    },


    # ══════════════════════════════════════════════════════════════════════════
    # SUSPICIOUS SERVICES — Cleartext & Legacy Protocols
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":     "Telnet Attempt",
        "type":     "pattern",
        "severity": "MEDIUM",
        "conditions": {
            # Any Telnet connection attempt. Telnet is cleartext — credentials
            # and session data are visible to any network observer.
            "dst_port": 23,
            "protocol": 6,
        },
    },

    {
        "name":     "FTP Cleartext Login",
        "type":     "pattern",
        "severity": "MEDIUM",
        "conditions": {
            # Any FTP connection. FTP sends credentials in plaintext.
            # Should be replaced by SFTP (port 22) or FTPS (port 990).
            "dst_port": 21,
            "protocol": 6,
        },
    },

    {
        "name":     "rlogin / rsh Attempt",
        "type":     "pattern",
        "severity": "HIGH",
        "conditions": {
            # Ports 512 (rexec), 513 (rlogin), 514 (rsh) — legacy Unix remote access.
            # These protocols have no encryption and trust host-based authentication.
            "dst_port": [512, 513, 514],
            "protocol": 6,
        },
    },

    {
        "name":     "TFTP Access",
        "type":     "pattern",
        "severity": "MEDIUM",
        "conditions": {
            # TFTP (port 69) has no authentication whatsoever.
            # Used by attackers to exfiltrate configs or deliver malware payloads.
            "dst_port": 69,
            "protocol": 17,
        },
    },

    {
        "name":     "SNMP Access (v1/v2)",
        "type":     "pattern",
        "severity": "MEDIUM",
        "conditions": {
            # SNMP v1/v2 uses community strings (effectively cleartext passwords).
            # Exposes full device MIB — an attacker can read/write device configuration.
            "dst_port": 161,
            "protocol": 17,
        },
    },

    {
        "name":     "NFS Access",
        "type":     "pattern",
        "severity": "MEDIUM",
        "conditions": {
            # NFS (port 2049) — if exposed externally, allows filesystem access.
            # Misconfigured NFS exports are a common data exfiltration vector.
            "dst_port": 2049,
            "protocol": [6, 17],
        },
    },


    # ══════════════════════════════════════════════════════════════════════════
    # MALWARE & C2 — Command and Control Indicators
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":     "Known C2 / Backdoor Port",
        "type":     "pattern",
        "severity": "CRITICAL",
        "conditions": {
            # Ports commonly associated with RATs, reverse shells, and C2 frameworks.
            # 4444: Metasploit default, 1337/31337: leet ports used by old-school backdoors,
            # 9001: Tor relay default (also Meterpreter), 6666/6667: IRC C2 channels,
            # 8888: common alternative HTTP C2, 1234/12345: generic backdoor defaults.
            "dst_port": [4444, 1337, 31337, 9001, 6666, 6667, 8888, 1234, 12345, 54321],
        },
    },

    {
        "name":     "Possible Reverse Shell (High Outbound Port)",
        "type":     "pattern",
        "severity": "HIGH",
        "conditions": {
            # Outbound TCP SYN to ports > 60000 — unusual for legitimate services.
            # Reverse shells often use high ephemeral-looking ports to blend in.
            # Note: this is a heuristic and will have false positives.
            "dst_port": [60000, 60001, 60002, 60003, 60004, 60005,
                         61000, 62000, 63000, 64000, 65000, 65535],
            "protocol": 6,
            "flags":    "S",
        },
    },

    {
        "name":     "IRC Traffic (Possible Botnet C2)",
        "type":     "pattern",
        "severity": "MEDIUM",
        "conditions": {
            # IRC ports 6660–6669 and 7000. IRC-based botnets use these for C2.
            # Legitimate IRC use is rare on corporate networks.
            "dst_port": [6660, 6661, 6662, 6663, 6664, 6665, 6668, 6669, 7000],
            "protocol": 6,
        },
    },

    {
        "name":     "Tor Default Port",
        "type":     "pattern",
        "severity": "MEDIUM",
        "conditions": {
            # Port 9050 (Tor SOCKS proxy) / 9150 (Tor Browser).
            # May indicate attempts to anonymize traffic or bypass DLP controls.
            "dst_port": [9050, 9150, 9051],
            "protocol": 6,
        },
    },

    {
        "name":     "DNS over Non-Standard Port (Possible DNS Tunneling)",
        "type":     "pattern",
        "severity": "MEDIUM",
        "conditions": {
            # DNS should only run on port 53 UDP/TCP.
            # DNS tunneling tools (dnscat2, iodine) sometimes use alternate ports.
            "dst_port": [5353, 5354, 8053, 8853],
            "protocol": 17,
        },
    },

    {
        "name":           "Beaconing — High Frequency Outbound (Possible C2 Heartbeat)",
        "type":           "rate",
        "severity":       "HIGH",
        "conditions": {
            # Malware beacons home at regular intervals. High SYN rate to a single
            # external destination is a C2 heartbeat signature.
            # Correlate with threat intel for best results.
            "flags":    "S",
            "protocol": 6,
        },
        "threshold":      60,
        "window_seconds": 60,
    },


    # ══════════════════════════════════════════════════════════════════════════
    # LATERAL MOVEMENT — Internal Spread
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":     "SMB Access (Possible Lateral Movement)",
        "type":     "pattern",
        "severity": "MEDIUM",
        "conditions": {
            # SMB (445) and NetBIOS (139) — primary protocols for Windows lateral movement.
            # Used by EternalBlue, WannaCry, NotPetya, and most ransomware families.
            "dst_port": [445, 139],
            "protocol": 6,
        },
    },

    {
        "name":           "SMB Sweep (Ransomware Propagation)",
        "type":           "rate",
        "severity":       "CRITICAL",
        "conditions": {
            # Rapid SMB connection attempts across many hosts = worm/ransomware spreading.
            # EternalBlue-based attacks produce exactly this pattern.
            "dst_port": 445,
            "protocol": 6,
            "flags":    "S",
        },
        "threshold":      10,
        "window_seconds": 10,
    },

    {
        "name":     "WinRM Access (Possible Lateral Movement)",
        "type":     "pattern",
        "severity": "MEDIUM",
        "conditions": {
            # WinRM ports 5985 (HTTP) and 5986 (HTTPS).
            # Used by PowerShell remoting and common in post-exploitation frameworks.
            "dst_port": [5985, 5986],
            "protocol": 6,
        },
    },

    {
        "name":     "DCOM / RPC Access",
        "type":     "pattern",
        "severity": "MEDIUM",
        "conditions": {
            # Port 135 (MS-RPC endpoint mapper) — used by DCOM lateral movement.
            # Many exploits chain port 135 with dynamic high ports for code execution.
            "dst_port": 135,
            "protocol": 6,
        },
    },

    {
        "name":     "Remote Registry Access",
        "type":     "pattern",
        "severity": "HIGH",
        "conditions": {
            # Port 137/138 NetBIOS Name Service — used for Windows host enumeration.
            "dst_port": [137, 138],
            "protocol": 17,
        },
    },

    {
        "name":     "LDAP Enumeration",
        "type":     "pattern",
        "severity": "MEDIUM",
        "conditions": {
            # LDAP (389) and LDAPS (636) — used for Active Directory enumeration.
            # Attackers query LDAP to map users, groups, and privilege structure.
            "dst_port": [389, 636],
            "protocol": [6, 17],
        },
    },

    {
        "name":           "Kerberos Brute Force (AS-REP Roasting / Password Spray)",
        "type":           "rate",
        "severity":       "CRITICAL",
        "conditions": {
            # High rate to port 88 (Kerberos) = AS-REP Roasting or Kerberoasting.
            # Attackers request service tickets to crack offline.
            "dst_port": 88,
            "protocol": [6, 17],
        },
        "threshold":      20,
        "window_seconds": 30,
    },


    # ══════════════════════════════════════════════════════════════════════════
    # EXPLOITATION — Vulnerable Services
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":     "Log4Shell Target Port (8080/8443)",
        "type":     "pattern",
        "severity": "HIGH",
        "conditions": {
            # Common ports for Java application servers targeted by Log4Shell (CVE-2021-44228).
            # Payload detection requires DPI — this flags inbound connections for review.
            "dst_port": [8080, 8443, 8009],
            "protocol": 6,
        },
    },

    {
        "name":     "Redis Exposed (No Auth)",
        "type":     "pattern",
        "severity": "CRITICAL",
        "conditions": {
            # Redis (6379) should never be externally accessible.
            # Unauthenticated Redis allows arbitrary command execution and data theft.
            "dst_port": 6379,
            "protocol": 6,
        },
    },

    {
        "name":     "Elasticsearch Exposed",
        "type":     "pattern",
        "severity": "CRITICAL",
        "conditions": {
            # Elasticsearch (9200, 9300) has no auth by default in older versions.
            # Exposed instances have led to massive data breaches.
            "dst_port": [9200, 9300],
            "protocol": 6,
        },
    },

    {
        "name":     "MongoDB Exposed",
        "type":     "pattern",
        "severity": "CRITICAL",
        "conditions": {
            # MongoDB (27017) with no auth = full database read/write access.
            # Exposed MongoDB instances are routinely wiped and ransomed.
            "dst_port": 27017,
            "protocol": 6,
        },
    },

    {
        "name":     "Docker API Exposed",
        "type":     "pattern",
        "severity": "CRITICAL",
        "conditions": {
            # Docker daemon API (2375 unencrypted, 2376 TLS).
            # An exposed Docker socket allows container escape and full host compromise.
            "dst_port": [2375, 2376],
            "protocol": 6,
        },
    },

    {
        "name":     "Kubernetes API Exposed",
        "type":     "pattern",
        "severity": "CRITICAL",
        "conditions": {
            # Kubernetes API server (6443, 8001).
            # Exposed K8s API allows cluster takeover and mass container deployment.
            "dst_port": [6443, 8001],
            "protocol": 6,
        },
    },

    {
        "name":     "etcd Exposed",
        "type":     "pattern",
        "severity": "CRITICAL",
        "conditions": {
            # etcd (2379, 2380) stores Kubernetes secrets and cluster state.
            # Direct etcd access bypasses all Kubernetes RBAC controls.
            "dst_port": [2379, 2380],
            "protocol": 6,
        },
    },

    {
        "name":     "Memcached Exposed (DDoS Amplification)",
        "type":     "pattern",
        "severity": "HIGH",
        "conditions": {
            # Memcached (11211) UDP — has been used for 50,000x amplification DDoS attacks.
            # Should never be accessible externally.
            "dst_port": 11211,
            "protocol": 17,
        },
    },

    {
        "name":     "CouchDB Exposed",
        "type":     "pattern",
        "severity": "HIGH",
        "conditions": {
            "dst_port": 5984,
            "protocol": 6,
        },
    },

    {
        "name":     "Hadoop / HDFS Exposed",
        "type":     "pattern",
        "severity": "HIGH",
        "conditions": {
            # Hadoop NameNode (9000), HDFS (50070), YARN ResourceManager (8088).
            # Exposed Hadoop clusters allow arbitrary code execution via YARN.
            "dst_port": [9000, 50070, 8088],
            "protocol": 6,
        },
    },


    # ══════════════════════════════════════════════════════════════════════════
    # EXFILTRATION — Data Leaving the Network
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":           "DNS Query Flood (Possible DNS Tunneling)",
        "type":           "rate",
        "severity":       "HIGH",
        "conditions": {
            # Abnormally high DNS query rate from one host = DNS tunneling.
            # Tools like dnscat2 and iodine encode data in DNS queries for exfiltration.
            "dst_port": 53,
            "protocol": 17,
        },
        "threshold":      200,
        "window_seconds": 60,
    },

    {
        "name":           "ICMP Exfiltration (Large Volume)",
        "type":           "rate",
        "severity":       "MEDIUM",
        "conditions": {
            # Sustained ICMP echo traffic can carry data in the payload.
            # Legitimate ping traffic is low volume and infrequent.
            "protocol":  1,
            "icmp_type": 8,
        },
        "threshold":      50,
        "window_seconds": 60,
    },

    {
        "name":     "FTP Data Channel (Possible Exfiltration)",
        "type":     "pattern",
        "severity": "LOW",
        "conditions": {
            # FTP data channel (port 20) — flag for review in environments that
            # have banned FTP. Large transfers may indicate data exfiltration.
            "src_port": 20,
            "protocol": 6,
        },
    },


    # ══════════════════════════════════════════════════════════════════════════
    # NETWORK INFRASTRUCTURE ATTACKS
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":           "DNS Amplification Attack",
        "type":           "rate",
        "severity":       "CRITICAL",
        "conditions": {
            # High rate of DNS responses (src_port 53) = amplification attack in progress.
            # Attacker spoofs victim IP; DNS servers send large responses to victim.
            "src_port": 53,
            "protocol": 17,
        },
        "threshold":      500,
        "window_seconds": 10,
    },

    {
        "name":           "NTP Amplification Attack",
        "type":           "rate",
        "severity":       "CRITICAL",
        "conditions": {
            # High rate of NTP responses (src_port 123) = NTP amplification DDoS.
            # Monlist command produces ~200x amplification factor.
            "src_port": 123,
            "protocol": 17,
        },
        "threshold":      200,
        "window_seconds": 10,
    },

    {
        "name":     "BGP Hijack Attempt",
        "type":     "pattern",
        "severity": "CRITICAL",
        "conditions": {
            # Unexpected BGP (port 179) connection from non-peering IP.
            # BGP session hijacking can reroute internet traffic at scale.
            "dst_port": 179,
            "protocol": 6,
        },
    },

    {
        "name":     "Spanning Tree / BPDU Injection",
        "type":     "pattern",
        "severity": "HIGH",
        "conditions": {
            # Unexpected traffic on port 7 (Echo) can indicate STP manipulation
            # or network topology probing in some implementations.
            "dst_port": 7,
            "protocol": [6, 17],
        },
    },

    {
        "name":     "OSPF / Routing Protocol Access",
        "type":     "pattern",
        "severity": "HIGH",
        "conditions": {
            # Traffic to port 89 (OSPF) from unexpected sources.
            # OSPF injection can poison routing tables across the network.
            "dst_port": 89,
            "protocol": 6,
        },
    },


    # ══════════════════════════════════════════════════════════════════════════
    # INDUSTRIAL / OT — ICS/SCADA Protocols
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":     "Modbus Access (ICS Protocol)",
        "type":     "pattern",
        "severity": "HIGH",
        "conditions": {
            # Modbus TCP (port 502) — industrial control system protocol.
            # Has no authentication; any device can read/write PLC registers.
            "dst_port": 502,
            "protocol": 6,
        },
    },

    {
        "name":     "DNP3 Access (ICS Protocol)",
        "type":     "pattern",
        "severity": "HIGH",
        "conditions": {
            # DNP3 (port 20000) — used in electric utilities and water systems.
            "dst_port": 20000,
            "protocol": [6, 17],
        },
    },

    {
        "name":     "EtherNet/IP Access (ICS Protocol)",
        "type":     "pattern",
        "severity": "HIGH",
        "conditions": {
            # EtherNet/IP (port 44818) — Rockwell/Allen-Bradley PLC protocol.
            "dst_port": 44818,
            "protocol": [6, 17],
        },
    },

    {
        "name":     "BACnet Access (Building Automation)",
        "type":     "pattern",
        "severity": "MEDIUM",
        "conditions": {
            # BACnet (port 47808) — HVAC, lighting, and building control systems.
            # Compromised BACnet can manipulate physical building infrastructure.
            "dst_port": 47808,
            "protocol": 17,
        },
    },


    # ══════════════════════════════════════════════════════════════════════════
    # MISCELLANEOUS — Low-Signal but Worth Logging
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":     "Proxy / Anonymizer Port",
        "type":     "pattern",
        "severity": "LOW",
        "conditions": {
            # Common open proxy and SOCKS ports (3128 Squid, 8080 generic, 1080 SOCKS).
            # May indicate policy violations or attempts to bypass network controls.
            "dst_port": [3128, 1080, 8118],
            "protocol": 6,
        },
    },

    {
        "name":     "P2P / BitTorrent Port",
        "type":     "pattern",
        "severity": "LOW",
        "conditions": {
            # BitTorrent commonly uses ports 6881–6889.
            # Indicates policy violation and potential copyright/malware risk.
            "dst_port": [6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889],
            "protocol": [6, 17],
        },
    },

    {
        "name":     "Cryptocurrency Mining Pool",
        "type":     "pattern",
        "severity": "HIGH",
        "conditions": {
            # Stratum protocol ports used by crypto mining pools (3333, 3334, 3335,
            # 4444 overlaps with Metasploit, 14444, 45700).
            # Outbound connections = cryptojacking malware on an internal host.
            "dst_port": [3333, 3334, 3335, 14444, 45700],
            "protocol": 6,
        },
    },

    {
        "name":     "Cobalt Strike Default Beacon Port",
        "type":     "pattern",
        "severity": "CRITICAL",
        "conditions": {
            # Port 50050 is Cobalt Strike's default team server port.
            # Any internal host connecting outbound to this port is compromised.
            "dst_port": 50050,
            "protocol": 6,
        },
    },

    {
        "name":     "Netcat / Bind Shell Default Port",
        "type":     "pattern",
        "severity": "HIGH",
        "conditions": {
            # Port 4242 is a common netcat bind shell default used in CTFs and attacks.
            "dst_port": 4242,
            "protocol": 6,
        },
    },

    {
        "name":           "Port Knocking Probe (Sequential Low Ports)",
        "type":           "rate",
        "severity":       "LOW",
        "conditions": {
            # Low-port TCP probes (ports < 1024) in rapid succession from one IP.
            # May indicate port knocking to trigger a hidden service.
            "protocol": 6,
            "flags":    "S",
        },
        "threshold":      15,
        "window_seconds": 3,
    },

]
