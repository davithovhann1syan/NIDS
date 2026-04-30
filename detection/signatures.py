from __future__ import annotations

from typing import Literal, NotRequired, TypedDict


Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class PatternRule(TypedDict):
    """Fires on a single packet that matches all conditions."""
    name:       str
    type:       Literal["pattern"]
    severity:   Severity
    conditions: dict[str, object]
    mitre:      NotRequired[str]


class RateRule(TypedDict):
    """Fires when a src_ip sends threshold+ matching packets within window_seconds."""
    name:           str
    type:           Literal["rate"]
    severity:       Severity
    conditions:     dict[str, object]
    threshold:      int
    window_seconds: int
    mitre:          NotRequired[str]


class MultiDestRule(TypedDict):
    """Fires when a src_ip reaches threshold+ *unique* tracked values (dst_port or dst_ip)
    within window_seconds.  More accurate than raw packet counts for scan detection."""
    name:           str
    type:           Literal["multi_destination"]
    severity:       Severity
    conditions:     dict[str, object]
    track:          Literal["dst_port", "dst_ip"]
    threshold:      int
    window_seconds: int
    mitre:          NotRequired[str]


Rule = PatternRule | RateRule | MultiDestRule


# Condition values support four forms — see sig_detector._matches_conditions for full docs:
#   plain value   → equality
#   [list]        → membership
#   {">": v}      → comparison operators (also >=, <, <=, !=, not_in, mask)
#   {"mask": v}   → bitmask: (actual & v) == v


SIGNATURES: list[Rule] = [

    # ══════════════════════════════════════════════════════════════════════════
    # RECONNAISSANCE — Port & Host Scanning
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":           "Port Scan (SYN)",
        "type":           "rate",
        "severity":       "HIGH",
        "mitre":          "T1046",
        "conditions": {
            # Flood of SYN-only packets — classic nmap -sS stealth scan signature.
            # Note: rate rules track per source IP, not per destination port, so this
            # also fires on worms or clients making many outbound connections quickly.
            "flags":    "S",
            "protocol": 6,
        },
        "threshold":      30,    # Raised from 20 to reduce FP on busy clients
        "window_seconds": 5,
    },

    {
        "name":     "Null Scan",
        "type":     "pattern",
        "severity": "HIGH",
        "mitre":    "T1046",
        "conditions": {
            # TCP packet with no flags set — always invalid per RFC 793.
            # Used to evade stateless firewalls and fingerprint OS TCP stacks.
            "protocol":  6,
            "flags_int": 0,
        },
    },

    {
        "name":     "XMAS Scan",
        "type":     "pattern",
        "severity": "HIGH",
        "mitre":    "T1046",
        "conditions": {
            # FIN + PSH + URG set simultaneously — never valid in a real TCP session.
            # RFC 793 compliant hosts respond RST; Windows ignores — used for OS detection.
            "protocol": 6,
            "flags":    "FPU",
        },
    },

    {
        "name":     "FIN Scan",
        "type":     "pattern",
        "severity": "MEDIUM",
        "mitre":    "T1046",
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
        "mitre":          "T1046",
        "conditions": {
            # FIN+ACK is normal in TCP teardown; a high rate from one IP in a short window
            # indicates the FIN+ACK variant of port scanning to bypass stateless ACLs.
            "protocol": 6,
            "flags":    "FA",
        },
        "threshold":      50,    # Raised from 20; connection pools can close many sessions quickly
        "window_seconds": 10,
    },

    {
        "name":           "ACK Scan",
        "type":           "rate",
        "severity":       "MEDIUM",
        "mitre":          "T1046",
        "conditions": {
            # Pure ACK is sent constantly in established TCP — not suspicious alone.
            # A very high rate of bare ACKs from one IP probes firewall stateful rules.
            "protocol": 6,
            "flags":    "A",
        },
        "threshold":      150,   # Raised from 50; legitimate TCP data flows easily exceed 50/5s
        "window_seconds": 5,
    },

    {
        "name":           "ICMP Host Sweep (Ping Sweep)",
        "type":           "rate",
        "severity":       "MEDIUM",
        "mitre":          "T1018",
        "conditions": {
            # High rate of ICMP echo requests = network host discovery.
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
        "mitre":          "T1046",
        "conditions": {
            # High rate of UDP from one IP.  Threshold is deliberately high because
            # VoIP, DNS, gaming, and NTP all generate heavy legitimate UDP traffic.
            "protocol": 17,
        },
        "threshold":      500,   # Raised from 100/5s to 500/10s
        "window_seconds": 10,
    },

    {
        "name":     "Invalid TCP Flags: SYN+RST",
        "type":     "pattern",
        "severity": "MEDIUM",
        "mitre":    "T1046",
        "conditions": {
            # SYN and RST cannot both be set — forbidden by RFC 793.
            # Used by some scanners to fingerprint TCP stacks or evade IDS rules.
            "protocol":  6,
            "flags_int": {"mask": 0x06},  # 0x02 (SYN) | 0x04 (RST) both set
        },
    },

    {
        "name":     "Invalid TCP Flags: SYN+FIN",
        "type":     "pattern",
        "severity": "MEDIUM",
        "mitre":    "T1046",
        "conditions": {
            # SYN and FIN cannot both be set — forbidden by RFC 793.
            # Appears in crafted packets designed to confuse stateless packet filters.
            "protocol":  6,
            "flags_int": {"mask": 0x03},  # 0x01 (FIN) | 0x02 (SYN) both set
        },
    },

    {
        "name":     "Oversized ICMP Packet",
        "type":     "pattern",
        "severity": "MEDIUM",
        "mitre":    "T1498.001",
        "conditions": {
            # Normal ICMP echo is 60–84 bytes (IP header + 8-byte ICMP + small payload).
            # Packets > 1000 bytes suggest a covert channel or ping-of-death derivative.
            "protocol":  1,
            "icmp_type": 8,
            "length":    {">": 1000},
        },
    },

    {
        "name":           "Port Scan (Distinct Ports)",
        "type":           "multi_destination",
        "severity":       "HIGH",
        "mitre":          "T1046",
        "conditions": {
            # Track unique destination ports from one source IP.
            # Unlike the raw-SYN rate rule, this fires only when the attacker is actually
            # probing multiple ports — normal clients don't hit 25 distinct ports in 30s.
            "protocol": 6,
            "flags":    "S",
        },
        "track":          "dst_port",
        "threshold":      25,
        "window_seconds": 30,
    },

    {
        "name":           "Host Discovery Sweep (Distinct IPs)",
        "type":           "multi_destination",
        "severity":       "HIGH",
        "mitre":          "T1018",
        "conditions": {
            # Track unique destination IPs from one source — covers both TCP SYN and ICMP.
            # A worm or scanner probing 20 distinct hosts in 30s is clearly malicious.
            "protocol": [6, 1],
        },
        "track":          "dst_ip",
        "threshold":      20,
        "window_seconds": 30,
    },

    {
        "name":     "Low TTL Probe (Traceroute / Evasion)",
        "type":     "pattern",
        "severity": "LOW",
        "mitre":    "T1040",
        "conditions": {
            # Packets arriving at the sensor with TTL 1–4 were sent with a deliberately
            # low initial TTL — classic traceroute signature and also used by some evasion
            # tools to map network topology without completing a full packet delivery.
            "ttl": {"<=": 4, ">": 0},
        },
    },

    {
        "name":     "ICMP Redirect (Routing Manipulation)",
        "type":     "pattern",
        "severity": "HIGH",
        "mitre":    "T1565",
        "conditions": {
            # ICMP type 5 tells a host to update its routing table to use a different
            # gateway.  Legitimate use is extremely rare on modern networks; crafted
            # ICMP redirects are a classic MITM route-poisoning technique.
            "protocol":  1,
            "icmp_type": 5,
        },
    },

    {
        "name":     "TCP SYN with Large Payload",
        "type":     "pattern",
        "severity": "MEDIUM",
        "mitre":    "T1499.002",
        "conditions": {
            # A valid TCP SYN contains only IP + TCP headers — typically 40–60 bytes.
            # A SYN packet > 80 bytes carries data in the payload, which is invalid
            # per RFC 793 and is seen in SYN-flood amplification tools and some exploits
            # that embed shellcode in the handshake to bypass DPI.
            "protocol": 6,
            "flags":    "S",
            "length":   {">": 80},
        },
    },


    # ══════════════════════════════════════════════════════════════════════════
    # BRUTE FORCE — Credential Attacks
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":           "SSH Brute Force",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1110.001",
        "conditions": {
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
        "mitre":          "T1110.001",
        "conditions": {
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
        "mitre":          "T1110.001",
        "conditions": {
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
        "mitre":          "T1110.001",
        "conditions": {
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
        "mitre":          "T1110.003",
        "conditions": {
            "dst_port": [587, 465],  # SMTP submission + SMTPS
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
        "mitre":          "T1110.001",
        "conditions": {
            "dst_port": [143, 993],  # IMAP + IMAPS
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
        "mitre":          "T1110.001",
        "conditions": {
            "dst_port": [110, 995],  # POP3 + POP3S
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
        "mitre":          "T1110.001",
        "conditions": {
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
        "mitre":          "T1110.001",
        "conditions": {
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
        "mitre":          "T1110.001",
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
        "mitre":          "T1110.001",
        "conditions": {
            "dst_port": 1433,
            "protocol": 6,
            "flags":    "S",
        },
        "threshold":      5,
        "window_seconds": 30,
    },

    {
        "name":           "Kerberos Brute Force (AS-REP Roasting / Password Spray)",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1558.003",
        "conditions": {
            "dst_port": 88,
            "protocol": [6, 17],
        },
        "threshold":      20,
        "window_seconds": 30,
    },


    # ══════════════════════════════════════════════════════════════════════════
    # DENIAL OF SERVICE — Flood Attacks
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":           "SYN Flood",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1498.001",
        "conditions": {
            # Much higher threshold than Port Scan — distinguishes DoS from scanning.
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
        "mitre":          "T1498.001",
        "conditions": {
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
        "mitre":          "T1498.001",
        "conditions": {
            "protocol": 17,
        },
        "threshold":      1000,
        "window_seconds": 10,
    },

    {
        "name":           "RST Flood",
        "type":           "rate",
        "severity":       "HIGH",
        "mitre":          "T1499",
        "conditions": {
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
        "mitre":          "T1498.001",
        "conditions": {
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
        "mitre":    "T1078",
        "conditions": {
            "dst_port": 23,
            "protocol": 6,
        },
    },

    {
        "name":     "FTP Cleartext Login",
        "type":     "pattern",
        "severity": "LOW",      # Informational — FTP Brute Force handles active attacks
        "mitre":    "T1078",
        "conditions": {
            "dst_port": 21,
            "protocol": 6,
        },
    },

    {
        "name":     "rlogin / rsh Attempt",
        "type":     "pattern",
        "severity": "HIGH",
        "mitre":    "T1021",
        "conditions": {
            # Ports 512 (rexec), 513 (rlogin), 514 (rsh) — legacy Unix remote access.
            # No encryption; trust host-based auth. Extinct on modern networks.
            "dst_port": [512, 513, 514],
            "protocol": 6,
        },
    },

    {
        "name":     "TFTP Access",
        "type":     "pattern",
        "severity": "MEDIUM",
        "mitre":    "T1105",
        "conditions": {
            "dst_port": 69,
            "protocol": 17,
        },
    },

    {
        "name":     "SNMP Access (v1/v2)",
        "type":     "pattern",
        "severity": "MEDIUM",
        "mitre":    "T1602",
        "conditions": {
            "dst_port": 161,
            "protocol": 17,
        },
    },

    {
        "name":     "NFS Access",
        "type":     "pattern",
        "severity": "MEDIUM",
        "mitre":    "T1039",
        "conditions": {
            "dst_port": 2049,
            "protocol": [6, 17],
        },
    },

    {
        "name":     "LLMNR Traffic (Possible Responder / MITM)",
        "type":     "pattern",
        "severity": "LOW",
        "mitre":    "T1557.001",
        "conditions": {
            # Link-Local Multicast Name Resolution (port 5355 UDP).
            # The Responder tool abuses LLMNR to intercept name queries and capture
            # NTLMv2 hashes from Windows hosts — especially dangerous on flat networks.
            "dst_port": 5355,
            "protocol": 17,
        },
    },

    {
        "name":     "SSDP / UPnP Discovery",
        "type":     "pattern",
        "severity": "LOW",
        "mitre":    "T1498.002",
        "conditions": {
            # SSDP (port 1900 UDP) is used for UPnP device discovery.
            # Misconfigured UPnP routers can be abused for UDP amplification DDoS attacks.
            "dst_port": 1900,
            "protocol": 17,
        },
    },


    # ══════════════════════════════════════════════════════════════════════════
    # MALWARE & C2 — Command and Control Indicators
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":     "Known C2 / Backdoor Port",
        "type":     "pattern",
        "severity": "CRITICAL",
        "mitre":    "T1571",
        "conditions": {
            # Ports commonly associated with RATs, reverse shells, and C2 frameworks.
            # 4444: Metasploit default  1337/31337: classic backdoor ports
            # 9001: Tor relay / Meterpreter  6666/6667: IRC C2
            # 8888: common HTTP C2 alt  1234/12345/54321: generic backdoor defaults
            "dst_port": [4444, 1337, 31337, 9001, 6666, 6667, 8888, 1234, 12345, 54321],
        },
    },

    {
        "name":     "Possible Reverse Shell (High Outbound Port)",
        "type":     "pattern",
        "severity": "HIGH",
        "mitre":    "T1059",
        "conditions": {
            # Outbound TCP SYN to ports > 60000.  No legitimate service listens above 60000
            # by default; reverse shells use high ports to blend in with ephemeral traffic.
            # Heuristic — expect some false positives from unusual client applications.
            "dst_port": {">": 60000},
            "protocol": 6,
            "flags":    "S",
        },
    },

    {
        "name":     "IRC Traffic (Possible Botnet C2)",
        "type":     "pattern",
        "severity": "MEDIUM",
        "mitre":    "T1571",
        "conditions": {
            "dst_port": [6660, 6661, 6662, 6663, 6664, 6665, 6668, 6669, 7000],
            "protocol": 6,
        },
    },

    {
        "name":     "Tor Default Port",
        "type":     "pattern",
        "severity": "MEDIUM",
        "mitre":    "T1090.003",
        "conditions": {
            "dst_port": [9050, 9150, 9051],
            "protocol": 6,
        },
    },

    {
        "name":     "DNS over Non-Standard Port (Possible DNS Tunneling)",
        "type":     "pattern",
        "severity": "MEDIUM",
        "mitre":    "T1071.004",
        "conditions": {
            # 8053 / 8853: alternate DNS ports used by tunneling tools (dnscat2, iodine).
            # Both UDP (primary) and TCP (dnscat2 TCP mode) are covered.
            # Port 53 (standard DNS) and 5353 (mDNS/Bonjour — RFC 6762) are excluded.
            "dst_port": [8053, 8853],
            "protocol": [6, 17],
        },
    },

    {
        "name":     "Cobalt Strike Default Beacon Port",
        "type":     "pattern",
        "severity": "CRITICAL",
        "mitre":    "T1105",
        "conditions": {
            # Port 50050 is Cobalt Strike's default team server port.
            "dst_port": 50050,
            "protocol": 6,
        },
    },

    {
        "name":     "Netcat / Bind Shell Default Port",
        "type":     "pattern",
        "severity": "HIGH",
        "mitre":    "T1059",
        "conditions": {
            "dst_port": 4242,
            "protocol": 6,
        },
    },

    {
        "name":           "Aggressive Outbound SYN Rate (Worm / Scanner)",
        "type":           "rate",
        "severity":       "MEDIUM",
        "mitre":          "T1595",
        "conditions": {
            # 300 SYNs in 60 s = 5 new TCP connections per second sustained for a minute.
            # Normal browsing peaks briefly; this threshold requires sustained aggressive
            # outbound activity characteristic of a worm spreading or a port scanner.
            # Cannot detect C2 beaconing (needs per-destination tracking) — see note.
            "flags":    "S",
            "protocol": 6,
        },
        "threshold":      300,
        "window_seconds": 60,
    },


    # ══════════════════════════════════════════════════════════════════════════
    # LATERAL MOVEMENT — Internal Spread
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":     "SMB Access (Possible Lateral Movement)",
        "type":     "pattern",
        "severity": "LOW",      # Every Windows host uses SMB constantly; informational only
        "mitre":    "T1021.002",
        "conditions": {
            "dst_port": [445, 139],
            "protocol": 6,
        },
    },

    {
        "name":           "SMB Sweep (Ransomware Propagation)",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1570",
        "conditions": {
            # Rapid SMB SYN flood across hosts = worm / ransomware spreading.
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
        "mitre":    "T1021.006",
        "conditions": {
            "dst_port": [5985, 5986],
            "protocol": 6,
        },
    },

    {
        "name":     "DCOM / RPC Access",
        "type":     "pattern",
        "severity": "MEDIUM",
        "mitre":    "T1021.003",
        "conditions": {
            "dst_port": 135,
            "protocol": 6,
        },
    },

    {
        "name":     "NetBIOS Name / Datagram Service",
        "type":     "pattern",
        "severity": "MEDIUM",
        "mitre":    "T1018",
        "conditions": {
            # Port 137 = NetBIOS Name Service (NBNS), 138 = NetBIOS Datagram (UDP only).
            # NBNS is exploited by Responder for MITM credential capture via name spoofing.
            # Previously mislabeled as "Remote Registry Access" — actual remote registry
            # goes through SMB (445) or RPC (135), both handled by separate rules.
            "dst_port": [137, 138],
            "protocol": 17,
        },
    },

    {
        "name":     "LDAP Enumeration",
        "type":     "pattern",
        "severity": "LOW",      # Constant in any Active Directory environment; informational
        "mitre":    "T1018",
        "conditions": {
            "dst_port": [389, 636],
            "protocol": [6, 17],
        },
    },


    # ══════════════════════════════════════════════════════════════════════════
    # EXPLOITATION — Vulnerable Services
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":     "Log4Shell Target Port (8080/8443)",
        "type":     "pattern",
        "severity": "LOW",      # Port alone cannot identify Log4Shell; informational only
        "mitre":    "T1190",
        "conditions": {
            "dst_port": [8080, 8443, 8009],
            "protocol": 6,
        },
    },

    {
        "name":     "Redis Exposed (No Auth)",
        "type":     "pattern",
        "severity": "CRITICAL",
        "mitre":    "T1190",
        "conditions": {
            "dst_port": 6379,
            "protocol": 6,
        },
    },

    {
        "name":     "Elasticsearch Exposed",
        "type":     "pattern",
        "severity": "CRITICAL",
        "mitre":    "T1190",
        "conditions": {
            "dst_port": [9200, 9300],
            "protocol": 6,
        },
    },

    {
        "name":     "MongoDB Exposed",
        "type":     "pattern",
        "severity": "CRITICAL",
        "mitre":    "T1190",
        "conditions": {
            "dst_port": 27017,
            "protocol": 6,
        },
    },

    {
        "name":     "Docker API Exposed",
        "type":     "pattern",
        "severity": "CRITICAL",
        "mitre":    "T1610",
        "conditions": {
            "dst_port": [2375, 2376],
            "protocol": 6,
        },
    },

    {
        "name":     "Kubernetes API Exposed",
        "type":     "pattern",
        "severity": "CRITICAL",
        "mitre":    "T1610",
        "conditions": {
            "dst_port": [6443, 8001],
            "protocol": 6,
        },
    },

    {
        "name":     "etcd Exposed",
        "type":     "pattern",
        "severity": "CRITICAL",
        "mitre":    "T1552.007",
        "conditions": {
            "dst_port": [2379, 2380],
            "protocol": 6,
        },
    },

    {
        "name":     "Memcached Exposed (DDoS Amplification)",
        "type":     "pattern",
        "severity": "HIGH",
        "mitre":    "T1498.002",
        "conditions": {
            "dst_port": 11211,
            "protocol": 17,
        },
    },

    {
        "name":     "CouchDB Exposed",
        "type":     "pattern",
        "severity": "HIGH",
        "mitre":    "T1190",
        "conditions": {
            "dst_port": 5984,
            "protocol": 6,
        },
    },

    {
        "name":     "Hadoop / HDFS Exposed",
        "type":     "pattern",
        "severity": "HIGH",
        "mitre":    "T1190",
        "conditions": {
            "dst_port": [9000, 50070, 8088],
            "protocol": 6,
        },
    },


    # ══════════════════════════════════════════════════════════════════════════
    # EXFILTRATION — Data Leaving the Network
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":           "DNS Query Flood UDP (Possible DNS Tunneling)",
        "type":           "rate",
        "severity":       "HIGH",
        "mitre":          "T1048.001",
        "conditions": {
            "dst_port": 53,
            "protocol": 17,
        },
        "threshold":      200,
        "window_seconds": 60,
    },

    {
        "name":           "DNS Query Flood TCP (Possible DNS Tunneling)",
        "type":           "rate",
        "severity":       "MEDIUM",
        "mitre":          "T1048.001",
        "conditions": {
            # DNS over TCP is valid for zone transfers and large responses, but a high
            # sustained rate from one host suggests iodine/dnscat2 in TCP mode.
            "dst_port": 53,
            "protocol": 6,
        },
        "threshold":      100,
        "window_seconds": 60,
    },

    {
        "name":           "ICMP Exfiltration (Large Volume)",
        "type":           "rate",
        "severity":       "MEDIUM",
        "mitre":          "T1048.003",
        "conditions": {
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
        "mitre":    "T1048",
        "conditions": {
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
        "mitre":          "T1498.002",
        "conditions": {
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
        "mitre":          "T1498.002",
        "conditions": {
            "src_port": 123,
            "protocol": 17,
        },
        "threshold":      200,
        "window_seconds": 10,
    },

    {
        "name":     "BGP Connection Attempt",
        "type":     "pattern",
        "severity": "HIGH",     # Downgraded from CRITICAL; legitimate between BGP-peered routers
        "mitre":    "T1557",
        "conditions": {
            # Unexpected BGP session setup from a non-router IP can indicate BGP hijack.
            # Correlate against your known router addresses before escalating.
            "dst_port": 179,
            "protocol": 6,
        },
    },

    {
        "name":     "OSPF Injection",
        "type":     "pattern",
        "severity": "HIGH",
        "mitre":    "T1565",
        "conditions": {
            # OSPF is IP protocol 89 — it runs directly over IP, not over TCP or UDP.
            # Previous rule incorrectly checked TCP port 89, which never fires.
            # Unexpected OSPF on a non-router network indicates route injection.
            "protocol": 89,
        },
    },

    {
        "name":     "EIGRP Traffic",
        "type":     "pattern",
        "severity": "HIGH",
        "mitre":    "T1565",
        "conditions": {
            # EIGRP is IP protocol 88 (Cisco interior routing protocol).
            # Crafted EIGRP packets can poison routing tables across the network.
            "protocol": 88,
        },
    },

    {
        "name":     "GRE Tunnel Traffic",
        "type":     "pattern",
        "severity": "MEDIUM",
        "mitre":    "T1572",
        "conditions": {
            # GRE (IP protocol 47) encapsulates arbitrary traffic inside IP packets.
            # Unexpected GRE on a network without GRE VPNs may indicate covert tunneling
            # to bypass stateful firewall or DPI inspection.
            "protocol": 47,
        },
    },

    {
        "name":     "IPv6-in-IPv4 Tunnel",
        "type":     "pattern",
        "severity": "MEDIUM",
        "mitre":    "T1572",
        "conditions": {
            # IP protocol 41 encapsulates IPv6 inside IPv4 (6to4, Teredo, ISATAP).
            # Can carry traffic that IPv4-only security inspection would miss entirely.
            "protocol": 41,
        },
    },


    # ══════════════════════════════════════════════════════════════════════════
    # INDUSTRIAL / OT — ICS/SCADA Protocols
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name":     "Modbus Access (ICS Protocol)",
        "type":     "pattern",
        "severity": "HIGH",
        "mitre":    "T0855",
        "conditions": {
            "dst_port": 502,
            "protocol": 6,
        },
    },

    {
        "name":     "DNP3 Access (ICS Protocol)",
        "type":     "pattern",
        "severity": "HIGH",
        "mitre":    "T0855",
        "conditions": {
            "dst_port": 20000,
            "protocol": [6, 17],
        },
    },

    {
        "name":     "EtherNet/IP Access (ICS Protocol)",
        "type":     "pattern",
        "severity": "HIGH",
        "mitre":    "T0855",
        "conditions": {
            "dst_port": 44818,
            "protocol": [6, 17],
        },
    },

    {
        "name":     "BACnet Access (Building Automation)",
        "type":     "pattern",
        "severity": "MEDIUM",
        "mitre":    "T0855",
        "conditions": {
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
        "mitre":    "T1090",
        "conditions": {
            "dst_port": [3128, 1080, 8118],
            "protocol": 6,
        },
    },

    {
        "name":     "P2P / BitTorrent Port",
        "type":     "pattern",
        "severity": "LOW",
        "mitre":    "T1048",
        "conditions": {
            "dst_port": [6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889],
            "protocol": [6, 17],
        },
    },

    {
        "name":     "Cryptocurrency Mining Pool",
        "type":     "pattern",
        "severity": "HIGH",
        "mitre":    "T1496",
        "conditions": {
            # Stratum protocol ports used by mining pools.
            # Outbound connections from internal hosts = cryptojacking malware.
            "dst_port": [3333, 3334, 3335, 14444, 45700],
            "protocol": 6,
        },
    },

]
