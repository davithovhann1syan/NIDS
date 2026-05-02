from __future__ import annotations

from typing import Literal, NotRequired, TypedDict


Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class PatternRule(TypedDict):
    """Fires once on a single packet that satisfies all conditions."""
    id:         str
    name:       str
    type:       Literal["pattern"]
    severity:   Severity
    conditions: dict[str, object]
    mitre:      NotRequired[str]


class RateRule(TypedDict):
    """Fires when src_ip sends ≥ threshold matching packets within window_seconds."""
    id:             str
    name:           str
    type:           Literal["rate"]
    severity:       Severity
    conditions:     dict[str, object]
    threshold:      int
    window_seconds: int
    mitre:          NotRequired[str]


class MultiDestRule(TypedDict):
    """Fires when src_ip reaches ≥ threshold *unique* tracked values within window_seconds.
    Accurate for scan detection — counts unique ports or IPs, not raw packet volume."""
    id:             str
    name:           str
    type:           Literal["multi_destination"]
    severity:       Severity
    conditions:     dict[str, object]
    track:          Literal["dst_port", "dst_ip"]
    threshold:      int
    window_seconds: int
    mitre:          NotRequired[str]


Rule = PatternRule | RateRule | MultiDestRule


# ─── Condition syntax ────────────────────────────────────────────────────────
# Plain value  →  equality           "protocol": 6
# [list]       →  membership         "dst_port": [80, 443]
# {op: val}    →  comparison         "length": {">": 1000}
#                 ops: >, >=, <, <=, !=, not_in, mask
# {"mask": v}  →  bitmask check      (actual & v) == v


SIGNATURES: list[Rule] = [

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 1 — RECONNAISSANCE  (R001–R016)
    #
    # Design notes:
    #  • Scan rules fire only when src_ip is EXTERNAL.  The main loop auto-
    #    excludes the machine's own IP so outbound browsing SYNs never appear
    #    as a port scan against yourself.
    #  • Rate thresholds are set conservatively: a normal browser opening
    #    30 tabs generates ~30 SYNs in a second, not 100 SYNs in 10 seconds.
    #  • multi_destination rules count *unique* ports/IPs — they do NOT false-
    #    positive on high-volume TCP sessions to a single endpoint.
    # ══════════════════════════════════════════════════════════════════════════

    {   # SYN-only packet flood — classic nmap -sS stealth scan.
        # Threshold raised to 100 / 10 s (= 10 new connections per second
        # sustained) so that a browser loading a resource-heavy page (30–50
        # concurrent SYNs in < 1 s) cannot reach it.
        "id":             "R001",
        "name":           "Port Scan (SYN)",
        "type":           "rate",
        "severity":       "HIGH",
        "mitre":          "T1046",
        "conditions":     {"flags": "S", "protocol": 6},
        "threshold":      100,
        "window_seconds": 10,
    },

    {   # Counts *unique destination ports* from one source IP.
        # 25 distinct ports in 30 s is unambiguous scanning regardless of rate.
        # False-positive safe: normal clients connect to the same handful of
        # service ports, not to 25 different ones in half a minute.
        "id":             "R002",
        "name":           "Port Scan (Distinct Ports)",
        "type":           "multi_destination",
        "severity":       "HIGH",
        "mitre":          "T1046",
        "conditions":     {"protocol": 6, "flags": "S"},
        "track":          "dst_port",
        "threshold":      25,
        "window_seconds": 30,
    },

    {   # Counts *unique destination IPs* from one source — host discovery sweep.
        # Covers both TCP SYN and ICMP echo so nmap -sP / -PE is detected.
        "id":             "R003",
        "name":           "Host Discovery Sweep (Distinct IPs)",
        "type":           "multi_destination",
        "severity":       "HIGH",
        "mitre":          "T1018",
        "conditions":     {"protocol": [6, 1]},
        "track":          "dst_ip",
        "threshold":      20,
        "window_seconds": 30,
    },

    {   # TCP with no flags set — always invalid per RFC 793.
        # Used to evade stateless firewalls and fingerprint OS TCP stacks.
        # No legitimate implementation sends a flagless TCP segment.
        "id":         "R004",
        "name":       "Null Scan",
        "type":       "pattern",
        "severity":   "HIGH",
        "mitre":      "T1046",
        "conditions": {"protocol": 6, "flags_int": 0},
    },

    {   # FIN + PSH + URG simultaneously — never valid in any real TCP session.
        # RFC 793 compliant hosts respond RST; Windows ignores — used for OS
        # fingerprinting.
        "id":         "R005",
        "name":       "XMAS Scan",
        "type":       "pattern",
        "severity":   "HIGH",
        "mitre":      "T1046",
        "conditions": {"protocol": 6, "flags": "FPU"},
    },

    {   # Bare FIN with no ACK — invalid in any legitimate TCP session.
        # TCP teardown always pairs FIN with ACK (FA).  A lone F is a scan probe.
        "id":         "R006",
        "name":       "FIN Scan",
        "type":       "pattern",
        "severity":   "MEDIUM",
        "mitre":      "T1046",
        "conditions": {"protocol": 6, "flags": "F"},
    },

    {   # FIN+ACK probes to many distinct ports — the Maimon scan technique.
        # multi_destination avoids false positives: a server closing many client
        # connections sends FA to ONE destination port per connection (the client's
        # ephemeral port), not to 20 different service ports.  Only an active
        # scanner sends FA to many different destination ports.
        "id":             "R007",
        "name":           "Maimon Scan",
        "type":           "multi_destination",
        "severity":       "MEDIUM",
        "mitre":          "T1046",
        "conditions":     {"protocol": 6, "flags": "FA"},
        "track":          "dst_port",
        "threshold":      20,
        "window_seconds": 30,
    },

    {   # Pure ACK probes to many distinct ports — ACK scan to map firewall rules.
        # multi_destination is key here: a TCP server legitimately sends ACK back
        # to a client's ONE ephemeral port (unique count = 1).  An ACK scanner
        # sends to many service ports → unique count climbs quickly.
        "id":             "R008",
        "name":           "ACK Scan",
        "type":           "multi_destination",
        "severity":       "MEDIUM",
        "mitre":          "T1046",
        "conditions":     {"protocol": 6, "flags": "A"},
        "track":          "dst_port",
        "threshold":      30,
        "window_seconds": 30,
    },

    {   # High rate of ICMP echo-request from one IP = host discovery sweep.
        "id":             "R009",
        "name":           "ICMP Host Sweep (Ping Sweep)",
        "type":           "rate",
        "severity":       "MEDIUM",
        "mitre":          "T1018",
        "conditions":     {"protocol": 1, "icmp_type": 8},
        "threshold":      20,
        "window_seconds": 10,
    },

    {   # High rate of UDP from one IP across any ports.
        # Threshold is deliberately high (500 / 10 s) because VoIP, DNS, NTP,
        # and gaming all generate heavy legitimate UDP; this only flags aggressive
        # flooding behaviour.
        "id":             "R010",
        "name":           "UDP Port Scan",
        "type":           "rate",
        "severity":       "MEDIUM",
        "mitre":          "T1046",
        "conditions":     {"protocol": 17},
        "threshold":      500,
        "window_seconds": 10,
    },

    {   # SYN and RST cannot both be set — forbidden by RFC 793.
        # Seen in crafted packets used to fingerprint TCP stacks and evade IDS.
        "id":         "R011",
        "name":       "Invalid TCP Flags: SYN+RST",
        "type":       "pattern",
        "severity":   "MEDIUM",
        "mitre":      "T1046",
        "conditions": {"protocol": 6, "flags_int": {"mask": 0x06}},
    },

    {   # SYN and FIN cannot both be set — forbidden by RFC 793.
        "id":         "R012",
        "name":       "Invalid TCP Flags: SYN+FIN",
        "type":       "pattern",
        "severity":   "MEDIUM",
        "mitre":      "T1046",
        "conditions": {"protocol": 6, "flags_int": {"mask": 0x03}},
    },

    {   # ICMP echo > 1 000 bytes — normal ping is 60–84 bytes.
        # Oversized ICMP suggests a covert channel or ping-of-death derivative.
        "id":         "R013",
        "name":       "Oversized ICMP Packet",
        "type":       "pattern",
        "severity":   "MEDIUM",
        "mitre":      "T1498.001",
        "conditions": {"protocol": 1, "icmp_type": 8, "length": {">": 1000}},
    },

    {   # Packets arriving with TTL ≤ 4 were sent with a deliberately low initial
        # TTL — classic traceroute signature and a topology-mapping evasion tool.
        # On a typical LAN (≤ 2 hops), normal traffic arrives with TTL 62–126+.
        "id":         "R014",
        "name":       "Low TTL Probe (Traceroute / Evasion)",
        "type":       "pattern",
        "severity":   "LOW",
        "mitre":      "T1040",
        "conditions": {"ttl": {"<=": 4, ">": 0}},
    },

    {   # ICMP type 5 — tells a host to reroute via a different gateway.
        # Legitimate use is essentially extinct on modern networks; crafted ICMP
        # redirects are a classic MITM route-poisoning vector.
        "id":         "R015",
        "name":       "ICMP Redirect (Routing Manipulation)",
        "type":       "pattern",
        "severity":   "HIGH",
        "mitre":      "T1565",
        "conditions": {"protocol": 1, "icmp_type": 5},
    },

    {   # A valid TCP SYN is 40–60 bytes (IP + TCP headers, no payload).
        # SYN > 80 bytes carries data, which is invalid per RFC 793 and appears
        # in SYN-flood amplification tools and some shellcode-embedding exploits.
        "id":         "R016",
        "name":       "TCP SYN with Large Payload",
        "type":       "pattern",
        "severity":   "MEDIUM",
        "mitre":      "T1499.002",
        "conditions": {"protocol": 6, "flags": "S", "length": {">": 80}},
    },


    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 2 — BRUTE FORCE  (R017–R028)
    #
    # All brute-force rules require: specific dst_port + TCP + SYN + rate.
    # Counting only SYN packets ensures each counted event is a NEW connection
    # attempt, not a retransmission or data packet within one session.
    # ══════════════════════════════════════════════════════════════════════════

    {
        "id":             "R017",
        "name":           "SSH Brute Force",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1110.001",
        "conditions":     {"dst_port": 22, "protocol": 6, "flags": "S"},
        "threshold":      10,
        "window_seconds": 60,
    },

    {
        "id":             "R018",
        "name":           "RDP Brute Force",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1110.001",
        "conditions":     {"dst_port": 3389, "protocol": 6, "flags": "S"},
        "threshold":      10,
        "window_seconds": 60,
    },

    {
        "id":             "R019",
        "name":           "FTP Brute Force",
        "type":           "rate",
        "severity":       "HIGH",
        "mitre":          "T1110.001",
        "conditions":     {"dst_port": 21, "protocol": 6, "flags": "S"},
        "threshold":      10,
        "window_seconds": 60,
    },

    {
        "id":             "R020",
        "name":           "Telnet Brute Force",
        "type":           "rate",
        "severity":       "HIGH",
        "mitre":          "T1110.001",
        "conditions":     {"dst_port": 23, "protocol": 6, "flags": "S"},
        "threshold":      5,
        "window_seconds": 30,
    },

    {   # SMTP submission (587) and SMTPS (465).
        "id":             "R021",
        "name":           "SMTP Auth Brute Force",
        "type":           "rate",
        "severity":       "HIGH",
        "mitre":          "T1110.003",
        "conditions":     {"dst_port": [587, 465], "protocol": 6, "flags": "S"},
        "threshold":      10,
        "window_seconds": 60,
    },

    {   # IMAP (143) and IMAPS (993).
        "id":             "R022",
        "name":           "IMAP Brute Force",
        "type":           "rate",
        "severity":       "HIGH",
        "mitre":          "T1110.001",
        "conditions":     {"dst_port": [143, 993], "protocol": 6, "flags": "S"},
        "threshold":      10,
        "window_seconds": 60,
    },

    {   # POP3 (110) and POP3S (995).
        "id":             "R023",
        "name":           "POP3 Brute Force",
        "type":           "rate",
        "severity":       "HIGH",
        "mitre":          "T1110.001",
        "conditions":     {"dst_port": [110, 995], "protocol": 6, "flags": "S"},
        "threshold":      10,
        "window_seconds": 60,
    },

    {
        "id":             "R024",
        "name":           "VNC Brute Force",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1110.001",
        "conditions":     {"dst_port": 5900, "protocol": 6, "flags": "S"},
        "threshold":      10,
        "window_seconds": 60,
    },

    {
        "id":             "R025",
        "name":           "MySQL Brute Force",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1110.001",
        "conditions":     {"dst_port": 3306, "protocol": 6, "flags": "S"},
        "threshold":      5,
        "window_seconds": 30,
    },

    {
        "id":             "R026",
        "name":           "PostgreSQL Brute Force",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1110.001",
        "conditions":     {"dst_port": 5432, "protocol": 6, "flags": "S"},
        "threshold":      5,
        "window_seconds": 30,
    },

    {
        "id":             "R027",
        "name":           "MSSQL Brute Force",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1110.001",
        "conditions":     {"dst_port": 1433, "protocol": 6, "flags": "S"},
        "threshold":      5,
        "window_seconds": 30,
    },

    {   # Kerberos AS-REQ flood = password spray / AS-REP Roasting prep.
        # Both TCP and UDP Kerberos are covered.
        "id":             "R028",
        "name":           "Kerberos Brute Force (AS-REP Roasting / Password Spray)",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1558.003",
        "conditions":     {"dst_port": 88, "protocol": [6, 17]},
        "threshold":      20,
        "window_seconds": 30,
    },


    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 3 — DENIAL OF SERVICE  (R029–R033)
    #
    # DoS thresholds are set well above the Brute Force / Scan thresholds to
    # create a clear three-tier ladder: scan → brute → flood.
    # ══════════════════════════════════════════════════════════════════════════

    {   # SYN Flood: 200 SYNs in 5 s = 40/second — unambiguous DoS territory.
        # Distinguished from Port Scan (SYN) by much higher threshold and
        # shorter window (burst, not sustained scanning rate).
        "id":             "R029",
        "name":           "SYN Flood",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1498.001",
        "conditions":     {"flags": "S", "protocol": 6},
        "threshold":      200,
        "window_seconds": 5,
    },

    {
        "id":             "R030",
        "name":           "ICMP Flood",
        "type":           "rate",
        "severity":       "HIGH",
        "mitre":          "T1498.001",
        "conditions":     {"protocol": 1, "icmp_type": 8},
        "threshold":      100,
        "window_seconds": 10,
    },

    {
        "id":             "R031",
        "name":           "UDP Flood",
        "type":           "rate",
        "severity":       "HIGH",
        "mitre":          "T1498.001",
        "conditions":     {"protocol": 17},
        "threshold":      1000,
        "window_seconds": 10,
    },

    {   # RST Flood: used to tear down existing TCP sessions (TCP reset attacks).
        "id":             "R032",
        "name":           "RST Flood",
        "type":           "rate",
        "severity":       "HIGH",
        "mitre":          "T1499",
        "conditions":     {"flags": "R", "protocol": 6},
        "threshold":      100,
        "window_seconds": 10,
    },

    {   # ACK Flood: saturates connection tables of stateful firewalls/servers.
        "id":             "R033",
        "name":           "ACK Flood",
        "type":           "rate",
        "severity":       "HIGH",
        "mitre":          "T1498.001",
        "conditions":     {"flags": "A", "protocol": 6},
        "threshold":      500,
        "window_seconds": 10,
    },


    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 4 — SUSPICIOUS SERVICES  (R034–R037)
    #
    # Removed from this section (were generating constant noise):
    #   • FTP Cleartext Login  — every FTP packet; R019 covers the attack case
    #   • SNMP Access          — normal monitoring software polls port 161 constantly
    #   • NFS Access           — normal on NAS networks
    #   • SSDP / UPnP          — normal on home/office LANs
    #   • SMB pattern          — every Windows share access; R046 (SMB Sweep) catches attacks
    #   • DCOM / RPC (135)     — every Windows network event
    #   • NetBIOS (137/138)    — every Windows name query
    #   • LDAP Enumeration     — constant in any Active Directory environment
    # ══════════════════════════════════════════════════════════════════════════

    {   # Any TCP SYN to Telnet port — unencrypted remote access.
        # Condition limited to SYN to suppress noise from established sessions.
        "id":         "R034",
        "name":       "Telnet Attempt",
        "type":       "pattern",
        "severity":   "MEDIUM",
        "mitre":      "T1078",
        "conditions": {"dst_port": 23, "protocol": 6, "flags": "S"},
    },

    {   # rexec (512), rlogin (513), rsh (514) — extinct legacy remote access.
        # No modern system sends traffic to these ports legitimately.
        "id":         "R035",
        "name":       "rlogin / rsh Attempt",
        "type":       "pattern",
        "severity":   "HIGH",
        "mitre":      "T1021",
        "conditions": {"dst_port": [512, 513, 514], "protocol": 6},
    },

    {   # TFTP (UDP 69) — unauthenticated file transfer; used for malware drops.
        "id":         "R036",
        "name":       "TFTP Access",
        "type":       "pattern",
        "severity":   "MEDIUM",
        "mitre":      "T1105",
        "conditions": {"dst_port": 69, "protocol": 17},
    },

    {   # LLMNR (UDP 5355) — abused by Responder to capture NTLMv2 hashes.
        "id":         "R037",
        "name":       "LLMNR Traffic (Possible Responder / MITM)",
        "type":       "pattern",
        "severity":   "LOW",
        "mitre":      "T1557.001",
        "conditions": {"dst_port": 5355, "protocol": 17},
    },


    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 5 — MALWARE & C2  (R038–R045)
    # ══════════════════════════════════════════════════════════════════════════

    {   # Ports tightly associated with RATs, reverse shells, and C2 frameworks.
        # Removed 8888 (common Jupyter Notebook) and 9001 (also Tor relay) to
        # reduce false positives; those are covered by dedicated rules below.
        "id":         "R038",
        "name":       "Known C2 / Backdoor Port",
        "type":       "pattern",
        "severity":   "CRITICAL",
        "mitre":      "T1571",
        "conditions": {
            "dst_port": [4444, 1337, 31337, 6666, 6667, 1234, 12345, 54321],
        },
    },

    {   # SYNs to 5+ distinct ports > 60 000 in 60 s — consistent with bind-shell
        # scanning or a reverse-shell tool probing for listener ports.
        # Changed from pattern (fired on every single high-port SYN, including
        # legitimate ephemeral client traffic) to multi_destination so a single
        # nmap probe to port 65432 does NOT trigger the rule.
        "id":             "R039",
        "name":           "Possible Reverse Shell (High Outbound Port)",
        "type":           "multi_destination",
        "severity":       "HIGH",
        "mitre":          "T1059",
        "conditions":     {"dst_port": {">": 60000}, "protocol": 6, "flags": "S"},
        "track":          "dst_port",
        "threshold":      5,
        "window_seconds": 60,
    },

    {   # Classic IRC ports used by IRC-based botnet C2 frameworks.
        "id":         "R040",
        "name":       "IRC Traffic (Possible Botnet C2)",
        "type":       "pattern",
        "severity":   "MEDIUM",
        "mitre":      "T1571",
        "conditions": {
            "dst_port": [6660, 6661, 6662, 6663, 6664, 6665, 6668, 6669, 7000],
            "protocol": 6,
        },
    },

    {   # Tor SOCKS proxy (9050), control port (9051), Tor Browser (9150).
        "id":         "R041",
        "name":       "Tor Default Port",
        "type":       "pattern",
        "severity":   "MEDIUM",
        "mitre":      "T1090.003",
        "conditions": {"dst_port": [9050, 9150, 9051], "protocol": 6},
    },

    {   # Alternate DNS ports used by tunneling tools (dnscat2, iodine).
        # Port 53 (standard) and 5353 (mDNS) are excluded.
        "id":         "R042",
        "name":       "DNS over Non-Standard Port (Possible DNS Tunneling)",
        "type":       "pattern",
        "severity":   "MEDIUM",
        "mitre":      "T1071.004",
        "conditions": {"dst_port": [8053, 8853], "protocol": [6, 17]},
    },

    {   # Port 50050 is Cobalt Strike's default team server port.
        "id":         "R043",
        "name":       "Cobalt Strike Default Beacon Port",
        "type":       "pattern",
        "severity":   "CRITICAL",
        "mitre":      "T1105",
        "conditions": {"dst_port": 50050, "protocol": 6},
    },

    {   # Port 4242 — default netcat bind shell / many CTF/red-team exercises.
        "id":         "R044",
        "name":       "Netcat / Bind Shell Default Port",
        "type":       "pattern",
        "severity":   "HIGH",
        "mitre":      "T1059",
        "conditions": {"dst_port": 4242, "protocol": 6},
    },

    {   # 300 SYNs in 60 s = 5 new connections per second sustained for a minute.
        # Distinguishes a worm spreading / aggressive scanner from a short burst.
        "id":             "R045",
        "name":           "Aggressive Outbound SYN Rate (Worm / Scanner)",
        "type":           "rate",
        "severity":       "MEDIUM",
        "mitre":          "T1595",
        "conditions":     {"flags": "S", "protocol": 6},
        "threshold":      300,
        "window_seconds": 60,
    },


    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 6 — LATERAL MOVEMENT  (R046–R047)
    #
    # SMB Access (pattern) removed — every Windows file share access triggered it.
    # SMB Sweep (rate) is kept because rapid SYN flooding of SMB = ransomware.
    # DCOM/RPC, NetBIOS, LDAP patterns removed — constant noise on Windows LANs.
    # ══════════════════════════════════════════════════════════════════════════

    {   # Rapid SYN flood to SMB port from one IP = worm or ransomware spreading.
        "id":             "R046",
        "name":           "SMB Sweep (Ransomware Propagation)",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1570",
        "conditions":     {"dst_port": 445, "protocol": 6, "flags": "S"},
        "threshold":      10,
        "window_seconds": 10,
    },

    {   # WinRM (HTTP 5985 / HTTPS 5986) used for remote PowerShell execution.
        # Unexpected external access suggests lateral movement or initial access.
        "id":         "R047",
        "name":       "WinRM Access (Possible Lateral Movement)",
        "type":       "pattern",
        "severity":   "MEDIUM",
        "mitre":      "T1021.006",
        "conditions": {"dst_port": [5985, 5986], "protocol": 6},
    },


    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 7 — EXPOSED SERVICES  (R048–R056)
    #
    # ALL rules in this section changed from pattern → rate (threshold 3 / 60 s).
    #
    # WHY: Pattern rules fired on a single nmap SYN probe.  That caused:
    #   1. "Kubernetes API Exposed" during a port scan when k8s isn't installed.
    #   2. 5–8 distinct rules firing → correlator escalated to CRITICAL.
    #   3. Misleading dashboard alerts for services that don't exist.
    #
    # With threshold = 3 / 60 s:
    #   • nmap -sS sends 1 SYN per port → no alert.
    #   • An attacker making 3+ connection attempts → alert.
    #   • Legitimate admin making 1–2 accidental connections → no alert.
    #
    # The SYN flag requirement means each counted event is a new connection
    # attempt, not packets within an established session.
    # ══════════════════════════════════════════════════════════════════════════

    {
        "id":             "R048",
        "name":           "Redis Exposed (No Auth)",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1190",
        "conditions":     {"dst_port": 6379, "protocol": 6, "flags": "S"},
        "threshold":      3,
        "window_seconds": 60,
    },

    {
        "id":             "R049",
        "name":           "Elasticsearch Exposed",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1190",
        "conditions":     {"dst_port": [9200, 9300], "protocol": 6, "flags": "S"},
        "threshold":      3,
        "window_seconds": 60,
    },

    {
        "id":             "R050",
        "name":           "MongoDB Exposed",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1190",
        "conditions":     {"dst_port": 27017, "protocol": 6, "flags": "S"},
        "threshold":      3,
        "window_seconds": 60,
    },

    {
        "id":             "R051",
        "name":           "Docker API Exposed",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1610",
        "conditions":     {"dst_port": [2375, 2376], "protocol": 6, "flags": "S"},
        "threshold":      3,
        "window_seconds": 60,
    },

    {   # 6443 = Kubernetes API server, 8001 = kubectl proxy.
        "id":             "R052",
        "name":           "Kubernetes API Exposed",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1610",
        "conditions":     {"dst_port": [6443, 8001], "protocol": 6, "flags": "S"},
        "threshold":      3,
        "window_seconds": 60,
    },

    {   # etcd client (2379) and peer (2380) ports — holds all k8s cluster secrets.
        "id":             "R053",
        "name":           "etcd Exposed",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1552.007",
        "conditions":     {"dst_port": [2379, 2380], "protocol": 6, "flags": "S"},
        "threshold":      3,
        "window_seconds": 60,
    },

    {   # Memcached UDP — can be abused for 51 000× amplification DDoS.
        "id":             "R054",
        "name":           "Memcached Exposed (DDoS Amplification)",
        "type":           "rate",
        "severity":       "HIGH",
        "mitre":          "T1498.002",
        "conditions":     {"dst_port": 11211, "protocol": 17},
        "threshold":      3,
        "window_seconds": 60,
    },

    {
        "id":             "R055",
        "name":           "CouchDB Exposed",
        "type":           "rate",
        "severity":       "HIGH",
        "mitre":          "T1190",
        "conditions":     {"dst_port": 5984, "protocol": 6, "flags": "S"},
        "threshold":      3,
        "window_seconds": 60,
    },

    {   # Hadoop NameNode UI (50070) and YARN ResourceManager (8088).
        # Port 9000 removed — used by many unrelated applications (Portainer,
        # SonarQube, etc.) which caused constant false positives.
        "id":             "R056",
        "name":           "Hadoop / HDFS Exposed",
        "type":           "rate",
        "severity":       "HIGH",
        "mitre":          "T1190",
        "conditions":     {"dst_port": [50070, 8088], "protocol": 6, "flags": "S"},
        "threshold":      3,
        "window_seconds": 60,
    },


    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 8 — EXFILTRATION  (R057–R060)
    # ══════════════════════════════════════════════════════════════════════════

    {   # 200 UDP DNS queries in 60 s = 3.3 qps sustained — normal clients generate
        # well under 10 qps; iodine/dnscat can sustain 50–100 qps.
        "id":             "R057",
        "name":           "DNS Query Flood UDP (Possible DNS Tunneling)",
        "type":           "rate",
        "severity":       "HIGH",
        "mitre":          "T1048.001",
        "conditions":     {"dst_port": 53, "protocol": 17},
        "threshold":      200,
        "window_seconds": 60,
    },

    {   # DNS over TCP at high rate — zone transfers are one-off; sustained TCP DNS
        # from one host suggests iodine/dnscat2 in TCP mode.
        "id":             "R058",
        "name":           "DNS Query Flood TCP (Possible DNS Tunneling)",
        "type":           "rate",
        "severity":       "MEDIUM",
        "mitre":          "T1048.001",
        "conditions":     {"dst_port": 53, "protocol": 6},
        "threshold":      100,
        "window_seconds": 60,
    },

    {   # High ICMP echo volume — covert channel or icmptunnel/ptunnel exfiltration.
        "id":             "R059",
        "name":           "ICMP Exfiltration (Large Volume)",
        "type":           "rate",
        "severity":       "MEDIUM",
        "mitre":          "T1048.003",
        "conditions":     {"protocol": 1, "icmp_type": 8},
        "threshold":      50,
        "window_seconds": 60,
    },

    {   # FTP data channel (src port 20) originating data toward a client.
        # High volume signals bulk exfiltration via passive FTP.
        "id":         "R060",
        "name":       "FTP Data Channel (Possible Exfiltration)",
        "type":       "pattern",
        "severity":   "LOW",
        "mitre":      "T1048",
        "conditions": {"src_port": 20, "protocol": 6},
    },


    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 9 — NETWORK INFRASTRUCTURE ATTACKS  (R061–R067)
    # ══════════════════════════════════════════════════════════════════════════

    {   # Many DNS responses arriving at the sensor = reflective amplification.
        # src_port 53 with high volume means open resolvers are flooding the host.
        "id":             "R061",
        "name":           "DNS Amplification Attack",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1498.002",
        "conditions":     {"src_port": 53, "protocol": 17},
        "threshold":      500,
        "window_seconds": 10,
    },

    {   # NTP monlist / readvar amplification: many NTP responses from port 123.
        "id":             "R062",
        "name":           "NTP Amplification Attack",
        "type":           "rate",
        "severity":       "CRITICAL",
        "mitre":          "T1498.002",
        "conditions":     {"src_port": 123, "protocol": 17},
        "threshold":      200,
        "window_seconds": 10,
    },

    {   # Unexpected BGP session setup (port 179) from a non-router IP may indicate
        # BGP hijacking.  Severity lowered from CRITICAL — legitimate between peers.
        "id":         "R063",
        "name":       "BGP Connection Attempt",
        "type":       "pattern",
        "severity":   "HIGH",
        "mitre":      "T1557",
        "conditions": {"dst_port": 179, "protocol": 6},
    },

    {   # OSPF runs as IP protocol 89 (not TCP/UDP).  Unexpected OSPF on a
        # non-router segment indicates route injection.
        "id":         "R064",
        "name":       "OSPF Injection",
        "type":       "pattern",
        "severity":   "HIGH",
        "mitre":      "T1565",
        "conditions": {"protocol": 89},
    },

    {   # EIGRP — Cisco IP protocol 88.  Crafted EIGRP poisons routing tables.
        "id":         "R065",
        "name":       "EIGRP Traffic",
        "type":       "pattern",
        "severity":   "HIGH",
        "mitre":      "T1565",
        "conditions": {"protocol": 88},
    },

    {   # GRE (IP protocol 47) encapsulates arbitrary traffic, bypassing DPI.
        "id":         "R066",
        "name":       "GRE Tunnel Traffic",
        "type":       "pattern",
        "severity":   "MEDIUM",
        "mitre":      "T1572",
        "conditions": {"protocol": 47},
    },

    {   # IP protocol 41 — IPv6-in-IPv4 (6to4 / Teredo / ISATAP).
        # Can carry traffic invisible to IPv4-only security inspection.
        "id":         "R067",
        "name":       "IPv6-in-IPv4 Tunnel",
        "type":       "pattern",
        "severity":   "MEDIUM",
        "mitre":      "T1572",
        "conditions": {"protocol": 41},
    },


    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 10 — ICS / SCADA  (R068–R071)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "id":         "R068",
        "name":       "Modbus Access (ICS Protocol)",
        "type":       "pattern",
        "severity":   "HIGH",
        "mitre":      "T0855",
        "conditions": {"dst_port": 502, "protocol": 6},
    },

    {
        "id":         "R069",
        "name":       "DNP3 Access (ICS Protocol)",
        "type":       "pattern",
        "severity":   "HIGH",
        "mitre":      "T0855",
        "conditions": {"dst_port": 20000, "protocol": [6, 17]},
    },

    {
        "id":         "R070",
        "name":       "EtherNet/IP Access (ICS Protocol)",
        "type":       "pattern",
        "severity":   "HIGH",
        "mitre":      "T0855",
        "conditions": {"dst_port": 44818, "protocol": [6, 17]},
    },

    {
        "id":         "R071",
        "name":       "BACnet Access (Building Automation)",
        "type":       "pattern",
        "severity":   "MEDIUM",
        "mitre":      "T0855",
        "conditions": {"dst_port": 47808, "protocol": 17},
    },


    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 11 — POLICY VIOLATIONS  (R072–R074)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "id":         "R072",
        "name":       "Proxy / Anonymizer Port",
        "type":       "pattern",
        "severity":   "LOW",
        "mitre":      "T1090",
        "conditions": {"dst_port": [3128, 1080, 8118], "protocol": 6},
    },

    {
        "id":         "R073",
        "name":       "P2P / BitTorrent Port",
        "type":       "pattern",
        "severity":   "LOW",
        "mitre":      "T1048",
        "conditions": {
            "dst_port": [6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889],
            "protocol": [6, 17],
        },
    },

    {   # Stratum mining-pool ports — outbound connections = cryptojacking malware.
        "id":         "R074",
        "name":       "Cryptocurrency Mining Pool",
        "type":       "pattern",
        "severity":   "HIGH",
        "mitre":      "T1496",
        "conditions": {
            "dst_port": [3333, 3334, 3335, 14444, 45700],
            "protocol": 6,
        },
    },

]
