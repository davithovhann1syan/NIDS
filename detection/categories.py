from __future__ import annotations

# Maps every rule name to its display category.
# Single source of truth — imported by dashboard/app.py, dashboard/pcap_app.py,
# and scripts/replay_pcap.py.  Update here whenever a rule is added or renamed.
RULE_CATEGORY: dict[str, str] = {
    # ── Reconnaissance (R001–R016) ────────────────────────────────────────────
    "Port Scan (SYN)":                                        "Reconnaissance",
    "Port Scan (Distinct Ports)":                             "Reconnaissance",
    "Host Discovery Sweep (Distinct IPs)":                    "Reconnaissance",
    "Null Scan":                                              "Reconnaissance",
    "XMAS Scan":                                              "Reconnaissance",
    "FIN Scan":                                               "Reconnaissance",
    "Maimon Scan":                                            "Reconnaissance",
    "ACK Scan":                                               "Reconnaissance",
    "ICMP Host Sweep (Ping Sweep)":                           "Reconnaissance",
    "UDP Port Scan":                                          "Reconnaissance",
    "Invalid TCP Flags: SYN+RST":                             "Reconnaissance",
    "Invalid TCP Flags: SYN+FIN":                             "Reconnaissance",
    "Oversized ICMP Packet":                                  "Reconnaissance",
    "Low TTL Probe (Traceroute / Evasion)":                   "Reconnaissance",
    "ICMP Redirect (Routing Manipulation)":                   "Infrastructure Attack",
    "TCP SYN with Large Payload":                             "Reconnaissance",
    # ── Brute Force (R017–R028) ───────────────────────────────────────────────
    "SSH Brute Force":                                        "Brute Force",
    "RDP Brute Force":                                        "Brute Force",
    "FTP Brute Force":                                        "Brute Force",
    "Telnet Brute Force":                                     "Brute Force",
    "SMTP Auth Brute Force":                                  "Brute Force",
    "IMAP Brute Force":                                       "Brute Force",
    "POP3 Brute Force":                                       "Brute Force",
    "VNC Brute Force":                                        "Brute Force",
    "MySQL Brute Force":                                      "Brute Force",
    "PostgreSQL Brute Force":                                 "Brute Force",
    "MSSQL Brute Force":                                      "Brute Force",
    "Kerberos Brute Force (AS-REP Roasting / Password Spray)":"Brute Force",
    # ── Denial of Service (R029–R033) ─────────────────────────────────────────
    "SYN Flood":                                              "Denial of Service",
    "ICMP Flood":                                             "Denial of Service",
    "UDP Flood":                                              "Denial of Service",
    "RST Flood":                                              "Denial of Service",
    "ACK Flood":                                              "Denial of Service",
    # ── Suspicious Services (R034–R037) ──────────────────────────────────────
    "Telnet Attempt":                                         "Suspicious Services",
    "rlogin / rsh Attempt":                                   "Suspicious Services",
    "TFTP Access":                                            "Suspicious Services",
    "LLMNR Traffic (Possible Responder / MITM)":              "Suspicious Services",
    # ── Malware & C2 (R038–R045) ─────────────────────────────────────────────
    "Known C2 / Backdoor Port":                               "Malware & C2",
    "Possible Reverse Shell (High Outbound Port)":            "Malware & C2",
    "IRC Traffic (Possible Botnet C2)":                       "Malware & C2",
    "Tor Default Port":                                       "Malware & C2",
    "DNS over Non-Standard Port (Possible DNS Tunneling)":    "Malware & C2",
    "Cobalt Strike Default Beacon Port":                      "Malware & C2",
    "Netcat / Bind Shell Default Port":                       "Malware & C2",
    "Aggressive Outbound SYN Rate (Worm / Scanner)":          "Malware & C2",
    # ── Lateral Movement (R046–R047) ──────────────────────────────────────────
    "SMB Sweep (Ransomware Propagation)":                     "Lateral Movement",
    "WinRM Access (Possible Lateral Movement)":               "Lateral Movement",
    # ── Exposed Services (R048–R056) ─────────────────────────────────────────
    "Redis Exposed (No Auth)":                                "Exposed Services",
    "Elasticsearch Exposed":                                  "Exposed Services",
    "MongoDB Exposed":                                        "Exposed Services",
    "Docker API Exposed":                                     "Exposed Services",
    "Kubernetes API Exposed":                                 "Exposed Services",
    "etcd Exposed":                                           "Exposed Services",
    "Memcached Exposed (DDoS Amplification)":                 "Exposed Services",
    "CouchDB Exposed":                                        "Exposed Services",
    "Hadoop / HDFS Exposed":                                  "Exposed Services",
    # ── Exfiltration (R057–R060) ──────────────────────────────────────────────
    "DNS Query Flood UDP (Possible DNS Tunneling)":           "Exfiltration",
    "DNS Query Flood TCP (Possible DNS Tunneling)":           "Exfiltration",
    "ICMP Exfiltration (Large Volume)":                       "Exfiltration",
    "FTP Data Channel (Possible Exfiltration)":               "Exfiltration",
    # ── Infrastructure Attack (R061–R067) ─────────────────────────────────────
    "DNS Amplification Attack":                               "Infrastructure Attack",
    "NTP Amplification Attack":                               "Infrastructure Attack",
    "BGP Connection Attempt":                                 "Infrastructure Attack",
    "OSPF Injection":                                         "Infrastructure Attack",
    "EIGRP Traffic":                                          "Infrastructure Attack",
    "GRE Tunnel Traffic":                                     "Infrastructure Attack",
    "IPv6-in-IPv4 Tunnel":                                    "Infrastructure Attack",
    # ── ICS / SCADA (R068–R071) ───────────────────────────────────────────────
    "Modbus Access (ICS Protocol)":                           "ICS / SCADA",
    "DNP3 Access (ICS Protocol)":                             "ICS / SCADA",
    "EtherNet/IP Access (ICS Protocol)":                      "ICS / SCADA",
    "BACnet Access (Building Automation)":                    "ICS / SCADA",
    # ── Policy Violation (R072–R074) ──────────────────────────────────────────
    "Proxy / Anonymizer Port":                                "Policy Violation",
    "P2P / BitTorrent Port":                                  "Policy Violation",
    "Cryptocurrency Mining Pool":                             "Policy Violation",
}

# Ordered from highest to lowest — used wherever a sorted severity list is needed.
SEV_ORDER: list[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
