"""
NIDS traffic generator — craft packets that trigger detection signatures.

Requires root (raw socket). Run from a separate machine or via loopback.

Single attack:
    sudo python scripts/gen_traffic.py --target 192.168.1.5 --attack syn_scan
    sudo python scripts/gen_traffic.py --target 192.168.1.5 --attack ssh_brute --port 22
    sudo python scripts/gen_traffic.py --list

Scenario (multi-step attack chain):
    sudo python scripts/gen_traffic.py --target 192.168.1.5 --scenario apt_campaign
    sudo python scripts/gen_traffic.py --scenarios

Interactive menu:
    sudo python scripts/gen_traffic.py --target 192.168.1.5 --interactive
"""
from __future__ import annotations

import argparse
import random
import sys
import time
from typing import Callable

try:
    from scapy.all import IP, TCP, UDP, ICMP, Raw, GRE, send, RandShort, conf as _scapy_conf
    _scapy_conf.verb = 0
except ImportError:
    sys.exit("scapy is not installed — pip install scapy")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _rfc1918() -> str:
    """Random RFC-1918 source IP."""
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _s(pkt: object, iface: str, delay: float) -> None:
    """Send one packet, optionally on a specific interface, with optional inter-packet delay."""
    kw = {"iface": iface} if iface else {}
    send(pkt, **kw)  # type: ignore[arg-type]
    if delay:
        time.sleep(delay)


def _progress(i: int, total: int, label: str) -> None:
    if total >= 50 and i % max(1, total // 10) == 0:
        pct = i * 100 // total
        bar  = "█" * (pct // 10) + "░" * (10 - pct // 10)
        print(f"\r    [{bar}] {pct:>3}% ({i}/{total})  {label}      ", end="", flush=True)
    if i == total:
        print()


def _subnet_hosts(target: str, n: int) -> list[str]:
    """Return up to n distinct IPs in the same /24 subnet as target."""
    parts = target.split(".")
    if len(parts) != 4:
        return [target]
    base = ".".join(parts[:3]) + "."
    my   = int(parts[3])
    pool = [f"{base}{i}" for i in range(1, 255) if i != my]
    random.shuffle(pool)
    return pool[:n]


# ── Attack functions ──────────────────────────────────────────────────────────
# Signature: (target, port, count, src_ip, iface, delay) -> None

# ─── Reconnaissance ──────────────────────────────────────────────────────────

def syn_scan(target, port, count, src_ip, iface, delay):
    """R001/R002 — SYN flood to random ports. Triggers Port Scan (SYN) and Port Scan (Distinct Ports)."""
    print(f"  → {count} SYN packets to {target} on random ports")
    for i in range(1, count + 1):
        dst = random.randint(1, 65535)
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=dst, flags="S"), iface, delay)
        _progress(i, count, "syn_scan")


def host_sweep(target, port, count, src_ip, iface, delay):
    """R003 — ICMP echo to many unique IPs. Triggers Host Discovery Sweep (Distinct IPs)."""
    hosts = _subnet_hosts(target, count)
    print(f"  → ICMP echo to {len(hosts)} hosts in {'.'.join(target.split('.')[:3])}.x/24")
    for i, host in enumerate(hosts, 1):
        _s(IP(src=src_ip, dst=host) / ICMP(type=8), iface, delay)
        _progress(i, len(hosts), "host_sweep")


def null_scan(target, port, count, src_ip, iface, delay):
    """R004 — TCP with no flags set. Triggers Null Scan."""
    print(f"  → {count} NULL-flag TCP packets to {target}:{port}")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=port, flags=0), iface, delay)
        _progress(i, count, "null_scan")


def xmas_scan(target, port, count, src_ip, iface, delay):
    """R005 — FIN+PSH+URG. Triggers XMAS Scan."""
    print(f"  → {count} XMAS-scan (FIN+PSH+URG) packets to {target}:{port}")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=port, flags="FPU"), iface, delay)
        _progress(i, count, "xmas_scan")


def fin_scan(target, port, count, src_ip, iface, delay):
    """R006 — FIN only (no ACK). Triggers FIN Scan."""
    print(f"  → {count} FIN-scan packets to {target}:{port}")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=port, flags="F"), iface, delay)
        _progress(i, count, "fin_scan")


def maimon_scan(target, port, count, src_ip, iface, delay):
    """R007 — FIN+ACK to many unique dst_ports. Triggers Maimon Scan."""
    print(f"  → {count} FIN+ACK packets to {target} on unique ports")
    ports_used: set[int] = set()
    sent = 0
    while sent < count:
        dst = random.randint(1, 65535)
        ports_used.add(dst)
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=dst, flags="FA"), iface, delay)
        sent += 1
        _progress(sent, count, f"maimon_scan  {len(ports_used)} unique ports")


def ack_scan(target, port, count, src_ip, iface, delay):
    """R008 — ACK-only to many unique dst_ports. Triggers ACK Scan."""
    print(f"  → {count} pure-ACK packets to {target} on unique ports")
    ports_used: set[int] = set()
    sent = 0
    while sent < count:
        dst = random.randint(1, 65535)
        ports_used.add(dst)
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=dst, flags="A"), iface, delay)
        sent += 1
        _progress(sent, count, f"ack_scan  {len(ports_used)} unique ports")


def icmp_sweep(target, port, count, src_ip, iface, delay):
    """R009 — ICMP echo burst. Triggers ICMP Host Sweep (Ping Sweep)."""
    print(f"  → {count} ICMP echo-request packets to {target}")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / ICMP(type=8), iface, delay)
        _progress(i, count, "icmp_sweep")


def udp_scan(target, port, count, src_ip, iface, delay):
    """R010 — UDP to random ports. Triggers UDP Port Scan."""
    print(f"  → {count} UDP packets to {target} on random ports")
    for i in range(1, count + 1):
        dst = random.randint(1, 65535)
        _s(IP(src=src_ip, dst=target) / UDP(sport=RandShort(), dport=dst), iface, delay)
        _progress(i, count, "udp_scan")


def syn_rst(target, port, count, src_ip, iface, delay):
    """R011 — SYN+RST simultaneously (RFC-forbidden). Triggers Invalid TCP Flags: SYN+RST."""
    print(f"  → {count} SYN+RST packets to {target}:{port}")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=port, flags="SR"), iface, delay)
        _progress(i, count, "syn+rst")


def syn_fin(target, port, count, src_ip, iface, delay):
    """R012 — SYN+FIN simultaneously (RFC-forbidden). Triggers Invalid TCP Flags: SYN+FIN."""
    print(f"  → {count} SYN+FIN packets to {target}:{port}")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=port, flags="FS"), iface, delay)
        _progress(i, count, "syn+fin")


def oversized_icmp(target, port, count, src_ip, iface, delay):
    """R013 — ICMP echo with 1 100-byte payload. Triggers Oversized ICMP Packet."""
    payload = Raw(b"X" * 1100)
    print(f"  → {count} oversized ICMP packets (1 100 B payload) to {target}")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / ICMP(type=8) / payload, iface, delay)
        _progress(i, count, "oversized_icmp")


def low_ttl_probe(target, port, count, src_ip, iface, delay):
    """R014 — TCP SYN with TTL=2. Triggers Low TTL Probe (Traceroute / Evasion)."""
    print(f"  → {count} SYN packets with TTL=2 to {target}:{port}")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target, ttl=2) / TCP(sport=RandShort(), dport=port, flags="S"), iface, delay)
        _progress(i, count, "low_ttl")


def icmp_redirect(target, port, count, src_ip, iface, delay):
    """R015 — ICMP type 5 (redirect). Triggers ICMP Redirect (Routing Manipulation)."""
    print(f"  → {count} ICMP Redirect (type=5) packets to {target}")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / ICMP(type=5, code=1), iface, delay)
        _progress(i, count, "icmp_redirect")


def syn_large_payload(target, port, count, src_ip, iface, delay):
    """R016 — TCP SYN with 100-byte payload. Triggers TCP SYN with Large Payload."""
    payload = Raw(b"A" * 100)
    print(f"  → {count} SYN packets with 100 B payload to {target}:{port}")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=port, flags="S") / payload, iface, delay)
        _progress(i, count, "syn_large")


# ─── Brute Force ─────────────────────────────────────────────────────────────

def brute_force(target, port, count, src_ip, iface, delay):
    """R017-R027 — Repeated SYNs to one service port. Triggers the matching brute-force rule."""
    svc = {22: "SSH", 3389: "RDP", 21: "FTP", 23: "Telnet", 5900: "VNC",
           3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL",
           587: "SMTP", 465: "SMTPS", 143: "IMAP", 993: "IMAPS",
           110: "POP3", 995: "POP3S"}.get(port, f"port {port}")
    print(f"  → {count} SYN packets to {target}:{port} ({svc} brute-force pattern)")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=port, flags="S"), iface, delay)
        _progress(i, count, f"brute_{svc.lower()}")


def kerberos_brute(target, port, count, src_ip, iface, delay):
    """R028 — SYN flood to Kerberos port 88. Triggers Kerberos Brute Force (AS-REP Roasting)."""
    print(f"  → {count} SYN packets to {target}:88 (Kerberos)")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=88, flags="S"), iface, delay)
        _progress(i, count, "kerberos_brute")


# ─── DoS / Floods ─────────────────────────────────────────────────────────────

def syn_flood(target, port, count, src_ip, iface, delay):
    """R029 — 200+ SYNs in 5 s from spoofed IPs. Triggers SYN Flood."""
    print(f"  → {count} SYN packets to {target}:{port} from random sources (SYN flood)")
    for i in range(1, count + 1):
        _s(IP(src=_rfc1918(), dst=target) / TCP(sport=RandShort(), dport=port, flags="S"), iface, delay)
        _progress(i, count, "syn_flood")


def icmp_flood(target, port, count, src_ip, iface, delay):
    """R030 — 100+ ICMP pings in 10 s. Triggers ICMP Flood."""
    print(f"  → {count} ICMP echo-request packets to {target} (ICMP flood)")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / ICMP(type=8), iface, delay)
        _progress(i, count, "icmp_flood")


def udp_flood(target, port, count, src_ip, iface, delay):
    """R031 — 1 000+ UDP packets in 10 s. Triggers UDP Flood."""
    print(f"  → {count} UDP packets to {target}:{port} (UDP flood)")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / UDP(sport=RandShort(), dport=port), iface, delay)
        _progress(i, count, "udp_flood")


def rst_flood(target, port, count, src_ip, iface, delay):
    """R032 — 100+ RST packets in 10 s. Triggers RST Flood (TCP session teardown attack)."""
    print(f"  → {count} RST packets to {target}:{port} from spoofed IPs")
    for i in range(1, count + 1):
        _s(IP(src=_rfc1918(), dst=target) / TCP(sport=RandShort(), dport=port, flags="R"), iface, delay)
        _progress(i, count, "rst_flood")


def ack_flood(target, port, count, src_ip, iface, delay):
    """R033 — 500+ ACK packets in 10 s. Triggers ACK Flood."""
    print(f"  → {count} ACK packets to {target}:{port} from spoofed IPs")
    for i in range(1, count + 1):
        _s(IP(src=_rfc1918(), dst=target) / TCP(sport=RandShort(), dport=port, flags="A"), iface, delay)
        _progress(i, count, "ack_flood")


# ─── Suspicious Services ──────────────────────────────────────────────────────

def telnet_attempt(target, port, count, src_ip, iface, delay):
    """R034 — SYN to Telnet port 23. Triggers Telnet Attempt."""
    print(f"  → {count} SYN packets to {target}:23 (Telnet)")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=23, flags="S"), iface, delay)
        _progress(i, count, "telnet")


def rsh_attempt(target, port, count, src_ip, iface, delay):
    """R035 — TCP to rexec/rlogin/rsh ports 512-514. Triggers rlogin / rsh Attempt."""
    print(f"  → {count} packets to {target} on legacy remote ports (512/513/514)")
    for i in range(1, count + 1):
        dst = random.choice([512, 513, 514])
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=dst), iface, delay)
        _progress(i, count, "rsh_attempt")


def tftp_access(target, port, count, src_ip, iface, delay):
    """R036 — UDP to TFTP port 69. Triggers TFTP Access (unauthenticated file transfer)."""
    print(f"  → {count} UDP packets to {target}:69 (TFTP)")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / UDP(sport=RandShort(), dport=69), iface, delay)
        _progress(i, count, "tftp")


def llmnr_probe(target, port, count, src_ip, iface, delay):
    """R037 — UDP to LLMNR port 5355. Triggers LLMNR Traffic (Possible Responder/MITM)."""
    print(f"  → {count} UDP packets to {target}:5355 (LLMNR/Responder probe)")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / UDP(sport=RandShort(), dport=5355), iface, delay)
        _progress(i, count, "llmnr")


# ─── Malware / C2 ─────────────────────────────────────────────────────────────

def c2_beacon(target, port, count, src_ip, iface, delay):
    """R038 — SYN to known backdoor port. Triggers Known C2 / Backdoor Port."""
    c2_ports = [4444, 1337, 31337, 6666, 6667, 1234, 12345, 54321]
    chosen = port if port in c2_ports else 4444
    print(f"  → {count} SYN packets to {target}:{chosen} (C2 beacon)")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=chosen, flags="S"), iface, delay)
        _progress(i, count, "c2_beacon")


def reverse_shell(target, port, count, src_ip, iface, delay):
    """R039 — SYN to 6+ unique ports >60000. Triggers Possible Reverse Shell (High Outbound Port)."""
    high_ports = random.sample(range(60001, 65535), min(count, 5000))[:count]
    print(f"  → SYN to {len(high_ports)} unique high ports (>60000) on {target}")
    for i, hp in enumerate(high_ports, 1):
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=hp, flags="S"), iface, delay)
        _progress(i, len(high_ports), f"reverse_shell  {i} unique ports")


def irc_c2(target, port, count, src_ip, iface, delay):
    """R040 — TCP to IRC ports 6660-6669,7000. Triggers IRC Traffic (Possible Botnet C2)."""
    irc_ports = [6660, 6661, 6662, 6663, 6664, 6665, 6668, 6669, 7000]
    print(f"  → {count} TCP packets to {target} on IRC ports")
    for i in range(1, count + 1):
        dst = random.choice(irc_ports)
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=dst), iface, delay)
        _progress(i, count, "irc_c2")


def tor_exit(target, port, count, src_ip, iface, delay):
    """R041 — TCP to Tor ports 9050/9051/9150. Triggers Tor Default Port."""
    tor_ports = [9050, 9051, 9150]
    print(f"  → {count} TCP packets to {target} on Tor SOCKS ports")
    for i in range(1, count + 1):
        dst = random.choice(tor_ports)
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=dst), iface, delay)
        _progress(i, count, "tor")


def dns_nonstandard(target, port, count, src_ip, iface, delay):
    """R042 — UDP/TCP to ports 8053/8853. Triggers DNS over Non-Standard Port."""
    print(f"  → {count} DNS-over-alt-port packets to {target} (8053/8853)")
    for i in range(1, count + 1):
        dst = random.choice([8053, 8853])
        _s(IP(src=src_ip, dst=target) / UDP(sport=RandShort(), dport=dst), iface, delay)
        _progress(i, count, "dns_nonstandard")


def cobalt_strike(target, port, count, src_ip, iface, delay):
    """R043 — TCP to port 50050. Triggers Cobalt Strike Default Beacon Port."""
    print(f"  → {count} TCP packets to {target}:50050 (Cobalt Strike team server)")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=50050), iface, delay)
        _progress(i, count, "cobalt_strike")


def netcat_shell(target, port, count, src_ip, iface, delay):
    """R044 — TCP to port 4242. Triggers Netcat / Bind Shell Default Port."""
    print(f"  → {count} TCP packets to {target}:4242 (netcat bind shell)")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=4242), iface, delay)
        _progress(i, count, "netcat")


def aggressive_syn(target, port, count, src_ip, iface, delay):
    """R045 — 300+ SYNs in 60 s from one source. Triggers Aggressive Outbound SYN Rate (Worm/Scanner)."""
    print(f"  → {count} SYN packets to {target} on random ports (worm rate)")
    for i in range(1, count + 1):
        dst = random.randint(1, 65535)
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=dst, flags="S"), iface, delay)
        _progress(i, count, "aggressive_syn")


# ─── Lateral Movement ─────────────────────────────────────────────────────────

def smb_sweep(target, port, count, src_ip, iface, delay):
    """R046 — 10+ SYNs to port 445 in 10 s. Triggers SMB Sweep (Ransomware Propagation)."""
    print(f"  → {count} SYN packets to {target}:445 (SMB sweep — ransomware propagation pattern)")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=445, flags="S"), iface, delay)
        _progress(i, count, "smb_sweep")


def winrm_access(target, port, count, src_ip, iface, delay):
    """R047 — TCP to WinRM ports 5985/5986. Triggers WinRM Access (Possible Lateral Movement)."""
    print(f"  → {count} TCP packets to {target} on WinRM ports (5985/5986)")
    for i in range(1, count + 1):
        dst = random.choice([5985, 5986])
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=dst), iface, delay)
        _progress(i, count, "winrm")


# ─── Exposed Services ─────────────────────────────────────────────────────────

def exposed_service(target, port, count, src_ip, iface, delay):
    """R048-R056 — 3+ SYNs to an exposed DB/infra port. Use --port: 6379 Redis, 27017 MongoDB,
    9200 Elasticsearch, 2375 Docker, 6443 Kubernetes, 2379 etcd, 11211 Memcached, 5984 CouchDB."""
    svc = {6379: "Redis", 9200: "Elasticsearch", 9300: "Elasticsearch (transport)",
           27017: "MongoDB", 2375: "Docker API", 2376: "Docker API (TLS)",
           6443: "Kubernetes API", 8001: "kubectl proxy",
           2379: "etcd client", 2380: "etcd peer",
           11211: "Memcached", 5984: "CouchDB",
           50070: "Hadoop NameNode", 8088: "Hadoop YARN"}.get(port, f"port {port}")
    proto = UDP if port == 11211 else TCP
    flags_kw = {"flags": "S"} if proto is TCP else {}
    print(f"  → {count} SYN packets to {target}:{port} ({svc} exposed service probe)")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / proto(sport=RandShort(), dport=port, **flags_kw), iface, delay)
        _progress(i, count, f"exposed_{svc.split()[0].lower()}")


# ─── Exfiltration ─────────────────────────────────────────────────────────────

def dns_tunnel(target, port, count, src_ip, iface, delay):
    """R057 — 200+ UDP DNS queries in 60 s. Triggers DNS Query Flood UDP (Possible DNS Tunneling)."""
    print(f"  → {count} UDP DNS queries to {target}:53")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / UDP(sport=RandShort(), dport=53), iface, delay)
        _progress(i, count, "dns_tunnel")


def icmp_exfil(target, port, count, src_ip, iface, delay):
    """R059 — 50+ ICMP pings in 60 s. Triggers ICMP Exfiltration (Large Volume)."""
    print(f"  → {count} ICMP echo packets to {target} (covert-channel pattern)")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / ICMP(type=8), iface, delay)
        _progress(i, count, "icmp_exfil")


# ─── Network Infrastructure Attacks ───────────────────────────────────────────

def dns_amplification(target, port, count, src_ip, iface, delay):
    """R061 — 500+ UDP packets with sport=53 in 10 s. Triggers DNS Amplification Attack.
    Simulates DNS reflection: open resolvers sending responses to the victim."""
    print(f"  → {count} UDP packets with src_port=53 destined to {target} (DNS reflection)")
    for i in range(1, count + 1):
        _s(IP(src=_rfc1918(), dst=target) / UDP(sport=53, dport=random.randint(1024, 65535)), iface, delay)
        _progress(i, count, "dns_amplification")


def ntp_amplification(target, port, count, src_ip, iface, delay):
    """R062 — 200+ UDP packets with sport=123 in 10 s. Triggers NTP Amplification Attack."""
    print(f"  → {count} UDP packets with src_port=123 destined to {target} (NTP reflection)")
    for i in range(1, count + 1):
        _s(IP(src=_rfc1918(), dst=target) / UDP(sport=123, dport=random.randint(1024, 65535)), iface, delay)
        _progress(i, count, "ntp_amplification")


def bgp_hijack(target, port, count, src_ip, iface, delay):
    """R063 — TCP to BGP port 179. Triggers BGP Connection Attempt."""
    print(f"  → {count} TCP packets to {target}:179 (BGP hijack probe)")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=179), iface, delay)
        _progress(i, count, "bgp_hijack")


def ospf_inject(target, port, count, src_ip, iface, delay):
    """R064 — IP protocol 89 (OSPF). Triggers OSPF Injection."""
    print(f"  → {count} raw OSPF packets (IP proto=89) to {target}")
    hello = b"\x02\x01" + b"\x00" * 22  # minimal OSPF Hello header
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target, proto=89) / Raw(hello), iface, delay)
        _progress(i, count, "ospf_inject")


def gre_tunnel(target, port, count, src_ip, iface, delay):
    """R066 — IP protocol 47 (GRE). Triggers GRE Tunnel Traffic."""
    print(f"  → {count} GRE-encapsulated packets to {target}")
    for i in range(1, count + 1):
        inner = IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=80, flags="S")
        _s(IP(src=src_ip, dst=target) / GRE() / inner, iface, delay)
        _progress(i, count, "gre_tunnel")


# ─── ICS / SCADA ──────────────────────────────────────────────────────────────

def modbus_access(target, port, count, src_ip, iface, delay):
    """R068 — TCP to Modbus port 502. Triggers Modbus Access (ICS Protocol)."""
    print(f"  → {count} TCP packets to {target}:502 (Modbus/ICS)")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=502), iface, delay)
        _progress(i, count, "modbus")


def dnp3_access(target, port, count, src_ip, iface, delay):
    """R069 — TCP/UDP to DNP3 port 20000. Triggers DNP3 Access (ICS Protocol)."""
    print(f"  → {count} packets to {target}:20000 (DNP3 SCADA)")
    for i in range(1, count + 1):
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=20000), iface, delay)
        _progress(i, count, "dnp3")


# ─── Policy Violations ────────────────────────────────────────────────────────

def proxy_access(target, port, count, src_ip, iface, delay):
    """R072 — TCP to proxy ports 3128/1080/8118. Triggers Proxy / Anonymizer Port."""
    proxy_ports = [3128, 1080, 8118]
    print(f"  → {count} TCP packets to {target} on proxy/anonymizer ports")
    for i in range(1, count + 1):
        dst = random.choice(proxy_ports)
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=dst), iface, delay)
        _progress(i, count, "proxy")


def mining_pool(target, port, count, src_ip, iface, delay):
    """R074 — TCP to crypto-mining pool ports. Triggers Cryptocurrency Mining Pool."""
    mining_ports = [3333, 3334, 3335, 14444, 45700]
    print(f"  → {count} TCP packets to {target} on Stratum mining-pool ports")
    for i in range(1, count + 1):
        dst = random.choice(mining_ports)
        _s(IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=dst), iface, delay)
        _progress(i, count, "mining_pool")


# ── Attack catalogue ──────────────────────────────────────────────────────────

ATTACKS: dict[str, dict] = {
    # ── Reconnaissance ──────────────────────────────────────────────────────
    "syn_scan":         {"fn": syn_scan,          "rule": "R001/R002", "sev": "HIGH",
                         "desc": "SYN flood to random ports (nmap -sS style)",
                         "count": 110,  "port": 80},
    "host_sweep":       {"fn": host_sweep,         "rule": "R003",      "sev": "HIGH",
                         "desc": "ICMP echo to 25 unique IPs in same /24",
                         "count": 25,   "port": 0},
    "null_scan":        {"fn": null_scan,          "rule": "R004",      "sev": "HIGH",
                         "desc": "TCP with no flags set (RFC-forbidden)",
                         "count": 3,    "port": 80},
    "xmas_scan":        {"fn": xmas_scan,          "rule": "R005",      "sev": "HIGH",
                         "desc": "TCP FIN+PSH+URG (XMAS scan)",
                         "count": 3,    "port": 80},
    "fin_scan":         {"fn": fin_scan,           "rule": "R006",      "sev": "MEDIUM",
                         "desc": "TCP FIN only (no ACK — RFC-forbidden teardown)",
                         "count": 3,    "port": 80},
    "maimon_scan":      {"fn": maimon_scan,        "rule": "R007",      "sev": "MEDIUM",
                         "desc": "FIN+ACK to 25 unique destination ports (Maimon scan)",
                         "count": 25,   "port": 0},
    "ack_scan":         {"fn": ack_scan,           "rule": "R008",      "sev": "MEDIUM",
                         "desc": "Pure ACK to 35 unique destination ports (firewall map)",
                         "count": 35,   "port": 0},
    "icmp_sweep":       {"fn": icmp_sweep,         "rule": "R009",      "sev": "MEDIUM",
                         "desc": "ICMP echo flood to single target (ping sweep)",
                         "count": 25,   "port": 0},
    "udp_scan":         {"fn": udp_scan,           "rule": "R010",      "sev": "MEDIUM",
                         "desc": "UDP to random ports",
                         "count": 510,  "port": 0},
    "syn_rst":          {"fn": syn_rst,            "rule": "R011",      "sev": "MEDIUM",
                         "desc": "SYN+RST simultaneously (RFC-forbidden, IDS evasion)",
                         "count": 3,    "port": 80},
    "syn_fin":          {"fn": syn_fin,            "rule": "R012",      "sev": "MEDIUM",
                         "desc": "SYN+FIN simultaneously (RFC-forbidden)",
                         "count": 3,    "port": 80},
    "oversized_icmp":   {"fn": oversized_icmp,     "rule": "R013",      "sev": "MEDIUM",
                         "desc": "ICMP echo with 1 100-byte payload (covert channel / ping-of-death)",
                         "count": 3,    "port": 0},
    "low_ttl_probe":    {"fn": low_ttl_probe,      "rule": "R014",      "sev": "LOW",
                         "desc": "SYN with TTL=2 (traceroute / topology evasion)",
                         "count": 3,    "port": 80},
    "icmp_redirect":    {"fn": icmp_redirect,      "rule": "R015",      "sev": "HIGH",
                         "desc": "ICMP Redirect type=5 (route poisoning / MITM)",
                         "count": 3,    "port": 0},
    "syn_large":        {"fn": syn_large_payload,  "rule": "R016",      "sev": "MEDIUM",
                         "desc": "SYN with 100-byte payload (shellcode embed / SYN amplification)",
                         "count": 3,    "port": 80},
    # ── Brute Force ─────────────────────────────────────────────────────────
    "brute_force":      {"fn": brute_force,        "rule": "R017-R027", "sev": "CRITICAL",
                         "desc": "Repeated SYNs to --port (22=SSH, 3389=RDP, 21=FTP, 5900=VNC …)",
                         "count": 12,   "port": 22},
    "kerberos_brute":   {"fn": kerberos_brute,     "rule": "R028",      "sev": "CRITICAL",
                         "desc": "SYN flood to Kerberos port 88 (AS-REP roasting prep)",
                         "count": 25,   "port": 88},
    # ── DoS / Floods ────────────────────────────────────────────────────────
    "syn_flood":        {"fn": syn_flood,          "rule": "R029",      "sev": "CRITICAL",
                         "desc": "High-rate SYN flood from spoofed IPs (DoS)",
                         "count": 210,  "port": 80},
    "icmp_flood":       {"fn": icmp_flood,         "rule": "R030",      "sev": "HIGH",
                         "desc": "High-rate ICMP ping flood (DoS)",
                         "count": 110,  "port": 0},
    "udp_flood":        {"fn": udp_flood,           "rule": "R031",     "sev": "HIGH",
                         "desc": "High-rate UDP flood to --port (DoS)",
                         "count": 1010, "port": 80},
    "rst_flood":        {"fn": rst_flood,           "rule": "R032",     "sev": "HIGH",
                         "desc": "RST flood to kill established TCP sessions",
                         "count": 110,  "port": 80},
    "ack_flood":        {"fn": ack_flood,           "rule": "R033",     "sev": "HIGH",
                         "desc": "ACK flood to saturate stateful firewall tables",
                         "count": 510,  "port": 80},
    # ── Suspicious Services ─────────────────────────────────────────────────
    "telnet_attempt":   {"fn": telnet_attempt,     "rule": "R034",      "sev": "MEDIUM",
                         "desc": "SYN to Telnet port 23 (unencrypted remote access)",
                         "count": 3,    "port": 23},
    "rsh_attempt":      {"fn": rsh_attempt,        "rule": "R035",      "sev": "HIGH",
                         "desc": "TCP to legacy rexec/rlogin/rsh ports 512-514",
                         "count": 3,    "port": 513},
    "tftp_access":      {"fn": tftp_access,        "rule": "R036",      "sev": "MEDIUM",
                         "desc": "UDP to TFTP port 69 (unauthenticated file transfer)",
                         "count": 3,    "port": 69},
    "llmnr_probe":      {"fn": llmnr_probe,        "rule": "R037",      "sev": "LOW",
                         "desc": "UDP to LLMNR port 5355 (Responder / hash capture setup)",
                         "count": 3,    "port": 5355},
    # ── Malware / C2 ────────────────────────────────────────────────────────
    "c2_beacon":        {"fn": c2_beacon,          "rule": "R038",      "sev": "CRITICAL",
                         "desc": "SYN to known backdoor port (default 4444, override with --port)",
                         "count": 3,    "port": 4444},
    "reverse_shell":    {"fn": reverse_shell,      "rule": "R039",      "sev": "HIGH",
                         "desc": "SYN to 6 unique ports >60 000 (bind-shell / reverse shell scan)",
                         "count": 6,    "port": 0},
    "irc_c2":           {"fn": irc_c2,             "rule": "R040",      "sev": "MEDIUM",
                         "desc": "TCP to IRC ports 6660-6669 (botnet C2)",
                         "count": 3,    "port": 6667},
    "tor_exit":         {"fn": tor_exit,           "rule": "R041",      "sev": "MEDIUM",
                         "desc": "TCP to Tor SOCKS ports 9050/9051/9150",
                         "count": 3,    "port": 9050},
    "dns_nonstandard":  {"fn": dns_nonstandard,    "rule": "R042",      "sev": "MEDIUM",
                         "desc": "DNS over alt port 8053/8853 (dnscat2/iodine)",
                         "count": 3,    "port": 8053},
    "cobalt_strike":    {"fn": cobalt_strike,      "rule": "R043",      "sev": "CRITICAL",
                         "desc": "TCP to Cobalt Strike team server port 50050",
                         "count": 3,    "port": 50050},
    "netcat_shell":     {"fn": netcat_shell,       "rule": "R044",      "sev": "HIGH",
                         "desc": "TCP to netcat/bind-shell default port 4242",
                         "count": 3,    "port": 4242},
    "aggressive_syn":   {"fn": aggressive_syn,     "rule": "R045",      "sev": "MEDIUM",
                         "desc": "300+ SYNs in 60 s from one IP (worm/scanner rate)",
                         "count": 310,  "port": 80},
    # ── Lateral Movement ────────────────────────────────────────────────────
    "smb_sweep":        {"fn": smb_sweep,          "rule": "R046",      "sev": "CRITICAL",
                         "desc": "10+ SYNs to SMB port 445 in 10 s (ransomware propagation)",
                         "count": 12,   "port": 445},
    "winrm_access":     {"fn": winrm_access,       "rule": "R047",      "sev": "MEDIUM",
                         "desc": "TCP to WinRM ports 5985/5986 (lateral movement via PowerShell)",
                         "count": 3,    "port": 5985},
    # ── Exposed Services ────────────────────────────────────────────────────
    "exposed_service":  {"fn": exposed_service,    "rule": "R048-R056", "sev": "CRITICAL",
                         "desc": "4 SYNs to exposed DB/infra port (--port: 6379 Redis, 27017 Mongo, 2375 Docker …)",
                         "count": 4,    "port": 6379},
    # ── Exfiltration ────────────────────────────────────────────────────────
    "dns_tunnel":       {"fn": dns_tunnel,         "rule": "R057",      "sev": "HIGH",
                         "desc": "200+ UDP DNS queries in 60 s (iodine/dnscat2 tunneling)",
                         "count": 210,  "port": 53},
    "icmp_exfil":       {"fn": icmp_exfil,         "rule": "R059",      "sev": "MEDIUM",
                         "desc": "50+ ICMP pings in 60 s (icmptunnel / ptunnel exfiltration)",
                         "count": 55,   "port": 0},
    # ── Network Infrastructure ───────────────────────────────────────────────
    "dns_amplification":{"fn": dns_amplification,  "rule": "R061",      "sev": "CRITICAL",
                         "desc": "500+ UDP pkts with src_port=53 (DNS reflection DDoS)",
                         "count": 510,  "port": 53},
    "ntp_amplification":{"fn": ntp_amplification,  "rule": "R062",      "sev": "CRITICAL",
                         "desc": "200+ UDP pkts with src_port=123 (NTP reflection DDoS)",
                         "count": 210,  "port": 123},
    "bgp_hijack":       {"fn": bgp_hijack,         "rule": "R063",      "sev": "HIGH",
                         "desc": "TCP to BGP port 179 (route hijack probe)",
                         "count": 3,    "port": 179},
    "ospf_inject":      {"fn": ospf_inject,        "rule": "R064",      "sev": "HIGH",
                         "desc": "Raw IP protocol 89 (OSPF route injection)",
                         "count": 3,    "port": 0},
    "gre_tunnel":       {"fn": gre_tunnel,         "rule": "R066",      "sev": "MEDIUM",
                         "desc": "GRE-encapsulated traffic (tunneling to evade DPI)",
                         "count": 3,    "port": 0},
    # ── ICS / SCADA ─────────────────────────────────────────────────────────
    "modbus_access":    {"fn": modbus_access,      "rule": "R068",      "sev": "HIGH",
                         "desc": "TCP to Modbus port 502 (ICS/PLC protocol)",
                         "count": 3,    "port": 502},
    "dnp3_access":      {"fn": dnp3_access,        "rule": "R069",      "sev": "HIGH",
                         "desc": "TCP to DNP3 port 20000 (SCADA protocol)",
                         "count": 3,    "port": 20000},
    # ── Policy Violations ───────────────────────────────────────────────────
    "proxy_access":     {"fn": proxy_access,       "rule": "R072",      "sev": "LOW",
                         "desc": "TCP to proxy/anonymizer ports 3128/1080/8118",
                         "count": 3,    "port": 3128},
    "mining_pool":      {"fn": mining_pool,        "rule": "R074",      "sev": "HIGH",
                         "desc": "TCP to Stratum crypto-mining pool ports (cryptojacking)",
                         "count": 3,    "port": 3333},
}


# ── Scenario catalogue ────────────────────────────────────────────────────────

class Step:
    def __init__(self, attack: str, port: int = 0, count: int = 0, pause: float = 1.5, note: str = ""):
        self.attack = attack
        self.port   = port   # 0 = use attack default
        self.count  = count  # 0 = use attack default
        self.pause  = pause
        self.note   = note


SCENARIOS: dict[str, dict] = {

    "apt_campaign": {
        "desc": "APT-style multi-stage attack: host discovery → port scan → SSH brute → C2 → DNS exfil",
        "steps": [
            Step("host_sweep",   pause=2,   note="Phase 1 — reconnaissance: mapping live hosts"),
            Step("syn_scan",     pause=2,   note="Phase 2 — port discovery on target"),
            Step("brute_force",  port=22,   pause=2, note="Phase 3 — credential attack on SSH"),
            Step("cobalt_strike",pause=1.5, note="Phase 4 — C2 channel establishment"),
            Step("dns_tunnel",   pause=0,   note="Phase 5 — data exfiltration via DNS tunneling"),
        ],
    },

    "ransomware": {
        "desc": "Ransomware outbreak: port scan → RDP brute → SMB propagation → C2 beacon",
        "steps": [
            Step("syn_scan",    count=110, pause=2,   note="Phase 1 — scanning for open RDP/SMB"),
            Step("brute_force", port=3389, count=12,  pause=2, note="Phase 2 — RDP credential brute-force"),
            Step("smb_sweep",   count=12,  pause=2,   note="Phase 3 — lateral movement via SMB (WannaCry pattern)"),
            Step("c2_beacon",   port=4444, count=3,   pause=0, note="Phase 4 — establish C2 for ransomware payload"),
        ],
    },

    "ddos_wave": {
        "desc": "Multi-vector DDoS: SYN flood + UDP flood + ICMP flood + ACK flood",
        "steps": [
            Step("syn_flood",  count=210, pause=0.5, note="Wave 1 — SYN flood (state exhaustion)"),
            Step("udp_flood",  count=1010,pause=0.5, note="Wave 2 — UDP flood (bandwidth saturation)"),
            Step("icmp_flood", count=110, pause=0.5, note="Wave 3 — ICMP flood"),
            Step("ack_flood",  count=510, pause=0,   note="Wave 4 — ACK flood (stateful firewall exhaustion)"),
        ],
    },

    "reflection_ddos": {
        "desc": "Amplification DDoS: DNS reflection + NTP reflection",
        "steps": [
            Step("dns_amplification", count=510, pause=1, note="DNS amplification (open resolver flood)"),
            Step("ntp_amplification", count=210, pause=0, note="NTP amplification (monlist flood)"),
        ],
    },

    "insider_threat": {
        "desc": "Insider threat / data theft: Telnet → TFTP → DNS tunnel → Tor → crypto mining",
        "steps": [
            Step("telnet_attempt", count=3,  pause=1.5, note="Phase 1 — unencrypted remote access"),
            Step("tftp_access",    count=3,  pause=1.5, note="Phase 2 — unauthenticated file transfer"),
            Step("dns_tunnel",     count=210,pause=1.5, note="Phase 3 — data exfiltration via DNS"),
            Step("tor_exit",       count=3,  pause=1.5, note="Phase 4 — traffic anonymization via Tor"),
            Step("mining_pool",    count=3,  pause=0,   note="Phase 5 — cryptojacking (unauthorized resource use)"),
        ],
    },

    "red_team_recon": {
        "desc": "Red-team recon toolkit: invalid flags → stealth scans → host sweep → service probes",
        "steps": [
            Step("null_scan",      count=3,  pause=1, note="Null scan — firewall evasion / OS fingerprint"),
            Step("xmas_scan",      count=3,  pause=1, note="XMAS scan — OS fingerprint"),
            Step("fin_scan",       count=3,  pause=1, note="FIN scan — stateless firewall bypass"),
            Step("syn_rst",        count=3,  pause=1, note="SYN+RST — IDS confusion technique"),
            Step("maimon_scan",    count=25, pause=1, note="Maimon scan — BSD firewall rule mapping"),
            Step("ack_scan",       count=35, pause=1, note="ACK scan — stateful firewall rule mapping"),
            Step("host_sweep",     count=25, pause=1, note="Host sweep — live host discovery"),
            Step("syn_scan",       count=110,pause=0, note="SYN scan — open port discovery"),
        ],
    },

    "exposed_databases": {
        "desc": "Cloud misconfiguration probe: scan for exposed databases and APIs",
        "steps": [
            Step("exposed_service", port=6379,  count=4, pause=1, note="Redis (no-auth RCE)"),
            Step("exposed_service", port=27017, count=4, pause=1, note="MongoDB (no-auth dump)"),
            Step("exposed_service", port=9200,  count=4, pause=1, note="Elasticsearch (no-auth read)"),
            Step("exposed_service", port=2375,  count=4, pause=1, note="Docker API (container escape)"),
            Step("exposed_service", port=6443,  count=4, pause=1, note="Kubernetes API (cluster takeover)"),
            Step("exposed_service", port=2379,  count=4, pause=0, note="etcd (k8s secret dump)"),
        ],
    },

    "ics_attack": {
        "desc": "ICS/SCADA attack: port scan → Modbus → DNP3 (critical infrastructure)",
        "steps": [
            Step("syn_scan",     count=110, pause=2, note="Phase 1 — scanning for ICS hosts"),
            Step("modbus_access",count=5,   pause=1, note="Phase 2 — Modbus PLC probe (R068)"),
            Step("dnp3_access",  count=5,   pause=0, note="Phase 3 — DNP3 SCADA probe (R069)"),
        ],
    },

    "infra_attack": {
        "desc": "Network infrastructure attack: BGP hijack → OSPF injection → GRE tunnel",
        "steps": [
            Step("bgp_hijack",  count=3, pause=1, note="BGP session hijack attempt"),
            Step("ospf_inject", count=3, pause=1, note="OSPF route injection"),
            Step("gre_tunnel",  count=3, pause=0, note="GRE covert tunnel"),
        ],
    },

    "full_demo": {
        "desc": "Full NIDS demo: one representative attack from all 11 detection categories",
        "steps": [
            Step("syn_scan",        count=110, pause=1.5, note="[Recon]           Port Scan (SYN)"),
            Step("brute_force",     port=22, count=12, pause=1.5, note="[Brute Force]      SSH Brute Force"),
            Step("syn_flood",       count=210, pause=1.5, note="[DoS]             SYN Flood"),
            Step("telnet_attempt",  count=3,   pause=1.5, note="[Suspicious Svc]  Telnet Attempt"),
            Step("cobalt_strike",   count=3,   pause=1.5, note="[Malware/C2]      Cobalt Strike Beacon"),
            Step("smb_sweep",       count=12,  pause=1.5, note="[Lateral Move]    SMB Sweep"),
            Step("exposed_service", port=6379, count=4, pause=1.5, note="[Exposed Svc]     Redis Exposed"),
            Step("dns_tunnel",      count=210, pause=1.5, note="[Exfiltration]    DNS Tunneling"),
            Step("dns_amplification",count=510,pause=1.5, note="[Infra Attack]    DNS Amplification"),
            Step("modbus_access",   count=3,   pause=1.5, note="[ICS/SCADA]       Modbus Access"),
            Step("mining_pool",     count=3,   pause=0,   note="[Policy]          Crypto Mining"),
        ],
    },
}


# ── Output helpers ────────────────────────────────────────────────────────────

_SEV_COLOR = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[94m", "LOW": "\033[96m"}
_RESET = "\033[0m"
_BOLD  = "\033[1m"
_DIM   = "\033[2m"


def _sev(sev: str) -> str:
    return f"{_SEV_COLOR.get(sev, '')}{sev}{_RESET}"


def _hr(char: str = "─", n: int = 70) -> None:
    print(f"{_DIM}{char * n}{_RESET}")


def _header(title: str) -> None:
    _hr("═")
    print(f"{_BOLD}  {title}{_RESET}")
    _hr("═")


def list_attacks() -> None:
    _header("Available Attacks")
    prev_category = ""
    categories = {
        "syn_scan": "── Reconnaissance ───────────────────────────────────────────────",
        "brute_force": "── Brute Force ──────────────────────────────────────────────────",
        "syn_flood": "── DoS / Floods ─────────────────────────────────────────────────",
        "telnet_attempt": "── Suspicious Services ──────────────────────────────────────────",
        "c2_beacon": "── Malware / C2 ─────────────────────────────────────────────────",
        "smb_sweep": "── Lateral Movement ─────────────────────────────────────────────",
        "exposed_service": "── Exposed Services ─────────────────────────────────────────────",
        "dns_tunnel": "── Exfiltration ─────────────────────────────────────────────────",
        "dns_amplification": "── Network Infrastructure ───────────────────────────────────────",
        "modbus_access": "── ICS / SCADA ───────────────────────────────────────────────────",
        "proxy_access": "── Policy Violations ────────────────────────────────────────────",
    }
    print(f"\n  {'ATTACK':<20}  {'RULE':<12}  {'SEV':<8}  {'PKT':<6}  DESCRIPTION")
    _hr()
    for name, meta in ATTACKS.items():
        if name in categories:
            print(f"\n  {_DIM}{categories[name]}{_RESET}")
        sev_s = _sev(meta["sev"])
        print(f"  {name:<20}  {meta['rule']:<12}  {sev_s:<17}  {meta['count']:<6}  {meta['desc']}")
    print()


def list_scenarios() -> None:
    _header("Available Scenarios")
    print(f"\n  {'SCENARIO':<22}  {'STEPS':<6}  DESCRIPTION")
    _hr()
    for name, sc in SCENARIOS.items():
        n = len(sc["steps"])
        print(f"  {name:<22}  {n:<6}  {sc['desc']}")
    print()


# ── Execution ─────────────────────────────────────────────────────────────────

def _run_one(name: str, target: str, port: int, count: int,
             src_ip: str, iface: str, delay: float) -> None:
    meta    = ATTACKS[name]
    port    = port  if port  else meta["port"]
    count   = count if count else meta["count"]
    fn: Callable = meta["fn"]

    sev_s = _sev(meta["sev"])
    print(f"\n  {_BOLD}{name}{_RESET}  [{meta['rule']}]  severity={sev_s}")
    print(f"  {_DIM}{meta['desc']}{_RESET}")
    t0 = time.monotonic()
    fn(target, port, count, src_ip, iface, delay)
    elapsed = time.monotonic() - t0
    print(f"  {_DIM}done — {count} packet(s) in {elapsed:.2f}s{_RESET}")


def run_scenario(name: str, target: str, src_ip: str, iface: str, delay: float) -> None:
    sc = SCENARIOS[name]
    _header(f"Scenario: {name}")
    print(f"  {sc['desc']}")
    print(f"  Target : {target}")
    print(f"  Src IP : {src_ip}")
    n = len(sc["steps"])
    t_scenario = time.monotonic()

    for idx, step in enumerate(sc["steps"], 1):
        _hr()
        if step.note:
            print(f"\n  {_BOLD}Step {idx}/{n}{_RESET}  {step.note}")
        meta  = ATTACKS[step.attack]
        port  = step.port  if step.port  else meta["port"]
        count = step.count if step.count else meta["count"]
        _run_one(step.attack, target, port, count, src_ip, iface, delay)
        if step.pause > 0 and idx < n:
            print(f"  {_DIM}pausing {step.pause}s…{_RESET}")
            time.sleep(step.pause)

    _hr("═")
    elapsed = time.monotonic() - t_scenario
    print(f"\n  {_BOLD}Scenario complete{_RESET} — {n} steps in {elapsed:.1f}s")
    print()


def interactive_menu(target: str, src_ip: str, iface: str, delay: float) -> None:
    _header("Interactive Mode")
    print(f"  Target : {target}   Src : {src_ip}\n")

    attack_names   = list(ATTACKS.keys())
    scenario_names = list(SCENARIOS.keys())

    while True:
        print(f"\n  {_BOLD}[A] Run attack    [S] Run scenario    [L] List attacks    [C] List scenarios    [Q] Quit{_RESET}")
        choice = input("\n  > ").strip().upper()

        if choice == "Q":
            break

        elif choice == "L":
            list_attacks()

        elif choice == "C":
            list_scenarios()

        elif choice == "A":
            print("\n  Attacks:")
            for i, n in enumerate(attack_names, 1):
                m = ATTACKS[n]
                print(f"  {i:>3}.  {n:<20}  [{m['rule']}]  {_sev(m['sev'])}")
            sel = input("\n  Enter attack name or number: ").strip()
            name = ""
            if sel.isdigit():
                idx = int(sel) - 1
                if 0 <= idx < len(attack_names):
                    name = attack_names[idx]
            elif sel in ATTACKS:
                name = sel
            if not name:
                print(f"  {_DIM}Unknown selection.{_RESET}")
                continue
            meta = ATTACKS[name]
            port_raw  = input(f"  Port  [{meta['port']}]: ").strip()
            count_raw = input(f"  Count [{meta['count']}]: ").strip()
            port  = int(port_raw)  if port_raw.isdigit()  else meta["port"]
            count = int(count_raw) if count_raw.isdigit() else meta["count"]
            _run_one(name, target, port, count, src_ip, iface, delay)

        elif choice == "S":
            print("\n  Scenarios:")
            for i, n in enumerate(scenario_names, 1):
                sc = SCENARIOS[n]
                print(f"  {i:>3}.  {n:<22}  ({len(sc['steps'])} steps)  {sc['desc'][:50]}…")
            sel = input("\n  Enter scenario name or number: ").strip()
            name = ""
            if sel.isdigit():
                idx = int(sel) - 1
                if 0 <= idx < len(scenario_names):
                    name = scenario_names[idx]
            elif sel in SCENARIOS:
                name = sel
            if not name:
                print(f"  {_DIM}Unknown selection.{_RESET}")
                continue
            run_scenario(name, target, src_ip, iface, delay)

        else:
            print(f"  {_DIM}Unknown command.{_RESET}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="NIDS traffic generator — craft packets that match detection signatures.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python scripts/gen_traffic.py --list\n"
            "  sudo python scripts/gen_traffic.py --scenarios\n"
            "  sudo python scripts/gen_traffic.py --target 192.168.1.5 --attack syn_scan\n"
            "  sudo python scripts/gen_traffic.py --target 192.168.1.5 --attack brute_force --port 22\n"
            "  sudo python scripts/gen_traffic.py --target 192.168.1.5 --scenario apt_campaign\n"
            "  sudo python scripts/gen_traffic.py --target 192.168.1.5 --interactive\n"
            "  sudo python scripts/gen_traffic.py --target 192.168.1.5 --attack udp_flood --delay 2\n"
        ),
    )
    p.add_argument("--list",        action="store_true", help="List all individual attacks and exit")
    p.add_argument("--scenarios",   action="store_true", help="List all scenarios and exit")
    p.add_argument("--interactive", action="store_true", help="Launch interactive menu")
    p.add_argument("--target",      metavar="IP",        help="Destination IP address")
    p.add_argument("--attack",      metavar="NAME",      help="Single attack to run (see --list)")
    p.add_argument("--scenario",    metavar="NAME",      help="Scenario to run (see --scenarios)")
    p.add_argument("--port",        metavar="N",  type=int, default=0,
                   help="Destination port override (0 = attack default)")
    p.add_argument("--count",       metavar="N",  type=int, default=0,
                   help="Packet count override (0 = attack default minimum to trigger rule)")
    p.add_argument("--src-ip",      metavar="IP", default="",
                   help="Spoof source IP (default: random RFC-1918)")
    p.add_argument("--iface",       metavar="IF", default="",
                   help="Network interface to send on (default: scapy auto-selects)")
    p.add_argument("--delay",       metavar="MS", type=float, default=0.0,
                   help="Inter-packet delay in milliseconds (default: 0 — send as fast as possible)")
    return p


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if args.list:
        list_attacks()
        return

    if args.scenarios:
        list_scenarios()
        return

    if not args.target and not args.interactive:
        parser.error("--target is required (or --list / --scenarios)")

    if args.target and not args.target.replace(".", "").isdigit():
        parser.error("--target must be an IPv4 address")

    src_ip = args.src_ip if args.src_ip else _rfc1918()
    delay  = args.delay / 1000.0  # ms → s
    target = args.target or ""

    if args.interactive:
        if not target:
            target = input("  Target IP: ").strip()
        interactive_menu(target, src_ip, args.iface, delay)
        return

    if args.scenario:
        if args.scenario not in SCENARIOS:
            parser.error(
                f"Unknown scenario '{args.scenario}'. "
                f"Available: {', '.join(SCENARIOS)}"
            )
        run_scenario(args.scenario, target, src_ip, args.iface, delay)
        return

    if not args.attack:
        parser.error("--attack or --scenario is required (use --list or --scenarios to browse)")

    if args.attack not in ATTACKS:
        parser.error(
            f"Unknown attack '{args.attack}'. "
            f"Available: {', '.join(ATTACKS)}"
        )

    _header("NIDS Traffic Generator")
    print(f"  Target   : {target}")
    print(f"  Src IP   : {src_ip}")
    if args.iface:
        print(f"  Interface: {args.iface}")
    if delay:
        print(f"  Delay    : {args.delay:.1f} ms / packet")

    t0 = time.monotonic()
    _run_one(args.attack, target, args.port, args.count, src_ip, args.iface, delay)
    print(f"\n  Total elapsed: {time.monotonic() - t0:.2f}s")
    print()


if __name__ == "__main__":
    main()
