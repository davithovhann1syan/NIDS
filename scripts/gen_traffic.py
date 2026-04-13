"""
Malicious traffic generator for NIDS testing.

Crafts and sends raw packets that match detection signatures, so you can verify
the NIDS alerts correctly without needing a real attacker.

Requires root (raw socket). Run on a separate machine or loopback:

    sudo python scripts/gen_traffic.py --target 192.168.1.5 --attack syn_flood
    sudo python scripts/gen_traffic.py --target 192.168.1.5 --attack brute_force --port 22
    sudo python scripts/gen_traffic.py --list
"""
from __future__ import annotations

import argparse
import random
import sys
import time

# ---------------------------------------------------------------------------
# Scapy import — must run as root for raw sockets
# ---------------------------------------------------------------------------
try:
    from scapy.all import (
        IP, TCP, UDP, ICMP,
        send, RandShort,
        conf as scapy_conf,
    )
    scapy_conf.verb = 0          # silence per-packet output
except ImportError:
    sys.exit("scapy is not installed. Run: pip install scapy")


# ---------------------------------------------------------------------------
# Attack catalogue
# Each entry: description + the function that runs the attack
# ---------------------------------------------------------------------------

def _random_src() -> str:
    """Return a random RFC-1918 source IP to simulate different attackers."""
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


# ── Reconnaissance ──────────────────────────────────────────────────────────

def syn_scan(target: str, port: int, count: int, src_ip: str) -> None:
    """
    Send SYN packets to many ports from one source IP.
    Triggers: Port Scan (SYN) — 20 SYNs within 5 s.
    """
    print(f"  Sending {count} SYN packets to {target} (ports vary) ...")
    for _ in range(count):
        dst_port = random.randint(1, 65535)
        pkt = IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=dst_port, flags="S")
        send(pkt)


def null_scan(target: str, port: int, count: int, src_ip: str) -> None:
    """
    TCP packet with zero flags.
    Triggers: Null Scan (single packet match).
    """
    print(f"  Sending {count} Null-scan packets to {target}:{port} ...")
    for _ in range(count):
        pkt = IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=port, flags=0)
        send(pkt)


def xmas_scan(target: str, port: int, count: int, src_ip: str) -> None:
    """
    FIN + PSH + URG simultaneously.
    Triggers: XMAS Scan (single packet match).
    """
    print(f"  Sending {count} XMAS-scan packets to {target}:{port} ...")
    for _ in range(count):
        pkt = IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=port, flags="FPU")
        send(pkt)


def fin_scan(target: str, port: int, count: int, src_ip: str) -> None:
    """
    FIN only (no ACK).
    Triggers: FIN Scan (single packet match).
    """
    print(f"  Sending {count} FIN-scan packets to {target}:{port} ...")
    for _ in range(count):
        pkt = IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=port, flags="F")
        send(pkt)


def icmp_sweep(target: str, port: int, count: int, src_ip: str) -> None:
    """
    ICMP echo-request flood from one source.
    Triggers: ICMP Host Sweep (Ping Sweep) — 20 pings in 10 s.
    """
    print(f"  Sending {count} ICMP echo requests to {target} ...")
    for _ in range(count):
        pkt = IP(src=src_ip, dst=target) / ICMP(type=8)
        send(pkt)


def udp_scan(target: str, port: int, count: int, src_ip: str) -> None:
    """
    UDP packets to many ports from one source.
    Triggers: UDP Port Scan — 100 UDP packets within 5 s.
    """
    print(f"  Sending {count} UDP packets to {target} (ports vary) ...")
    for _ in range(count):
        dst_port = random.randint(1, 65535)
        pkt = IP(src=src_ip, dst=target) / UDP(sport=RandShort(), dport=dst_port)
        send(pkt)


# ── Brute Force ─────────────────────────────────────────────────────────────

def brute_force(target: str, port: int, count: int, src_ip: str) -> None:
    """
    Repeated SYN packets to a specific port (e.g. 22, 3389, 21, 3306).
    Triggers: SSH/RDP/FTP/MySQL/... Brute Force depending on port.
    """
    print(f"  Sending {count} SYN packets to {target}:{port} (brute-force pattern) ...")
    for _ in range(count):
        pkt = IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=port, flags="S")
        send(pkt)


def smb_sweep(target: str, port: int, count: int, src_ip: str) -> None:
    """
    Rapid SYN flood to SMB port 445.
    Triggers: SMB Sweep (Ransomware Propagation) — 10 SYNs in 10 s.
    """
    print(f"  Sending {count} SYN packets to {target}:445 (SMB sweep) ...")
    for _ in range(count):
        pkt = IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=445, flags="S")
        send(pkt)


# ── DoS / Floods ────────────────────────────────────────────────────────────

def syn_flood(target: str, port: int, count: int, src_ip: str) -> None:
    """
    Very high rate SYN flood to a single port.
    Triggers: SYN Flood — 200 SYNs in 5 s.
    """
    print(f"  Sending {count} SYN packets to {target}:{port} (SYN flood) ...")
    for _ in range(count):
        spoof = _random_src()
        pkt = IP(src=spoof, dst=target) / TCP(sport=RandShort(), dport=port, flags="S")
        send(pkt)


def icmp_flood(target: str, port: int, count: int, src_ip: str) -> None:
    """
    High-rate ICMP ping flood from one source.
    Triggers: ICMP Flood — 100 pings in 10 s.
    """
    print(f"  Sending {count} ICMP echo requests to {target} (ICMP flood) ...")
    for _ in range(count):
        pkt = IP(src=src_ip, dst=target) / ICMP(type=8)
        send(pkt)


def udp_flood(target: str, port: int, count: int, src_ip: str) -> None:
    """
    High-rate UDP flood.
    Triggers: UDP Flood — 1000 UDP packets in 10 s.
    """
    print(f"  Sending {count} UDP packets to {target}:{port} (UDP flood) ...")
    for _ in range(count):
        pkt = IP(src=src_ip, dst=target) / UDP(sport=RandShort(), dport=port)
        send(pkt)


# ── Malware / C2 ────────────────────────────────────────────────────────────

def c2_beacon(target: str, port: int, count: int, src_ip: str) -> None:
    """
    SYN to a known C2/backdoor port (4444, 1337, 31337, etc.).
    Triggers: Known C2 / Backdoor Port (single packet match).
    Use --port to specify which C2 port to target.
    """
    c2_ports = [4444, 1337, 31337, 9001, 6666, 6667, 8888, 1234, 12345, 54321]
    chosen = port if port in c2_ports else 4444
    print(f"  Sending {count} packets to {target}:{chosen} (C2 beacon) ...")
    for _ in range(count):
        pkt = IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=chosen, flags="S")
        send(pkt)


def cobalt_strike(target: str, port: int, count: int, src_ip: str) -> None:
    """
    SYN to Cobalt Strike default team server port (50050).
    Triggers: Cobalt Strike Default Beacon Port (single packet match).
    """
    print(f"  Sending {count} packets to {target}:50050 (Cobalt Strike beacon) ...")
    for _ in range(count):
        pkt = IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=50050, flags="S")
        send(pkt)


def dns_tunnel(target: str, port: int, count: int, src_ip: str) -> None:
    """
    High-rate DNS queries (UDP 53) from one source.
    Triggers: DNS Query Flood (Possible DNS Tunneling) — 200 queries in 60 s.
    """
    print(f"  Sending {count} DNS queries to {target}:53 (DNS tunneling) ...")
    for _ in range(count):
        pkt = IP(src=src_ip, dst=target) / UDP(sport=RandShort(), dport=53)
        send(pkt)


# ── Exposed Services ─────────────────────────────────────────────────────────

def exposed_service(target: str, port: int, count: int, src_ip: str) -> None:
    """
    SYN to an exposed service port (Redis 6379, MongoDB 27017, etc.).
    Triggers: Redis Exposed / MongoDB Exposed / Elasticsearch Exposed etc.
    Use --port to pick the service: 6379, 9200, 27017, 2375, 6443 ...
    """
    print(f"  Sending {count} SYN packets to {target}:{port} (exposed service probe) ...")
    for _ in range(count):
        pkt = IP(src=src_ip, dst=target) / TCP(sport=RandShort(), dport=port, flags="S")
        send(pkt)


# ── Catalogue mapping ────────────────────────────────────────────────────────

ATTACKS: dict[str, dict] = {
    # name          → description, function, suggested count, notes
    "syn_scan":       {"desc": "SYN port scan across random ports (nmap -sS style)",
                       "fn": syn_scan,       "default_count": 25,
                       "trigger": "Port Scan (SYN)"},
    "null_scan":      {"desc": "TCP packet with no flags set",
                       "fn": null_scan,      "default_count": 5,
                       "trigger": "Null Scan"},
    "xmas_scan":      {"desc": "TCP FIN+PSH+URG flags (XMAS scan)",
                       "fn": xmas_scan,      "default_count": 5,
                       "trigger": "XMAS Scan"},
    "fin_scan":       {"desc": "TCP FIN-only packet",
                       "fn": fin_scan,       "default_count": 5,
                       "trigger": "FIN Scan"},
    "icmp_sweep":     {"desc": "ICMP echo flood — host discovery / ping sweep",
                       "fn": icmp_sweep,     "default_count": 25,
                       "trigger": "ICMP Host Sweep (Ping Sweep)"},
    "udp_scan":       {"desc": "UDP packets to random ports",
                       "fn": udp_scan,       "default_count": 110,
                       "trigger": "UDP Port Scan"},
    "brute_force":    {"desc": "Repeated SYNs to --port (SSH=22, RDP=3389, FTP=21 …)",
                       "fn": brute_force,    "default_count": 15,
                       "trigger": "SSH / RDP / FTP / MySQL Brute Force (depends on port)"},
    "smb_sweep":      {"desc": "Rapid SYNs to SMB port 445 — ransomware spread pattern",
                       "fn": smb_sweep,      "default_count": 15,
                       "trigger": "SMB Sweep (Ransomware Propagation)"},
    "syn_flood":      {"desc": "High-rate SYN flood to --port (DoS)",
                       "fn": syn_flood,      "default_count": 210,
                       "trigger": "SYN Flood"},
    "icmp_flood":     {"desc": "High-rate ICMP ping flood (DoS)",
                       "fn": icmp_flood,     "default_count": 110,
                       "trigger": "ICMP Flood"},
    "udp_flood":      {"desc": "High-rate UDP flood to --port (DoS)",
                       "fn": udp_flood,      "default_count": 1010,
                       "trigger": "UDP Flood"},
    "c2_beacon":      {"desc": "SYN to C2/backdoor port (default 4444, override with --port)",
                       "fn": c2_beacon,      "default_count": 5,
                       "trigger": "Known C2 / Backdoor Port"},
    "cobalt_strike":  {"desc": "SYN to Cobalt Strike team server port 50050",
                       "fn": cobalt_strike,  "default_count": 5,
                       "trigger": "Cobalt Strike Default Beacon Port"},
    "dns_tunnel":     {"desc": "DNS query flood to port 53 (tunneling pattern)",
                       "fn": dns_tunnel,     "default_count": 210,
                       "trigger": "DNS Query Flood (Possible DNS Tunneling)"},
    "exposed_service":{"desc": "Probe an exposed service port (use --port: 6379, 27017, 9200 …)",
                       "fn": exposed_service,"default_count": 5,
                       "trigger": "Redis / MongoDB / Elasticsearch Exposed (depends on port)"},
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def list_attacks() -> None:
    col_w = 18
    print(f"\n  {'ATTACK':<{col_w}}  {'DEFAULT COUNT':<14}  TRIGGERS RULE")
    print(f"  {'─'*col_w}  {'─'*14}  {'─'*50}")
    for name, meta in ATTACKS.items():
        print(f"  {name:<{col_w}}  {meta['default_count']:<14}  {meta['trigger']}")
    print()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="NIDS traffic generator — craft packets that match detection signatures.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  sudo python scripts/gen_traffic.py --list\n"
            "  sudo python scripts/gen_traffic.py --target 192.168.1.5 --attack syn_scan\n"
            "  sudo python scripts/gen_traffic.py --target 192.168.1.5 --attack brute_force --port 22\n"
            "  sudo python scripts/gen_traffic.py --target 192.168.1.5 --attack syn_flood --count 250\n"
            "  sudo python scripts/gen_traffic.py --target 192.168.1.5 --attack c2_beacon --port 4444\n"
        ),
    )
    p.add_argument("--list",   action="store_true",  help="List all available attacks and exit")
    p.add_argument("--target", metavar="IP",         help="Destination IP address")
    p.add_argument("--attack", metavar="NAME",       help="Attack type (see --list)")
    p.add_argument("--port",   metavar="N", type=int, default=80,
                   help="Destination port for attacks that need one (default: 80)")
    p.add_argument("--count",  metavar="N", type=int, default=0,
                   help="Packet count override (default: attack-specific minimum to trigger rule)")
    p.add_argument("--src-ip", metavar="IP",         default="",
                   help="Spoof source IP (default: random RFC-1918 address)")
    return p


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if args.list:
        list_attacks()
        return

    if not args.target:
        parser.error("--target is required (use --list to see available attacks)")
    if not args.attack:
        parser.error("--attack is required (use --list to see available attacks)")
    if args.attack not in ATTACKS:
        parser.error(
            f"Unknown attack '{args.attack}'. "
            f"Available: {', '.join(ATTACKS)}"
        )

    meta    = ATTACKS[args.attack]
    count   = args.count if args.count > 0 else meta["default_count"]
    src_ip  = args.src_ip if args.src_ip else _random_src()

    print()
    print(f"  Target   : {args.target}")
    print(f"  Attack   : {args.attack}")
    print(f"  Port     : {args.port}")
    print(f"  Count    : {count}")
    print(f"  Src IP   : {src_ip}")
    print(f"  Triggers : {meta['trigger']}")
    print()

    start = time.monotonic()
    meta["fn"](args.target, args.port, count, src_ip)
    elapsed = time.monotonic() - start

    print()
    print(f"  Done. Sent {count} packet(s) in {elapsed:.2f}s.")
    print()


if __name__ == "__main__":
    main()
