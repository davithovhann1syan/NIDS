from __future__ import annotations

import time
from typing import TypedDict

from scapy.all import ICMP, IP, TCP, UDP, Packet


class FeatureDict(TypedDict):
    timestamp:  float
    src_ip:     str
    dst_ip:     str
    protocol:   int           # IP proto number: 6=TCP, 17=UDP, 1=ICMP
    length:     int           # IP-declared total length (header + payload)
    ttl:        int
    src_port:   int | None    # None if not TCP/UDP
    dst_port:   int | None    # None if not TCP/UDP
    flags:      str | None    # e.g. "S", "SA", "PA" — None if not TCP
    flags_int:  int           # TCP flags as bitmask, 0 if not TCP
    icmp_type:  int | None    # None if not ICMP


def extract(pkt: Packet) -> FeatureDict:
    """Convert a raw Scapy packet into a feature dict.

    Expects an IPv4 packet. Raises ValueError if the IP layer is absent.
    Missing transport layers (TCP/UDP/ICMP) are handled safely — their
    fields default to None or 0 rather than raising.

    Args:
        pkt: A raw Scapy packet, typically from the capture queue.

    Returns:
        A FeatureDict with all fields populated.

    Raises:
        ValueError: If pkt does not contain an IP layer.
    """
    if IP not in pkt:
        raise ValueError(f"extract() received a non-IP packet: {pkt.summary()}")

    ip       = pkt[IP]
    src_ip   = ip.src
    dst_ip   = ip.dst
    protocol = ip.proto
    ttl      = ip.ttl
    length   = ip.len   # IP-declared length — more meaningful than Python object size
                        # and can itself be a detection signal (e.g. abnormally small/large)

    # Transport-layer fields — defaults applied before match/case overrides them.
    src_port:  int | None = None
    dst_port:  int | None = None
    flags:     str | None = None
    flags_int: int        = 0
    icmp_type: int | None = None

    match protocol:
        case 6:   # TCP
            if TCP in pkt:
                tcp       = pkt[TCP]
                src_port  = tcp.sport
                dst_port  = tcp.dport
                flags     = str(tcp.flags)
                flags_int = int(tcp.flags)
        case 17:  # UDP
            if UDP in pkt:
                udp      = pkt[UDP]
                src_port = udp.sport
                dst_port = udp.dport
        case 1:   # ICMP
            if ICMP in pkt:
                icmp_type = pkt[ICMP].type
        case _:
            pass  # unsupported protocol — transport fields stay at defaults

    return FeatureDict(
        timestamp=time.time(),
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        length=length,
        ttl=ttl,
        src_port=src_port,
        dst_port=dst_port,
        flags=flags,
        flags_int=flags_int,
        icmp_type=icmp_type,
    )
