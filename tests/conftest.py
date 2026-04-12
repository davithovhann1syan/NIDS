from __future__ import annotations

import pytest
from scapy.all import Ether, IP, TCP, UDP, ICMP


# ── Raw Scapy packets ─────────────────────────────────────────────────────────

@pytest.fixture
def syn_packet() -> Ether:
    """TCP SYN from 10.0.0.1 → 10.0.0.2:80."""
    return Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=12345, dport=80, flags="S")


@pytest.fixture
def udp_packet() -> Ether:
    """UDP from 10.0.0.1 → 10.0.0.2:53."""
    return Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=54321, dport=53)


@pytest.fixture
def icmp_packet() -> Ether:
    """ICMP echo-request from 10.0.0.1 → 10.0.0.2."""
    return Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8)


@pytest.fixture
def non_ip_packet() -> Ether:
    """Raw Ethernet frame with no IP layer."""
    return Ether()


# ── Pre-built feature dicts ───────────────────────────────────────────────────

@pytest.fixture
def sample_feature_dict() -> dict:
    """A fully-populated FeatureDict matching the schema in extractor.py."""
    return {
        "timestamp": 1_700_000_000.0,
        "src_ip":    "10.0.0.1",
        "dst_ip":    "10.0.0.2",
        "protocol":  6,
        "length":    60,
        "ttl":       64,
        "src_port":  12345,
        "dst_port":  80,
        "flags":     "S",
        "flags_int": 2,
        "icmp_type": None,
    }


@pytest.fixture
def udp_feature_dict() -> dict:
    """Feature dict for a UDP packet (no flags, no icmp_type)."""
    return {
        "timestamp": 1_700_000_001.0,
        "src_ip":    "10.0.0.3",
        "dst_ip":    "10.0.0.4",
        "protocol":  17,
        "length":    40,
        "ttl":       128,
        "src_port":  54321,
        "dst_port":  53,
        "flags":     None,
        "flags_int": 0,
        "icmp_type": None,
    }


@pytest.fixture
def icmp_feature_dict() -> dict:
    """Feature dict for an ICMP echo-request."""
    return {
        "timestamp": 1_700_000_002.0,
        "src_ip":    "192.168.1.10",
        "dst_ip":    "192.168.1.1",
        "protocol":  1,
        "length":    28,
        "ttl":       64,
        "src_port":  None,
        "dst_port":  None,
        "flags":     None,
        "flags_int": 0,
        "icmp_type": 8,
    }
