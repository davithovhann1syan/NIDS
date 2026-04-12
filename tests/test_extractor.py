from __future__ import annotations

import pytest
from scapy.all import Ether, IP, TCP, UDP, ICMP

from parser.extractor import extract, FeatureDict


class TestExtractTCP:
    def test_returns_all_keys(self, syn_packet):
        feat = extract(syn_packet)
        expected_keys = {
            "timestamp", "src_ip", "dst_ip", "protocol",
            "length", "ttl", "src_port", "dst_port",
            "flags", "flags_int", "icmp_type",
        }
        assert set(feat.keys()) == expected_keys

    def test_src_dst_ip(self, syn_packet):
        feat = extract(syn_packet)
        assert feat["src_ip"] == "10.0.0.1"
        assert feat["dst_ip"] == "10.0.0.2"

    def test_protocol_is_tcp(self, syn_packet):
        assert extract(syn_packet)["protocol"] == 6

    def test_ports(self, syn_packet):
        feat = extract(syn_packet)
        assert feat["src_port"] == 12345
        assert feat["dst_port"] == 80

    def test_syn_flags(self, syn_packet):
        feat = extract(syn_packet)
        assert feat["flags"] == "S"
        assert feat["flags_int"] == 2

    def test_icmp_type_none_for_tcp(self, syn_packet):
        assert extract(syn_packet)["icmp_type"] is None

    def test_timestamp_is_float(self, syn_packet):
        assert isinstance(extract(syn_packet)["timestamp"], float)

    def test_ttl_populated(self, syn_packet):
        feat = extract(syn_packet)
        assert isinstance(feat["ttl"], int)
        assert feat["ttl"] > 0

    def test_xmas_flags(self):
        """FIN+PSH+URG (XMAS scan) — flags_int should reflect all three bits."""
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(flags="FPU")
        feat = extract(pkt)
        assert "F" in feat["flags"]
        assert "P" in feat["flags"]
        assert "U" in feat["flags"]
        assert feat["flags_int"] != 0

    def test_null_scan_flags(self):
        """No TCP flags set — flags_int must be 0."""
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(flags=0)
        feat = extract(pkt)
        assert feat["flags_int"] == 0


class TestExtractUDP:
    def test_protocol_is_udp(self, udp_packet):
        assert extract(udp_packet)["protocol"] == 17

    def test_ports(self, udp_packet):
        feat = extract(udp_packet)
        assert feat["src_port"] == 54321
        assert feat["dst_port"] == 53

    def test_flags_none_for_udp(self, udp_packet):
        feat = extract(udp_packet)
        assert feat["flags"] is None
        assert feat["flags_int"] == 0

    def test_icmp_type_none_for_udp(self, udp_packet):
        assert extract(udp_packet)["icmp_type"] is None


class TestExtractICMP:
    def test_protocol_is_icmp(self, icmp_packet):
        assert extract(icmp_packet)["protocol"] == 1

    def test_icmp_type_echo_request(self, icmp_packet):
        assert extract(icmp_packet)["icmp_type"] == 8

    def test_ports_none_for_icmp(self, icmp_packet):
        feat = extract(icmp_packet)
        assert feat["src_port"] is None
        assert feat["dst_port"] is None

    def test_flags_none_for_icmp(self, icmp_packet):
        assert extract(icmp_packet)["flags"] is None
        assert extract(icmp_packet)["flags_int"] == 0

    def test_icmp_echo_reply(self):
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=0)
        assert extract(pkt)["icmp_type"] == 0


class TestExtractErrors:
    def test_raises_on_non_ip_packet(self, non_ip_packet):
        with pytest.raises(ValueError, match="non-IP"):
            extract(non_ip_packet)

    def test_non_ip_error_message_contains_summary(self, non_ip_packet):
        with pytest.raises(ValueError) as exc_info:
            extract(non_ip_packet)
        assert "non-IP" in str(exc_info.value)


class TestExtractUnknownProtocol:
    def test_unknown_protocol_defaults(self):
        """Protocol 47 (GRE) — transport fields should all be None/0."""
        pkt = Ether() / IP(src="1.1.1.1", dst="2.2.2.2", proto=47)
        feat = extract(pkt)
        assert feat["protocol"] == 47
        assert feat["src_port"] is None
        assert feat["dst_port"] is None
        assert feat["flags"] is None
        assert feat["flags_int"] == 0
        assert feat["icmp_type"] is None
