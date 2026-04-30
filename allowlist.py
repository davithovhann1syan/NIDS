from __future__ import annotations

import ipaddress
import json
import threading
from pathlib import Path

import config

_lock    = threading.RLock()
_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
_PATH    = Path(config.ALLOWLIST_PATH)


def reload() -> None:
    global _networks
    with _lock:
        _networks = _parse_file()


def is_allowlisted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    with _lock:
        return any(addr in net for net in _networks)


def get_entries() -> list[str]:
    if not _PATH.exists():
        return []
    try:
        data = json.loads(_PATH.read_text())
        return data.get("entries", [])
    except (OSError, json.JSONDecodeError):
        return []


def add_entry(entry: str) -> bool:
    try:
        net = ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False
    canonical = str(net)
    entries = get_entries()
    if canonical not in entries:
        entries.append(canonical)
        _save(entries)
    reload()
    return True


def remove_entry(entry: str) -> bool:
    try:
        canonical = str(ipaddress.ip_network(entry, strict=False))
    except ValueError:
        canonical = entry
    entries = get_entries()
    if canonical in entries:
        entries.remove(canonical)
        _save(entries)
        reload()
        return True
    return False


def _parse_file() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    if not _PATH.exists():
        return []
    try:
        data = json.loads(_PATH.read_text())
        result = []
        for e in data.get("entries", []):
            try:
                result.append(ipaddress.ip_network(e, strict=False))
            except ValueError:
                pass
        return result
    except (OSError, json.JSONDecodeError):
        return []


def _save(entries: list[str]) -> None:
    _PATH.parent.mkdir(parents=True, exist_ok=True)
    _PATH.write_text(json.dumps({"entries": entries}, indent=2))


reload()
