"""Tor exit-list loader and matcher. IPs from captured packets are matched in memory only."""

import ipaddress
import os
import threading
import time
import urllib.request

from scapy.layers.inet import IP


TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
CACHE_PATH = os.path.join(RESULTS_DIR, "tor_exit_list.txt")

MAX_AGE_SECONDS = 24 * 3600
MIN_EXPECTED_ENTRIES = 100

_lock = threading.Lock()

_memory = {
    "ips": set(),
    "info": None,
    "loaded_at": 0.0
}


def _parse(text):
    ips = set()

    for line in text.splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        try:
            ip = ipaddress.ip_address(line)
        except ValueError:
            continue

        if ip.version == 4:
            ips.add(str(ip))

    return ips


def _read_cache():
    with open(CACHE_PATH, "r", encoding="utf-8") as f:
        return _parse(f.read())


def _download():
    req = urllib.request.Request(
        TOR_LIST_URL,
        headers={"User-Agent": "vpn-traffic-lab/1.0"}
    )

    with urllib.request.urlopen(req, timeout=10) as resp:
        text = resp.read().decode("utf-8", "replace")

    ips = _parse(text)

    if len(ips) < MIN_EXPECTED_ENTRIES:
        raise ValueError("downloaded list looks too small, ignoring it")

    os.makedirs(RESULTS_DIR, exist_ok=True)

    tmp = CACHE_PATH + ".tmp"

    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(ips)) + "\n")

    os.replace(tmp, CACHE_PATH)

    return ips


def _cache_age_hours():
    try:
        return round(
            (time.time() - os.path.getmtime(CACHE_PATH)) / 3600,
            1
        )
    except OSError:
        return None


def load_exit_list():
    """Return (IPv4 set, info). Never raises; failure returns an empty set."""

    with _lock:
        now = time.time()

        if (
            _memory["info"]
            and now - _memory["loaded_at"] < MAX_AGE_SECONDS
        ):
            return _memory["ips"], _memory["info"]

        ips, status = set(), "unavailable"

        age = _cache_age_hours()

        fresh = (
            age is not None
            and age * 3600 < MAX_AGE_SECONDS
        )

        if fresh:
            try:
                ips, status = _read_cache(), "cache"
            except OSError:
                pass

        if not ips:
            try:
                ips, status = _download(), "downloaded"

            except Exception:
                try:
                    ips, status = _read_cache(), "cache_stale"

                except OSError:
                    ips, status = set(), "unavailable"

        info = {
            "status": status,
            "list_size": len(ips),
            "list_age_hours": _cache_age_hours()
        }

        _memory.update(
            ips=ips,
            info=info,
            loaded_at=now
        )

        return ips, info


def packet_touches_tor_exit(pkt, tor_ips):
    if not tor_ips or not pkt.haslayer(IP):
        return False

    ip = pkt[IP]

    return ip.src in tor_ips or ip.dst in tor_ips


def build_tor_summary(matched_packets, ip_packets, info):
    return {
        "matched_packets": matched_packets,
        "ip_packets": ip_packets,
        "list_size": info["list_size"],
        "list_status": info["status"],
        "list_age_hours": info["list_age_hours"],
    }