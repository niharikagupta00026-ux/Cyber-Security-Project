"""
VPN Traffic Analysis Lab - backend (Stage 7 + live capture)
-----------------------------------------------------------
Captures LIVE packets from a selected network adapter and computes
observable, metadata-level features. It NEVER decrypts payloads.

The classifier is a HEURISTIC traffic-analysis score, not a definitive
VPN or Tor detector. HTTPS and other encrypted traffic can also show high
entropy, and VPNs can use any port.

How a capture works:
  1. POST /capture/start  -> starts a background thread, answers at once (202)
  2. The thread sniffs packets; a callback updates live counters per packet
  3. GET /capture/status  -> the browser polls this to draw live charts
  4. When sniffing ends, the thread analyses the packets and stores the result

Run as Administrator (Windows) or with sudo (Linux/macOS):
    pip install -r requirements.txt
    python app.py
Then open http://127.0.0.1:5000
"""

import csv
import io
import json
import math
import os
import re
import statistics
import threading
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory, Response
from scapy.all import conf, sniff, IP, TCP, UDP, Raw

from tor_list import load_exit_list, packet_touches_tor_exit, build_tor_summary

BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR / "results"
EXPERIMENTS_FILE = RESULTS_DIR / "experiments.json"

# static_folder=None stops Flask from serving every file in this folder.
app = Flask(__name__, static_folder=None)

# ---------------------------------------------------------------------------
# Capture limits
# ---------------------------------------------------------------------------
MIN_DURATION_SEC = 3
MAX_DURATION_SEC = 60
MAX_CAPTURE_PACKETS = 20000

# ---------------------------------------------------------------------------
# Heuristic parameters. MANUALLY CHOSEN values, not statistically derived.
# ---------------------------------------------------------------------------
MIN_TOTAL_PACKETS = 50
MIN_ENTROPY_SAMPLES = 20
MIN_PAYLOAD_BYTES = 64
MIN_INTERVALS_FOR_CV = 10
TYPICAL_MTU_BYTES = 1400
SAMPLE_ROW_LIMIT = 30
HIST_BUCKET_BYTES = 100
HIST_BUCKET_COUNT = 16

WEIGHT_ENTROPY = 0.45
WEIGHT_VPN_PORT = 0.35
WEIGHT_SIZE = 0.10
WEIGHT_TIMING = 0.10
VPN_LIKE_THRESHOLD = 60
NORMAL_LIKE_THRESHOLD = 40

VPN_PORTS = {
    1194: "OpenVPN (default)",
    51820: "WireGuard (default)",
    500: "IKE / IPsec",
    4500: "IPsec NAT traversal",
    1701: "L2TP",
}

CLASSIFICATION_LABELS = {
    "vpn_like": "VPN-like traffic pattern",
    "normal_like": "Normal-like traffic pattern",
    "inconclusive": "Inconclusive",
}

EXPERIMENT_LABELS = {
    "normal": "Normal-like traffic",
    "vpn": "VPN-like traffic",
    "inconclusive": "Inconclusive traffic",
}

EXPERIMENT_COLUMNS = [
    "id", "label_code", "label", "captured_at", "interface",
    "requested_duration_sec", "total_packets", "total_bytes", "capture_span_sec",
    "mean_frame_bytes", "payload_samples", "mean_bits_per_byte",
    "mean_normalized_entropy", "transport_packets", "vpn_port_matched",
    "vpn_port_match_ratio", "interval_count", "mean_gap_ms", "stdev_gap_ms",
    "cv", "tor_matched_packets", "ip_packets", "heuristic_score", "classification",
]

capture_lock = threading.Lock()
state_lock = threading.Lock()
experiments_lock = threading.Lock()


def new_state() -> dict:
    return {
        "status": "idle",
        "started": 0.0,
        "elapsed": 0.0,
        "duration": 0,
        "interface": "",
        "packets": 0,
        "bytes": 0,
        "timeline": [],
        "error": None,
        "result": None,
        "captured_at": None,
        "saved": False,
        "auto_saved_label": None,
        "auto_save_error": None,
    }


cap = new_state()


# ---------------------------------------------------------------------------
# Basic measurements
# ---------------------------------------------------------------------------
def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def normalized_entropy(payload: bytes) -> float:
    """Entropy scaled to 0..1."""
    length = len(payload)
    if length < 2:
        return 0.0
    max_bits = min(8.0, math.log2(length))
    return min(shannon_entropy(payload) / max_bits, 1.0)


def protocol_of(pkt) -> str:
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(IP):
        return "Other IPv4"
    return "Non-IPv4"


def ports_of(pkt):
    if pkt.haslayer(TCP):
        return pkt[TCP].sport, pkt[TCP].dport
    if pkt.haslayer(UDP):
        return pkt[UDP].sport, pkt[UDP].dport
    return None, None


def count_protocols(packets) -> dict:
    counts = Counter(protocol_of(pkt) for pkt in packets)
    return {
        "tcp_packets": counts.get("TCP", 0),
        "udp_packets": counts.get("UDP", 0),
        "other_ipv4_packets": counts.get("Other IPv4", 0),
        "non_ipv4_packets": counts.get("Non-IPv4", 0),
    }


def payload_entropy_stats(packets) -> dict:
    bits_values = []
    normalized_values = []

    for pkt in packets:
        if not pkt.haslayer(Raw):
            continue
        payload = bytes(pkt[Raw].load)
        if len(payload) < MIN_PAYLOAD_BYTES:
            continue
        bits_values.append(shannon_entropy(payload))
        normalized_values.append(normalized_entropy(payload))

    if not normalized_values:
        return {
            "samples": 0,
            "mean_bits_per_byte": None,
            "mean_normalized": None
        }

    return {
        "samples": len(normalized_values),
        "mean_bits_per_byte": round(statistics.mean(bits_values), 3),
        "mean_normalized": round(statistics.mean(normalized_values), 3),
    }


def vpn_port_stats(packets) -> dict:
    transport_total = 0
    matched_total = 0
    per_port = Counter()

    for pkt in packets:
        sport, dport = ports_of(pkt)
        if sport is None:
            continue

        transport_total += 1
        hit_ports = {port for port in (sport, dport) if port in VPN_PORTS}

        if hit_ports:
            matched_total += 1
            per_port.update(hit_ports)

    ratio = matched_total / transport_total if transport_total else 0.0

    return {
        "transport_packets": transport_total,
        "matched_packets": matched_total,
        "match_ratio": round(ratio, 3),
        "per_port": {
            str(port): count
            for port, count in sorted(per_port.items())
        },
    }


def timing_stats(packets) -> dict:
    """Gaps between consecutive packet timestamps."""
    times = sorted(float(pkt.time) for pkt in packets)
    intervals = [
        later - earlier
        for earlier, later in zip(times, times[1:])
    ]

    result = {
        "interval_count": len(intervals),
        "mean_ms": None,
        "stdev_ms": None,
        "cv": None
    }

    if len(intervals) < 2:
        return result

    mean_gap = statistics.mean(intervals)
    stdev_gap = statistics.stdev(intervals)

    result["mean_ms"] = round(mean_gap * 1000, 3)
    result["stdev_ms"] = round(stdev_gap * 1000, 3)

    if len(intervals) >= MIN_INTERVALS_FOR_CV and mean_gap > 0:
        result["cv"] = round(stdev_gap / mean_gap, 3)

    return result


def timing_regularity_score(cv) -> float:
    if cv is None:
        return 0.0
    return max(0.0, 1.0 - min(cv, 1.0))


def interval_histogram(packets) -> list:
    """Count observed gaps between packets."""
    times = sorted(float(pkt.time) for pkt in packets)
    intervals_ms = [
        (b - a) * 1000
        for a, b in zip(times, times[1:])
    ]

    ranges = [
        (0, 1, '0-1 ms'),
        (1, 5, '1-5 ms'),
        (5, 10, '5-10 ms'),
        (10, 50, '10-50 ms'),
        (50, 100, '50-100 ms'),
        (100, float('inf'), '100+ ms'),
    ]

    return [
        {
            "label": label,
            "count": sum(
                1 for value in intervals_ms
                if low <= value < high
            )
        }
        for low, high, label in ranges
    ]


def size_histogram(sizes) -> list:
    """Counts packets in 100-byte buckets."""
    counts = [0] * HIST_BUCKET_COUNT

    for size in sizes:
        counts[min(size // HIST_BUCKET_BYTES, HIST_BUCKET_COUNT - 1)] += 1

    buckets = []

    for index, count in enumerate(counts):
        start = index * HIST_BUCKET_BYTES
        last = index == HIST_BUCKET_COUNT - 1
        label = f"{start}+" if last else f"{start}-{start + HIST_BUCKET_BYTES - 1}"

        buckets.append({
            "start": start,
            "label": label,
            "count": count
        })

    return buckets


def build_packet_sample(packets, start_time: float) -> list:
    """Packet metadata sample. No IP addresses, no payloads."""
    if not packets:
        return []

    step = max(1, len(packets) // SAMPLE_ROW_LIMIT)
    rows = []

    for index in range(0, len(packets), step):
        pkt = packets[index]
        sport, dport = ports_of(pkt)

        rows.append({
            "number": index + 1,
            "time_rel_sec": round(float(pkt.time) - start_time, 4),
            "protocol": protocol_of(pkt),
            "src_port": sport,
            "dst_port": dport,
            "size_bytes": len(pkt),
        })

        if len(rows) >= SAMPLE_ROW_LIMIT:
            break

    return rows


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------
def classify(total_packets: int, entropy_samples: int, score: float):
    if total_packets < MIN_TOTAL_PACKETS:
        return "inconclusive", (
            f"Only {total_packets} packets captured (minimum {MIN_TOTAL_PACKETS}). "
            "Capture longer or generate more traffic."
        )

    if entropy_samples < MIN_ENTROPY_SAMPLES:
        return "inconclusive", (
            f"Only {entropy_samples} payload samples (minimum {MIN_ENTROPY_SAMPLES}). "
            "The entropy feature is not reliable with so few payloads."
        )

    if score >= VPN_LIKE_THRESHOLD:
        return "vpn_like", (
            "Features are consistent with VPN-like traffic. "
            "This is not proof of VPN use."
        )

    if score <= NORMAL_LIKE_THRESHOLD:
        return "normal_like", (
            "Features are consistent with normal-like traffic. "
            "This does not rule out a VPN."
        )

    return "inconclusive", (
        "The score falls between the two thresholds, "
        "so the features do not clearly point either way."
    )


def analyze_packets(packets) -> dict:
    total = len(packets)

    if total == 0:
        return {
            "error": "No packets were captured. Generate some traffic "
                     "(open a website) during the capture and try again."
        }

    times = [float(pkt.time) for pkt in packets]
    start_time = min(times)
    capture_span = max(times) - start_time

    sizes = [len(pkt) for pkt in packets]
    mean_size = statistics.mean(sizes)

    protocol_counts = count_protocols(packets)
    entropy = payload_entropy_stats(packets)
    ports = vpn_port_stats(packets)
    timing = timing_stats(packets)

    feature_values = {
        "entropy": (
            entropy["mean_normalized"]
            if entropy["mean_normalized"] is not None else 0.0
        ),
        "vpn_port": ports["match_ratio"],
        "packet_size": min(mean_size / TYPICAL_MTU_BYTES, 1.0),
        "timing_regularity": timing_regularity_score(timing["cv"]),
    }

    weights = {
        "entropy": WEIGHT_ENTROPY,
        "vpn_port": WEIGHT_VPN_PORT,
        "packet_size": WEIGHT_SIZE,
        "timing_regularity": WEIGHT_TIMING,
    }

    breakdown = {}
    score = 0.0

    for name, value in feature_values.items():
        points = weights[name] * value * 100
        score += points
        breakdown[name] = {
            "value": round(value, 3),
            "weight": weights[name],
            "points": round(points, 2)
        }

    score = round(score, 1)

    classification, reason = classify(
        total,
        entropy["samples"],
        score
    )

    return {
        "classification": classification,
        "label": CLASSIFICATION_LABELS[classification],
        "reason": reason,
        "heuristic_score": score,
        "score_breakdown": breakdown,

        "traffic": {
            "total_packets": total,
            "total_bytes": sum(sizes),
            **protocol_counts,
            "capture_span_sec": round(capture_span, 2),
        },

        "size": {
            "mean_bytes": round(mean_size, 1),
            "min_bytes": min(sizes),
            "max_bytes": max(sizes),
        },

        "size_histogram": size_histogram(sizes),
        "entropy": entropy,
        "vpn_ports": ports,

        "timing": {
            **timing,
            "interval_histogram": interval_histogram(packets)
        },

        "packet_sample": build_packet_sample(packets, start_time),
    }


def count_tor_matches(packets):
    """Compares packet IPs with the Tor exit list in memory."""
    tor_ips, info = load_exit_list()
    ip_packets = 0
    matched = 0

    for pkt in packets:
        if pkt.haslayer(IP):
            ip_packets += 1
            if packet_touches_tor_exit(pkt, tor_ips):
                matched += 1

    return build_tor_summary(matched, ip_packets, info)


# ---------------------------------------------------------------------------
# Input validation and interface discovery
# ---------------------------------------------------------------------------
def list_interfaces() -> list:
    result = []

    for iface in conf.ifaces.values():
        name = getattr(iface, "name", str(iface))
        description = getattr(iface, "description", None) or name

        result.append({
            "name": name,
            "description": description
        })

    return result


def parse_capture_request(data: dict):
    iface = data.get("interface")

    if not isinstance(iface, str) or not iface.strip():
        return None, None, "No network adapter selected."

    valid_names = {
        item["name"] for item in list_interfaces()
    }

    if iface not in valid_names:
        return None, None, (
            "The selected adapter was not found on this machine. "
            "Click 'Refresh adapters' and try again."
        )

    try:
        duration = int(data.get("duration", 10))
    except (TypeError, ValueError):
        return None, None, "Duration must be a whole number of seconds."

    if duration < MIN_DURATION_SEC or duration > MAX_DURATION_SEC:
        return None, None, (
            f"Duration must be between {MIN_DURATION_SEC} "
            f"and {MAX_DURATION_SEC} seconds."
        )

    return iface, duration, None


# ---------------------------------------------------------------------------
# Background capture thread
# ---------------------------------------------------------------------------
def pad_timeline(timeline: list, length: int) -> None:
    while len(timeline) < length:
        timeline.append({
            "packets": 0,
            "bytes": 0
        })


def run_capture(iface: str, duration: int) -> None:
    packets = []

    def on_packet(pkt):
        """Called by Scapy for every packet."""
        second = min(
            int(time.time() - cap["started"]),
            duration - 1
        )

        with state_lock:
            pad_timeline(cap["timeline"], second + 1)

            bucket = cap["timeline"][second]
            bucket["packets"] += 1
            bucket["bytes"] += len(pkt)

            cap["packets"] += 1
            cap["bytes"] += len(pkt)

        packets.append(pkt)

    try:
        sniff(
            iface=iface,
            timeout=duration,
            count=MAX_CAPTURE_PACKETS,
            store=False,
            prn=on_packet
        )

        with state_lock:
            cap["status"] = "analyzing"
            cap["elapsed"] = round(time.time() - cap["started"], 1)

        result = analyze_packets(packets)

        if "error" in result:
            with state_lock:
                cap.update(
                    status="error",
                    error=result["error"]
                )
            return

        result["tor"] = count_tor_matches(packets)

        with state_lock:
            pad_timeline(cap["timeline"], duration)

            result["timeline"] = [
                dict(bucket)
                for bucket in cap["timeline"]
            ]
            captured_at = datetime.now(timezone.utc).isoformat(
                timespec="seconds"
            )

            # Keep the UI waiting until the automatic experiment record is saved.
            cap.update(
                status="saving",
                result=result,
                captured_at=captured_at,
            )

            capture_snapshot = {
                "result": result,
                "captured_at": captured_at,
                "interface": iface,
                "duration": duration,
            }

        # Use the classifier's own output; never ask the user to label a run.
        label_code = {
            "vpn_like": "vpn",
            "normal_like": "normal",
            "inconclusive": "inconclusive",
        }.get(result.get("classification"), "inconclusive")

        auto_save_error = None
        try:
            row = build_experiment_row(capture_snapshot, label_code)
            with experiments_lock:
                rows = load_experiments()
                rows.append(row)
                save_experiments(rows)
        except Exception:
            app.logger.exception("Could not automatically save classified capture")
            auto_save_error = (
                "Analysis completed, but the automatic experiment save failed. "
                "Check the server console."
            )

        with state_lock:
            cap.update(
                status="done",
                saved=(auto_save_error is None),
                auto_saved_label=label_code if auto_save_error is None else None,
                auto_save_error=auto_save_error,
            )

    except PermissionError:
        with state_lock:
            cap.update(
                status="error",
                error=(
                    "Permission denied. Run the terminal as Administrator "
                    "(Windows) or with sudo (Linux/macOS)."
                )
            )

    except Exception as exc:
        app.logger.exception("Capture failed")

        message = (
            "Capture failed. On Windows make sure Npcap is installed "
            "and the terminal is run as Administrator."
        )

        with state_lock:
            cap.update(
                status="error",
                error=f"{message} ({type(exc).__name__})"
            )

    finally:
        capture_lock.release()


# ---------------------------------------------------------------------------
# Experiment storage (summaries only)
# ---------------------------------------------------------------------------
def load_experiments() -> list:
    if not EXPERIMENTS_FILE.exists():
        return []

    with EXPERIMENTS_FILE.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if not isinstance(data, list):
        raise ValueError("experiments.json does not contain a list")

    return data


def save_experiments(rows: list) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    temp_path = EXPERIMENTS_FILE.with_suffix(".json.tmp")

    with temp_path.open("w", encoding="utf-8") as handle:
        json.dump(rows, handle, indent=2)

    os.replace(temp_path, EXPERIMENTS_FILE)


def build_experiment_row(capture: dict, label_code: str) -> dict:
    """One flat row of summary numbers."""
    result = capture["result"]
    traffic = result["traffic"]
    size = result["size"]
    entropy = result["entropy"]
    ports = result["vpn_ports"]
    timing = result["timing"]
    tor = result.get("tor") or {}
    timeline = result.get("timeline", [])

    return {
        "id": uuid.uuid4().hex,
        "label_code": label_code,
        "label": EXPERIMENT_LABELS[label_code],
        "captured_at": capture["captured_at"],
        "interface": capture["interface"],
        "requested_duration_sec": capture["duration"],
        "total_packets": traffic["total_packets"],
        "total_bytes": traffic["total_bytes"],
        "capture_span_sec": traffic["capture_span_sec"],
        "mean_frame_bytes": size["mean_bytes"],
        "payload_samples": entropy["samples"],
        "mean_bits_per_byte": entropy["mean_bits_per_byte"],
        "mean_normalized_entropy": entropy["mean_normalized"],
        "transport_packets": ports["transport_packets"],
        "vpn_port_matched": ports["matched_packets"],
        "vpn_port_match_ratio": ports["match_ratio"],
        "interval_count": timing["interval_count"],
        "mean_gap_ms": timing["mean_ms"],
        "stdev_gap_ms": timing["stdev_ms"],
        "cv": timing["cv"],
        "tor_matched_packets": tor.get("matched_packets"),
        "ip_packets": tor.get("ip_packets"),
        "heuristic_score": result["heuristic_score"],
        "classification": result["classification"],
        "timeline_packets": [b["packets"] for b in timeline],
        "timeline_bytes": [b["bytes"] for b in timeline],
    }


# ---------------------------------------------------------------------------
# Routes: main page and frontend files
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return send_from_directory(BASE_DIR, "index.html")


# ADDED: Serve the separate CSS file
@app.route("/style.css")
def style_file():
    return send_from_directory(BASE_DIR, "style.css")


# ADDED: Serve the separate JavaScript file
@app.route("/script.js")
def script_file():
    return send_from_directory(BASE_DIR, "script.js")


# ---------------------------------------------------------------------------
# Routes: capture
# ---------------------------------------------------------------------------
@app.route("/interfaces", methods=["GET"])
def interfaces():
    try:
        return jsonify({
            "interfaces": list_interfaces()
        })

    except Exception:
        app.logger.exception("Could not list network adapters")

        return jsonify({
            "error": "Could not list network adapters. Check the server console for details."
        }), 500


@app.route("/capture/start", methods=["POST"])
def capture_start():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        data = {}

    iface, duration, error = parse_capture_request(data)

    if error:
        return jsonify({"error": error}), 400

    if not capture_lock.acquire(blocking=False):
        return jsonify({
            "error": "Another capture is already running. Wait for it to finish."
        }), 409

    with state_lock:
        cap.clear()
        cap.update(new_state())

        cap.update(
            status="capturing",
            started=time.time(),
            duration=duration,
            interface=iface
        )

    threading.Thread(
        target=run_capture,
        args=(iface, duration),
        daemon=True
    ).start()

    return jsonify({
        "status": "capturing",
        "duration": duration
    }), 202


@app.route("/capture/status", methods=["GET"])
def capture_status():
    with state_lock:
        status = cap["status"]

        if status == "capturing":
            elapsed = round(
                min(time.time() - cap["started"], cap["duration"]),
                1
            )
            length = min(cap["duration"], int(elapsed) + 1)

        else:
            elapsed = cap["elapsed"]
            length = len(cap["timeline"])

        timeline = [
            dict(b)
            for b in cap["timeline"]
        ]

        pad_timeline(timeline, length)

        return jsonify({
            "status": status,
            "elapsed": elapsed,
            "duration": cap["duration"],
            "interface": cap["interface"],
            "packets": cap["packets"],
            "bytes": cap["bytes"],
            "timeline": timeline,
            "error": cap["error"],
            "result": cap["result"],
            "can_save": False,
            "auto_saved_label": cap.get("auto_saved_label"),
            "auto_save_error": cap.get("auto_save_error"),
        })


# ---------------------------------------------------------------------------
# Routes: experiments
# ---------------------------------------------------------------------------
@app.route("/experiments", methods=["GET"])
def list_experiments():
    try:
        with experiments_lock:
            rows = load_experiments()

        return jsonify({
            "experiments": rows
        })

    except Exception:
        app.logger.exception("Could not read experiments file")

        return jsonify({
            "error": "Could not read saved experiments. Check the server console."
        }), 500


@app.route("/experiments", methods=["POST"])
def save_experiment():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        data = {}

    label_code = data.get("label")

    if not isinstance(label_code, str) or label_code not in EXPERIMENT_LABELS:
        return jsonify({
            "error": "Choose a label: 'normal' or 'vpn'."
        }), 400

    with state_lock:
        if cap["status"] != "done" or cap["result"] is None:
            return jsonify({
                "error": "Run a capture first, then save it as an experiment."
            }), 400

        if cap["saved"]:
            return jsonify({
                "error": "This capture is already saved. Run a new capture to save another."
            }), 409

        row = build_experiment_row(cap, label_code)

    try:
        with experiments_lock:
            rows = load_experiments()
            rows.append(row)
            save_experiments(rows)

    except Exception:
        app.logger.exception("Could not write experiments file")

        return jsonify({
            "error": "Could not save the experiment. Check the server console."
        }), 500

    with state_lock:
        cap["saved"] = True

    return jsonify(row), 201


@app.route("/experiments/<row_id>", methods=["DELETE"])
def delete_experiment(row_id):
    if not re.fullmatch(r"[0-9a-f]{32}", row_id):
        return jsonify({
            "error": "Experiment not found."
        }), 404

    try:
        with experiments_lock:
            rows = load_experiments()

            remaining = [
                row for row in rows
                if row.get("id") != row_id
            ]

            if len(remaining) == len(rows):
                return jsonify({
                    "error": "Experiment not found."
                }), 404

            save_experiments(remaining)

    except Exception:
        app.logger.exception("Could not delete experiment")

        return jsonify({
            "error": "Could not delete the experiment. Check the server console."
        }), 500

    return jsonify({
        "deleted": row_id
    })


@app.route("/experiments.csv", methods=["GET"])
def export_experiments_csv():
    try:
        with experiments_lock:
            rows = load_experiments()

    except Exception:
        app.logger.exception("Could not read experiments file for CSV export")

        return jsonify({
            "error": "Could not read saved experiments. Check the server console."
        }), 500

    buffer = io.StringIO()

    writer = csv.DictWriter(
        buffer,
        fieldnames=EXPERIMENT_COLUMNS,
        extrasaction="ignore"
    )

    writer.writeheader()

    for row in rows:
        writer.writerow(row)

    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=experiments.csv"
        },
    )


# ---------------------------------------------------------------------------
# Start application
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Load the Tor exit list in the background.
    threading.Thread(
        target=load_exit_list,
        daemon=True
    ).start()

    # Bound to localhost only.
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )