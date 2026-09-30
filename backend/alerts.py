"""Rule engine: high-risk open ports, traffic spikes, and new devices joining.

Severity tiers
--------------
critical  — direct remote-code-execution / active-exploit targets (RDP, Telnet, SMB)
high      — credential-exposure or unauthenticated data stores (MySQL, MSSQL, Redis, MongoDB)
medium    — information-disclosure / lateral-movement helpers (MSRPC, NetBIOS, FTP)
low       — weak/legacy services worth tracking (VNC)
"""

import logging
import statistics
import time

from backend import db

log = logging.getLogger(__name__)

# ── Port metadata ────────────────────────────────────────────────────────────
# Each entry: (service_name, severity, description)
PORT_INFO: dict[int, tuple[str, str, str]] = {
    23:    ("Telnet",   "critical", "Telnet is unencrypted and frequently exploited"),
    3389:  ("RDP",      "critical", "RDP is a top target for ransomware and brute force"),
    445:   ("SMB",      "critical", "SMB has been the target of major ransomware (WannaCry, NotPetya)"),
    1433:  ("MSSQL",    "high",     "MSSQL exposed to the network can be brute-forced"),
    3306:  ("MySQL",    "high",     "MySQL exposed to the network can be brute-forced"),
    6379:  ("Redis",    "high",     "Redis has no auth by default and is often exposed by mistake"),
    27017: ("MongoDB",  "high",     "MongoDB has no auth by default and is often exposed by mistake"),
    21:    ("FTP",      "medium",   "FTP allows unencrypted credential transfer"),
    135:   ("MSRPC",    "medium",   "MSRPC is a common attack surface (e.g. worms)"),
    139:   ("NetBIOS",  "medium",   "NetBIOS can leak host and share information"),
    5900:  ("VNC",      "low",      "VNC is frequently left unauthenticated"),
}

# Keep HIGH_RISK_PORTS as a flat dict for backward-compat with app.py / API meta endpoint
HIGH_RISK_PORTS: dict[int, str] = {p: info[2] for p, info in PORT_INFO.items()}

# ── Cooldowns ────────────────────────────────────────────────────────────────
# Per (port) — grouped alerts fire at most once per hour per port
RISKY_PORT_COOLDOWN = 3600
# Per direction — traffic-spike alerts fire at most once per 5 minutes
SPIKE_COOLDOWN = 300

# ── In-memory dedup caches ───────────────────────────────────────────────────
# key = port,      value = {"last_seen": float, "hosts": set[str]}
_port_state: dict[int, dict] = {}
# key = direction, value = last alert timestamp
_spike_seen: dict[str, float] = {}


# ── Internal helpers ─────────────────────────────────────────────────────────

def _emit(severity: str, category: str, message: str) -> dict:
    alert = {
        "timestamp": time.time(),
        "severity": severity,
        "category": category,
        "message": message,
    }
    db.insert_alert(alert)
    log.info("ALERT severity=%-8s category=%-12s  %s", severity, category, message)
    return alert


# ── Public rule functions ────────────────────────────────────────────────────

def check_traffic_spike(history: list) -> list:
    """Flag upload/download rates that are far above their recent baseline."""
    SPIKE_WINDOW = 30
    SPIKE_MULTIPLIER = 4
    SPIKE_MIN_RATE = 50 * 1024   # 50 KB/s floor so idle jitter doesn't fire

    alerts = []
    if len(history) < SPIKE_WINDOW + 1:
        return alerts

    recent = history[-(SPIKE_WINDOW + 1):]
    baseline, latest = recent[:-1], recent[-1]
    now = time.time()

    for direction, key in (("upload", "send_rate"), ("download", "recv_rate")):
        mean = statistics.mean(h[key] for h in baseline)
        if not (latest[key] > SPIKE_MIN_RATE and mean > 0 and latest[key] > mean * SPIKE_MULTIPLIER):
            continue
        if now - _spike_seen.get(direction, 0) < SPIKE_COOLDOWN:
            continue
        _spike_seen[direction] = now
        alerts.append(
            _emit(
                "warning",
                "traffic_spike",
                f"Unusual {direction} spike: {latest[key] / 1024:.0f} KB/s "
                f"(baseline {mean / 1024:.0f} KB/s)",
            )
        )
    return alerts


def check_new_devices(devices: list) -> list:
    """Diff discovered devices against known MACs and flag newcomers."""
    alerts = []
    known = db.get_known_devices()
    now = time.time()
    for dev in devices:
        is_new = dev["mac"] not in known
        db.upsert_known_device(dev["mac"], dev["ip"], dev.get("hostname", ""), "", now)
        if is_new:
            label = f" - {dev['hostname']}" if dev.get("hostname") else ""
            alerts.append(
                _emit(
                    "info",
                    "new_device",
                    f"New device joined the network: {dev['ip']} ({dev['mac']}){label}",
                )
            )
    return alerts


def check_risky_ports(host: str, open_ports: list) -> list:
    """Flag high-risk open ports with proper severity tiering.

    Grouping: instead of one alert per (host, port), we accumulate hosts that
    share the same open port and emit a single grouped alert per port per
    cooldown window — e.g. 'NetBIOS (139) exposed on 14 hosts: 10.1.20.12,
    10.1.20.13, …'.  This keeps the panel readable on busy LANs.

    Severity is read from PORT_INFO, not hardcoded to 'critical'.
    """
    alerts = []
    now = time.time()

    for entry in open_ports:
        port = entry["port"]
        if port not in PORT_INFO:
            continue

        service, severity, description = PORT_INFO[port]

        state = _port_state.setdefault(port, {"last_seen": 0.0, "hosts": set()})
        state["hosts"].add(host)

        if now - state["last_seen"] < RISKY_PORT_COOLDOWN:
            # Still within the cooldown window — accumulate the host but don't emit yet
            continue

        # Cooldown expired — emit a grouped alert covering all accumulated hosts
        state["last_seen"] = now
        hosts_snapshot = sorted(state["hosts"])
        state["hosts"] = set()   # reset accumulator for next window

        count = len(hosts_snapshot)
        if count == 1:
            host_summary = hosts_snapshot[0]
        elif count <= 4:
            host_summary = ", ".join(hosts_snapshot)
        else:
            host_summary = f"{', '.join(hosts_snapshot[:3])}, +{count - 3} more"

        message = (
            f"{service} (port {port}) exposed on {count} host{'s' if count > 1 else ''}: "
            f"{host_summary} — {description}"
        )
        alerts.append(_emit(severity, "risky_port", message))

    return alerts


def get_recent_alerts(limit: int = 100) -> list:
    return db.get_alerts(limit)
