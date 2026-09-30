"""Rule engine: risky ports, traffic spikes, new devices.

THIS IS THE FUNCTION THAT CREATES ALERT RECORDS.

check_risky_ports() is the entry point for port-scan results.
It calls db.upsert_port_finding() for every open risky port:
  - If (host, port) is new  → inserts one row into port_findings AND
                               writes one entry to the alerts event log.
  - If (host, port) exists  → only updates last_seen + seen_count.
                               NO new alert row is created.

Severity comes from PORT_INFO below — never hardcoded to "critical".

Severity tiers:
  critical — direct RCE targets         : Telnet (23), RDP (3389), SMB (445)
  high     — unauthenticated data stores : MySQL (3306), MSSQL (1433), Redis (6379), MongoDB (27017)
  medium   — info-disclosure helpers    : MSRPC (135), NetBIOS (139), FTP (21)
  low      — weak legacy services       : VNC (5900)
"""

import logging
import statistics
import time

from backend import db

log = logging.getLogger(__name__)

# ── Severity-tiered port catalogue ───────────────────────────────────────────
# Search for 'critical' in this file: it only appears inside PORT_INFO values
# and is NEVER passed directly to _emit() from check_risky_ports().
# The severity for each port is looked up from this dict at runtime.
PORT_INFO: dict = {
    # port : (display_name, severity,   description)
    23:    ("Telnet",  "critical", "Telnet is unencrypted and frequently exploited"),
    3389:  ("RDP",     "critical", "RDP is a top target for ransomware and brute force"),
    445:   ("SMB",     "critical", "SMB has been the target of major ransomware (WannaCry, NotPetya)"),
    1433:  ("MSSQL",   "high",     "MSSQL exposed to the network can be brute-forced"),
    3306:  ("MySQL",   "high",     "MySQL exposed to the network can be brute-forced"),
    6379:  ("Redis",   "high",     "Redis has no auth by default and is often exposed by mistake"),
    27017: ("MongoDB", "high",     "MongoDB has no auth by default and is often exposed by mistake"),
    21:    ("FTP",     "medium",   "FTP allows unencrypted credential transfer"),
    135:   ("MSRPC",   "medium",   "MSRPC is a common attack surface (e.g. worms)"),
    139:   ("NetBIOS", "medium",   "NetBIOS can leak host and share information"),
    5900:  ("VNC",     "low",      "VNC is frequently left unauthenticated"),
}

# Flat description map kept for backward-compat (/api/meta uses this)
HIGH_RISK_PORTS: dict = {p: info[2] for p, info in PORT_INFO.items()}

# Traffic-spike cooldown per direction — 5 min between repeated alerts
SPIKE_COOLDOWN = 300
_spike_seen: dict = {}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _emit(severity: str, category: str, message: str) -> dict:
    """Write a one-time event to the alerts log."""
    alert = {
        "timestamp": time.time(),
        "severity":  severity,
        "category":  category,
        "message":   message,
    }
    db.insert_alert(alert)
    # This log line appears in the backend terminal for every alert emitted.
    # grep for [ALERT] to verify severity values at generation time.
    log.info("[ALERT] severity=%-8s  category=%-14s  %s", severity, category, message)
    return alert


# ── Public rule functions ─────────────────────────────────────────────────────

def check_traffic_spike(history: list) -> list:
    SPIKE_WINDOW = 30
    SPIKE_MULTIPLIER = 4
    SPIKE_MIN_RATE = 50 * 1024

    alerts_out = []
    if len(history) < SPIKE_WINDOW + 1:
        return alerts_out

    recent = history[-(SPIKE_WINDOW + 1):]
    baseline, latest = recent[:-1], recent[-1]
    now = time.time()

    for direction, key in (("upload", "send_rate"), ("download", "recv_rate")):
        mean = statistics.mean(h[key] for h in baseline)
        if not (latest[key] > SPIKE_MIN_RATE and mean > 0
                and latest[key] > mean * SPIKE_MULTIPLIER):
            continue
        if now - _spike_seen.get(direction, 0) < SPIKE_COOLDOWN:
            continue
        _spike_seen[direction] = now
        alerts_out.append(_emit("warning", "traffic_spike",
            f"Unusual {direction} spike: {latest[key]/1024:.0f} KB/s "
            f"(baseline {mean/1024:.0f} KB/s)"))
    return alerts_out


def check_new_devices(devices: list) -> list:
    alerts_out = []
    known = db.get_known_devices()
    now = time.time()
    for dev in devices:
        is_new = dev["mac"] not in known
        db.upsert_known_device(dev["mac"], dev["ip"], dev.get("hostname", ""), "", now)
        if is_new:
            label = f" - {dev['hostname']}" if dev.get("hostname") else ""
            alerts_out.append(_emit("info", "new_device",
                f"New device joined the network: {dev['ip']} ({dev['mac']}){label}"))
    return alerts_out


def check_risky_ports(host: str, open_ports: list) -> list:
    """THE deduplication entry point for port scan results.

    For every open port found on 'host':
      1. Look up (service, severity, description) from PORT_INFO.
         severity is NEVER hardcoded here — it always comes from PORT_INFO.
      2. Call db.upsert_port_finding(host, port, ...).
         - is_new=True  → first time ever: also write one alert event.
         - is_new=False → already known: only last_seen/seen_count updated.
      3. Log [FINDING] line at DEBUG level with the actual severity value
         so you can grep the terminal to verify.
    """
    new_alerts = []
    now = time.time()

    for entry in open_ports:
        port = entry["port"]
        if port not in PORT_INFO:
            continue

        service, severity, description = PORT_INFO[port]

        # ── Verification log — grep for [FINDING] in backend terminal ──────
        log.debug(
            "[FINDING] host=%-16s  port=%-5s  service=%-8s  severity=%s",
            host, port, service, severity,
        )

        # ── Persistent upsert (dedup) ───────────────────────────────────────
        is_new = db.upsert_port_finding(
            host, port, service, severity, description, now
        )

        if is_new:
            # Only fires once per (host, port) — never on subsequent scans.
            new_alerts.append(_emit(severity, "risky_port",
                f"{service} (port {port}) first detected on {host}: {description}"))
        else:
            log.debug(
                "[FINDING] SKIPPED duplicate alert for %s port %s (seen before)", host, port
            )

    return new_alerts


def get_recent_alerts(limit: int = 100) -> list:
    return db.get_alerts(limit)


def get_port_findings(limit: int = 200) -> list:
    return db.get_port_findings(limit)
