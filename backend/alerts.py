"""Rule engine: risky ports, traffic spikes, new, departed and returning devices.

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
SPIKE_WINDOW = 30
SPIKE_MULTIPLIER = 4
SPIKE_MIN_RATE = 50 * 1024
_spike_seen: dict = {}

# A device counts as "left" once it has been missing from scans this long.
# ARP/ping discovery is lossy (sleeping phones, dropped replies), so this must
# span several 30s scan passes to avoid flapping alerts.
DEVICE_OFFLINE_AFTER = 300
_departures_baselined = False


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
        prior = known.get(dev["mac"])
        db.upsert_known_device(dev["mac"], dev["ip"], dev.get("hostname", ""), "", now)
        label = f" - {dev['hostname']}" if dev.get("hostname") else ""
        if prior is None:
            alerts_out.append(_emit("info", "new_device",
                f"New device joined the network: {dev['ip']} ({dev['mac']}){label}"))
        elif not prior.get("online", 1):
            # Previously reported as left by check_departed_devices().
            alerts_out.append(_emit("info", "device_returned",
                f"Device came back: {dev['ip']} ({dev['mac']}){label}"))
    return alerts_out


def check_departed_devices(found: list) -> list:
    """Alert once for each known device that has been absent from scans for
    DEVICE_OFFLINE_AFTER seconds. It is marked offline so it isn't re-reported,
    and goes back online (silently) the next time a scan sees it.

    Call after check_new_devices(), which refreshes last_seen for devices
    that are present.
    """
    global _departures_baselined
    # A scan that found nothing means the network/scanner is down, not that
    # every device left at once.
    if not found:
        return []

    now = time.time()
    departed = db.mark_stale_devices_offline(now - DEVICE_OFFLINE_AFTER)

    # First pass after startup: devices already stale from before we started
    # (e.g. the app was off overnight) are marked offline without alerting.
    if not _departures_baselined:
        _departures_baselined = True
        return []

    alerts_out = []
    for dev in departed:
        label = f" - {dev['hostname']}" if dev.get("hostname") else ""
        alerts_out.append(_emit("info", "device_left",
            f"Device left the network: {dev['ip']} ({dev['mac']}){label}"))
    return alerts_out


def check_risky_ports(host: str, open_ports: list, scanned_ports=None) -> list:
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
                f"{service} (port {port}) detected on {host}: {description}"))
        else:
            log.debug(
                "[FINDING] SKIPPED duplicate alert for %s port %s (seen before)", host, port
            )

    if scanned_ports is not None:
        closed = db.close_missing_findings(
            host, scanned_ports, [e["port"] for e in open_ports], now
        )
        if closed:
            log.info("[FINDING] %d finding(s) on %s no longer open", closed, host)

    return new_alerts


def get_recent_alerts(limit: int = 100) -> list:
    return db.get_alerts(limit)


def get_port_findings(limit: int = 200) -> list:
    return db.get_port_findings(limit)
