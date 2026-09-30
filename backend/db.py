"""SQLite persistence for traffic history, alerts, known devices, and port findings."""

import os
import sqlite3
import threading

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "scan_history.db"
)
_lock = threading.Lock()

# Module-level persistent connection — avoids reopening the file on every query.
# Protected by _lock; SQLite itself is not thread-safe without check_same_thread=False.
_conn: sqlite3.Connection | None = None


def get_connection() -> sqlite3.Connection:
    """Return the shared persistent connection, creating it on first call."""
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        # WAL mode: readers never block writers and writers never block readers.
        _conn.execute("PRAGMA journal_mode=WAL")
        # Keep 64 MB of WAL in memory before flushing — reduces fsync calls.
        _conn.execute("PRAGMA wal_autocheckpoint=1000")
        # Synchronous=NORMAL is safe with WAL and much faster than FULL.
        _conn.execute("PRAGMA synchronous=NORMAL")
        # 8 MB page cache in memory.
        _conn.execute("PRAGMA cache_size=-8000")
        _conn.commit()
    return _conn


def init_db():
    with _lock:
        conn = get_connection()
        conn.execute(
            """CREATE TABLE IF NOT EXISTS traffic_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                bytes_sent INTEGER NOT NULL,
                bytes_recv INTEGER NOT NULL,
                send_rate REAL NOT NULL,
                recv_rate REAL NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                message TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS known_devices (
                mac TEXT PRIMARY KEY,
                ip TEXT,
                hostname TEXT,
                vendor TEXT,
                first_seen REAL,
                last_seen REAL
            )"""
        )
        # ── Port findings: one row per (host, port) — updated on every rescan,
        # never duplicated.  This is the source of truth for the findings panel.
        conn.execute(
            """CREATE TABLE IF NOT EXISTS port_findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                host        TEXT    NOT NULL,
                port        INTEGER NOT NULL,
                service     TEXT    NOT NULL,
                severity    TEXT    NOT NULL,
                description TEXT    NOT NULL,
                first_seen  REAL    NOT NULL,
                last_seen   REAL    NOT NULL,
                seen_count  INTEGER NOT NULL DEFAULT 1,
                UNIQUE(host, port)
            )"""
        )
        # Indexes make ORDER BY id DESC LIMIT n fast even on large tables.
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_traffic_id ON traffic_history(id DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_id ON alerts(id DESC)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_sev ON port_findings(severity, last_seen DESC)"
        )
        conn.commit()


# Persisted every TRAFFIC_PERSIST_INTERVAL (5s, see app.py) — 17280 rows
# covers roughly 24h at that cadence.
TRAFFIC_HISTORY_RETENTION = 17280


def insert_traffic(sample):
    with _lock:
        conn = get_connection()
        conn.execute(
            "INSERT INTO traffic_history (timestamp, bytes_sent, bytes_recv, send_rate, recv_rate) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                sample["timestamp"],
                sample["bytes_sent"],
                sample["bytes_recv"],
                sample["send_rate"],
                sample["recv_rate"],
            ),
        )
        conn.execute(
            "DELETE FROM traffic_history WHERE id NOT IN "
            "(SELECT id FROM traffic_history ORDER BY id DESC LIMIT ?)",
            (TRAFFIC_HISTORY_RETENTION,),
        )
        conn.commit()


def get_traffic_history(limit=200):
    with _lock:
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM traffic_history ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in reversed(rows)]


def insert_alert(alert):
    with _lock:
        conn = get_connection()
        conn.execute(
            "INSERT INTO alerts (timestamp, severity, category, message) VALUES (?, ?, ?, ?)",
            (alert["timestamp"], alert["severity"], alert["category"], alert["message"]),
        )
        conn.execute(
            "DELETE FROM alerts WHERE id NOT IN (SELECT id FROM alerts ORDER BY id DESC LIMIT 500)"
        )
        conn.commit()


def get_alerts(limit=100):
    with _lock:
        conn = get_connection()
        rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


# ── Port findings ────────────────────────────────────────────────────────────

def upsert_port_finding(host: str, port: int, service: str, severity: str,
                        description: str, now: float) -> bool:
    """Insert or update a (host, port) finding.

    Returns True  → this is a brand-new finding (first time we've seen it).
    Returns False → finding already existed; last_seen + seen_count updated.
    """
    with _lock:
        conn = get_connection()
        existing = conn.execute(
            "SELECT id FROM port_findings WHERE host=? AND port=?", (host, port)
        ).fetchone()

        if existing:
            conn.execute(
                """UPDATE port_findings
                   SET last_seen=?, seen_count=seen_count+1, severity=?, service=?
                   WHERE host=? AND port=?""",
                (now, severity, service, host, port),
            )
            conn.commit()
            return False
        else:
            conn.execute(
                """INSERT INTO port_findings
                   (host, port, service, severity, description, first_seen, last_seen, seen_count)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
                (host, port, service, severity, description, now, now),
            )
            conn.commit()
            return True


def get_port_findings(limit: int = 200) -> list[dict]:
    """Return active port findings ordered by severity tier then most-recently seen."""
    _sev_order = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
    with _lock:
        conn = get_connection()
        rows = conn.execute(
            f"SELECT * FROM port_findings ORDER BY {_sev_order}, last_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


# ── Known devices ────────────────────────────────────────────────────────────

def upsert_known_device(mac, ip, hostname, vendor, now):
    """Returns True if this MAC was not previously known (i.e. a new device)."""
    with _lock:
        conn = get_connection()
        existing = conn.execute("SELECT mac FROM known_devices WHERE mac=?", (mac,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE known_devices SET ip=?, hostname=?, vendor=?, last_seen=? WHERE mac=?",
                (ip, hostname, vendor, now, mac),
            )
        else:
            conn.execute(
                "INSERT INTO known_devices (mac, ip, hostname, vendor, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (mac, ip, hostname, vendor, now, now),
            )
        conn.commit()
        return existing is None


def get_known_devices():
    with _lock:
        conn = get_connection()
        rows = conn.execute("SELECT * FROM known_devices").fetchall()
        return {r["mac"]: dict(r) for r in rows}
