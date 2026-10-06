"""SQLite persistence for traffic history, alerts, known devices, and port findings."""

import os
import sqlite3
import threading

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "scan_history.db"
)
_lock = threading.Lock()
_conn: sqlite3.Connection | None = None


def get_connection() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA wal_autocheckpoint=1000")
        _conn.execute("PRAGMA synchronous=NORMAL")
        _conn.execute("PRAGMA cache_size=-8000")
        _conn.commit()
    return _conn


def init_db():
    with _lock:
        conn = get_connection()
        conn.execute("""CREATE TABLE IF NOT EXISTS traffic_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   REAL    NOT NULL,
            bytes_sent  INTEGER NOT NULL,
            bytes_recv  INTEGER NOT NULL,
            send_rate   REAL    NOT NULL,
            recv_rate   REAL    NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL    NOT NULL,
            severity  TEXT    NOT NULL,
            category  TEXT    NOT NULL,
            message   TEXT    NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS known_devices (
            mac        TEXT PRIMARY KEY,
            ip         TEXT,
            hostname   TEXT,
            vendor     TEXT,
            first_seen REAL,
            last_seen  REAL
        )""")
        # ── port_findings: ONE row per (host, port).
        # updated in-place every scan — never duplicated.
        conn.execute("""CREATE TABLE IF NOT EXISTS port_findings (
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
        )""")
        # Migration: findings used to be open forever. `status` tracks whether
        # the port was open on the most recent scan that covered it.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(port_findings)")}
        if "status" not in cols:
            conn.execute("ALTER TABLE port_findings ADD COLUMN status TEXT NOT NULL DEFAULT 'open'")
        if "closed_at" not in cols:
            conn.execute("ALTER TABLE port_findings ADD COLUMN closed_at REAL")
        dev_cols = {r["name"] for r in conn.execute("PRAGMA table_info(known_devices)")}
        if "online" not in dev_cols:
            conn.execute("ALTER TABLE known_devices ADD COLUMN online INTEGER NOT NULL DEFAULT 1")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_id ON traffic_history(id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_id   ON alerts(id DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_sev ON port_findings(severity, last_seen DESC)")
        conn.commit()


TRAFFIC_HISTORY_RETENTION = 17280
ALERTS_RETENTION = 500

# Pruning scans the table, so do it every N inserts rather than on each one.
# Tables can overshoot their retention by at most N-1 rows in between.
PRUNE_EVERY = 100
_inserts_since_prune = {"traffic_history": 0, "alerts": 0}


def _should_prune(table):
    """Call with _lock held. True once every PRUNE_EVERY inserts (and on the
    first insert after startup, so a restart still trims an oversized table)."""
    count = _inserts_since_prune[table]
    _inserts_since_prune[table] = (count + 1) % PRUNE_EVERY
    return count == 0


def insert_traffic(sample):
    with _lock:
        conn = get_connection()
        conn.execute(
            "INSERT INTO traffic_history (timestamp,bytes_sent,bytes_recv,send_rate,recv_rate) VALUES (?,?,?,?,?)",
            (sample["timestamp"], sample["bytes_sent"], sample["bytes_recv"],
             sample["send_rate"], sample["recv_rate"]),
        )
        if _should_prune("traffic_history"):
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
            "INSERT INTO alerts (timestamp,severity,category,message) VALUES (?,?,?,?)",
            (alert["timestamp"], alert["severity"], alert["category"], alert["message"]),
        )
        if _should_prune("alerts"):
            conn.execute(
                "DELETE FROM alerts WHERE id NOT IN (SELECT id FROM alerts ORDER BY id DESC LIMIT ?)",
                (ALERTS_RETENTION,),
            )
        conn.commit()


def get_alerts(limit=100):
    with _lock:
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# ── port_findings upsert ─────────────────────────────────────────────────────

def upsert_port_finding(host: str, port: int, service: str, severity: str,
                        description: str, now: float) -> bool:
    """Insert or update a (host, port) finding.

    Returns True  = brand-new finding, or one re-opened after being closed.
    Returns False = already open; last_seen + seen_count updated.
    """
    with _lock:
        conn = get_connection()
        existing = conn.execute(
            "SELECT status FROM port_findings WHERE host=? AND port=?", (host, port)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE port_findings SET last_seen=?, seen_count=seen_count+1, severity=?, service=?, "
                "status='open', closed_at=NULL WHERE host=? AND port=?",
                (now, severity, service, host, port),
            )
            conn.commit()
            return existing["status"] == "closed"   # re-opened counts as new
        else:
            conn.execute(
                "INSERT INTO port_findings "
                "(host,port,service,severity,description,first_seen,last_seen,seen_count) "
                "VALUES (?,?,?,?,?,?,?,1)",
                (host, port, service, severity, description, now, now),
            )
            conn.commit()
            return True         # new


def close_missing_findings(host: str, scanned_ports, open_ports, now: float) -> int:
    """Mark open findings on `host` as closed if their port was part of this
    scan (`scanned_ports`) but not found open (`open_ports`). Ports outside
    the scan are left alone. Returns the number of findings closed."""
    to_close = [p for p in set(scanned_ports) - set(open_ports)]
    if not to_close:
        return 0
    with _lock:
        conn = get_connection()
        marks = ",".join("?" * len(to_close))
        cur = conn.execute(
            f"UPDATE port_findings SET status='closed', closed_at=? "
            f"WHERE host=? AND status='open' AND port IN ({marks})",
            (now, host, *to_close),
        )
        conn.commit()
        return cur.rowcount


def get_port_findings(limit: int = 200) -> list:
    _sev = ("CASE severity "
            "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2  WHEN 'low'  THEN 3 ELSE 4 END")
    with _lock:
        conn = get_connection()
        rows = conn.execute(
            f"SELECT * FROM port_findings ORDER BY (status='closed'), {_sev}, last_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


# ── known devices ────────────────────────────────────────────────────────────

def upsert_known_device(mac, ip, hostname, vendor, now):
    """Returns True if this MAC was not previously known."""
    with _lock:
        conn = get_connection()
        existing = conn.execute(
            "SELECT mac FROM known_devices WHERE mac=?", (mac,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE known_devices SET ip=?,hostname=?,vendor=?,last_seen=?,online=1 WHERE mac=?",
                (ip, hostname, vendor, now, mac),
            )
        else:
            conn.execute(
                "INSERT INTO known_devices (mac,ip,hostname,vendor,first_seen,last_seen) "
                "VALUES (?,?,?,?,?,?)",
                (mac, ip, hostname, vendor, now, now),
            )
        conn.commit()
        return existing is None


def mark_stale_devices_offline(cutoff: float) -> list:
    """Flip online devices not seen since `cutoff` to offline and return them
    (as dicts, with their last known ip/hostname)."""
    with _lock:
        conn = get_connection()
        rows = conn.execute(
            "SELECT * FROM known_devices WHERE online=1 AND last_seen < ?", (cutoff,)
        ).fetchall()
        if rows:
            marks = ",".join("?" * len(rows))
            conn.execute(
                f"UPDATE known_devices SET online=0 WHERE mac IN ({marks})",
                [r["mac"] for r in rows],
            )
            conn.commit()
        return [dict(r) for r in rows]


def get_known_devices():
    with _lock:
        conn = get_connection()
        rows = conn.execute("SELECT * FROM known_devices").fetchall()
        return {r["mac"]: dict(r) for r in rows}
