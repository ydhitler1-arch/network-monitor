"""Live bandwidth in/out sampling via psutil."""

import threading
import time
from collections import deque

import psutil

_history = deque(maxlen=300)
_lock = threading.Lock()
_last = None


def sample():
    """Take one bandwidth sample and append it to the in-memory history."""
    global _last
    counters = psutil.net_io_counters()
    now = time.time()
    with _lock:
        if _last is None:
            send_rate = recv_rate = 0.0
        else:
            dt = max(now - _last["timestamp"], 1e-6)
            send_rate = (counters.bytes_sent - _last["bytes_sent"]) / dt
            recv_rate = (counters.bytes_recv - _last["bytes_recv"]) / dt
        entry = {
            "timestamp": now,
            "bytes_sent": counters.bytes_sent,
            "bytes_recv": counters.bytes_recv,
            "send_rate": max(send_rate, 0.0),
            "recv_rate": max(recv_rate, 0.0),
        }
        _last = entry
        _history.append(entry)
    return entry


def get_current():
    with _lock:
        return _history[-1] if _history else None


def get_history(limit=120):
    with _lock:
        return list(_history)[-limit:]


def get_per_interface():
    return {
        name: {"bytes_sent": s.bytes_sent, "bytes_recv": s.bytes_recv}
        for name, s in psutil.net_io_counters(pernic=True).items()
    }
