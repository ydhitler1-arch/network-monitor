"""Runtime configuration, loaded from environment variables (and a .env file if present)."""

import os
import secrets

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


def _bool_env(name, default=False):
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


HOST = os.environ.get("NETMON_HOST", "127.0.0.1")
PORT = int(os.environ.get("NETMON_PORT", "5000"))

AUTH_USERNAME = os.environ.get("NETMON_USERNAME", "admin")
AUTH_PASSWORD = os.environ.get("NETMON_PASSWORD")
GENERATED_PASSWORD = AUTH_PASSWORD is None
if GENERATED_PASSWORD:
    AUTH_PASSWORD = secrets.token_urlsafe(12)

CORS_ORIGINS = [
    o.strip()
    for o in os.environ.get("NETMON_CORS_ORIGINS", "http://localhost:5173").split(",")
    if o.strip()
]

# Waitress worker threads. A synchronous scan holds one for its whole duration,
# so keep this comfortably above MAX_CONCURRENT_SCANS in app.py.
THREADS = int(os.environ.get("NETMON_THREADS", "8"))

SCAN_RATE_LIMIT = os.environ.get("NETMON_SCAN_RATE_LIMIT", "10 per minute")
LOGIN_RATE_LIMIT = os.environ.get("NETMON_LOGIN_RATE_LIMIT", "5 per minute")

SECRET_KEY = os.environ.get("NETMON_SECRET_KEY")
GENERATED_SECRET_KEY = SECRET_KEY is None
if GENERATED_SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)

# Only send the session cookie over HTTPS. Keep False for local http:// testing;
# set True once this runs behind a TLS-terminating reverse proxy.
COOKIE_SECURE = _bool_env("NETMON_COOKIE_SECURE", False)


def warn_startup():
    if GENERATED_PASSWORD:
        print("=" * 72)
        print("NETMON_PASSWORD is not set - generated a one-time password for this run.")
        print(f"  username: {AUTH_USERNAME}")
        print(f"  password: {AUTH_PASSWORD}")
        print("Set NETMON_USERNAME / NETMON_PASSWORD (e.g. in a .env file) to keep")
        print("credentials stable across restarts.")
        print("=" * 72)
    if GENERATED_SECRET_KEY:
        print("=" * 72)
        print("NETMON_SECRET_KEY is not set - generated a random one for this run.")
        print("Every restart will invalidate existing login sessions until you set")
        print("NETMON_SECRET_KEY (e.g. in a .env file) to a stable value.")
        print("=" * 72)
