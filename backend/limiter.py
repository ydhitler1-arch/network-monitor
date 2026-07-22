"""Shared Limiter instance. Kept separate from app.py so both app.py and
auth.py can decorate routes with it without a circular import.

In-memory storage is intentional here (not an oversight the warning is
guarding against): this app runs as a single process, so there's no
multi-worker state to lose track of. Set explicitly to silence the warning."""

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=[], storage_uri="memory://")
