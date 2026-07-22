"""Guards against turning the port scanner into an open scanning proxy.

The scan target is user-supplied (the `host` query param), so it must be
restricted to private/local addresses only — otherwise anyone with access
to this dashboard could point it at arbitrary internet hosts and use this
server (and its IP) to run unauthorized scans against third parties.
"""

import ipaddress
import socket


def is_scan_target_allowed(host):
    """Returns (allowed: bool, resolved_ip_or_reason: str)."""
    try:
        resolved = socket.gethostbyname(host)
    except socket.gaierror:
        return False, f"Could not resolve host '{host}'."

    try:
        ip = ipaddress.ip_address(resolved)
    except ValueError:
        return False, f"'{host}' did not resolve to a valid IP address."

    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return True, resolved

    return False, (
        f"'{host}' resolves to {resolved}, a public address. This scanner is "
        "restricted to private/local network targets only."
    )
