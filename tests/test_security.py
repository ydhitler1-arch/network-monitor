"""backend/security.py restricts port-scan targets to private/local
addresses — this is what stops the scanner from becoming an open scanning
proxy against third parties, so it's worth pinning down with tests."""

import socket

from backend.security import is_scan_target_allowed


def test_allows_loopback():
    allowed, resolved = is_scan_target_allowed("127.0.0.1")
    assert allowed
    assert resolved == "127.0.0.1"


def test_allows_private_ip():
    allowed, _ = is_scan_target_allowed("192.168.1.1")
    assert allowed


def test_blocks_public_ip():
    allowed, reason = is_scan_target_allowed("8.8.8.8")
    assert not allowed
    assert "public address" in reason


def test_blocks_unresolvable_host(monkeypatch):
    def fake_gethostbyname(_host):
        raise socket.gaierror("mock failure")

    monkeypatch.setattr(socket, "gethostbyname", fake_gethostbyname)
    allowed, reason = is_scan_target_allowed("this-host-does-not-exist.invalid")
    assert not allowed
    assert "Could not resolve" in reason
