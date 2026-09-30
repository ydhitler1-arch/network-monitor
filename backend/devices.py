"""Local network device discovery — real IP/MAC pairs.

Discovery tiers, best-effort in order:
1. scapy ARP scan of each local subnet (fast, accurate; needs scapy + Npcap/root).
2. Ping sweep to populate the OS ARP cache, then parse that cache
   (`arp -a` on Windows, `arp -n` on Linux/macOS). Needs no extra privileges.
"""

import ipaddress
import platform
import re
import socket
import subprocess
import threading
import time

import psutil

try:
    from scapy.all import ARP, Ether, srp

    _SCAPY_AVAILABLE = True
except Exception:
    _SCAPY_AVAILABLE = False


def get_local_networks():
    """Return the IPv4 subnets this machine is directly attached to."""
    networks = []
    for _iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address and not addr.address.startswith("127."):
                try:
                    netmask = addr.netmask or "255.255.255.0"
                    network = ipaddress.IPv4Network(f"{addr.address}/{netmask}", strict=False)
                    if network.num_addresses <= 1024:
                        networks.append(network)
                except ValueError:
                    continue
    return networks


def _resolve_hostname(ip):
    try:
        socket.setdefaulttimeout(0.5)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _scapy_scan(network, timeout=2):
    try:
        arp = ARP(pdst=str(network))
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered = srp(ether / arp, timeout=timeout, verbose=0)[0]
        return [{"ip": rcv.psrc, "mac": rcv.hwsrc.upper()} for _sent, rcv in answered]
    except Exception:
        return None


def _ping(ip):
    system = platform.system().lower()
    cmd = ["ping", "-n", "1", "-w", "300", ip] if system == "windows" else ["ping", "-c", "1", "-W", "1", ip]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
    except Exception:
        pass


def _ping_sweep(network, max_hosts=254):
    hosts = list(network.hosts())[:max_hosts]
    threads = [threading.Thread(target=_ping, args=(str(ip),), daemon=True) for ip in hosts]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=2)


def _parse_arp_table():
    system = platform.system().lower()
    devices = []
    try:
        if system == "windows":
            output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                m = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)", line)
                if m:
                    ip, mac, _kind = m.groups()
                    devices.append({"ip": ip, "mac": mac.replace("-", ":").upper()})
        else:
            output = subprocess.check_output(["arp", "-n"], text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3 and re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", parts[2]):
                    devices.append({"ip": parts[0], "mac": parts[2].upper()})
    except Exception:
        pass
    return devices


def scan_devices():
    """Discover devices on all attached local subnets. Returns a list of
    {ip, mac, hostname, last_seen} dicts."""
    networks = get_local_networks()
    found = {}

    for network in networks:
        result = _scapy_scan(network) if _SCAPY_AVAILABLE else None
        if result:
            for d in result:
                found[d["mac"]] = d
        else:
            _ping_sweep(network)

    if not found:
        for d in _parse_arp_table():
            found.setdefault(d["mac"], d)

    now = time.time()
    devices = []
    for mac, d in found.items():
        devices.append(
            {
                "ip": d["ip"],
                "mac": mac,
                "hostname": _resolve_hostname(d["ip"]),
                "last_seen": now,
            }
        )

    def _sort_key(d):
        try:
            return tuple(int(p) for p in d["ip"].split("."))
        except ValueError:
            return (255, 255, 255, 255)

    devices.sort(key=_sort_key)
    return devices


def scapy_available():
    return _SCAPY_AVAILABLE
