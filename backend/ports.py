"""Port scanning — threaded socket connect scan, with optional python-nmap engine."""

import concurrent.futures
import socket
import time

try:
    import nmap

    _NMAP_AVAILABLE = True
except Exception:
    _NMAP_AVAILABLE = False

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 1723, 3306, 3389, 5000, 5432, 5900, 6379, 8080, 8443, 27017,
]

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5000: "UPnP/Sync", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def _scan_one(host, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            is_open = s.connect_ex((host, port)) == 0
            return port, is_open
    except Exception:
        return port, False


def socket_scan(host, ports=None, timeout=0.6, max_workers=50):
    ports = ports or COMMON_PORTS
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_scan_one, host, p, timeout) for p in ports]
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
    open_ports.sort()
    return [{"port": p, "service": SERVICE_NAMES.get(p, "unknown"), "state": "open"} for p in open_ports]


def nmap_scan(host, ports=None):
    if not _NMAP_AVAILABLE:
        raise RuntimeError("python-nmap / the nmap binary is not available")
    scanner = nmap.PortScanner()
    port_str = ",".join(str(p) for p in (ports or COMMON_PORTS))
    scanner.scan(host, port_str, arguments="-T4")
    results = []
    if host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port, info in scanner[host][proto].items():
                if info["state"] == "open":
                    results.append(
                        {"port": port, "service": info.get("name", "unknown") or "unknown", "state": "open"}
                    )
    results.sort(key=lambda r: r["port"])
    return results


def scan_ports(host, ports=None, use_nmap=False):
    started = time.time()
    if use_nmap and _NMAP_AVAILABLE:
        try:
            results = nmap_scan(host, ports)
            engine = "nmap"
        except Exception:
            results = socket_scan(host, ports)
            engine = "socket"
    else:
        results = socket_scan(host, ports)
        engine = "socket"
    return {
        "host": host,
        "scanned_ports": len(ports or COMMON_PORTS),
        "open_ports": results,
        "duration_s": round(time.time() - started, 2),
        "engine": engine,
    }


def nmap_available():
    return _NMAP_AVAILABLE
