"""python-nmap wrapper. Synchronous — run via asyncio.to_thread from callers."""
import logging
import os
from dataclasses import dataclass, field

import nmap  # python-nmap

log = logging.getLogger(__name__)


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


# OS fingerprinting (-O) needs raw sockets. Without root, nmap aborts the entire
# scan. Drop the flag when unprivileged so the service/version pass still runs.
_OS_FLAG = "-O " if _is_root() else ""


@dataclass
class NmapHost:
    ip: str
    hostname: str | None = None
    state: str = "unknown"
    os_guess: str | None = None
    ports: list[dict] = field(default_factory=list)


def _extract_os(host_data: dict) -> str | None:
    matches = host_data.get("osmatch") or []
    if matches:
        return matches[0].get("name")
    return None


def discover_hosts(subnet: str) -> list[str]:
    """Ping sweep — returns list of live host IPs."""
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments="-sn -T4")
    return [h for h in nm.all_hosts() if nm[h].state() == "up"]


def scan_host(ip: str, ports: str = "1-1024,3306,5000,5432,6379,8080,8443,9200,27017") -> NmapHost:
    """Port scan + service/version detection + OS fingerprint for a single host."""
    nm = nmap.PortScanner()
    # -sV service version, -O OS detect, -T4 speed, --host-timeout bounded
    nm.scan(hosts=ip, ports=ports, arguments=f"-sV {_OS_FLAG}-T4 --host-timeout 120s")
    if ip not in nm.all_hosts():
        return NmapHost(ip=ip, state="down")
    data = nm[ip]
    hostnames = data.hostnames() or []
    hostname = hostnames[0]["name"] if hostnames else None
    ports_out: list[dict] = []
    for proto in data.all_protocols():
        for port, pinfo in data[proto].items():
            ports_out.append({
                "port": port,
                "protocol": proto,
                "state": pinfo.get("state", "unknown"),
                "service": pinfo.get("name"),
                "version": pinfo.get("version") or pinfo.get("product"),
                "product": pinfo.get("product"),
            })
    return NmapHost(
        ip=ip,
        hostname=hostname or None,
        state=data.state(),
        os_guess=_extract_os(data),
        ports=ports_out,
    )


def scan_subnet(subnet: str) -> list[NmapHost]:
    hosts = discover_hosts(subnet)
    return [scan_host(h) for h in hosts]
