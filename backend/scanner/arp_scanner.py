"""Scapy ARP sweep — finds hosts that block ICMP. Requires root/cap_net_raw."""
import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)


@dataclass
class ArpHost:
    ip: str
    mac: str


def arp_scan(subnet: str, timeout: float = 2.0) -> list[ArpHost]:
    """Broadcast ARP who-has across the given subnet. Returns responders."""
    try:
        from scapy.all import ARP, Ether, srp  # imported lazily — needs root
    except ImportError as e:
        log.warning("scapy unavailable: %s", e)
        return []

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    try:
        answered, _ = srp(pkt, timeout=timeout, verbose=False)
    except PermissionError:
        log.warning("arp_scan needs root/cap_net_raw; falling back to empty")
        return []
    except Exception as e:
        log.warning("arp_scan error: %s", e)
        return []

    return [ArpHost(ip=rcv.psrc, mac=rcv.hwsrc) for _, rcv in answered]
