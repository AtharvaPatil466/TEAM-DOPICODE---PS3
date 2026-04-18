"""Risk score 0-100. Weights: CVE severity, exposed admin, open ports, exposure."""
from dataclasses import dataclass


@dataclass
class RiskInput:
    open_port_count: int
    max_cvss: float  # 0-10
    cve_count: int
    admin_panel_exposed: bool
    internet_facing: bool
    ssl_broken: bool = False
    self_signed: bool = False
    expired_cert: bool = False


# Weights tuned so a CVSS-9.8 internet-facing host with an exposed admin panel
# lands in the critical band (>=80) even with a modest port count.
W_CVSS = 6.0       # * cvss  → up to 60
W_ADMIN = 15.0     # exposed admin panel
W_EXPOSURE = 8.0   # internet-facing
W_PORTS = 1.2      # * min(open_ports, 10) → up to 12
W_SSL = 6.0        # broken SSL on HTTPS host
W_CVE_VOLUME = 0.8 # * min(cve_count, 10) → up to 8


def score(inp: RiskInput) -> float:
    s = 0.0
    s += W_CVSS * max(0.0, min(inp.max_cvss, 10.0))
    if inp.admin_panel_exposed:
        s += W_ADMIN
    if inp.internet_facing:
        s += W_EXPOSURE
    s += W_PORTS * min(inp.open_port_count, 10)
    if inp.ssl_broken or inp.expired_cert:
        s += W_SSL
    elif inp.self_signed:
        s += W_SSL * 0.5
    s += W_CVE_VOLUME * min(inp.cve_count, 10)
    return round(max(0.0, min(s, 100.0)), 1)


def level(s: float) -> str:
    if s >= 80:
        return "critical"
    if s >= 60:
        return "high"
    if s >= 30:
        return "medium"
    return "low"
