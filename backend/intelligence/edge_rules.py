"""Named rulebook for graph edge creation.

Every edge in the attack graph is produced by exactly one named rule in this
module. When a judge asks "why does this edge exist?", the answer should be a
rule ID plus a deterministic rationale tied to the evidence on the source and
target assets.
"""
from dataclasses import dataclass
from typing import Callable, Optional

from backend.db.models import Asset, CVE

INTERNET_NODE = 0


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    relationship: str
    rationale: str
    weight_modifier: float = 1.0


@dataclass
class EdgeRule:
    id: str
    name: str
    description: str
    evaluate: Callable[[Optional[Asset], Asset, dict], Optional[RuleMatch]]


_AUTH_KEYWORDS = ("auth", "credential", "bypass", "login", "password", "session", "token")
_RCE_KEYWORDS = (
    "remote code execution",
    "command execution",
    "code execution",
    "rce",
    "deserialization",
    "path traversal",
    "arbitrary file read",
    "file disclosure",
)
_LOGIN_KEYWORDS = ("login", "signin", "auth", "admin", "portal", "console")
_MFA_KEYWORDS = ("mfa", "2fa", "otp", "totp", "duo", "okta verify", "authenticator")


def _label(asset: Asset) -> str:
    return asset.hostname or asset.ip_address or f"asset-{asset.id}"


def _strongest_cve(asset: Asset, min_cvss: float, vector: Optional[str] = None) -> Optional[CVE]:
    best: Optional[CVE] = None
    for cve in asset.cves:
        if (cve.cvss_score or 0) < min_cvss:
            continue
        if vector and (cve.attack_vector or "").upper() != vector:
            continue
        if best is None or (cve.cvss_score or 0) > (best.cvss_score or 0):
            best = cve
    return best


def _remote_exploit_cve(asset: Asset) -> Optional[CVE]:
    best: Optional[CVE] = None
    for cve in asset.cves:
        if (cve.cvss_score or 0) < 8.0:
            continue
        if (cve.attack_vector or "").upper() != "NETWORK":
            continue
        desc = (cve.description or "").lower()
        if desc and not any(keyword in desc for keyword in _RCE_KEYWORDS):
            continue
        if best is None or (cve.cvss_score or 0) > (best.cvss_score or 0):
            best = cve
    return best or _strongest_cve(asset, min_cvss=8.0, vector="NETWORK")


def _auth_cve(asset: Asset) -> Optional[CVE]:
    best: Optional[CVE] = None
    for cve in asset.cves:
        desc = (cve.description or "").lower()
        if not any(keyword in desc for keyword in _AUTH_KEYWORDS):
            continue
        if best is None or (cve.cvss_score or 0) > (best.cvss_score or 0):
            best = cve
    return best


def _has_login_surface(asset: Asset) -> bool:
    for panel in asset.admin_panels or []:
        path = (panel.get("path") or "").lower()
        if any(keyword in path for keyword in _LOGIN_KEYWORDS):
            return True
    return False


def _has_mfa_signal(asset: Asset) -> bool:
    haystacks = []
    if asset.tech_stack:
        haystacks.append(str(asset.tech_stack).lower())
    if asset.admin_panels:
        haystacks.append(str(asset.admin_panels).lower())
    if asset.ssl_info:
        haystacks.append(str(asset.ssl_info).lower())
    return any(keyword in " ".join(haystacks) for keyword in _MFA_KEYWORDS)


def _net_002(src: Optional[Asset], dst: Asset, ctx: dict) -> Optional[RuleMatch]:
    if src is not None or dst.exposure != "external":
        return None
    surfaces = []
    if dst.tech_stack:
        surfaces.append("HTTP fingerprint")
    if dst.admin_panels:
        surfaces.append("admin/login probe")
    if dst.ssl_info:
        surfaces.append("TLS handshake")
    evidence = ", ".join(surfaces) if surfaces else "external asset discovery"
    return RuleMatch(
        "NET-002",
        "Internet Reachability",
        "internet_reachable",
        f"{_label(dst)} is internet-facing and was confirmed during {evidence}.",
    )


def _misc_001(src: Optional[Asset], dst: Asset, ctx: dict) -> Optional[RuleMatch]:
    if src is not None or dst.exposure != "external":
        return None
    panels = dst.admin_panels or []
    unauth = [panel for panel in panels if not panel.get("auth")]
    if not unauth:
        return None
    paths = ", ".join(panel.get("path", "?") for panel in unauth[:3])
    return RuleMatch(
        "MISC-001",
        "Exposed Admin Panel",
        "admin_exposure",
        f"{_label(dst)} exposes unauthenticated admin/login surface(s) at {paths}.",
        weight_modifier=0.7,
    )


def _conf_001(src: Optional[Asset], dst: Asset, ctx: dict) -> Optional[RuleMatch]:
    if src is not None:
        return None
    ssl_info = dst.ssl_info or {}
    flaw = None
    if ssl_info.get("expired"):
        flaw = "expired certificate"
    elif ssl_info.get("self_signed"):
        flaw = "self-signed certificate"
    elif ssl_info.get("hostname_match") is False:
        flaw = "certificate hostname mismatch"
    if flaw is None:
        return None
    return RuleMatch(
        "CONF-001",
        "Weak TLS Posture",
        "tls_weakness",
        f"{_label(dst)} presents a {flaw}, weakening trust and credential handling.",
        weight_modifier=0.95,
    )


def _supply_001(src: Optional[Asset], dst: Asset, ctx: dict) -> Optional[RuleMatch]:
    if src is not None:
        return None
    techs = ((dst.tech_stack or {}).get("technologies") or [])
    versioned = [tech for tech in techs if tech.get("version")]
    if not versioned or not dst.cves:
        return None
    tech = versioned[0]
    return RuleMatch(
        "SUPPLY-001",
        "Outdated Dependency",
        "outdated_software",
        f"{_label(dst)} runs {tech['name']} {tech['version']} with {len(dst.cves)} mapped CVE(s).",
        weight_modifier=0.9,
    )


def _exp_001(src: Optional[Asset], dst: Asset, ctx: dict) -> Optional[RuleMatch]:
    cve = _remote_exploit_cve(dst)
    if cve is None:
        return None
    complexity = (cve.attack_complexity or "").upper()[:1] or "?"
    return RuleMatch(
        "EXP-001",
        "Remote Exploit",
        "rce_exploit",
        f"{_label(dst)} exposes {cve.cve_id} (CVSS {cve.cvss_score}, AV:N, AC:{complexity}), "
        "making direct remote exploitation viable.",
        weight_modifier=0.5,
    )


def _cred_001(src: Optional[Asset], dst: Asset, ctx: dict) -> Optional[RuleMatch]:
    if not _has_login_surface(dst):
        return None
    if _has_mfa_signal(dst):
        return None
    auth_cve = _auth_cve(dst)
    if auth_cve is None:
        return None
    return RuleMatch(
        "CRED-001",
        "Credential Path",
        "credential_access",
        f"{_label(dst)} presents a login surface, shows no MFA indicator, and carries "
        f"{auth_cve.cve_id} (CVSS {auth_cve.cvss_score}) in the authentication layer.",
        weight_modifier=0.65,
    )


def _exp_002(src: Optional[Asset], dst: Asset, ctx: dict) -> Optional[RuleMatch]:
    if src is None or not ctx["same_subnet"](src, dst):
        return None
    cve = _strongest_cve(dst, min_cvss=7.0, vector="LOCAL")
    if cve is None:
        return None
    complexity = (cve.attack_complexity or "").upper()[:1] or "?"
    return RuleMatch(
        "EXP-002",
        "Privilege Escalation",
        "priv_escalation",
        f"After landing on subnet {ctx['subnet_of'](dst)}, {cve.cve_id} (CVSS {cve.cvss_score}, "
        f"AV:L, AC:{complexity}) can elevate privileges on {_label(dst)}.",
        weight_modifier=0.8,
    )


def _net_001(src: Optional[Asset], dst: Asset, ctx: dict) -> Optional[RuleMatch]:
    if src is None or dst.exposure != "internal":
        return None
    if not ctx["same_subnet"](src, dst):
        return None
    return RuleMatch(
        "NET-001",
        "Lateral Reachability",
        "lateral_move",
        f"{_label(src)} and {_label(dst)} share {ctx['subnet_of'](dst)} with no segmentation evidence.",
    )


def _shadow_001(src: Optional[Asset], dst: Asset, ctx: dict) -> Optional[RuleMatch]:
    if src is None or not src.is_shadow_device:
        return None
    if not ctx["same_subnet"](src, dst):
        return None
    return RuleMatch(
        "SHADOW-001",
        "Shadow Device Pivot",
        "shadow_pivot",
        f"Unmanaged device {_label(src)} sits on the same subnet as {_label(dst)} and can bypass monitored paths.",
        weight_modifier=0.75,
    )


def _data_001(src: Optional[Asset], dst: Asset, ctx: dict) -> Optional[RuleMatch]:
    if src is None or not dst.is_crown_jewel:
        return None
    if not ctx["same_subnet"](src, dst):
        return None
    return RuleMatch(
        "DATA-001",
        "Crown Jewel Access",
        "crown_jewel_access",
        f"{_label(dst)} is tagged as the crown jewel and is reachable from compromised host {_label(src)}.",
        weight_modifier=0.5,
    )


RULES: list[EdgeRule] = [
    EdgeRule("NET-002", "Internet Reachability",
             "External asset is confirmed reachable from the public internet.", _net_002),
    EdgeRule("MISC-001", "Exposed Admin Panel",
             "External asset exposes unauthenticated admin or login functionality.", _misc_001),
    EdgeRule("CONF-001", "Weak TLS Posture",
             "TLS certificate state weakens trust or enables interception scenarios.", _conf_001),
    EdgeRule("SUPPLY-001", "Outdated Dependency",
             "Fingerprinted software version is tied to known CVE exposure.", _supply_001),
    EdgeRule("EXP-001", "Remote Exploit",
             "Service version has a high-severity network-exploitable CVE.", _exp_001),
    EdgeRule("CRED-001", "Credential Path",
             "Login surface exists, MFA indicators are absent, and an auth-related CVE exists.", _cred_001),
    EdgeRule("EXP-002", "Privilege Escalation",
             "Target has a local privilege-escalation CVE usable after subnet foothold.", _exp_002),
    EdgeRule("NET-001", "Lateral Reachability",
             "Source and target share a /24 and there is no segmentation evidence.", _net_001),
    EdgeRule("SHADOW-001", "Shadow Device Pivot",
             "Unmanaged device on the same subnet can move laterally toward the target.", _shadow_001),
    EdgeRule("DATA-001", "Crown Jewel Access",
             "Compromised source can reach a designated crown-jewel asset.", _data_001),
]

RULES_BY_ID: dict[str, EdgeRule] = {rule.id: rule for rule in RULES}


def evaluate_all(src: Optional[Asset], dst: Asset, ctx: dict) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for rule in RULES:
        match = rule.evaluate(src, dst, ctx)
        if match is not None:
            matches.append(match)
    return matches


def rulebook() -> list[dict]:
    return [
        {"id": rule.id, "name": rule.name, "description": rule.description}
        for rule in RULES
    ]
