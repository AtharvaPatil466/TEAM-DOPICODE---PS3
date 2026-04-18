"""Named rulebook for graph edge creation.

Every edge in the attack graph is produced by exactly one named rule in this
module. When a judge asks "why does this edge exist?", the answer is a rule
ID + human rationale + MITRE ATT&CK technique(s) + a structured evidence dict
naming the specific fields that satisfied the predicate.
"""
from dataclasses import dataclass, field
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
    attack_techniques: list[str] = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    detection_probability: float = 0.5
    compliance_controls: list[str] = field(default_factory=list)


@dataclass
class EdgeRule:
    id: str
    name: str
    description: str
    attack_techniques: list[str]
    detection_probability: float
    compliance_controls: list[str]
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


def _is_internet_gateway(asset: Asset) -> bool:
    tech = asset.tech_stack or {}
    return bool(tech.get("internet_exposed"))


def _edge_reachable(src: Optional[Asset], dst: Asset, ctx: dict) -> bool:
    """Topology gate for rules that would otherwise fire on any (src, dst) pair.

    - src=None (Internet)        → external asset, or internal gateway.
    - src external               → internal-only reachable via a gateway dst.
    - src internal               → must share a subnet with dst (lateral).
    - src internal, dst external → never (no reverse-pivot modeled).
    """
    if src is None:
        if dst.exposure == "external":
            return True
        return _is_internet_gateway(dst)
    if src.exposure == "external":
        return dst.exposure == "internal" and _is_internet_gateway(dst)
    if dst.exposure == "external":
        return False
    return ctx["same_subnet"](src, dst)


def _matched_rce_keyword(cve: CVE) -> Optional[str]:
    desc = (cve.description or "").lower()
    for keyword in _RCE_KEYWORDS:
        if keyword in desc:
            return keyword
    return None


def _auth_cve(asset: Asset) -> tuple[Optional[CVE], Optional[str]]:
    best: Optional[CVE] = None
    matched_keyword: Optional[str] = None
    for cve in asset.cves:
        desc = (cve.description or "").lower()
        hit = next((keyword for keyword in _AUTH_KEYWORDS if keyword in desc), None)
        if hit is None:
            continue
        if best is None or (cve.cvss_score or 0) > (best.cvss_score or 0):
            best = cve
            matched_keyword = hit
    return best, matched_keyword


def _login_panel_paths(asset: Asset) -> list[str]:
    hits: list[str] = []
    for panel in asset.admin_panels or []:
        path = (panel.get("path") or "").lower()
        if any(keyword in path for keyword in _LOGIN_KEYWORDS):
            hits.append(panel.get("path") or "")
    return hits


def _has_mfa_signal(asset: Asset) -> Optional[str]:
    haystacks = []
    if asset.tech_stack:
        haystacks.append(str(asset.tech_stack).lower())
    if asset.admin_panels:
        haystacks.append(str(asset.admin_panels).lower())
    if asset.ssl_info:
        haystacks.append(str(asset.ssl_info).lower())
    blob = " ".join(haystacks)
    for keyword in _MFA_KEYWORDS:
        if keyword in blob:
            return keyword
    return None


def _net_002(src: Optional[Asset], dst: Asset, ctx: dict) -> Optional[RuleMatch]:
    if src is not None:
        return None
    if dst.exposure != "external" and not _is_internet_gateway(dst):
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
        attack_techniques=["T1595", "T1590"],
        evidence={"surfaces_confirmed": surfaces, "exposure": dst.exposure},
    )


def _misc_001(src: Optional[Asset], dst: Asset, ctx: dict) -> Optional[RuleMatch]:
    if src is not None or dst.exposure != "external":
        return None
    panels = dst.admin_panels or []
    unauth = [panel for panel in panels if not panel.get("auth")]
    if not unauth:
        return None
    paths = [panel.get("path", "?") for panel in unauth[:3]]
    return RuleMatch(
        "MISC-001",
        "Exposed Admin Panel",
        "admin_exposure",
        f"{_label(dst)} exposes unauthenticated admin/login surface(s) at {', '.join(paths)}.",
        weight_modifier=0.7,
        attack_techniques=["T1190", "T1133"],
        evidence={"unauthenticated_panels": paths},
    )


def _conf_001(src: Optional[Asset], dst: Asset, ctx: dict) -> Optional[RuleMatch]:
    if src is not None:
        return None
    ssl_info = dst.ssl_info or {}
    flaw = None
    evidence_key = None
    if ssl_info.get("expired"):
        flaw = "expired certificate"
        evidence_key = "expired"
    elif ssl_info.get("self_signed"):
        flaw = "self-signed certificate"
        evidence_key = "self_signed"
    elif ssl_info.get("hostname_match") is False:
        flaw = "certificate hostname mismatch"
        evidence_key = "hostname_match"
    if flaw is None:
        return None
    return RuleMatch(
        "CONF-001",
        "Weak TLS Posture",
        "tls_weakness",
        f"{_label(dst)} presents a {flaw}, weakening trust and credential handling.",
        weight_modifier=0.95,
        attack_techniques=["T1557", "T1040"],
        evidence={"tls_flaw": evidence_key, "ssl_info": {k: ssl_info.get(k) for k in ("expired", "self_signed", "hostname_match")}},
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
        attack_techniques=["T1195.002"],
        evidence={"component": tech.get("name"), "version": tech.get("version"), "cve_count": len(dst.cves)},
    )


def _cloud_001(src: Optional[Asset], dst: Asset, ctx: dict) -> Optional[RuleMatch]:
    if src is not None or dst.asset_type != "storage":
        return None
    meta = dst.tech_stack or {}
    if meta.get("issue") != "public_listing":
        return None
    sample_files = (meta.get("sample_files") or [])[:3]
    sample_hint = f" Sample objects include {', '.join(sample_files)}." if sample_files else ""
    bucket_name = meta.get("bucket_name") or _label(dst)
    return RuleMatch(
        "CLOUD-001",
        "Public Bucket Exposure",
        "public_bucket",
        f"{bucket_name} allows unauthenticated object listing and direct data exposure.{sample_hint}",
        weight_modifier=0.4,
        attack_techniques=["T1530", "T1619"],
        evidence={"bucket": bucket_name, "issue": meta.get("issue"), "sample_files": sample_files},
    )


def _exp_001(src: Optional[Asset], dst: Asset, ctx: dict) -> Optional[RuleMatch]:
    if not _edge_reachable(src, dst, ctx):
        return None
    cve = _remote_exploit_cve(dst)
    if cve is None:
        return None
    complexity = (cve.attack_complexity or "").upper()[:1] or "?"
    matched = _matched_rce_keyword(cve)
    kev_flag = bool(getattr(cve, "in_kev", False))
    kev_rw = bool(getattr(cve, "kev_ransomware", False))
    kev_suffix = ""
    if kev_rw:
        kev_suffix = " On CISA KEV with known ransomware campaign use."
    elif kev_flag:
        kev_suffix = " On CISA KEV (actively exploited in the wild)."
    weight_modifier = 0.5
    if kev_rw:
        weight_modifier = 0.3
    elif kev_flag:
        weight_modifier = 0.35
    return RuleMatch(
        "EXP-001",
        "Remote Exploit",
        "rce_exploit",
        f"{_label(dst)} exposes {cve.cve_id} (CVSS {cve.cvss_score}, AV:N, AC:{complexity}), "
        f"making direct remote exploitation viable.{kev_suffix}",
        weight_modifier=weight_modifier,
        attack_techniques=["T1190", "T1210"],
        evidence={
            "cve_id": cve.cve_id,
            "cvss": cve.cvss_score,
            "attack_vector": cve.attack_vector,
            "attack_complexity": cve.attack_complexity,
            "matched_keyword": matched,
            "in_kev": kev_flag,
            "kev_ransomware": kev_rw,
            "kev_date_added": getattr(cve, "kev_date_added", None),
        },
    )


def _cred_001(src: Optional[Asset], dst: Asset, ctx: dict) -> Optional[RuleMatch]:
    if not _edge_reachable(src, dst, ctx):
        return None
    login_paths = _login_panel_paths(dst)
    if not login_paths:
        return None
    mfa_hit = _has_mfa_signal(dst)
    if mfa_hit is not None:
        return None
    auth_cve, matched = _auth_cve(dst)
    if auth_cve is None:
        return None
    return RuleMatch(
        "CRED-001",
        "Credential Path",
        "credential_access",
        f"{_label(dst)} presents a login surface, shows no MFA indicator, and carries "
        f"{auth_cve.cve_id} (CVSS {auth_cve.cvss_score}) in the authentication layer.",
        weight_modifier=0.65,
        attack_techniques=["T1078", "T1110", "T1556"],
        evidence={
            "login_paths": login_paths,
            "mfa_signal": None,
            "cve_id": auth_cve.cve_id,
            "matched_keyword": matched,
        },
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
        attack_techniques=["T1068", "T1548"],
        evidence={
            "subnet": ctx["subnet_of"](dst),
            "cve_id": cve.cve_id,
            "cvss": cve.cvss_score,
            "attack_vector": cve.attack_vector,
            "attack_complexity": cve.attack_complexity,
        },
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
        attack_techniques=["T1021", "T1570"],
        evidence={"subnet": ctx["subnet_of"](dst), "segmentation": "none_observed"},
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
        attack_techniques=["T1200", "T1021"],
        evidence={"shadow_source": _label(src), "subnet": ctx["subnet_of"](dst)},
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
        attack_techniques=["T1213", "T1005", "T1041"],
        evidence={"target": _label(dst), "source": _label(src), "tag": "crown_jewel"},
    )


RULES: list[EdgeRule] = [
    EdgeRule("NET-002", "Internet Reachability",
             "External asset is confirmed reachable from the public internet.",
             ["T1595", "T1590"], 0.10,
             ["NIST AC-17", "CIS 12.2"], _net_002),
    EdgeRule("MISC-001", "Exposed Admin Panel",
             "External asset exposes unauthenticated admin or login functionality.",
             ["T1190", "T1133"], 0.40,
             ["PCI 1.2.1", "SOC2 CC6.1", "NIST AC-3"], _misc_001),
    EdgeRule("CONF-001", "Weak TLS Posture",
             "TLS certificate state weakens trust or enables interception scenarios.",
             ["T1557", "T1040"], 0.15,
             ["PCI 4.1", "SOC2 CC6.7", "NIST SC-8"], _conf_001),
    EdgeRule("SUPPLY-001", "Outdated Dependency",
             "Fingerprinted software version is tied to known CVE exposure.",
             ["T1195.002"], 0.20,
             ["NIST SI-2", "PCI 6.2", "SOC2 CC7.1"], _supply_001),
    EdgeRule("CLOUD-001", "Public Bucket Exposure",
             "Cloud object storage is publicly listable and exposes stored data directly.",
             ["T1530", "T1619"], 0.05,
             ["SOC2 CC6.1", "NIST AC-3", "ISO 27001 A.9.4"], _cloud_001),
    EdgeRule("EXP-001", "Remote Exploit",
             "Service version has a high-severity network-exploitable CVE.",
             ["T1190", "T1210"], 0.75,
             ["NIST SI-2", "NIST SI-4", "PCI 6.2"], _exp_001),
    EdgeRule("CRED-001", "Credential Path",
             "Login surface exists, MFA indicators are absent, and an auth-related CVE exists.",
             ["T1078", "T1110", "T1556"], 0.35,
             ["PCI 8.3.1", "SOC2 CC6.1", "NIST IA-2"], _cred_001),
    EdgeRule("EXP-002", "Privilege Escalation",
             "Target has a local privilege-escalation CVE usable after subnet foothold.",
             ["T1068", "T1548"], 0.65,
             ["NIST AC-6", "NIST SI-4"], _exp_002),
    EdgeRule("NET-001", "Lateral Reachability",
             "Source and target share a /24 and there is no segmentation evidence.",
             ["T1021", "T1570"], 0.25,
             ["PCI 1.2", "NIST SC-7", "CIS 12.2"], _net_001),
    EdgeRule("SHADOW-001", "Shadow Device Pivot",
             "Unmanaged device on the same subnet can move laterally toward the target.",
             ["T1200", "T1021"], 0.10,
             ["NIST CM-8", "CIS 1.1", "SOC2 CC6.1"], _shadow_001),
    EdgeRule("DATA-001", "Crown Jewel Access",
             "Compromised source can reach a designated crown-jewel asset.",
             ["T1213", "T1005", "T1041"], 0.55,
             ["PCI 3.4", "SOC2 CC6.1", "NIST SC-7"], _data_001),
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
        {
            "id": rule.id,
            "name": rule.name,
            "description": rule.description,
            "attack_techniques": rule.attack_techniques,
        }
        for rule in RULES
    ]
