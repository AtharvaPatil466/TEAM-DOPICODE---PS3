"""Attack-path ranking.

Single source of truth for entry/target selection, top-k candidate paths via
`nx.shortest_simple_paths` on inverted-risk weights, per-hop time-to-breach
estimates derived from CVE attack_vector / attack_complexity, and aggregated
remediation candidates ranked by how many modeled paths they break.

Both `compute_attack_path` (called during scan orchestration, persists the
primary path) and `backend.intelligence.report.build_pdf` / the `/attack-path`
API consume the same ranking — they never disagree on "the" attack path.
"""
from dataclasses import dataclass, field
from itertools import islice
from typing import Optional

import networkx as nx
from sqlalchemy.orm import Session

from backend.db.models import Asset, AttackPath, CVE, Scan

from .graph_builder import INTERNET_NODE
from .path_validator import PathValidator, summarize as summarize_validations


def asset_label(asset: Asset) -> str:
    return asset.hostname or asset.ip_address or f"asset-{asset.id}"


def top_cve(asset: Asset) -> Optional[CVE]:
    return max(asset.cves, key=lambda cve: cve.cvss_score or 0, default=None)


def pick_entry_and_target(g: nx.DiGraph, scan: Scan) -> tuple[Optional[int], Optional[int]]:
    entry: Optional[int] = None
    if INTERNET_NODE in g and g.out_degree(INTERNET_NODE) > 0:
        entry = INTERNET_NODE
    else:
        externals = [a for a in scan.assets if a.exposure == "external"]
        if externals:
            entry = max(externals, key=lambda a: a.risk_score or 0).id

    crowns = [a for a in scan.assets if a.is_crown_jewel]
    if crowns:
        target = max(crowns, key=lambda a: a.risk_score or 0).id
    else:
        internals = [a for a in scan.assets if a.exposure == "internal"]
        if internals:
            target = max(internals, key=lambda a: a.risk_score or 0).id
        else:
            externals = [a for a in scan.assets if a.exposure == "external"]
            target = max(externals, key=lambda a: a.risk_score or 0).id if externals else None
    return entry, target


PERSONAS = {
    "script_kiddie": {"label": "Script Kiddie", "low_mult": 2.0, "high_mult": 2.5, "hard_ac_mult": 3.0},
    "criminal":      {"label": "Criminal Operator", "low_mult": 1.0, "high_mult": 1.0, "hard_ac_mult": 1.2},
    "apt":           {"label": "Nation-State / APT", "low_mult": 0.55, "high_mult": 0.6, "hard_ac_mult": 0.8},
}
DEFAULT_PERSONA = "criminal"


def persona_spec(persona: Optional[str]) -> dict:
    return PERSONAS.get(persona or DEFAULT_PERSONA, PERSONAS[DEFAULT_PERSONA])


def estimate_hop_minutes(
    cve: Optional[CVE],
    relationship: Optional[str],
    persona: Optional[str] = None,
) -> tuple[int, int]:
    spec = persona_spec(persona)
    low_mult = spec["low_mult"]
    high_mult = spec["high_mult"]
    hard_ac_mult = spec["hard_ac_mult"]
    if cve is None:
        base = {
            "internet_reachable": (45, 120),
            "admin_exposure": (30, 90),
            "credential_access": (45, 180),
            "public_bucket": (15, 45),
            "lateral_move": (60, 180),
            "shadow_pivot": (45, 120),
            "crown_jewel_access": (60, 180),
        }
        low, high = base.get(relationship or "", (60, 180))
        return int(round(low * low_mult)), int(round(high * high_mult))

    vector = (cve.attack_vector or "").upper()
    complexity = (cve.attack_complexity or "").upper()
    matrix = {
        ("NETWORK", "LOW"): (30, 90),
        ("NETWORK", "HIGH"): (180, 480),
        ("ADJACENT", "LOW"): (60, 180),
        ("ADJACENT", "HIGH"): (240, 720),
        ("LOCAL", "LOW"): (120, 360),
        ("LOCAL", "HIGH"): (480, 1440),
        ("PHYSICAL", "LOW"): (1440, 2880),
        ("PHYSICAL", "HIGH"): (2880, 4320),
    }
    low, high = matrix.get((vector, complexity), (90, 240))
    if relationship in {"credential_access", "admin_exposure"}:
        low += 30
        high += 120
    elif relationship in {"tls_weakness", "outdated_software"}:
        low += 60
        high += 180
    elif relationship == "crown_jewel_access":
        low += 30
        high += 90
    low = int(round(low * low_mult))
    high = int(round(high * high_mult))
    if complexity == "HIGH":
        low = int(round(low * hard_ac_mult))
        high = int(round(high * hard_ac_mult))
    return low, high


def format_duration(minutes: int) -> str:
    if minutes < 60:
        return f"{minutes} minutes"
    if minutes < 1440:
        hours = max(1, round(minutes / 60))
        return f"{hours} hour" if hours == 1 else f"{hours} hours"
    days = max(1, round(minutes / 1440))
    return f"{days} day" if days == 1 else f"{days} days"


def format_duration_range(low: int, high: int) -> str:
    return f"{format_duration(low)} to {format_duration(high)}"


def path_sentence(path: dict) -> str:
    chain: list[str] = []
    for label, hop in zip(path["sequence_labels"][1:], path["hops"]):
        token = label
        if hop.get("rule_id"):
            token += f" [{hop['rule_id']}]"
        if hop.get("cve_id"):
            token += f" via {hop['cve_id']}"
        chain.append(token)
    return "Internet -> " + " -> ".join(chain)


def _category_fingerprint(
    path: list[int],
    edge_rules: list[str],
    assets_by_id: dict,
) -> tuple:
    """Group paths by their internal-pivot signature.

    Two paths are the same category when they traverse the same internal pivot
    set with the same final rule. The external entry (which front door) does
    not differentiate — "legacy.xyz→apache→mysql" and "admin.xyz→apache→mysql"
    are both Category 1 (direct RCE to crown).
    """
    internal_pivots = tuple(
        node for node in path[1:-1]
        if node != INTERNET_NODE
        and (assets_by_id.get(node) is not None)
        and assets_by_id[node].exposure == "internal"
    )
    final_rule = edge_rules[-1] if edge_rules else ""
    return (internal_pivots, final_rule)


def build_candidate_paths(
    scan: Scan,
    g: nx.DiGraph,
    limit: int = 8,
    persona: Optional[str] = None,
    pool_size: int = 60,
) -> list[dict]:
    entry, target = pick_entry_and_target(g, scan)
    if entry is None or target is None or entry == target:
        return []
    if entry not in g or target not in g:
        return []

    assets_by_id = {a.id: a for a in scan.assets}
    try:
        raw_paths = list(islice(nx.shortest_simple_paths(g, entry, target, weight="weight"), pool_size))
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []

    seen_categories: set[tuple] = set()
    kept_paths: list[list[int]] = []
    for path in raw_paths:
        edge_rules = [
            g.get_edge_data(src, dst, default={}).get("rule_id", "") for src, dst in zip(path, path[1:])
        ]
        fingerprint = _category_fingerprint(path, edge_rules, assets_by_id)
        if fingerprint in seen_categories:
            continue
        seen_categories.add(fingerprint)
        kept_paths.append(path)
        if len(kept_paths) >= limit:
            break

    candidates: list[dict] = []
    import hashlib
    for path in kept_paths:
        # Create a deterministic ID based on the node sequence so simulation 
        # deltas (path comparisons) work even when some paths are removed.
        path_hash = hashlib.md5("-".join(map(str, path)).encode()).hexdigest()[:8].upper()
        path_id = f"PATH-{path_hash}"

        hops: list[dict] = []
        total_weight = 0.0
        total_low = 0
        total_high = 0
        for hop_index, (source, target_id) in enumerate(zip(path, path[1:]), start=1):
            edge = g.get_edge_data(source, target_id, default={})
            total_weight += edge.get("weight", 0.0)
            asset = assets_by_id.get(target_id)
            if asset is None:
                continue
            cve = top_cve(asset)
            hop_low, hop_high = estimate_hop_minutes(cve, edge.get("relationship"), persona)
            total_low += hop_low
            total_high += hop_high
            source_label = "Internet" if source == INTERNET_NODE else asset_label(assets_by_id[source])
            hops.append({
                "step": hop_index,
                "source_id": source,
                "target_id": target_id,
                "source_label": source_label,
                "target_label": asset_label(asset),
                "role": "crown jewel" if asset.is_crown_jewel else (asset.asset_type or "asset"),
                "rule_id": edge.get("rule_id"),
                "rule_name": edge.get("rule_name"),
                "relationship": edge.get("relationship"),
                "rationale": edge.get("rationale"),
                "attack_techniques": edge.get("attack_techniques") or [],
                "evidence": edge.get("evidence") or {},
                "verified_at": edge.get("verified_at"),
                "cve_id": cve.cve_id if cve else None,
                "cvss": cve.cvss_score if cve else None,
                "attack_vector": cve.attack_vector if cve else None,
                "attack_complexity": cve.attack_complexity if cve else None,
                "remediation": cve.remediation if cve else None,
                "estimated_minutes_low": hop_low,
                "estimated_minutes_high": hop_high,
                "estimated_window": format_duration_range(hop_low, hop_high),
            })

        candidates.append({
            "path_id": path_id,
            "asset_sequence": path,
            "sequence_labels": [
                "Internet" if asset_id == INTERNET_NODE else asset_label(assets_by_id[asset_id])
                for asset_id in path
                if asset_id == INTERNET_NODE or asset_id in assets_by_id
            ],
            "total_risk_score": round(
                sum((assets_by_id[asset_id].risk_score or 0.0) for asset_id in path if asset_id in assets_by_id),
                1,
            ),
            "total_weight": round(total_weight, 2),
            "estimated_minutes_low": total_low,
            "estimated_minutes_high": total_high,
            "estimated_window": format_duration_range(total_low, total_high),
            "persona": persona_spec(persona)["label"],
            "hops": hops,
        })
    return candidates


_RULE_FALLBACK_FIX = {
    "CRED-001": "Put {label} behind SSO and MFA, and remove direct internet exposure for login/admin paths.",
    "CONF-001": "Replace the certificate and enforce valid TLS on {label}.",
    "NET-001": "Segment east-west access to {label} and restrict unnecessary service ports.",
    "NET-002": "Reduce public exposure to {label} with allowlists, VPN-only access, or service shutdown.",
    "MISC-001": "Require authentication and IP restriction for the admin surface on {label}.",
    "SHADOW-001": "Remove unmanaged subnet access around {label} or place it behind monitored controls.",
    "DATA-001": "Restrict direct access to crown-jewel system {label} to approved application hosts only.",
    "EXP-002": "Patch or harden local privilege-escalation paths on {label}.",
}


def _fix_for_hop(hop: dict) -> dict:
    target_id = hop["target_id"]
    target_label = hop["target_label"]
    remediation = (hop.get("remediation") or "").strip()
    if remediation:
        summary = remediation.rstrip(".")
        if target_label.lower() not in summary.lower():
            summary = f"{summary} on {target_label}"
        return {
            "key": f"asset:{target_id}:patch",
            "summary": summary + ".",
            "target_id": target_id,
            "rule_id": hop.get("rule_id"),
            "cvss": hop.get("cvss") or 0.0,
        }

    rule_id = hop.get("rule_id")
    template = _RULE_FALLBACK_FIX.get(
        rule_id, "Reduce direct reachability to {label} and harden the exposed service."
    )
    return {
        "key": f"asset:{target_id}:{rule_id or 'control'}",
        "summary": template.format(label=target_label),
        "target_id": target_id,
        "rule_id": rule_id,
        "cvss": hop.get("cvss") or 0.0,
    }


def build_remediation_candidates(paths: list[dict]) -> list[dict]:
    aggregated: dict[str, dict] = {}
    for path in paths:
        seen_keys: set[str] = set()
        for hop in path["hops"]:
            fix = _fix_for_hop(hop)
            key = fix["key"]
            if key in seen_keys:
                continue
            seen_keys.add(key)
            bucket = aggregated.setdefault(key, {
                "summary": fix["summary"],
                "path_ids": set(),
                "hop_indexes": [],
                "target_assets": set(),
                "rule_ids": set(),
                "max_cvss": 0.0,
            })
            bucket["path_ids"].add(path["path_id"])
            bucket["hop_indexes"].append(hop["step"])
            bucket["target_assets"].add(hop["target_label"])
            if hop.get("rule_id"):
                bucket["rule_ids"].add(hop["rule_id"])
            bucket["max_cvss"] = max(bucket["max_cvss"], fix["cvss"])

    candidates: list[dict] = []
    for bucket in aggregated.values():
        candidates.append({
            "summary": bucket["summary"],
            "blocks_paths": len(bucket["path_ids"]),
            "path_ids": sorted(bucket["path_ids"]),
            "avg_hop_index": round(sum(bucket["hop_indexes"]) / len(bucket["hop_indexes"]), 2),
            "target_assets": sorted(bucket["target_assets"]),
            "rule_ids": sorted(bucket["rule_ids"]),
            "max_cvss": bucket["max_cvss"],
        })
    candidates.sort(
        key=lambda item: (-item["blocks_paths"], item["avg_hop_index"], -item["max_cvss"], item["summary"])
    )
    return candidates


def narrate_primary(path: dict) -> str:
    hops: list[str] = []
    hops.append("Step 1: Attacker starts on the public internet.")
    for hop in path["hops"]:
        action = "Objective" if hop["step"] == len(path["hops"]) or hop["role"] == "crown jewel" else (
            "Initial access" if hop["source_id"] == INTERNET_NODE else "Pivot"
        )
        rule_hint = f" using {hop.get('rule_id') or hop.get('relationship') or 'edge'}"
        vuln = f" via {hop['cve_id']} (CVSS {hop['cvss']})" if hop.get("cve_id") else ""
        hops.append(
            f"Step {hop['step'] + 1}: {action} to {hop['target_label']} ({hop['role']}){rule_hint}{vuln}."
        )
    return " ".join(hops)


@dataclass
class PathResult:
    asset_ids: list[int]
    total_risk: float
    narrative: str
    estimated_window: str
    primary_path: dict
    alternates: list[dict] = field(default_factory=list)
    remediations: list[dict] = field(default_factory=list)


def rank_paths(
    scan: Scan,
    g: nx.DiGraph,
    limit: int = 8,
    persona: Optional[str] = None,
) -> Optional[PathResult]:
    paths = build_candidate_paths(scan, g, limit=limit, persona=persona)
    if not paths:
        return None
    primary = paths[0]
    remediations = build_remediation_candidates(paths)
    return PathResult(
        asset_ids=primary["asset_sequence"],
        total_risk=primary["total_risk_score"],
        narrative=narrate_primary(primary),
        estimated_window=primary["estimated_window"],
        primary_path=primary,
        alternates=paths[1:],
        remediations=remediations,
    )


async def validate_and_rerank(
    paths: list[dict],
    assets_by_id: dict[int, Asset],
) -> tuple[list[dict], dict]:
    """Attach validation to every path, re-rank so CONFIRMED > PARTIAL > UNVERIFIED.

    Returns the re-ranked paths plus a summary dict for the WS event payload.
    """
    if not paths:
        return paths, {"confirmed": 0, "partial": 0, "unverified": 0, "total": 0}
    validator = PathValidator(assets_by_id)
    ranked = await validator.validate_paths(paths)
    return ranked, summarize_validations(ranked)


async def rank_paths_validated(
    scan: Scan,
    g: nx.DiGraph,
    limit: int = 8,
    persona: Optional[str] = None,
) -> tuple[Optional[PathResult], dict]:
    paths = build_candidate_paths(scan, g, limit=limit, persona=persona)
    if not paths:
        return None, {"confirmed": 0, "partial": 0, "unverified": 0, "total": 0}
    assets_by_id = {a.id: a for a in scan.assets}
    paths, summary = await validate_and_rerank(paths, assets_by_id)
    primary = paths[0]
    remediations = build_remediation_candidates(paths)
    return PathResult(
        asset_ids=primary["asset_sequence"],
        total_risk=primary["total_risk_score"],
        narrative=narrate_primary(primary),
        estimated_window=primary["estimated_window"],
        primary_path=primary,
        alternates=paths[1:],
        remediations=remediations,
    ), summary


def compute_attack_path(db: Session, scan: Scan, g: nx.DiGraph) -> Optional[PathResult]:
    result = rank_paths(scan, g)
    if result is None:
        top_assets = sorted(scan.assets, key=lambda a: a.risk_score or 0.0, reverse=True)[:4]
        if not top_assets or top_assets[0].risk_score == 0:
            return None
            
        fallback_narrative = (
            "No full end-to-end attack pipeline discovered. "
            "Highlighting highest-risk standalone fragments required for immediate remediation."
        )
        fake_ids = [a.id for a in top_assets]
        fake_risk = sum(a.risk_score or 0.0 for a in top_assets)
        
        hop_fakes = []
        for step, a in enumerate(top_assets, start=1):
            cve = top_cve(a)
            hop_fakes.append({
                "step": step,
                "source_id": INTERNET_NODE,
                "target_id": a.id,
                "source_label": "Isolated Target",
                "target_label": asset_label(a),
                "role": a.asset_type or "asset",
                "relationship": "standalone_exposure",
                "cve_id": cve.cve_id if cve else None,
                "cvss": cve.cvss_score if cve else None,
                "remediation": cve.remediation if cve else None,
                "estimated_window": "N/A"
            })
            
        primary_fake = {
            "asset_sequence": fake_ids,
            "sequence_labels": [asset_label(a) for a in top_assets],
            "hops": hop_fakes,
            "total_risk_score": fake_risk,
            "estimated_window": "N/A"
        }
        
        result = PathResult(
            asset_ids=fake_ids,
            total_risk=fake_risk,
            narrative=fallback_narrative,
            estimated_window="N/A",
            primary_path=primary_fake,
            alternates=[],
            remediations=[]
        )

    db.query(AttackPath).filter(AttackPath.scan_id == scan.id).delete()
    db.add(AttackPath(
        scan_id=scan.id,
        asset_sequence=result.asset_ids,
        total_risk_score=result.total_risk,
        narrative=result.narrative,
    ))
    db.commit()
    return result
