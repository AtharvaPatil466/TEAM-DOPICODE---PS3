"""Compute highest-risk attack path via Dijkstra on inverted-risk weights."""
from dataclasses import dataclass

import networkx as nx
from sqlalchemy.orm import Session

from backend.db.models import Asset, AttackPath, Scan

from .graph_builder import INTERNET_NODE


@dataclass
class PathResult:
    asset_ids: list[int]
    total_risk: float
    narrative: str


def _pick_entry_and_target(g: nx.DiGraph, scan: Scan) -> tuple[int | None, int | None]:
    # Entry: virtual Internet if it has outgoing edges, else highest-risk external.
    entry: int | None = None
    if g.out_degree(INTERNET_NODE) > 0:
        entry = INTERNET_NODE
    else:
        externals = [a for a in scan.assets if a.exposure == "external"]
        if externals:
            entry = max(externals, key=lambda a: a.risk_score or 0).id

    # Target: highest-risk crown jewel, else highest-risk internal asset.
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


def _narrate(scan: Scan, g: nx.DiGraph, path: list[int]) -> str:
    by_id = {a.id: a for a in scan.assets}
    hops: list[str] = []
    for i, aid in enumerate(path):
        if aid == INTERNET_NODE:
            hops.append("Step 1: Attacker starts on the public internet.")
            continue
        a = by_id.get(aid)
        if a is None:
            continue
        label = a.hostname or a.ip_address or f"asset-{aid}"
        top_cve = max(a.cves, key=lambda c: c.cvss_score or 0, default=None)
        vuln = f" via {top_cve.cve_id} (CVSS {top_cve.cvss_score})" if top_cve else ""
        role = "crown jewel" if a.is_crown_jewel else a.asset_type or "asset"
        prev = path[i - 1] if i > 0 else None
        edge = g.get_edge_data(prev, aid, default={}) if prev is not None else {}
        rule_id = edge.get("rule_id")
        relationship = edge.get("relationship")
        if prev == INTERNET_NODE and i == len(path) - 1:
            action = "Objective"
        elif prev == INTERNET_NODE:
            action = "Initial access"
        elif a.is_crown_jewel or i == len(path) - 1:
            action = "Objective"
        else:
            action = "Pivot"
        rule_hint = f" using {rule_id}" if rule_id else (f" using {relationship}" if relationship else "")
        hops.append(f"Step {len(hops) + 1}: {action} to {label} ({role}){rule_hint}{vuln}.")
    return " ".join(hops)


def compute_attack_path(db: Session, scan: Scan, g: nx.DiGraph) -> PathResult | None:
    entry, target = _pick_entry_and_target(g, scan)
    if entry is None or target is None or entry == target:
        return None
    if entry not in g or target not in g:
        return None
    try:
        path = nx.dijkstra_path(g, entry, target, weight="weight")
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return None

    by_id = {a.id: a for a in scan.assets}
    total_risk = sum((by_id[aid].risk_score or 0.0) for aid in path if aid in by_id)
    narrative = _narrate(scan, g, path)

    result = PathResult(asset_ids=path, total_risk=round(total_risk, 1), narrative=narrative)

    db.query(AttackPath).filter(AttackPath.scan_id == scan.id).delete()
    db.add(AttackPath(
        scan_id=scan.id,
        asset_sequence=path,
        total_risk_score=result.total_risk,
        narrative=narrative,
    ))
    db.commit()
    return result
