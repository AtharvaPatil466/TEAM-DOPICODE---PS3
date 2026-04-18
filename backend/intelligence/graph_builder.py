"""Build a directed attack graph from scan assets using the named rulebook."""
from dataclasses import dataclass
from typing import Optional

import networkx as nx
from sqlalchemy.orm import Session

from backend.db.models import Asset, GraphEdge, Scan

from .edge_rules import RULES_BY_ID, RuleMatch, evaluate_all

INTERNET_NODE = 0  # reserved virtual node id for "the public internet"


@dataclass
class EdgeSpec:
    source: int
    target: int
    relationship: str
    weight: float
    rule_id: str
    rationale: str
    attack_techniques: list[str]
    evidence: dict


def _edge_weight(target: Asset) -> float:
    """Invert risk so easier / riskier targets are preferred by Dijkstra."""
    return max(1.0, 101.0 - (target.risk_score or 0.0))


def _same_network(a: Asset, b: Asset) -> bool:
    if not a.ip_address or not b.ip_address:
        return False
    return a.ip_address.rsplit(".", 1)[0] == b.ip_address.rsplit(".", 1)[0]


def _subnet_of(asset: Asset) -> str:
    if not asset.ip_address:
        return "unknown"
    prefix = asset.ip_address.rsplit(".", 1)[0]
    return f"{prefix}.0/24"


def _should_consider_pair(src: Optional[Asset], dst: Asset) -> bool:
    if src is None:
        return dst.exposure == "external"
    if src.id == dst.id or dst.exposure != "internal":
        return False
    return bool(dst.ports or dst.cves or dst.admin_panels or dst.is_crown_jewel)


def _rule_context(scan: Scan) -> dict:
    return {
        "scan": scan,
        "same_subnet": _same_network,
        "subnet_of": _subnet_of,
    }


def _effective_weight(target: Asset, match: RuleMatch) -> float:
    return round(max(0.5, _edge_weight(target) * match.weight_modifier), 2)


def _pick_rule(src: Optional[Asset], dst: Asset, ctx: dict) -> RuleMatch | None:
    matches = evaluate_all(src, dst, ctx)
    if not matches:
        return None
    return min(matches, key=lambda match: (_effective_weight(dst, match), match.rule_id))


def build_edges(scan: Scan) -> list[EdgeSpec]:
    edges: list[EdgeSpec] = []
    assets = list(scan.assets)
    ctx = _rule_context(scan)

    for dst in assets:
        if not _should_consider_pair(None, dst):
            continue
        match = _pick_rule(None, dst, ctx)
        if match is None:
            continue
        edges.append(EdgeSpec(
            source=INTERNET_NODE,
            target=dst.id,
            relationship=match.relationship,
            weight=_effective_weight(dst, match),
            rule_id=match.rule_id,
            rationale=match.rationale,
            attack_techniques=list(match.attack_techniques),
            evidence=dict(match.evidence),
        ))

    for src in assets:
        for dst in assets:
            if not _should_consider_pair(src, dst):
                continue
            match = _pick_rule(src, dst, ctx)
            if match is None:
                continue
            edges.append(EdgeSpec(
                source=src.id,
                target=dst.id,
                relationship=match.relationship,
                weight=_effective_weight(dst, match),
                rule_id=match.rule_id,
                rationale=match.rationale,
                attack_techniques=list(match.attack_techniques),
                evidence=dict(match.evidence),
            ))
    return edges


def persist_edges(db: Session, scan: Scan, edges: list[EdgeSpec]) -> None:
    db.query(GraphEdge).filter(GraphEdge.scan_id == scan.id).delete()
    for edge in edges:
        db.add(GraphEdge(
            scan_id=scan.id,
            source_id=edge.source,
            target_id=edge.target,
            relationship_type=edge.relationship,
            weight=edge.weight,
            rule_id=edge.rule_id,
            rationale=edge.rationale,
            attack_techniques=edge.attack_techniques,
            evidence=edge.evidence,
        ))
    db.commit()


def to_networkx(scan: Scan, edges: list[EdgeSpec]) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_node(INTERNET_NODE, label="Internet", is_virtual=True)
    for asset in scan.assets:
        graph.add_node(
            asset.id,
            label=asset.hostname or asset.ip_address or f"asset-{asset.id}",
            risk_score=asset.risk_score,
            asset_type=asset.asset_type,
            is_crown_jewel=asset.is_crown_jewel,
        )
    for edge in edges:
        graph.add_edge(
            edge.source,
            edge.target,
            weight=edge.weight,
            relationship=edge.relationship,
            rule_id=edge.rule_id,
            rule_name=RULES_BY_ID[edge.rule_id].name if edge.rule_id in RULES_BY_ID else edge.rule_id,
            rationale=edge.rationale,
            attack_techniques=edge.attack_techniques,
            evidence=edge.evidence,
        )
    return graph
