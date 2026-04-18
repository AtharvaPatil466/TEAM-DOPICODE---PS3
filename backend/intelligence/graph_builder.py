"""Build a directed reachability graph from scan assets.

Nodes = assets. Edges = one asset can reach another on an open port.
External-facing assets always have an implicit edge from a virtual INTERNET
node so attack paths can start from "the public internet".
"""
from dataclasses import dataclass

import networkx as nx
from sqlalchemy.orm import Session

from backend.db.models import Asset, GraphEdge, Scan

INTERNET_NODE = 0  # reserved virtual node id for "the public internet"


@dataclass
class EdgeSpec:
    source: int
    target: int
    relationship: str
    weight: float


def _edge_weight(target: Asset) -> float:
    """Dijkstra wants small = preferable. We want the path with highest
    exploitability to be shortest, so invert risk: weight = 101 - risk."""
    return max(1.0, 101.0 - (target.risk_score or 0.0))


def _same_network(a: Asset, b: Asset) -> bool:
    """Cheap approximation: same /24 = mutually reachable."""
    if not a.ip_address or not b.ip_address:
        return False
    return a.ip_address.rsplit(".", 1)[0] == b.ip_address.rsplit(".", 1)[0]


def build_edges(scan: Scan) -> list[EdgeSpec]:
    edges: list[EdgeSpec] = []
    assets = list(scan.assets)

    for a in assets:
        if a.exposure == "external":
            edges.append(EdgeSpec(
                source=INTERNET_NODE,
                target=a.id,
                relationship="internet_reachable",
                weight=_edge_weight(a),
            ))

    for a in assets:
        for b in assets:
            if a.id == b.id:
                continue
            if not b.ports:
                continue
            if a.exposure == "external" and b.exposure == "internal" and _same_network(a, b):
                edges.append(EdgeSpec(a.id, b.id, "pivot_internal", _edge_weight(b)))
            elif a.exposure == "internal" and b.exposure == "internal" and _same_network(a, b):
                edges.append(EdgeSpec(a.id, b.id, "lateral", _edge_weight(b)))
    return edges


def persist_edges(db: Session, scan: Scan, edges: list[EdgeSpec]) -> None:
    db.query(GraphEdge).filter(GraphEdge.scan_id == scan.id).delete()
    for e in edges:
        db.add(GraphEdge(
            scan_id=scan.id,
            source_id=e.source,
            target_id=e.target,
            relationship_type=e.relationship,
            weight=e.weight,
        ))
    db.commit()


def to_networkx(scan: Scan, edges: list[EdgeSpec]) -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node(INTERNET_NODE, label="Internet", is_virtual=True)
    for a in scan.assets:
        g.add_node(
            a.id,
            label=a.hostname or a.ip_address or f"asset-{a.id}",
            risk_score=a.risk_score,
            asset_type=a.asset_type,
            is_crown_jewel=a.is_crown_jewel,
        )
    for e in edges:
        g.add_edge(e.source, e.target, weight=e.weight, relationship=e.relationship)
    return g
