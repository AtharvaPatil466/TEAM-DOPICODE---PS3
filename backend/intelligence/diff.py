"""Scan-to-scan diff.

Compares two persisted scans and reports what an operator would want to see on
the stand: which assets appeared/disappeared, which graph edges were broken or
introduced, which attack paths stopped working, and how total risk shifted.
"""
from dataclasses import dataclass
from typing import Optional

from backend.db.models import Scan

from .attack_path import rank_paths, PathResult
from .graph_builder import build_edges, to_networkx


def _asset_key(asset) -> str:
    return asset.hostname or asset.ip_address or f"asset-{asset.id}"


def _edge_key(edge) -> tuple[str, str, str]:
    return (str(edge.source_id), str(edge.target_id), edge.relationship_type or "")


@dataclass
class ScanDiff:
    before_id: int
    after_id: int
    assets_added: list[dict]
    assets_removed: list[dict]
    edges_added: list[dict]
    edges_removed: list[dict]
    paths_broken: list[str]
    paths_introduced: list[str]
    risk_delta: float
    time_to_breach_delta_minutes: Optional[int]
    summary: str


def _asset_snapshot(asset) -> dict:
    return {
        "id": asset.id,
        "label": _asset_key(asset),
        "risk_score": asset.risk_score,
        "exposure": asset.exposure,
        "asset_type": asset.asset_type,
    }


def _edge_snapshot(edge, asset_label_by_id: dict[int, str]) -> dict:
    return {
        "source": asset_label_by_id.get(edge.source_id, "Internet" if edge.source_id == 0 else f"asset-{edge.source_id}"),
        "target": asset_label_by_id.get(edge.target_id, f"asset-{edge.target_id}"),
        "relationship": edge.relationship_type,
        "rule_id": edge.rule_id,
    }


def _path_midpoint(result: Optional[PathResult]) -> Optional[int]:
    if result is None:
        return None
    p = result.primary_path
    return (p["estimated_minutes_low"] + p["estimated_minutes_high"]) // 2


def _path_id_set(result: Optional[PathResult]) -> set[str]:
    if result is None:
        return set()
    ids = {result.primary_path["path_id"]}
    ids.update(path["path_id"] for path in result.alternates)
    return ids


def compute_diff(before: Scan, after: Scan) -> ScanDiff:
    before_assets = {_asset_key(a): a for a in before.assets}
    after_assets = {_asset_key(a): a for a in after.assets}

    added_labels = sorted(set(after_assets) - set(before_assets))
    removed_labels = sorted(set(before_assets) - set(after_assets))
    assets_added = [_asset_snapshot(after_assets[label]) for label in added_labels]
    assets_removed = [_asset_snapshot(before_assets[label]) for label in removed_labels]

    before_label_by_id = {a.id: _asset_key(a) for a in before.assets}
    after_label_by_id = {a.id: _asset_key(a) for a in after.assets}

    before_edges = {_edge_key(e): e for e in before.edges}
    after_edges = {_edge_key(e): e for e in after.edges}
    edges_added = [
        _edge_snapshot(after_edges[k], after_label_by_id) for k in sorted(set(after_edges) - set(before_edges))
    ]
    edges_removed = [
        _edge_snapshot(before_edges[k], before_label_by_id) for k in sorted(set(before_edges) - set(after_edges))
    ]

    before_result = rank_paths(before, to_networkx(before, build_edges(before)))
    after_result = rank_paths(after, to_networkx(after, build_edges(after)))
    broken = sorted(_path_id_set(before_result) - _path_id_set(after_result))
    introduced = sorted(_path_id_set(after_result) - _path_id_set(before_result))

    before_risk = sum((a.risk_score or 0) for a in before.assets)
    after_risk = sum((a.risk_score or 0) for a in after.assets)
    risk_delta = round(after_risk - before_risk, 1)

    before_mid = _path_midpoint(before_result)
    after_mid = _path_midpoint(after_result)
    time_delta = None
    if before_mid is not None and after_mid is not None:
        time_delta = after_mid - before_mid

    parts: list[str] = []
    if assets_added or assets_removed:
        parts.append(f"assets +{len(assets_added)} / -{len(assets_removed)}")
    if edges_added or edges_removed:
        parts.append(f"edges +{len(edges_added)} / -{len(edges_removed)}")
    if broken:
        parts.append(f"{len(broken)} path(s) blocked")
    if introduced:
        parts.append(f"{len(introduced)} new path(s) appeared")
    if time_delta is not None and time_delta != 0:
        direction = "slower" if time_delta > 0 else "faster"
        parts.append(f"time-to-breach {abs(time_delta)} min {direction}")
    if risk_delta:
        parts.append(f"total risk {risk_delta:+.1f}")
    summary = "; ".join(parts) or "No material change between scans."

    return ScanDiff(
        before_id=before.id,
        after_id=after.id,
        assets_added=assets_added,
        assets_removed=assets_removed,
        edges_added=edges_added,
        edges_removed=edges_removed,
        paths_broken=broken,
        paths_introduced=introduced,
        risk_delta=risk_delta,
        time_to_breach_delta_minutes=time_delta,
        summary=summary,
    )
