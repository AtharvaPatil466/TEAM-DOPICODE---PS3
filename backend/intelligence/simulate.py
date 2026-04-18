"""What-if remediation simulator.

Builds a read-only view of a Scan with certain assets and/or CVEs stripped,
then reuses the existing rulebook + path ranker to show how the attack graph
collapses when proposed fixes land. The view never touches the DB.
"""
from dataclasses import dataclass
from typing import Iterable, Optional

from backend.db.models import Asset, Scan

from .attack_path import rank_paths, PathResult
from .graph_builder import build_edges, to_networkx


class _AssetView:
    def __init__(self, asset: Asset, patched_cves: set[str]):
        self._asset = asset
        self._patched = patched_cves

    def __getattr__(self, name: str):
        return getattr(self._asset, name)

    @property
    def cves(self):
        return [cve for cve in self._asset.cves if cve.cve_id not in self._patched]


class _ScanView:
    def __init__(self, scan: Scan, patched_asset_ids: set[int], patched_cves: set[str]):
        self._scan = scan
        self._patched_assets = patched_asset_ids
        self._patched_cves = patched_cves

    def __getattr__(self, name: str):
        return getattr(self._scan, name)

    @property
    def assets(self):
        return [
            _AssetView(asset, self._patched_cves)
            for asset in self._scan.assets
            if asset.id not in self._patched_assets
        ]


@dataclass
class SimulationDelta:
    baseline: Optional[PathResult]
    simulated: Optional[PathResult]
    blocked_path_ids: list[str]
    introduced_path_ids: list[str]
    time_to_breach_delta_minutes: Optional[int]
    summary: str


def _path_id_set(result: Optional[PathResult]) -> set[str]:
    if result is None:
        return set()
    ids = {result.primary_path["path_id"]}
    ids.update(path["path_id"] for path in result.alternates)
    return ids


def _time_to_breach_midpoint(result: Optional[PathResult]) -> Optional[int]:
    if result is None:
        return None
    primary = result.primary_path
    return (primary["estimated_minutes_low"] + primary["estimated_minutes_high"]) // 2


def simulate_remediation(
    scan: Scan,
    patched_asset_ids: Iterable[int],
    patched_cve_ids: Iterable[str],
    persona: Optional[str] = None,
) -> SimulationDelta:
    baseline_edges = build_edges(scan)
    baseline_graph = to_networkx(scan, baseline_edges)
    baseline = rank_paths(scan, baseline_graph, persona=persona)

    view = _ScanView(scan, set(patched_asset_ids), {cve.upper() for cve in patched_cve_ids})
    sim_edges = build_edges(view)
    sim_graph = to_networkx(view, sim_edges)
    simulated = rank_paths(view, sim_graph, persona=persona)

    baseline_ids = _path_id_set(baseline)
    simulated_ids = _path_id_set(simulated)
    blocked = sorted(baseline_ids - simulated_ids)
    introduced = sorted(simulated_ids - baseline_ids)

    baseline_midpoint = _time_to_breach_midpoint(baseline)
    simulated_midpoint = _time_to_breach_midpoint(simulated)
    delta_minutes = None
    if baseline_midpoint is not None and simulated_midpoint is not None:
        delta_minutes = simulated_midpoint - baseline_midpoint
    elif baseline_midpoint is not None and simulated is None:
        delta_minutes = None  # infinite — all paths closed

    if baseline is None:
        summary = "No baseline attack path exists — nothing to simulate against."
    elif simulated is None:
        summary = (
            f"Proposed remediation closes every modeled attack path ({len(baseline_ids)} eliminated). "
            "Crown-jewel is unreachable under the new evidence set."
        )
    elif not blocked and delta_minutes is not None and delta_minutes <= 0:
        summary = (
            "Proposed remediation did not break any modeled path. "
            "Consider a higher-leverage fix from the /attack-path remediation candidates."
        )
    else:
        parts = []
        if blocked:
            parts.append(f"{len(blocked)} path(s) blocked: {', '.join(blocked)}")
        if introduced:
            parts.append(f"{len(introduced)} new path(s) surfaced: {', '.join(introduced)}")
        if delta_minutes is not None:
            direction = "slower" if delta_minutes > 0 else "faster"
            parts.append(f"primary time-to-breach shifts {abs(delta_minutes)} min {direction}")
        summary = "; ".join(parts) or "No meaningful change."

    return SimulationDelta(
        baseline=baseline,
        simulated=simulated,
        blocked_path_ids=blocked,
        introduced_path_ids=introduced,
        time_to_breach_delta_minutes=delta_minutes,
        summary=summary,
    )
