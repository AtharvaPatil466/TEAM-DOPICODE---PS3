"""Replay a cached scan over the websocket bus with deterministic timing."""
from __future__ import annotations

import asyncio

from sqlalchemy.orm import selectinload

from backend.api.events import bus
from backend.db import SessionLocal
from backend.db.models import Asset, AttackPath, Scan, ImpactReport

_REPLAY_LOCK = asyncio.Lock()
_REPLAY_DELAY_SECONDS = 0.16
_HOST_ORDER = {
    "www": 10,
    "api": 20,
    "staging": 30,
    "dev": 40,
    "admin": 50,
    "legacy": 60,
    "backup": 70,
    "mail": 80,
    "ci": 90,
    "internal": 100,
}


def _label(asset: Asset) -> str:
    return asset.hostname or asset.ip_address or f"asset-{asset.id}"


def _host_sort_key(asset: Asset) -> tuple[int, str]:
    if asset.asset_type == "storage":
        return (999, _label(asset))
    host = asset.hostname or ""
    prefix = host.split(".", 1)[0].lower() if "." in host else host.lower()
    return (_HOST_ORDER.get(prefix, 500), _label(asset))


def _tech_names(asset: Asset) -> list[str]:
    techs = (asset.tech_stack or {}).get("technologies") or []
    return [tech.get("name") for tech in techs if tech.get("name")]


async def _pause() -> None:
    await asyncio.sleep(_REPLAY_DELAY_SECONDS)


async def _publish_progress(scan_id: int, phase: str, percent: int, **payload: object) -> None:
    body = {"phase": phase, "percent": percent}
    body.update(payload)
    await bus.publish("progress", body, scan_id)


async def replay_scan(scan_id: int) -> bool:
    async with _REPLAY_LOCK:
        db = SessionLocal()
        try:
            scan = (
                db.query(Scan)
                .options(
                    selectinload(Scan.assets).selectinload(Asset.ports),
                    selectinload(Scan.assets).selectinload(Asset.cves),
                    selectinload(Scan.paths),
                    selectinload(Scan.impact_reports),
                )
                .filter(Scan.id == scan_id)
                .first()
            )
            if scan is None:
                return False

            external_assets = sorted(
                [asset for asset in scan.assets if asset.exposure == "external"],
                key=_host_sort_key,
            )
            internal_assets = sorted(
                [asset for asset in scan.assets if asset.exposure == "internal"],
                key=_host_sort_key,
            )
            subdomain_assets = [asset for asset in external_assets if asset.asset_type != "storage"]
            storage_assets = [asset for asset in external_assets if asset.asset_type == "storage"]
            best_path = max(scan.paths, key=lambda path: path.total_risk_score, default=None)

            await bus.reset_history()
            await bus.publish("scan_started", {
                "domain": scan.target_domain,
                "subnet": scan.target_subnet,
                "cached": True,
                "internal_scope": bool(internal_assets),
            }, scan.id)
            await _pause()

            await _publish_progress(scan.id, "subdomain_enum", 10, found=len(subdomain_assets))
            await _pause()

            total_external = max(len(subdomain_assets), 1)
            for index, asset in enumerate(subdomain_assets, start=1):
                percent = 18 + int(28 * index / total_external)
                await _publish_progress(scan.id, "live_prober", percent, asset=_label(asset))
                await bus.publish("host_discovered", {
                    "asset_id": asset.id,
                    "hostname": asset.hostname,
                    "ip": asset.ip_address,
                    "asset_type": asset.asset_type,
                    "exposure": asset.exposure,
                    "risk_score": asset.risk_score,
                    "tech": _tech_names(asset),
                }, scan.id)
                for cve in sorted(asset.cves, key=lambda item: item.cvss_score or 0, reverse=True):
                    await bus.publish("cve_found", {
                        "asset_id": asset.id,
                        "cve_id": cve.cve_id,
                        "cvss": cve.cvss_score,
                    }, scan.id)
                await _pause()

            if storage_assets:
                await _publish_progress(scan.id, "cloud_bucket", 52, found=len(storage_assets))
                for asset in storage_assets:
                    bucket_name = (asset.tech_stack or {}).get("bucket_name") or asset.hostname
                    await bus.publish("host_discovered", {
                        "asset_id": asset.id,
                        "hostname": asset.hostname,
                        "asset_type": asset.asset_type,
                        "exposure": asset.exposure,
                        "risk_score": asset.risk_score,
                        "tech": [bucket_name],
                    }, scan.id)
                    await bus.publish("cloud_bucket_found", {
                        "asset_id": asset.id,
                        "url": (asset.tech_stack or {}).get("url") or asset.hostname,
                        "provider": (asset.tech_stack or {}).get("provider", "aws"),
                        "public": True,
                        "sample_files": (asset.tech_stack or {}).get("sample_files", []),
                    }, scan.id)
                    await _pause()

            if external_assets:
                await _publish_progress(scan.id, "ssl_analyzer", 60, checked=len(external_assets))
                await _pause()

            if internal_assets:
                total_internal = max(len(internal_assets), 1)
                for index, asset in enumerate(internal_assets, start=1):
                    percent = 62 + int(22 * index / total_internal)
                    await _publish_progress(scan.id, "internal_projection", percent, asset=_label(asset))
                    await bus.publish("host_discovered", {
                        "asset_id": asset.id,
                        "hostname": asset.hostname,
                        "ip": asset.ip_address,
                        "asset_type": asset.asset_type,
                        "exposure": asset.exposure,
                        "is_crown_jewel": asset.is_crown_jewel,
                        "risk_score": asset.risk_score,
                    }, scan.id)
                    for port in asset.ports:
                        await bus.publish("port_open", {
                            "asset_id": asset.id,
                            "ip": asset.ip_address,
                            "port": port.port_number,
                            "service": port.service_name,
                            "version": port.service_version,
                        }, scan.id)
                    for cve in sorted(asset.cves, key=lambda item: item.cvss_score or 0, reverse=True):
                        await bus.publish("cve_found", {
                            "asset_id": asset.id,
                            "cve_id": cve.cve_id,
                            "cvss": cve.cvss_score,
                        }, scan.id)
                    await _pause()

            await _publish_progress(scan.id, "graph_reasoning", 90)
            await _pause()

            if best_path is not None:
                await bus.publish("attack_path_computed", {
                    "asset_sequence": best_path.asset_sequence,
                    "total_risk_score": best_path.total_risk_score,
                    "narrative": best_path.narrative,
                }, scan.id)
                await _pause()

            report = max(scan.impact_reports, key=lambda r: r.id, default=None)
            if report is not None:
                await bus.publish("impact_computed", {
                    "total_exposure_min": report.total_exposure_min_inr,
                    "total_exposure_max": report.total_exposure_max_inr,
                    "scenario_count": len(report.scenario_matrix or []),
                    "top_scenario": report.scenario_matrix[0]["name"] if report.scenario_matrix else "None",
                }, scan.id)
                await _pause()

            await _publish_progress(scan.id, "completed", 100)
            await bus.publish("scan_completed", {
                "total_assets": scan.total_assets,
                "total_cves": scan.total_cves,
                "cached": True,
                "internal_scope": bool(internal_assets),
            }, scan.id)
            return True
        finally:
            db.close()
