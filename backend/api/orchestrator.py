"""Scan job orchestrator. Runs the full pipeline and emits live events."""
import asyncio
import logging
from datetime import datetime
from ipaddress import ip_address, ip_network

from sqlalchemy.orm import Session

from backend.config import LAB_CROWN_JEWEL, LAB_ENTRY_HOST, SCAN_IGNORE_IPS
from backend.db import SessionLocal
from backend.db.models import Asset, AttackPath, CVE, Port, Scan
from backend.api.events import bus

from backend.scanner.subdomain import enumerate_subdomains
from backend.scanner.live_prober import LiveHost, probe_hosts
from backend.scanner.tech_fingerprint import fingerprint
from backend.scanner.admin_panel import detect_admin_panels
from backend.scanner.cloud_buckets import check_buckets
from backend.scanner.ssl_analyzer import analyze_batch
from backend.scanner import nmap_scanner

from backend.intelligence.cve_fetcher import fetch_cves
from backend.intelligence.risk_scorer import RiskInput, score as risk_score
from backend.intelligence.graph_builder import build_edges, persist_edges, to_networkx
from backend.intelligence.attack_path import rank_paths_validated
from backend.intelligence.anomaly import get_detector

log = logging.getLogger(__name__)


async def _emit_progress(scan_id: int, db: Session, scan: Scan, phase: str, pct: int) -> None:
    scan.progress = pct
    db.commit()
    await bus.publish("progress", {"phase": phase, "percent": pct}, scan_id)


async def _external_phase(db: Session, scan: Scan) -> list[Asset]:
    scan_id = scan.id
    domain = scan.target_domain

    await _emit_progress(scan_id, db, scan, "subdomain_enum", 5)
    subs = await enumerate_subdomains(domain)
    await bus.publish("progress", {"phase": "subdomain_enum", "found": len(subs)}, scan_id)

    await _emit_progress(scan_id, db, scan, "live_prober", 15)
    live: list[LiveHost] = await probe_hosts(subs)

    await _emit_progress(scan_id, db, scan, "admin_panel", 25)
    admin_hits = await detect_admin_panels(live)
    admin_by_host: dict[str, list[dict]] = {}
    for h in admin_hits:
        admin_by_host.setdefault(h.host, []).append({
            "path": h.path, "status": h.status_code, "auth": h.requires_auth,
        })

    await _emit_progress(scan_id, db, scan, "cloud_bucket", 35)
    buckets = await check_buckets(domain)
    for b in buckets:
        await bus.publish("cloud_bucket_found", {
            "url": b.url, "provider": b.provider, "public": b.public,
        }, scan_id)

    await _emit_progress(scan_id, db, scan, "ssl_analyzer", 40)
    https_hosts = [h.host for h in live if h.is_https()]
    ssl_results = await analyze_batch(https_hosts) if https_hosts else []
    ssl_by_host = {s.host: s for s in ssl_results}

    assets: list[Asset] = []
    for h in live:
        fp = fingerprint(h, h.body)
        ssl_info = ssl_by_host.get(h.host)
        ssl_dict = None
        ssl_broken = False
        if ssl_info is not None:
            ssl_dict = {
                "issuer": ssl_info.issuer,
                "not_after": ssl_info.not_after,
                "days_to_expiry": ssl_info.days_to_expiry,
                "hostname_match": ssl_info.hostname_match,
                "self_signed": ssl_info.self_signed,
                "expired": ssl_info.expired,
                "expiring_soon": ssl_info.expiring_soon,
                "error": ssl_info.error,
            }
            ssl_broken = ssl_info.expired or not ssl_info.hostname_match

        asset = Asset(
            scan_id=scan_id,
            hostname=h.host,
            ip_address=None,
            asset_type="web",
            os_guess=None,
            risk_score=0.0,
            exposure="external",
            tech_stack={
                "technologies": fp.technologies,
                "server": fp.server,
                "powered_by": fp.powered_by,
            },
            admin_panels=admin_by_host.get(h.host, []),
            ssl_info=ssl_dict,
        )
        db.add(asset)
        db.flush()
        assets.append(asset)
        await bus.publish("host_discovered", {
            "asset_id": asset.id,
            "hostname": h.host,
            "exposure": "external",
            "tech": fp.names(),
        }, scan_id)

        # Try to lookup CVEs based on fingerprinted server+version.
        top_tech = next((t for t in fp.technologies if "version" in t), None)
        if top_tech:
            await _attach_cves(db, asset, top_tech["name"], top_tech.get("version"))

        # Risk
        max_cvss = max((c.cvss_score or 0 for c in asset.cves), default=0.0)
        asset.risk_score = risk_score(RiskInput(
            open_port_count=0,
            max_cvss=max_cvss,
            cve_count=len(asset.cves),
            admin_panel_exposed=bool(asset.admin_panels),
            internet_facing=True,
            ssl_broken=ssl_broken,
            self_signed=bool(ssl_info and ssl_info.self_signed),
            expired_cert=bool(ssl_info and ssl_info.expired),
        ))
        db.commit()

    if len(live) < 5:
        log.info("Sparse results, firing crt.sh fallback for %s", domain)
        from backend.scanner.subdomain import _crtsh
        crt_subs = await _crtsh(domain)
        live_hostnames = {h.host for h in live}
        dormant = [h for h in crt_subs if h not in live_hostnames][:15]
        for d in dormant:
            asset = Asset(
                scan_id=scan_id,
                hostname=d,
                asset_type="internet",
                exposure="external",
                risk_score=0.0,
                tech_stack={
                    "status": "potentially_dormant",
                    "issue_summary": "Historical asset from Certificate Transparency logs. Status unknown."
                }
            )
            db.add(asset)
            db.flush()
            assets.append(asset)
            await bus.publish("host_discovered", {
                "asset_id": asset.id,
                "hostname": d,
                "exposure": "external",
                "tech": ["dormant"],
            }, scan_id)
        db.commit()

    return assets


def _own_ips() -> set[str]:
    """Best-effort detection of the scanner's own addresses so we don't treat
    them as discovered targets. Works both on bare-metal and inside a container
    on a shared docker network."""
    import socket
    ips: set[str] = set()
    try:
        ips.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except Exception:
        pass
    return ips


def _filter_discovered_hosts(hosts: list[str]) -> list[str]:
    ignore = SCAN_IGNORE_IPS | _own_ips()
    return [h for h in hosts if h not in ignore]


async def _internal_phase(db: Session, scan: Scan) -> list[Asset]:
    scan_id = scan.id
    subnet = scan.target_subnet
    if not subnet:
        return []

    await _emit_progress(scan_id, db, scan, "nmap_host_discovery", 55)
    try:
        hosts = await asyncio.to_thread(nmap_scanner.discover_hosts, subnet)
    except Exception as e:
        log.warning("nmap discovery failed: %s", e)
        hosts = []
    hosts = _filter_discovered_hosts(hosts)
    await bus.publish("progress", {"phase": "nmap_host_discovery", "found": len(hosts)}, scan_id)

    crown_ip = LAB_CROWN_JEWEL
    try:
        crown_net = ip_network(subnet, strict=False)
        crown_addr = ip_address(crown_ip)
        is_crown_in_range = crown_addr in crown_net
    except ValueError:
        is_crown_in_range = False

    assets: list[Asset] = []
    total = max(len(hosts), 1)
    for i, ip in enumerate(hosts):
        pct = 55 + int(25 * (i + 1) / total)
        await _emit_progress(scan_id, db, scan, f"nmap_scan:{ip}", pct)
        try:
            host = await asyncio.to_thread(nmap_scanner.scan_host, ip)
        except Exception as e:
            log.warning("nmap scan_host %s failed: %s", ip, e)
            continue

        is_crown = is_crown_in_range and ip == crown_ip
        is_gateway = ip == LAB_ENTRY_HOST
        tech_stack = None
        if is_gateway:
            tech_stack = {
                "internet_exposed": True,
                "exposure_hint": f"lab_entry_host:{LAB_ENTRY_HOST}",
                "issue": "perimeter_rce",
                "issue_summary": f"{ip} is the configured lab perimeter gateway and was reachable from the scanner host.",
                "remediation_summary": "Restrict inbound access, patch the exposed service, and place it behind an authenticated reverse proxy.",
            }
        asset = Asset(
            scan_id=scan_id,
            hostname=host.hostname,
            ip_address=ip,
            asset_type="db" if is_crown else _infer_asset_type(host.ports, host.os_guess),
            os_guess=host.os_guess,
            exposure="internal",
            is_crown_jewel=is_crown,
            tech_stack=tech_stack,
            risk_score=0.0,
        )
        db.add(asset)
        db.flush()

        for p in host.ports:
            if p.get("state") != "open":
                continue
            service = p.get("service")
            version = p.get("version")
            if service == "redis" and not version:
                version = await asyncio.to_thread(_probe_redis_version, ip, p["port"])
            db.add(Port(
                asset_id=asset.id,
                port_number=p["port"],
                protocol=p.get("protocol", "tcp"),
                service_name=service,
                service_version=version,
                state=p.get("state", "open"),
            ))
            await bus.publish("port_open", {
                "asset_id": asset.id,
                "ip": ip,
                "port": p["port"],
                "service": p.get("service"),
                "version": p.get("version"),
            }, scan_id)
        db.commit()
        db.refresh(asset)

        await _emit_progress(scan_id, db, scan, f"cve_lookup:{ip}", pct)
        for port in asset.ports:
            if port.service_name and port.service_version:
                await _attach_cves(db, asset, port.service_name, port.service_version)

        max_cvss = max((c.cvss_score or 0 for c in asset.cves), default=0.0)
        asset.risk_score = risk_score(RiskInput(
            open_port_count=len(asset.ports),
            max_cvss=max_cvss,
            cve_count=len(asset.cves),
            admin_panel_exposed=False,
            internet_facing=False,
        ))
        db.commit()
        assets.append(asset)
        await bus.publish("host_discovered", {
            "asset_id": asset.id,
            "ip": ip,
            "exposure": "internal",
            "is_crown_jewel": is_crown,
            "risk_score": asset.risk_score,
        }, scan_id)
    return assets


def _probe_redis_version(ip: str, port: int = 6379, timeout: float = 1.5) -> str | None:
    """nmap's -sV often misses Redis versions; the INFO command returns one line
    with redis_version:X.Y.Z which we read directly."""
    import socket
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.sendall(b"*1\r\n$4\r\nINFO\r\n")
            sock.settimeout(timeout)
            buf = b""
            while b"redis_version:" not in buf and len(buf) < 4096:
                chunk = sock.recv(2048)
                if not chunk:
                    break
                buf += chunk
    except OSError:
        return None
    marker = b"redis_version:"
    idx = buf.find(marker)
    if idx < 0:
        return None
    end = buf.find(b"\r\n", idx)
    if end < 0:
        return None
    return buf[idx + len(marker):end].decode("ascii", errors="ignore").strip() or None


def _infer_asset_type(ports: list[dict], os_guess: str | None) -> str:
    port_set = {p["port"] for p in ports if p.get("state") == "open"}
    if port_set & {3306, 5432, 27017, 6379, 9200}:
        return "db"
    if port_set & {80, 443, 8080, 8443}:
        return "web"
    if port_set & {22, 23}:
        return "workstation"
    if os_guess and "iot" in os_guess.lower():
        return "iot"
    return "unknown"


async def _attach_cves(db: Session, asset: Asset, product: str, version: str | None) -> None:
    try:
        recs = await fetch_cves(db, product, version)
    except Exception as e:
        log.warning("CVE fetch failed for %s %s: %s", product, version, e)
        return
    for r in recs:
        if any(c.cve_id == r.cve_id for c in asset.cves):
            continue
        db.add(CVE(
            asset_id=asset.id,
            cve_id=r.cve_id,
            description=r.description,
            cvss_score=r.cvss_score,
            attack_vector=r.attack_vector,
            attack_complexity=r.attack_complexity,
            remediation=r.remediation,
        ))
        await bus.publish("cve_found", {
            "asset_id": asset.id,
            "cve_id": r.cve_id,
            "cvss": r.cvss_score,
        }, asset.scan_id)
    db.commit()


async def _graph_phase(db: Session, scan: Scan) -> None:
    await _emit_progress(scan.id, db, scan, "graph_build", 88)
    edges = build_edges(scan)
    persist_edges(db, scan, edges)
    g = to_networkx(scan, edges)

    await _emit_progress(scan.id, db, scan, "attack_path", 95)
    result, validation_summary = await rank_paths_validated(scan, g)
    if result is not None:
        db.query(AttackPath).filter(AttackPath.scan_id == scan.id).delete()
        db.add(AttackPath(
            scan_id=scan.id,
            asset_sequence=result.asset_ids,
            total_risk_score=result.total_risk,
            narrative=result.narrative,
        ))
        db.commit()
        await bus.publish("attack_path_computed", {
            "hops": result.asset_ids,
            "total_risk": result.total_risk,
            "narrative": result.narrative,
            "validation_summary": validation_summary,
        }, scan.id)


async def _impact_phase(db: Session, scan: Scan) -> None:
    await _emit_progress(scan.id, db, scan, "impact_simulation", 97)
    from backend.intelligence.impact_simulator import compute_impact
    result = compute_impact(db, scan)
    if result is not None:
        await bus.publish("impact_computed", {
            "total_exposure_min": result.get("total_exposure_min_inr", 0),
            "total_exposure_max": result.get("total_exposure_max_inr", 0),
            "scenario_count": result.get("scenario_count", 0),
            "top_scenario": result.get("top_scenario_name", "None"),
        }, scan.id)


async def run_scan(scan_id: int, domain: str, subnet: str | None) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = "running"
        db.commit()
        await bus.publish("scan_started", {"domain": domain, "subnet": subnet}, scan_id)

        try:
            external = await asyncio.wait_for(_external_phase(db, scan), timeout=180.0)
        except asyncio.TimeoutError:
            log.warning("External phase timed out for scan %d, proceeding with partial results", scan_id)
            external = db.query(Asset).filter_by(scan_id=scan.id, exposure="external").all()

        internal = await _internal_phase(db, scan) if subnet else []

        if internal:
            await _emit_progress(scan_id, db, scan, "anomaly_classify", 85)
            try:
                results = get_detector().classify(internal)
                for r in results:
                    if not r.is_shadow:
                        continue
                    asset = db.get(Asset, r.asset_id)
                    if asset is None:
                        continue
                    asset.is_shadow_device = True
                    await bus.publish("shadow_device_detected", {
                        "asset_id": r.asset_id,
                        "ip": asset.ip_address,
                        "score": r.score,
                    }, scan_id)
                db.commit()
            except Exception as e:
                log.warning("anomaly classify failed: %s", e)

        scan.total_assets = len(external) + len(internal)
        scan.total_cves = sum(len(a.cves) for a in external + internal)
        db.commit()

        await _graph_phase(db, scan)
        await _impact_phase(db, scan)

        scan.status = "completed"
        scan.progress = 100
        scan.end_time = datetime.utcnow()
        db.commit()
        await bus.publish("scan_completed", {
            "scan_id": scan_id,
            "assets": scan.total_assets,
            "cves": scan.total_cves,
        }, scan_id)
    except Exception as e:
        log.exception("scan failed")
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            db.commit()
        await bus.publish("scan_failed", {"error": str(e)}, scan_id)
    finally:
        db.close()
