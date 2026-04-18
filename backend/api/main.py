import asyncio
import logging
from datetime import datetime

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.config import LOG_LEVEL
from backend.db import init_db, get_db
from backend.db.models import Scan, Asset, Port, CVE, GraphEdge, AttackPath
from backend.api import schemas
from backend.api.demo_replay import replay_scan
from backend.api.events import bus
from backend.intelligence.edge_rules import rulebook as graph_rulebook

logging.basicConfig(level=LOG_LEVEL)

app = FastAPI(title="ShadowTrace API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/scan/start", response_model=schemas.ScanStartResponse)
async def scan_start(req: schemas.ScanStartRequest, db: Session = Depends(get_db)) -> schemas.ScanStartResponse:
    from backend.api.orchestrator import run_scan

    scan = Scan(target_domain=req.domain, target_subnet=req.subnet, status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    asyncio.create_task(run_scan(scan.id, req.domain, req.subnet))
    return schemas.ScanStartResponse(scan_id=scan.id, status=scan.status)


@app.get("/scan/status/{scan_id}", response_model=schemas.ScanStatusResponse)
def scan_status(scan_id: int, db: Session = Depends(get_db)) -> schemas.ScanStatusResponse:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    return schemas.ScanStatusResponse(
        scan_id=scan.id,
        status=scan.status,
        progress=scan.progress,
        total_assets=scan.total_assets,
        total_cves=scan.total_cves,
        start_time=scan.start_time,
        end_time=scan.end_time,
    )


@app.get("/scan/latest", response_model=schemas.LatestScanResponse)
def latest_scan(db: Session = Depends(get_db)) -> schemas.LatestScanResponse:
    scan = _latest_scan(db)
    if scan is None:
        raise HTTPException(404, "no scans available")
    return _scan_to_response(scan)


@app.websocket("/scan/live")
async def scan_live(ws: WebSocket) -> None:
    await bus.connect(ws)
    try:
        while True:
            # keep alive — client may send pings/ignored messages
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await bus.disconnect(ws)


def _latest_scan(db: Session) -> Scan | None:
    return db.query(Scan).order_by(desc(Scan.id)).first()


def _scan_to_response(scan: Scan) -> schemas.LatestScanResponse:
    return schemas.LatestScanResponse(
        scan_id=scan.id,
        domain=scan.target_domain,
        subnet=scan.target_subnet,
        status=scan.status,
        progress=scan.progress,
        total_assets=scan.total_assets,
        total_cves=scan.total_cves,
        start_time=scan.start_time,
        end_time=scan.end_time,
        internal_scope=any(asset.exposure == "internal" for asset in scan.assets),
    )


def _risk_level(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _asset_to_summary(a: Asset) -> schemas.AssetSummary:
    return schemas.AssetSummary(
        id=a.id,
        hostname=a.hostname,
        ip=a.ip_address,
        asset_type=a.asset_type,
        os=a.os_guess,
        risk_score=a.risk_score,
        is_shadow_device=a.is_shadow_device,
        is_crown_jewel=a.is_crown_jewel,
        exposure=a.exposure,
        open_ports=[p.port_number for p in a.ports],
        services=[p.service_name for p in a.ports if p.service_name],
        cve_count=len(a.cves),
    )


@app.get("/assets", response_model=list[schemas.AssetSummary])
def list_assets(db: Session = Depends(get_db)) -> list[schemas.AssetSummary]:
    scan = _latest_scan(db)
    if scan is None:
        return []
    return [_asset_to_summary(a) for a in scan.assets]


@app.get("/asset/{asset_id}", response_model=schemas.AssetDetail)
def asset_detail(asset_id: int, db: Session = Depends(get_db)) -> schemas.AssetDetail:
    a = db.get(Asset, asset_id)
    if a is None:
        raise HTTPException(404, "asset not found")
    base = _asset_to_summary(a).model_dump()
    return schemas.AssetDetail(
        **base,
        tech_stack=a.tech_stack,
        admin_panels=a.admin_panels,
        ssl_info=a.ssl_info,
        ports=[schemas.PortOut(port=p.port_number, protocol=p.protocol, service=p.service_name,
                               version=p.service_version, state=p.state) for p in a.ports],
        cves=[schemas.CVEOut(cve_id=c.cve_id, description=c.description, cvss=c.cvss_score,
                             attack_vector=c.attack_vector, attack_complexity=c.attack_complexity,
                             remediation=c.remediation) for c in a.cves],
        graph_position=None,
    )


@app.get("/graph", response_model=schemas.GraphResponse)
def graph(db: Session = Depends(get_db)) -> schemas.GraphResponse:
    scan = _latest_scan(db)
    if scan is None:
        return schemas.GraphResponse(nodes=[], edges=[])
    nodes = [
        schemas.GraphNode(
            id=a.id,
            label=a.hostname or a.ip_address or f"asset-{a.id}",
            risk_level=_risk_level(a.risk_score),
            asset_type=a.asset_type,
            is_crown_jewel=a.is_crown_jewel,
            is_shadow_device=a.is_shadow_device,
        )
        for a in scan.assets
    ]
    if any(edge.source_id == 0 or edge.target_id == 0 for edge in scan.edges):
        nodes.insert(0, schemas.GraphNode(
            id=0,
            label="Internet",
            risk_level="low",
            asset_type="internet",
            is_crown_jewel=False,
            is_shadow_device=False,
        ))
    edges = [
        schemas.GraphEdgeOut(
            source=e.source_id,
            target=e.target_id,
            relationship=e.relationship_type,
            rule_id=e.rule_id,
            rationale=e.rationale,
            weight=e.weight,
        )
        for e in scan.edges
    ]
    return schemas.GraphResponse(nodes=nodes, edges=edges)


@app.get("/rulebook", response_model=list[schemas.RulebookRuleOut])
def rulebook() -> list[schemas.RulebookRuleOut]:
    return [schemas.RulebookRuleOut(**rule) for rule in graph_rulebook()]


@app.post("/demo/replay/latest", response_model=schemas.LatestScanResponse)
async def demo_replay_latest(db: Session = Depends(get_db)) -> schemas.LatestScanResponse:
    scan = _latest_scan(db)
    if scan is None:
        raise HTTPException(404, "no scans available")
    asyncio.create_task(replay_scan(scan.id))
    return _scan_to_response(scan)


@app.get("/attack-path", response_model=schemas.AttackPathResponse)
def attack_path(db: Session = Depends(get_db)) -> schemas.AttackPathResponse:
    scan = _latest_scan(db)
    if scan is None or not scan.paths:
        return schemas.AttackPathResponse(hops=[], total_risk_score=0.0, narrative="No attack path computed yet.")
    path = max(scan.paths, key=lambda p: p.total_risk_score)
    assets_by_id = {a.id: a for a in scan.assets}
    hops: list[schemas.AttackPathHop] = []
    for aid in path.asset_sequence:
        a = assets_by_id.get(aid)
        if a is None:
            continue
        top_cve = max(a.cves, key=lambda c: c.cvss_score or 0, default=None)
        hops.append(schemas.AttackPathHop(
            asset_id=a.id,
            label=a.hostname or a.ip_address or f"asset-{a.id}",
            vulnerability=top_cve.cve_id if top_cve else None,
            description=top_cve.description if top_cve else None,
        ))
    return schemas.AttackPathResponse(
        hops=hops,
        total_risk_score=path.total_risk_score,
        narrative=path.narrative or "",
    )


@app.get("/report/pdf")
def report_pdf(db: Session = Depends(get_db)) -> Response:
    scan = _latest_scan(db)
    if scan is None:
        raise HTTPException(404, "no scans available")
    try:
        from backend.intelligence.report import build_pdf
    except ImportError:
        raise HTTPException(503, "report module not yet implemented")
    pdf_bytes = build_pdf(db, scan)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="shadowtrace-scan-{scan.id}.pdf"'},
    )
