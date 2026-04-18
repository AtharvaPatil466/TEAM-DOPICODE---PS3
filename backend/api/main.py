import asyncio
import logging
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, Depends
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
                             remediation=c.remediation, in_kev=bool(c.in_kev),
                             kev_ransomware=bool(c.kev_ransomware),
                             kev_date_added=c.kev_date_added) for c in a.cves],
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
            attack_techniques=e.attack_techniques or [],
            evidence=e.evidence,
            verified_at=e.verified_at,
            verification_evidence=e.verification_evidence,
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


def _hop_to_schema(hop: dict, asset: Asset | None) -> schemas.AttackPathHop:
    description = None
    if asset is not None:
        top = max(asset.cves, key=lambda c: c.cvss_score or 0, default=None)
        if top is not None and top.cve_id == hop.get("cve_id"):
            description = top.description
    return schemas.AttackPathHop(
        asset_id=hop["target_id"],
        label=hop["target_label"],
        vulnerability=hop.get("cve_id"),
        description=description,
        rule_id=hop.get("rule_id"),
        rule_name=hop.get("rule_name"),
        rationale=hop.get("rationale"),
        relationship=hop.get("relationship"),
        cvss=hop.get("cvss"),
        attack_vector=hop.get("attack_vector"),
        attack_complexity=hop.get("attack_complexity"),
        estimated_window=hop.get("estimated_window"),
        attack_techniques=hop.get("attack_techniques") or [],
        evidence=hop.get("evidence"),
        verified_at=hop.get("verified_at"),
    )


def _candidate_to_schema(path: dict, assets_by_id: dict[int, Asset]) -> schemas.AttackPathCandidate:
    return schemas.AttackPathCandidate(
        path_id=path["path_id"],
        sequence_labels=path["sequence_labels"],
        total_risk_score=path["total_risk_score"],
        estimated_window=path["estimated_window"],
        hops=[_hop_to_schema(hop, assets_by_id.get(hop["target_id"])) for hop in path["hops"]],
    )


def _result_to_response(result, scan: Scan) -> schemas.AttackPathResponse:
    from backend.intelligence.attack_path import persona_spec
    if result is None:
        return schemas.AttackPathResponse(hops=[], total_risk_score=0.0, narrative="No attack path computed yet.")
    assets_by_id = {a.id: a for a in scan.assets}
    primary = result.primary_path
    return schemas.AttackPathResponse(
        hops=[_hop_to_schema(hop, assets_by_id.get(hop["target_id"])) for hop in primary["hops"]],
        total_risk_score=primary["total_risk_score"],
        narrative=result.narrative,
        path_id=primary["path_id"],
        estimated_window=primary["estimated_window"],
        persona=primary.get("persona"),
        alternates=[_candidate_to_schema(p, assets_by_id) for p in result.alternates],
        remediation_candidates=[
            schemas.RemediationCandidate(
                summary=item["summary"],
                blocks_paths=item["blocks_paths"],
                path_ids=item["path_ids"],
                target_assets=item["target_assets"],
                rule_ids=item["rule_ids"],
                max_cvss=item["max_cvss"],
            )
            for item in result.remediations
        ],
    )


@app.get("/attack-path", response_model=schemas.AttackPathResponse)
def attack_path(
    persona: Optional[schemas.Persona] = Query(None, description="Attacker persona: script_kiddie | criminal | apt"),
    db: Session = Depends(get_db),
) -> schemas.AttackPathResponse:
    from backend.intelligence.attack_path import rank_paths
    from backend.intelligence.graph_builder import build_edges, to_networkx

    scan = _latest_scan(db)
    if scan is None:
        return schemas.AttackPathResponse(hops=[], total_risk_score=0.0, narrative="No attack path computed yet.")
    edges = build_edges(scan)
    graph = to_networkx(scan, edges)
    result = rank_paths(scan, graph, persona=persona)
    return _result_to_response(result, scan)


@app.post("/attack-path/simulate", response_model=schemas.SimulateResponse)
def attack_path_simulate(
    req: schemas.SimulateRequest,
    db: Session = Depends(get_db),
) -> schemas.SimulateResponse:
    from backend.intelligence.simulate import simulate_remediation

    scan = _latest_scan(db)
    if scan is None:
        raise HTTPException(404, "no scans available")
    delta = simulate_remediation(
        scan,
        req.patched_asset_ids,
        req.patched_cve_ids,
        persona=req.persona,
    )
    return schemas.SimulateResponse(
        summary=delta.summary,
        blocked_path_ids=delta.blocked_path_ids,
        introduced_path_ids=delta.introduced_path_ids,
        time_to_breach_delta_minutes=delta.time_to_breach_delta_minutes,
        baseline=_result_to_response(delta.baseline, scan),
        simulated=_result_to_response(delta.simulated, scan),
    )


@app.get("/scan/diff", response_model=schemas.ScanDiffResponse)
def scan_diff(
    before: int = Query(..., description="Earlier scan ID"),
    after: int = Query(..., description="Later scan ID"),
    db: Session = Depends(get_db),
) -> schemas.ScanDiffResponse:
    from backend.intelligence.diff import compute_diff

    before_scan = db.get(Scan, before)
    after_scan = db.get(Scan, after)
    if before_scan is None or after_scan is None:
        raise HTTPException(404, "one or both scans not found")
    d = compute_diff(before_scan, after_scan)
    return schemas.ScanDiffResponse(
        before_id=d.before_id,
        after_id=d.after_id,
        summary=d.summary,
        assets_added=d.assets_added,
        assets_removed=d.assets_removed,
        edges_added=d.edges_added,
        edges_removed=d.edges_removed,
        paths_broken=d.paths_broken,
        paths_introduced=d.paths_introduced,
        risk_delta=d.risk_delta,
        time_to_breach_delta_minutes=d.time_to_breach_delta_minutes,
    )


@app.post("/lab/validate", response_model=schemas.LabValidateResponse)
async def lab_validate(db: Session = Depends(get_db)) -> schemas.LabValidateResponse:
    from backend.lab.validator import validate_scan

    scan = _latest_scan(db)
    if scan is None:
        raise HTTPException(404, "no scans available")
    results = await validate_scan(db, scan)
    verified = sum(1 for r in results if r.get("verified"))
    return schemas.LabValidateResponse(
        scan_id=scan.id,
        probes_run=len(results),
        verified=verified,
        results=[schemas.LabValidationResult(**r) for r in results],
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
