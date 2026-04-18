import asyncio
import logging
import time
from collections import defaultdict
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.config import LOG_LEVEL
from backend.db import init_db, get_db
from backend.db.models import Scan, Asset, Port, CVE, GraphEdge, AttackPath, ImpactReport
from backend.api import schemas
from backend.api.demo_replay import replay_scan
from backend.api.events import bus
from backend.intelligence.edge_rules import rulebook as graph_rulebook, RULES

logging.basicConfig(level=LOG_LEVEL)

# ── Rate Limiter ──────────────────────────────────────────────
RATE_LIMIT_SECONDS = 30
_last_scan_by_ip: dict[str, float] = defaultdict(float)

def _check_rate_limit(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    if now - _last_scan_by_ip[client_ip] < RATE_LIMIT_SECONDS:
        remaining = int(RATE_LIMIT_SECONDS - (now - _last_scan_by_ip[client_ip]))
        raise HTTPException(429, f"Rate limited. Wait {remaining}s before starting another scan.")
    _last_scan_by_ip[client_ip] = now

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
async def scan_start(req: schemas.ScanStartRequest, request: Request, db: Session = Depends(get_db)) -> schemas.ScanStartResponse:
    _check_rate_limit(request)
    from backend.api.orchestrator import run_scan

    scan = Scan(
        target_domain=req.domain,
        target_subnet=req.subnet,
        company_size=req.company_size,
        industry_sector=req.industry_sector,
        processes_pii=req.processes_pii if req.processes_pii is not None else True,
        status="pending"
    )
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


def _validation_to_schema(raw: dict | None) -> schemas.PathValidation | None:
    if not raw:
        return None
    return schemas.PathValidation(
        validated=raw.get("validated", False),
        confidence=raw.get("confidence", "UNVERIFIED"),
        hop_results=[schemas.HopValidation(**hop) for hop in (raw.get("hop_results") or [])],
    )


def _candidate_to_schema(path: dict, assets_by_id: dict[int, Asset]) -> schemas.AttackPathCandidate:
    return schemas.AttackPathCandidate(
        path_id=path["path_id"],
        sequence_labels=path["sequence_labels"],
        total_risk_score=path["total_risk_score"],
        estimated_window=path["estimated_window"],
        hops=[_hop_to_schema(hop, assets_by_id.get(hop["target_id"])) for hop in path["hops"]],
        validation=_validation_to_schema(path.get("validation")),
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
        validation=_validation_to_schema(primary.get("validation")),
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
async def attack_path(
    persona: Optional[schemas.Persona] = Query(None, description="Attacker persona: script_kiddie | criminal | apt"),
    db: Session = Depends(get_db),
) -> schemas.AttackPathResponse:
    from backend.intelligence.attack_path import rank_paths_validated
    from backend.intelligence.graph_builder import build_edges, to_networkx

    scan = _latest_scan(db)
    if scan is None:
        return schemas.AttackPathResponse(hops=[], total_risk_score=0.0, narrative="No attack path computed yet.")
    edges = build_edges(scan)
    graph = to_networkx(scan, edges)
    result, _summary = await rank_paths_validated(scan, graph, persona=persona)
    return _result_to_response(result, scan)


@app.post("/attack-path/simulate", response_model=schemas.SimulateResponse)
async def attack_path_simulate(
    req: schemas.SimulateRequest,
    db: Session = Depends(get_db),
) -> schemas.SimulateResponse:
    from backend.intelligence.simulate import simulate_remediation
    from backend.intelligence.delta_narrator import narrate_simulation_delta

    scan = _latest_scan(db)
    if scan is None:
        raise HTTPException(404, "no scans available")
    delta = await simulate_remediation(
        scan,
        req.patched_asset_ids,
        req.patched_cve_ids,
        persona=req.persona,
    )
    patched_labels = [
        (a.hostname or a.ip_address or f"asset-{a.id}")
        for a in scan.assets
        if a.id in set(req.patched_asset_ids or [])
    ]
    delta_summary = await narrate_simulation_delta(
        patched_labels=patched_labels,
        patched_cves=list(req.patched_cve_ids or []),
        before=delta.before_validation,
        after=delta.after_validation,
        blocked_path_ids=delta.blocked_path_ids,
    )
    return schemas.SimulateResponse(
        summary=delta.summary,
        blocked_path_ids=delta.blocked_path_ids,
        introduced_path_ids=delta.introduced_path_ids,
        time_to_breach_delta_minutes=delta.time_to_breach_delta_minutes,
        baseline=_result_to_response(delta.baseline, scan),
        simulated=_result_to_response(delta.simulated, scan),
        before=schemas.ValidationSummary(**delta.before_validation),
        after=schemas.ValidationSummary(**delta.after_validation),
        delta_summary=delta_summary,
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


@app.get("/impact", response_model=schemas.ImpactResponse)
def impact(db: Session = Depends(get_db)) -> schemas.ImpactResponse:
    scan = _latest_scan(db)
    if scan is None:
        raise HTTPException(404, "no scans available")
    
    report = db.query(ImpactReport).filter(ImpactReport.scan_id == scan.id).order_by(desc(ImpactReport.id)).first()
    if not report:
        raise HTTPException(404, "no impact report available for latest scan")
        
    return schemas.ImpactResponse(
        scan_id=scan.id,
        company_size=scan.company_size or "small",
        industry_sector=scan.industry_sector or "technology",
        asset_classifications=report.asset_classifications,
        regulatory_exposure=schemas.RegulatoryExposure(
            min_inr=report.regulatory_min_inr,
            max_inr=report.regulatory_max_inr,
            min_formatted=f"₹{report.regulatory_min_inr:,.0f}",  # Basic fallback formatting
            max_formatted=f"₹{report.regulatory_max_inr:,.0f}",
            applicable_law="DPDP Act 2023",
            penalty_tier=report.regulatory_breakdown.get("penalty_tier", "Unknown"),
            breakdown=report.regulatory_breakdown,
        ),
        operational_loss=schemas.OperationalLoss(
            downtime={
                "min_inr": report.downtime_cost_min_inr,
                "max_inr": report.downtime_cost_max_inr,
                "mttr_hours_low": report.operational_breakdown.get("mttr_low", 0),
                "mttr_hours_high": report.operational_breakdown.get("mttr_high", 0),
            },
            incident_response={
                "min_inr": report.incident_response_min_inr,
                "max_inr": report.incident_response_max_inr,
            },
            customer_churn={
                "min_inr": report.churn_cost_min_inr,
                "max_inr": report.churn_cost_max_inr,
            },
            total_min_inr=report.downtime_cost_min_inr + report.incident_response_min_inr + report.churn_cost_min_inr,
            total_max_inr=report.downtime_cost_max_inr + report.incident_response_max_inr + report.churn_cost_max_inr,
        ),
        total_exposure_min_inr=report.total_exposure_min_inr,
        total_exposure_max_inr=report.total_exposure_max_inr,
        total_formatted=f"₹{report.total_exposure_min_inr:,.0f} - ₹{report.total_exposure_max_inr:,.0f}",
        executive_advisory=report.executive_advisory,
    )


def _normalize_scenario_hop(hop: dict) -> dict:
    if "asset_id" in hop and "label" in hop:
        return hop
    out = dict(hop)
    out.setdefault("asset_id", hop.get("target_id") or hop.get("asset_id") or 0)
    out.setdefault("label", hop.get("target_label") or hop.get("label") or "unknown")
    out.setdefault("vulnerability", hop.get("cve_id"))
    return out


def _normalize_scenario(scenario: dict) -> dict:
    out = dict(scenario)
    out["paths"] = [
        {**p, "hops": [_normalize_scenario_hop(h) for h in (p.get("hops") or [])]}
        for p in (scenario.get("paths") or [])
    ]
    return out


@app.get("/impact/scenarios", response_model=schemas.ScenarioMatrixResponse)
def impact_scenarios(db: Session = Depends(get_db)) -> schemas.ScenarioMatrixResponse:
    scan = _latest_scan(db)
    if scan is None:
        raise HTTPException(404, "no scans available")

    report = db.query(ImpactReport).filter(ImpactReport.scan_id == scan.id).order_by(desc(ImpactReport.id)).first()
    if not report:
        raise HTTPException(404, "no impact report available for latest scan")

    scenarios = [_normalize_scenario(s) for s in (report.scenario_matrix or [])]
    total_paths = sum(s.get("path_count", 0) for s in scenarios)

    return schemas.ScenarioMatrixResponse(
        scan_id=scan.id,
        total_paths=total_paths,
        total_scenarios=len(scenarios),
        scenarios=scenarios,
    )


@app.get("/compliance", response_model=schemas.ComplianceSummaryResponse)
def compliance_summary(db: Session = Depends(get_db)) -> schemas.ComplianceSummaryResponse:
    scan = _latest_scan(db)
    if scan is None:
        return schemas.ComplianceSummaryResponse(scan_id=0, total_violations=0, controls=[])

    # Collect which compliance controls are violated by edges in this scan
    rules_by_id = {r.id: r for r in RULES}
    control_hits: dict[str, dict] = {}
    for edge in scan.edges:
        rule = rules_by_id.get(edge.rule_id)
        if rule is None:
            continue
        for control_tag in rule.compliance_controls:
            bucket = control_hits.setdefault(control_tag, {
                "control": control_tag,
                "rule_ids": set(),
                "edge_count": 0,
                "framework": control_tag.split(" ")[0] if " " in control_tag else control_tag,
            })
            bucket["rule_ids"].add(edge.rule_id)
            bucket["edge_count"] += 1

    controls = [
        schemas.ComplianceControl(
            control=v["control"],
            framework=v["framework"],
            rule_ids=sorted(v["rule_ids"]),
            edge_count=v["edge_count"],
        )
        for v in sorted(control_hits.values(), key=lambda x: -x["edge_count"])
    ]

    return schemas.ComplianceSummaryResponse(
        scan_id=scan.id,
        total_violations=len(controls),
        controls=controls,
    )
