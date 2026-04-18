"""PDF report generation.

Page 1: Threat-analyst assessment generated from structured attack-chain JSON.
Page 2: Attack-surface overview counters.
Page 3: Primary attack chain with named-rule evidence.
Page 4+: Asset inventory and rulebook appendix.

Path ranking and remediation aggregation live in
`backend.intelligence.attack_path` so the PDF, the `/attack-path` API, and the
orchestrator agree on the same primary chain.
"""
import html
import io
import json
import logging

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy.orm import Session

from backend.config import ANTHROPIC_API_KEY
from backend.db.models import Asset, Scan, ImpactReport

from .attack_path import (
    build_candidate_paths,
    build_remediation_candidates,
    path_sentence,
)
from .edge_rules import rulebook as named_rulebook
from .graph_builder import build_edges, to_networkx

log = logging.getLogger(__name__)


def _style_body() -> ParagraphStyle:
    styles = getSampleStyleSheet()
    return ParagraphStyle("body", parent=styles["BodyText"], fontSize=10, leading=13)


def _risk_color(score: float) -> colors.Color:
    if score >= 80:
        return colors.HexColor("#c0392b")
    if score >= 60:
        return colors.HexColor("#e67e22")
    if score >= 30:
        return colors.HexColor("#f1c40f")
    return colors.HexColor("#27ae60")


def _asset_label(asset: Asset) -> str:
    return asset.hostname or asset.ip_address or f"asset-{asset.id}"


def _chain_payload(scan: Scan, paths: list[dict], remediations: list[dict]) -> dict:
    critical_assets = sum(1 for asset in scan.assets if (asset.risk_score or 0) >= 80)
    return {
        "target_domain": scan.target_domain,
        "target_subnet": scan.target_subnet,
        "summary": {
            "total_assets": scan.total_assets,
            "total_cves": scan.total_cves,
            "critical_assets": critical_assets,
        },
        "candidate_paths": paths,
        "remediation_candidates": remediations[:5],
    }

def _chain_payload_with_impact(scan: Scan, paths: list[dict], remediations: list[dict], impact: dict) -> dict:
    payload = _chain_payload(scan, paths, remediations)
    payload["impact_simulation"] = impact
    return payload


def _fallback_assessment(paths: list[dict], remediations: list[dict]) -> str:
    if not paths:
        return (
            "Most likely path: No end-to-end attack path could be computed from the current graph evidence.\n\n"
            "Time to breach: A breach-time estimate is not defensible until a complete path from public entry "
            "to target is present.\n\n"
            "Highest-leverage remediation: Close the highest-risk internet-facing exposure first, then recompute "
            "the graph to confirm the crown-jewel path is broken."
        )

    primary = paths[0]
    slowest_hop = max(primary["hops"], key=lambda hop: hop["estimated_minutes_high"])
    best_fix = remediations[0] if remediations else None
    remediation_line = (
        f"{best_fix['summary']} This action cuts {best_fix['blocks_paths']} of {len(paths)} modeled path(s)."
        if best_fix
        else "Patch the first externally reachable hop in the path and recompute the graph."
    )
    return (
        f"Most likely path: {path_sentence(primary)}. This route has the lowest effective resistance in the graph "
        f"and strings together the cleanest exploit path into the highest-impact objective in scope.\n\n"
        f"Time to breach: A realistic operator could move from initial access to impact in "
        f"{primary['estimated_window']}. The slowest step is {slowest_hop['target_label']} under "
        f"{slowest_hop.get('rule_id') or slowest_hop.get('relationship')} because its exploit window alone is "
        f"{slowest_hop['estimated_window']}.\n\n"
        f"Highest-leverage remediation: {remediation_line}"
    )


def _analyst_assessment(scan: Scan, paths: list[dict], remediations: list[dict], impact_report: ImpactReport | None) -> str:
    impact_data = {}
    if impact_report:
        impact_data = {
            "total_exposure_min": impact_report.total_exposure_min_inr,
            "total_exposure_max": impact_report.total_exposure_max_inr,
            "scenarios": impact_report.scenario_matrix,
        }
        
    payload = _chain_payload_with_impact(scan, paths, remediations, impact_data)
    
    if ANTHROPIC_API_KEY and paths:
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            
            prompt_content = (
                "You are a threat analyst writing for technical judges. You will receive structured "
                "attack-chain JSON. Decide which path a real attacker would take, estimate time to breach "
                "using the CVE attack_vector and attack_complexity fields, and select the single remediation "
                "that breaks the most modeled paths.\n\n"
                "Return exactly three short paragraphs with these labels:\n"
                "Most likely path:\n"
                "Time to breach:\n"
                "Highest-leverage remediation:\n\n"
                "Requirements:\n"
                "- Mention rule IDs and CVEs where they materially support the reasoning.\n"
                "- Use direct, technical language.\n"
                "- No bullet points.\n"
                "- No executive-summary fluff or marketing phrasing.\n\n"
            )
            
            if impact_data:
                prompt_content = (
                    "You are a board-level risk advisor writing an executive summary based on structured "
                    "attack-chain and impact JSON. Explain the worst-case financial outcome, propose the single "
                    "best remediation investment, estimate the payback period/ROI ratio, and outline a 30/90/180-day "
                    "remediation plan.\n\n"
                    "Return exactly four short paragraphs with these labels:\n"
                    "Worst-case outcome:\n"
                    "Best investment:\n"
                    "ROI Assessment:\n"
                    "30/90/180-day plan:\n\n"
                    "Requirements:\n"
                    "- Provide concise executive-level insights.\n"
                    "- Use the provided Rupee values for exposure and prevention estimation.\n"
                    "- No bullet points.\n\n"
                )

            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            msg = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=600,
                messages=[{
                    "role": "user",
                    "content": prompt_content + f"Attack-chain and Impact JSON:\n{json.dumps(payload, indent=2)}",
                }],
            )
            parts = [block.text for block in msg.content if getattr(block, "type", "") == "text"]
            if parts:
                advisory_text = "".join(parts).strip()
                if impact_report and not impact_report.executive_advisory:
                    from backend.db import SessionLocal
                    with SessionLocal() as session:
                        rep = session.get(ImpactReport, impact_report.id)
                        if rep:
                            rep.executive_advisory = advisory_text
                            session.commit()
                return advisory_text
        except Exception as exc:
            log.warning("Anthropic assessment failed, using fallback: %s", exc)
    return _fallback_assessment(paths, remediations)


def _paragraph_text(text: str) -> str:
    return html.escape(text).replace("\n\n", "<br/><br/>").replace("\n", "<br/>")


def build_pdf(db: Session, scan: Scan) -> bytes:
    del db  # report generation only needs the hydrated scan object

    edges = build_edges(scan)
    graph = to_networkx(scan, edges)
    candidate_paths = build_candidate_paths(scan, graph)
    remediation_candidates = build_remediation_candidates(candidate_paths)
    impact_report = max(scan.impact_reports, key=lambda r: r.id, default=None)
    
    analyst_assessment = impact_report.executive_advisory if impact_report and impact_report.executive_advisory else _analyst_assessment(scan, candidate_paths, remediation_candidates, impact_report)
    primary_path = candidate_paths[0] if candidate_paths else None

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title=f"ShadowTrace Scan {scan.id}")
    styles = getSampleStyleSheet()
    body = _style_body()
    elems: list = []

    elems.append(Paragraph("ShadowTrace Attack Surface Report", styles["Title"]))
    elems.append(Spacer(1, 0.15 * inch))
    elems.append(Paragraph(f"Target: <b>{html.escape(scan.target_domain)}</b>", body))
    if scan.target_subnet:
        elems.append(Paragraph(f"Internal subnet: <b>{html.escape(scan.target_subnet)}</b>", body))
    elems.append(Paragraph(f"Scan completed: {scan.end_time or scan.start_time}", body))
    elems.append(Spacer(1, 0.3 * inch))
    elems.append(Paragraph("Threat Analyst Assessment", styles["Heading2"]))
    elems.append(Paragraph(_paragraph_text(analyst_assessment), body))
    elems.append(PageBreak())

    elems.append(Paragraph("Attack Surface Overview", styles["Heading2"]))
    by_level = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for asset in scan.assets:
        score = asset.risk_score or 0
        if score >= 80:
            by_level["critical"] += 1
        elif score >= 60:
            by_level["high"] += 1
        elif score >= 30:
            by_level["medium"] += 1
        else:
            by_level["low"] += 1
    admin_count = sum(1 for asset in scan.assets if asset.admin_panels)
    shadow_count = sum(1 for asset in scan.assets if asset.is_shadow_device)
    critical_cves = sum(1 for asset in scan.assets for cve in asset.cves if (cve.cvss_score or 0) >= 9)

    overview = [
        ["Total assets discovered", scan.total_assets],
        ["Critical-risk assets", by_level["critical"]],
        ["High-risk assets", by_level["high"]],
        ["Medium-risk assets", by_level["medium"]],
        ["Low-risk assets", by_level["low"]],
        ["Exposed admin panels", admin_count],
        ["Shadow devices detected", shadow_count],
        ["CVEs found (total)", scan.total_cves],
        ["Critical CVEs (CVSS \u2265 9)", critical_cves],
    ]
    overview_table = Table(overview, colWidths=[3.5 * inch, 1.5 * inch])
    overview_table.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
    ]))
    elems.append(overview_table)
    elems.append(PageBreak())

    elems.append(Paragraph("Primary Attack Chain", styles["Heading2"]))
    if primary_path is None:
        elems.append(Paragraph("No attack path computed.", body))
    else:
        elems.append(Paragraph(f"Selected path: <b>{html.escape(path_sentence(primary_path))}</b>", body))
        elems.append(Paragraph(
            f"Total path risk: <b>{primary_path['total_risk_score']}</b> | "
            f"Estimated time to breach: <b>{html.escape(primary_path['estimated_window'])}</b>",
            body,
        ))
        if remediation_candidates:
            elems.append(Paragraph(
                f"Best single choke point: <b>{html.escape(remediation_candidates[0]['summary'])}</b>",
                body,
            ))
        elems.append(Spacer(1, 0.15 * inch))
        rows = [["Hop", "Asset", "Role", "Rule", "Top CVE", "CVSS"]]
        for hop in primary_path["hops"]:
            rows.append([
                hop["step"],
                hop["target_label"],
                hop["role"],
                hop.get("rule_id") or "\u2014",
                hop.get("cve_id") or "\u2014",
                f"{hop['cvss']}" if hop.get("cvss") else "\u2014",
            ])
        chain_table = Table(rows, colWidths=[0.45 * inch, 1.8 * inch, 1.05 * inch, 0.9 * inch, 1.55 * inch, 0.55 * inch])
        chain_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(chain_table)
        elems.append(Spacer(1, 0.2 * inch))
        elems.append(Paragraph("Hop Evidence", styles["Heading3"]))
        for hop in primary_path["hops"]:
            evidence = (
                f"Hop {hop['step']} ({hop['source_label']} -> {hop['target_label']}): "
                f"{hop.get('rule_id') or hop.get('relationship')} \u2014 {hop.get('rationale') or 'No rationale recorded.'}"
            )
            elems.append(Paragraph(_paragraph_text(evidence), body))
    elems.append(PageBreak())
    
    if impact_report:
        elems.append(Paragraph("Breach Impact Assessment", styles["Heading2"]))
        elems.append(Paragraph(
            f"Estimated total regulatory and operational exposure: <b>₹{impact_report.total_exposure_min_inr:,.0f} - ₹{impact_report.total_exposure_max_inr:,.0f}</b>",
            body
        ))
        elems.append(Spacer(1, 0.15 * inch))
        
        elems.append(Paragraph("Operational Loss Breakdown", styles["Heading3"]))
        op_rows = [
            ["Category", "Min Range (₹)", "Max Range (₹)"],
            ["Downtime", f"{impact_report.downtime_cost_min_inr:,.0f}", f"{impact_report.downtime_cost_max_inr:,.0f}"],
            ["Incident Response", f"{impact_report.incident_response_min_inr:,.0f}", f"{impact_report.incident_response_max_inr:,.0f}"],
            ["Customer Churn", f"{impact_report.churn_cost_min_inr:,.0f}", f"{impact_report.churn_cost_max_inr:,.0f}"]
        ]
        op_table = Table(op_rows, colWidths=[2 * inch, 2 * inch, 2 * inch])
        op_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(op_table)
        elems.append(Spacer(1, 0.2 * inch))
        
        elems.append(Paragraph("Top Attack Scenarios", styles["Heading3"]))
        if impact_report.scenario_matrix:
            sc_rows = [["Scenario", "Paths", "Exposure (₹)", "Prevention Cost (₹)"]]
            for scenario in impact_report.scenario_matrix[:3]:
                sc_rows.append([
                    scenario["name"],
                    str(scenario["path_count"]),
                    f"{scenario['total_exposure_min_inr']:,.0f}",
                    f"{scenario['prevention_cost_inr']:,.0f}"
                ])
            sc_table = Table(sc_rows, colWidths=[2.5 * inch, 0.7 * inch, 1.5 * inch, 1.3 * inch])
            sc_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elems.append(sc_table)
        
        elems.append(PageBreak())

    elems.append(Paragraph("Asset Inventory", styles["Heading2"]))
    assets_sorted = sorted(scan.assets, key=lambda asset: -(asset.risk_score or 0))
    for asset in assets_sorted:
        label = _asset_label(asset)
        tags = []
        if asset.is_crown_jewel:
            tags.append("crown jewel")
        if asset.is_shadow_device:
            tags.append("shadow device")
        if asset.admin_panels:
            tags.append(f"{len(asset.admin_panels)} admin panel(s)")
        tag_str = f" - <font color='#666'>{', '.join(tags)}</font>" if tags else ""
        elems.append(Paragraph(
            f"<b>{html.escape(label)}</b> ({html.escape(asset.asset_type or 'unknown')}) "
            f"<font color='{_risk_color(asset.risk_score or 0).hexval()}'>"
            f"risk {asset.risk_score}</font>{tag_str}",
            body,
        ))
        if asset.ports:
            ports_line = ", ".join(
                f"{port.port_number}/{port.protocol}"
                + (f" {port.service_name}" if port.service_name else "")
                + (f" {port.service_version}" if port.service_version else "")
                for port in asset.ports
            )
            elems.append(Paragraph(f"Open ports: {html.escape(ports_line)}", body))
        if asset.cves:
            rows = [["CVE", "CVSS", "AC", "Remediation"]]
            for cve in sorted(asset.cves, key=lambda item: -(item.cvss_score or 0))[:5]:
                rows.append([
                    cve.cve_id,
                    f"{cve.cvss_score or '\u2014'}",
                    cve.attack_complexity or "\u2014",
                    cve.remediation or "",
                ])
            cve_table = Table(rows, colWidths=[1.2 * inch, 0.55 * inch, 0.45 * inch, 3.8 * inch])
            cve_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ecf0f1")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elems.append(cve_table)
        elems.append(Spacer(1, 0.12 * inch))

    elems.append(PageBreak())
    elems.append(Paragraph("Named Rulebook", styles["Heading2"]))
    rule_rows = [["ID", "Rule", "Definition"]]
    for rule in named_rulebook():
        rule_rows.append([rule["id"], rule["name"], rule["description"]])
    rule_table = Table(rule_rows, colWidths=[0.8 * inch, 1.7 * inch, 4.6 * inch])
    rule_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elems.append(rule_table)

    doc.build(elems)
    return buf.getvalue()
