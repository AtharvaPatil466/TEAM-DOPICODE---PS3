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


def _fallback_assessment(paths: list[dict], remediations: list[dict], domain: str) -> str:
    company = domain.split('.')[0].capitalize()
    if not paths:
        return (
            f"Dear {company}, here is what we found.\\n\\n"
            "Right now, we haven't identified a direct path for attackers to reach your critical data. "
            "Continue to monitor your systems and keep public-facing services updated.\\n\\n"
            "We found no immediate critical security gaps. "
            "As a next step, ensure you are frequently reviewing your exposed areas."
        )

    lines = [f"Dear {company}, here is what we found.\\n\\n"]
    for i, path in enumerate(paths[:3]):
        primary = path["hops"][-1]
        fix = remediations[i] if len(remediations) > i else remediations[0] if remediations else None
        
        target = primary.get('target_label', 'a critical system')
        problem = primary.get('relationship', 'an exposed area')
        fix_action = fix['summary'] if fix else 'Secure this system immediately.'
        
        lines.append(f"We discovered {problem} that allows unauthorized access to {target}. ")
        lines.append(f"To fix this, {fix_action.lower()}\\n\\n")
        
    return "".join(lines).strip()


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
                f"You are writing a letter to the leadership of {scan.target_domain}.\n"
                "Format it exactly like a letter. You must open with 'Dear [Company], here is what we found.'\n"
                "Write a maximum of 3 findings based on the JSON. Each finding must be exactly two sentences: "
                "Sentence 1: What is wrong. Sentence 2: What to do about it.\n\n"
                "CRITICAL RULES:\n"
                "- Do NOT use the word 'vulnerability'. Use 'security gap' or 'exposed area' instead.\n"
                "- Do NOT use technical jargon, CVE IDs, CVSS scores, or acronyms.\n"
                "- Write in plain English.\n"
                "- No bullet points, just paragraph text separated by double newlines.\n\n"
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
    return _fallback_assessment(paths, remediations, scan.target_domain)


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
    elems.append(Paragraph("Executive Summary Letter", styles["Heading2"]))
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

    # Remediation priorities
    if remediation_candidates:
        elems.append(Paragraph("Remediation Priorities", styles["Heading2"]))
        elems.append(Paragraph(
            "Fixes ranked by how many modeled attack paths they break — highest leverage first.",
            body,
        ))
        elems.append(Spacer(1, 0.1 * inch))
        rem_rows = [["#", "Fix", "Paths Blocked", "Rules", "Max CVSS"]]
        for i, rc in enumerate(remediation_candidates[:8], 1):
            rem_rows.append([
                str(i),
                rc["summary"],
                str(rc["blocks_paths"]),
                ", ".join(rc.get("rule_ids", [])),
                f"{rc['max_cvss']:.1f}" if rc.get("max_cvss") else "—",
            ])
        rem_table = Table(rem_rows, colWidths=[0.35 * inch, 2.8 * inch, 0.8 * inch, 1.2 * inch, 0.7 * inch])
        rem_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(rem_table)
        elems.append(Spacer(1, 0.15 * inch))

    # Compliance controls mapping
    from backend.intelligence.edge_rules import RULES as all_rules
    control_hits: dict[str, list[str]] = {}
    for edge in edges:
        rule_obj = next((r for r in all_rules if r.id == edge.rule_id), None)
        if rule_obj:
            for ctrl in rule_obj.compliance_controls:
                control_hits.setdefault(ctrl, [])
                if edge.rule_id not in control_hits[ctrl]:
                    control_hits[ctrl].append(edge.rule_id)

    if control_hits:
        elems.append(Paragraph("Compliance Control Mapping", styles["Heading2"]))
        elems.append(Paragraph(
            "Controls referenced by at least one active edge in the attack graph.",
            body,
        ))
        elems.append(Spacer(1, 0.1 * inch))
        ctrl_rows = [["Framework", "Control", "Triggered By"]]
        for ctrl in sorted(control_hits.keys()):
            framework = ctrl.split(" ")[0] if " " in ctrl else ctrl
            ctrl_rows.append([framework, ctrl, ", ".join(control_hits[ctrl])])
        ctrl_table = Table(ctrl_rows, colWidths=[1.0 * inch, 2.5 * inch, 2.5 * inch])
        ctrl_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(ctrl_table)

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


def _format_inr_hero(amount_min: float, amount_max: float) -> str:
    """Collapse the min-max range into a single dramatic headline figure."""
    avg = (amount_min + amount_max) / 2
    if avg >= 10000000:
        return f"₹{avg / 10000000:.1f} Cr"
    if avg >= 100000:
        return f"₹{avg / 100000:.1f} L"
    return f"₹{avg:,.0f}"


def _risk_gauge(score: float, width: float = 4.5 * inch, height: float = 0.45 * inch):
    """Horizontal tri-color gauge: green → amber → red, with a needle at `score`."""
    from reportlab.graphics.shapes import Drawing, Rect, Polygon, String
    d = Drawing(width, height + 20)
    seg = width / 3.0
    d.add(Rect(0, 10, seg, height, fillColor=colors.HexColor("#22c55e"), strokeColor=None))
    d.add(Rect(seg, 10, seg, height, fillColor=colors.HexColor("#fbbf24"), strokeColor=None))
    d.add(Rect(seg * 2, 10, seg, height, fillColor=colors.HexColor("#ef4444"), strokeColor=None))
    needle_x = max(0, min(width, (score / 100.0) * width))
    d.add(Polygon(
        points=[needle_x - 5, 10 + height, needle_x + 5, 10 + height, needle_x, 10 + height - 10],
        fillColor=colors.HexColor("#0b1220"), strokeColor=colors.HexColor("#0b1220"),
    ))
    d.add(String(0, 0, "Low", fontSize=8, fillColor=colors.grey))
    d.add(String(width / 2 - 10, 0, "Moderate", fontSize=8, fillColor=colors.grey))
    d.add(String(width - 25, 0, "Critical", fontSize=8, fillColor=colors.grey))
    return d


def _plain_english_findings(scan: Scan, paths: list[dict]) -> list[str]:
    """Top 5 findings translated for a non-technical reader."""
    out: list[str] = []
    # Subdomain takeovers are the "highest drama" per PRD — list first.
    for a in scan.assets:
        t = (a.tech_stack or {}).get("subdomain_takeover") if isinstance(a.tech_stack, dict) else None
        if t:
            out.append(f"A subdomain ({a.hostname}) points at {t.get('provider')} with no live tenant — an attacker can claim it and serve content under your brand.")
            if len(out) >= 5:
                return out
    # Exposed admin panels.
    for a in scan.assets:
        if a.admin_panels:
            p = a.admin_panels[0]
            out.append(f"An administrator login page is exposed to the public internet at {a.hostname}{p.get('path', '')} — anyone on the internet can attempt to sign in.")
            if len(out) >= 5:
                return out
            break
    # High-CVSS CVEs.
    for a in scan.assets:
        for c in a.cves:
            if (c.cvss_score or 0) >= 9.0:
                out.append(f"{a.hostname} runs software with a critical vulnerability ({c.cve_id}, CVSS {c.cvss_score:.1f}) — a patch exists and should be applied immediately.")
                if len(out) >= 5:
                    return out
                break
    # Crown-jewel reachability from attack paths.
    if paths:
        top = paths[0]
        labels = top.get("sequence_labels") or []
        if labels:
            out.append(f"An attacker starting from the public internet can reach {labels[-1]} in {len(labels) - 1} step(s) — this is the shortest modeled kill chain.")
    # TLS posture.
    for a in scan.assets:
        ssl = a.ssl_info if isinstance(a.ssl_info, dict) else None
        if ssl and (ssl.get("expired") or not ssl.get("hostname_match", True)):
            reason = "expired" if ssl.get("expired") else "mismatched hostname"
            out.append(f"TLS certificate on {a.hostname} is {reason} — browsers will warn your customers and attackers can impersonate the service.")
            if len(out) >= 5:
                return out
            break
    return out[:5]


def build_executive_pdf(db: Session, scan: Scan) -> bytes:
    """2-page executive report.

    Page 1 (Fear): large centered rupee hero, risk gauge, top-5 findings in
    plain English.
    Page 2 (Fix): numbered prioritized action list ranked by paths blocked.
    """
    from sqlalchemy import desc as _desc
    edges = build_edges(scan)
    g = to_networkx(scan, edges)
    paths = build_candidate_paths(scan, g, limit=25)
    remediations = build_remediation_candidates(paths, scan)
    impact = db.query(ImpactReport).filter(ImpactReport.scan_id == scan.id).order_by(_desc(ImpactReport.id)).first()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title=f"ShadowTrace Executive {scan.id}",
                            leftMargin=0.7 * inch, rightMargin=0.7 * inch,
                            topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    brand = ParagraphStyle("brand", parent=styles["BodyText"], fontSize=10, leading=12,
                           textColor=colors.HexColor("#6b7280"), alignment=1)
    subtitle = ParagraphStyle("subtitle", parent=styles["BodyText"], fontSize=13, leading=16,
                              textColor=colors.HexColor("#0b1220"), alignment=1)
    hero = ParagraphStyle("hero", parent=styles["Heading1"], fontSize=64, leading=72,
                          textColor=colors.HexColor("#c0392b"), alignment=1)
    hero_caption = ParagraphStyle("hero_caption", parent=styles["BodyText"], fontSize=10,
                                  leading=12, textColor=colors.HexColor("#6b7280"), alignment=1)
    section = ParagraphStyle("section", parent=styles["Heading2"], fontSize=13, leading=16,
                             textColor=colors.HexColor("#0b1220"), spaceBefore=8, spaceAfter=4)
    fear_h1 = ParagraphStyle("fear_h1", parent=styles["Heading1"], fontSize=26, leading=30,
                             textColor=colors.HexColor("#0b1220"), alignment=1)
    body = _style_body()
    elems = []

    # ── Page 1: Fear ─────────────────────────────────────────────
    elems.append(Paragraph("SHADOWTRACE EXECUTIVE BRIEF", brand))
    elems.append(Paragraph(html.escape(scan.target_domain or "unknown"), subtitle))
    elems.append(Spacer(1, 0.25 * inch))

    elems.append(Paragraph("Estimated breach exposure", fear_h1))
    elems.append(Spacer(1, 0.1 * inch))
    if impact:
        hero_amount = _format_inr_hero(impact.total_exposure_min_inr, impact.total_exposure_max_inr)
        range_text = f"₹{impact.total_exposure_min_inr:,.0f} — ₹{impact.total_exposure_max_inr:,.0f}"
    else:
        hero_amount = "₹—"
        range_text = "Impact model not yet computed"
    elems.append(Paragraph(hero_amount, hero))
    elems.append(Paragraph(range_text, hero_caption))
    elems.append(Spacer(1, 0.15 * inch))

    max_risk = max((a.risk_score or 0 for a in scan.assets), default=0)
    gauge = _risk_gauge(float(max_risk))
    gauge.hAlign = "CENTER"
    elems.append(gauge)
    elems.append(Spacer(1, 0.2 * inch))

    elems.append(Paragraph("Top findings", section))
    findings = _plain_english_findings(scan, paths)
    if findings:
        for i, f in enumerate(findings, start=1):
            elems.append(Paragraph(f"<b>{i}.</b> {html.escape(f)}", body))
            elems.append(Spacer(1, 0.05 * inch))
    else:
        elems.append(Paragraph("No material findings — attack surface appears clean for the inputs provided.", body))

    elems.append(PageBreak())

    # ── Page 2: Fix ──────────────────────────────────────────────
    elems.append(Paragraph("What to fix first", fear_h1))
    elems.append(Spacer(1, 0.1 * inch))
    elems.append(Paragraph(
        "Remediations are ranked by how many modeled attack paths each one breaks. "
        "Work top-down — each fix removes the largest remaining slice of risk.",
        body,
    ))
    elems.append(Spacer(1, 0.2 * inch))

    if remediations:
        for i, r in enumerate(remediations[:5], start=1):
            elems.append(Paragraph(
                f"<b>{i}. {html.escape(r['summary'])}</b>",
                ParagraphStyle("rem_h", parent=body, fontSize=12, leading=15,
                               textColor=colors.HexColor("#0b1220")),
            ))
            detail = f"Breaks <b>{r['blocks_paths']}</b> modeled attack path(s)"
            if r.get("max_cvss"):
                detail += f" · highest CVSS addressed: <b>{r['max_cvss']:.1f}</b>"
            if r.get("rule_ids"):
                detail += f" · rules: {', '.join(r['rule_ids'][:3])}"
            elems.append(Paragraph(detail, body))
            elems.append(Spacer(1, 0.18 * inch))
    else:
        elems.append(Paragraph("No remediations generated — graph is empty.", body))

    doc.build(elems)
    return buf.getvalue()
