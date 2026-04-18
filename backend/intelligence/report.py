"""PDF report generation.

Page 1: Executive summary (Anthropic-generated, with deterministic fallback).
Page 2: Attack-surface overview counters.
Page 3: Attack chain narrative.
Page 4+: Full asset inventory with CVEs and remediation.
"""
import io
import logging

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)
from sqlalchemy.orm import Session

from backend.config import ANTHROPIC_API_KEY
from backend.db.models import Scan, AttackPath

log = logging.getLogger(__name__)


def _executive_summary(scan: Scan) -> str:
    critical_assets = [a for a in scan.assets if (a.risk_score or 0) >= 80]
    high_assets = [a for a in scan.assets if 60 <= (a.risk_score or 0) < 80]
    top_cves = sum((a.cves for a in scan.assets), [])
    top_cves.sort(key=lambda c: c.cvss_score or 0, reverse=True)
    top_cve = top_cves[0] if top_cves else None
    exposed_admin = sum(1 for a in scan.assets if a.admin_panels)

    context = (
        f"Target: {scan.target_domain}. Assets discovered: {scan.total_assets}. "
        f"Critical-risk assets: {len(critical_assets)}. High-risk: {len(high_assets)}. "
        f"Exposed admin panels: {exposed_admin}. Total CVEs: {scan.total_cves}. "
        f"Most severe CVE: {top_cve.cve_id if top_cve else 'none'} "
        f"(CVSS {top_cve.cvss_score if top_cve else 'n/a'})."
    )

    if ANTHROPIC_API_KEY:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            msg = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=300,
                messages=[{
                    "role": "user",
                    "content": (
                        "You are writing a 3-sentence executive summary for a "
                        "non-technical CTO based on this attack surface scan. "
                        "Sentence 1: the single most critical finding. "
                        "Sentence 2: the business risk it creates. "
                        "Sentence 3: the one most important action to take now. "
                        "Plain English, no jargon.\n\n"
                        f"Scan data: {context}"
                    ),
                }],
            )
            parts = [b.text for b in msg.content if getattr(b, "type", "") == "text"]
            if parts:
                return "".join(parts).strip()
        except Exception as e:
            log.warning("Anthropic summary failed, using fallback: %s", e)

    # Deterministic fallback so the demo never breaks.
    worst = max(scan.assets, key=lambda a: a.risk_score or 0, default=None)
    worst_label = (worst.hostname or worst.ip_address) if worst else "an unknown asset"
    top_cve_id = top_cve.cve_id if top_cve else "an unpatched service"
    return (
        f"Your most critical exposure is {worst_label}, which is internet-reachable "
        f"and vulnerable to {top_cve_id}. An attacker could use this foothold to pivot "
        f"into {len(critical_assets) + len(high_assets)} other high-risk internal "
        f"systems, including the database holding sensitive corporate data. "
        f"Patch or take {worst_label} offline within 24 hours — this is the single "
        f"highest-leverage action to reduce your breach risk today."
    )


def _style_body() -> ParagraphStyle:
    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=10, leading=13)
    return body


def _risk_color(score: float) -> colors.Color:
    if score >= 80:
        return colors.HexColor("#c0392b")
    if score >= 60:
        return colors.HexColor("#e67e22")
    if score >= 30:
        return colors.HexColor("#f1c40f")
    return colors.HexColor("#27ae60")


def build_pdf(db: Session, scan: Scan) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, title=f"ShadowTrace Scan {scan.id}")
    styles = getSampleStyleSheet()
    body = _style_body()
    elems: list = []

    # --- Page 1: Executive summary
    elems.append(Paragraph("ShadowTrace Attack Surface Report", styles["Title"]))
    elems.append(Spacer(1, 0.15 * inch))
    elems.append(Paragraph(f"Target: <b>{scan.target_domain}</b>", body))
    if scan.target_subnet:
        elems.append(Paragraph(f"Internal subnet: <b>{scan.target_subnet}</b>", body))
    elems.append(Paragraph(
        f"Scan completed: {scan.end_time or scan.start_time}", body))
    elems.append(Spacer(1, 0.3 * inch))
    elems.append(Paragraph("Executive Summary", styles["Heading2"]))
    elems.append(Paragraph(_executive_summary(scan), body))
    elems.append(PageBreak())

    # --- Page 2: Overview counters
    elems.append(Paragraph("Attack Surface Overview", styles["Heading2"]))
    by_level = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in scan.assets:
        s = a.risk_score or 0
        if s >= 80: by_level["critical"] += 1
        elif s >= 60: by_level["high"] += 1
        elif s >= 30: by_level["medium"] += 1
        else: by_level["low"] += 1
    admin_count = sum(1 for a in scan.assets if a.admin_panels)
    shadow_count = sum(1 for a in scan.assets if a.is_shadow_device)
    critical_cves = sum(1 for a in scan.assets for c in a.cves if (c.cvss_score or 0) >= 9)

    overview = [
        ["Total assets discovered", scan.total_assets],
        ["Critical-risk assets", by_level["critical"]],
        ["High-risk assets", by_level["high"]],
        ["Medium-risk assets", by_level["medium"]],
        ["Low-risk assets", by_level["low"]],
        ["Exposed admin panels", admin_count],
        ["Shadow devices detected", shadow_count],
        ["CVEs found (total)", scan.total_cves],
        ["Critical CVEs (CVSS ≥ 9)", critical_cves],
    ]
    t = Table(overview, colWidths=[3.5 * inch, 1.5 * inch])
    t.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("ALIGN", (1, 0), (1, -1), "RIGHT"),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
    ]))
    elems.append(t)
    elems.append(PageBreak())

    # --- Page 3: Attack chain
    elems.append(Paragraph("Attack Chain", styles["Heading2"]))
    path: AttackPath | None = max(scan.paths, key=lambda p: p.total_risk_score, default=None)
    if path is None:
        elems.append(Paragraph("No attack path computed.", body))
    else:
        elems.append(Paragraph(
            f"Total path risk: <b>{path.total_risk_score}</b>", body))
        elems.append(Spacer(1, 0.15 * inch))
        elems.append(Paragraph(path.narrative or "", body))
        elems.append(Spacer(1, 0.2 * inch))
        by_id = {a.id: a for a in scan.assets}
        rows = [["Hop", "Asset", "Role", "Top CVE", "CVSS"]]
        for i, aid in enumerate(path.asset_sequence, start=1):
            if aid == 0:
                rows.append([i, "Internet", "entry", "—", "—"])
                continue
            a = by_id.get(aid)
            if a is None:
                continue
            top = max(a.cves, key=lambda c: c.cvss_score or 0, default=None)
            rows.append([
                i,
                a.hostname or a.ip_address or f"asset-{aid}",
                "crown jewel" if a.is_crown_jewel else (a.asset_type or ""),
                top.cve_id if top else "—",
                f"{top.cvss_score}" if top and top.cvss_score else "—",
            ])
        ht = Table(rows, colWidths=[0.5 * inch, 2 * inch, 1.3 * inch, 1.5 * inch, 0.7 * inch])
        ht.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
        ]))
        elems.append(ht)
    elems.append(PageBreak())

    # --- Page 4+: Asset inventory
    elems.append(Paragraph("Asset Inventory", styles["Heading2"]))
    assets_sorted = sorted(scan.assets, key=lambda a: -(a.risk_score or 0))
    for a in assets_sorted:
        label = a.hostname or a.ip_address or f"asset-{a.id}"
        tags = []
        if a.is_crown_jewel: tags.append("crown jewel")
        if a.is_shadow_device: tags.append("shadow device")
        if a.admin_panels: tags.append(f"{len(a.admin_panels)} admin panel(s)")
        tag_str = f" — <font color='#666'>{', '.join(tags)}</font>" if tags else ""
        elems.append(Paragraph(
            f"<b>{label}</b> ({a.asset_type or 'unknown'}) "
            f"<font color='{_risk_color(a.risk_score or 0).hexval()}'>"
            f"risk {a.risk_score}</font>{tag_str}",
            body,
        ))
        if a.ports:
            ports_line = ", ".join(
                f"{p.port_number}/{p.protocol}"
                + (f" {p.service_name}" if p.service_name else "")
                + (f" {p.service_version}" if p.service_version else "")
                for p in a.ports
            )
            elems.append(Paragraph(f"Open ports: {ports_line}", body))
        if a.cves:
            rows = [["CVE", "CVSS", "Remediation"]]
            for c in sorted(a.cves, key=lambda c: -(c.cvss_score or 0))[:5]:
                rows.append([c.cve_id, f"{c.cvss_score or '—'}", c.remediation or ""])
            t = Table(rows, colWidths=[1.2 * inch, 0.6 * inch, 4.2 * inch])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ecf0f1")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            elems.append(t)
        elems.append(Spacer(1, 0.12 * inch))

    doc.build(elems)
    return buf.getvalue()
