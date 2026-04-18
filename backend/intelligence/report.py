"""PDF report generation.

Page 1: Threat-analyst assessment generated from structured attack-chain JSON.
Page 2: Attack-surface overview counters.
Page 3: Primary attack chain with named-rule evidence.
Page 4+: Asset inventory and rulebook appendix.
"""
import html
import io
import json
import logging
from itertools import islice

import networkx as nx
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
from backend.db.models import Asset, CVE, Scan

from .edge_rules import rulebook as named_rulebook
from .graph_builder import INTERNET_NODE, build_edges, to_networkx

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


def _top_cve(asset: Asset) -> CVE | None:
    return max(asset.cves, key=lambda cve: cve.cvss_score or 0, default=None)


def _pick_entry_and_target(g: nx.DiGraph, scan: Scan) -> tuple[int | None, int | None]:
    entry: int | None = None
    if g.out_degree(INTERNET_NODE) > 0:
        entry = INTERNET_NODE
    else:
        externals = [asset for asset in scan.assets if asset.exposure == "external"]
        if externals:
            entry = max(externals, key=lambda asset: asset.risk_score or 0).id

    crowns = [asset for asset in scan.assets if asset.is_crown_jewel]
    if crowns:
        target = max(crowns, key=lambda asset: asset.risk_score or 0).id
    else:
        internals = [asset for asset in scan.assets if asset.exposure == "internal"]
        target = max(internals, key=lambda asset: asset.risk_score or 0).id if internals else None
    return entry, target


def _estimate_hop_minutes(cve: CVE | None, relationship: str | None) -> tuple[int, int]:
    if cve is None:
        base = {
            "internet_reachable": (45, 120),
            "admin_exposure": (30, 90),
            "credential_access": (45, 180),
            "lateral_move": (60, 180),
            "shadow_pivot": (45, 120),
            "crown_jewel_access": (60, 180),
        }
        return base.get(relationship or "", (60, 180))

    vector = (cve.attack_vector or "").upper()
    complexity = (cve.attack_complexity or "").upper()
    matrix = {
        ("NETWORK", "LOW"): (30, 90),
        ("NETWORK", "HIGH"): (180, 480),
        ("ADJACENT", "LOW"): (60, 180),
        ("ADJACENT", "HIGH"): (240, 720),
        ("LOCAL", "LOW"): (120, 360),
        ("LOCAL", "HIGH"): (480, 1440),
        ("PHYSICAL", "LOW"): (1440, 2880),
        ("PHYSICAL", "HIGH"): (2880, 4320),
    }
    low, high = matrix.get((vector, complexity), (90, 240))
    if relationship in {"credential_access", "admin_exposure"}:
        low += 30
        high += 120
    elif relationship in {"tls_weakness", "outdated_software"}:
        low += 60
        high += 180
    elif relationship == "crown_jewel_access":
        low += 30
        high += 90
    return low, high


def _format_duration(minutes: int) -> str:
    if minutes < 60:
        return f"{minutes} minutes"
    if minutes < 1440:
        hours = max(1, round(minutes / 60))
        return f"{hours} hour" if hours == 1 else f"{hours} hours"
    days = max(1, round(minutes / 1440))
    return f"{days} day" if days == 1 else f"{days} days"


def _format_duration_range(low: int, high: int) -> str:
    return f"{_format_duration(low)} to {_format_duration(high)}"


def _build_candidate_paths(scan: Scan, g: nx.DiGraph, limit: int = 3) -> list[dict]:
    entry, target = _pick_entry_and_target(g, scan)
    if entry is None or target is None or entry == target:
        return []
    if entry not in g or target not in g:
        return []

    assets_by_id = {asset.id: asset for asset in scan.assets}
    try:
        raw_paths = list(islice(nx.shortest_simple_paths(g, entry, target, weight="weight"), limit))
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        return []

    candidates: list[dict] = []
    for index, path in enumerate(raw_paths, start=1):
        hops: list[dict] = []
        total_weight = 0.0
        total_low = 0
        total_high = 0
        for hop_index, (source, target_id) in enumerate(zip(path, path[1:]), start=1):
            edge = g.get_edge_data(source, target_id, default={})
            total_weight += edge.get("weight", 0.0)
            asset = assets_by_id.get(target_id)
            if asset is None:
                continue
            top_cve = _top_cve(asset)
            hop_low, hop_high = _estimate_hop_minutes(top_cve, edge.get("relationship"))
            total_low += hop_low
            total_high += hop_high
            source_label = "Internet" if source == INTERNET_NODE else _asset_label(assets_by_id[source])
            hops.append({
                "step": hop_index,
                "source_id": source,
                "target_id": target_id,
                "source_label": source_label,
                "target_label": _asset_label(asset),
                "role": "crown jewel" if asset.is_crown_jewel else (asset.asset_type or "asset"),
                "rule_id": edge.get("rule_id"),
                "rule_name": edge.get("rule_name"),
                "relationship": edge.get("relationship"),
                "rationale": edge.get("rationale"),
                "cve_id": top_cve.cve_id if top_cve else None,
                "cvss": top_cve.cvss_score if top_cve else None,
                "attack_vector": top_cve.attack_vector if top_cve else None,
                "attack_complexity": top_cve.attack_complexity if top_cve else None,
                "remediation": top_cve.remediation if top_cve else None,
                "estimated_minutes_low": hop_low,
                "estimated_minutes_high": hop_high,
                "estimated_window": _format_duration_range(hop_low, hop_high),
            })

        candidates.append({
            "path_id": f"PATH-{index:02d}",
            "asset_sequence": path,
            "sequence_labels": [
                "Internet" if asset_id == INTERNET_NODE else _asset_label(assets_by_id[asset_id])
                for asset_id in path
                if asset_id == INTERNET_NODE or asset_id in assets_by_id
            ],
            "total_risk_score": round(
                sum((assets_by_id[asset_id].risk_score or 0.0) for asset_id in path if asset_id in assets_by_id),
                1,
            ),
            "total_weight": round(total_weight, 2),
            "estimated_minutes_low": total_low,
            "estimated_minutes_high": total_high,
            "estimated_window": _format_duration_range(total_low, total_high),
            "hops": hops,
        })
    return candidates


def _fix_for_hop(hop: dict) -> dict:
    target_id = hop["target_id"]
    target_label = hop["target_label"]
    remediation = (hop.get("remediation") or "").strip()
    if remediation:
        summary = remediation.rstrip(".")
        if target_label.lower() not in summary.lower():
            summary = f"{summary} on {target_label}"
        return {
            "key": f"asset:{target_id}:patch",
            "summary": summary + ".",
            "target_id": target_id,
            "rule_id": hop.get("rule_id"),
            "cvss": hop.get("cvss") or 0.0,
        }

    rule_id = hop.get("rule_id")
    fallback = {
        "CRED-001": f"Put {target_label} behind SSO and MFA, and remove direct internet exposure for login/admin paths.",
        "CONF-001": f"Replace the certificate and enforce valid TLS on {target_label}.",
        "NET-001": f"Segment east-west access to {target_label} and restrict unnecessary service ports.",
        "NET-002": f"Reduce public exposure to {target_label} with allowlists, VPN-only access, or service shutdown.",
        "MISC-001": f"Require authentication and IP restriction for the admin surface on {target_label}.",
        "SHADOW-001": f"Remove unmanaged subnet access around {target_label} or place it behind monitored controls.",
        "DATA-001": f"Restrict direct access to crown-jewel system {target_label} to approved application hosts only.",
        "EXP-002": f"Patch or harden local privilege-escalation paths on {target_label}.",
    }
    return {
        "key": f"asset:{target_id}:{rule_id or 'control'}",
        "summary": fallback.get(rule_id, f"Reduce direct reachability to {target_label} and harden the exposed service."),
        "target_id": target_id,
        "rule_id": rule_id,
        "cvss": hop.get("cvss") or 0.0,
    }


def _build_remediation_candidates(paths: list[dict]) -> list[dict]:
    aggregated: dict[str, dict] = {}
    for path in paths:
        seen_keys: set[str] = set()
        for hop in path["hops"]:
            fix = _fix_for_hop(hop)
            key = fix["key"]
            if key in seen_keys:
                continue
            seen_keys.add(key)
            bucket = aggregated.setdefault(key, {
                "summary": fix["summary"],
                "path_ids": set(),
                "hop_indexes": [],
                "target_assets": set(),
                "rule_ids": set(),
                "max_cvss": 0.0,
            })
            bucket["path_ids"].add(path["path_id"])
            bucket["hop_indexes"].append(hop["step"])
            bucket["target_assets"].add(hop["target_label"])
            if hop.get("rule_id"):
                bucket["rule_ids"].add(hop["rule_id"])
            bucket["max_cvss"] = max(bucket["max_cvss"], fix["cvss"])

    candidates: list[dict] = []
    for bucket in aggregated.values():
        candidates.append({
            "summary": bucket["summary"],
            "blocks_paths": len(bucket["path_ids"]),
            "path_ids": sorted(bucket["path_ids"]),
            "avg_hop_index": round(sum(bucket["hop_indexes"]) / len(bucket["hop_indexes"]), 2),
            "target_assets": sorted(bucket["target_assets"]),
            "rule_ids": sorted(bucket["rule_ids"]),
            "max_cvss": bucket["max_cvss"],
        })
    candidates.sort(
        key=lambda item: (-item["blocks_paths"], item["avg_hop_index"], -item["max_cvss"], item["summary"])
    )
    return candidates


def _path_sentence(path: dict) -> str:
    chain: list[str] = []
    for label, hop in zip(path["sequence_labels"][1:], path["hops"]):
        token = label
        if hop.get("rule_id"):
            token += f" [{hop['rule_id']}]"
        if hop.get("cve_id"):
            token += f" via {hop['cve_id']}"
        chain.append(token)
    return "Internet -> " + " -> ".join(chain)


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
        f"Most likely path: {_path_sentence(primary)}. This route has the lowest effective resistance in the graph "
        f"and strings together the cleanest exploit path into the crown jewel.\n\n"
        f"Time to breach: A realistic operator could move from initial access to impact in "
        f"{primary['estimated_window']}. The slowest step is {slowest_hop['target_label']} under "
        f"{slowest_hop.get('rule_id') or slowest_hop.get('relationship')} because its exploit window alone is "
        f"{slowest_hop['estimated_window']}.\n\n"
        f"Highest-leverage remediation: {remediation_line}"
    )


def _analyst_assessment(scan: Scan, paths: list[dict], remediations: list[dict]) -> str:
    payload = _chain_payload(scan, paths, remediations)
    if ANTHROPIC_API_KEY and paths:
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            msg = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=500,
                messages=[{
                    "role": "user",
                    "content": (
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
                        f"Attack-chain JSON:\n{json.dumps(payload, indent=2)}"
                    ),
                }],
            )
            parts = [block.text for block in msg.content if getattr(block, "type", "") == "text"]
            if parts:
                return "".join(parts).strip()
        except Exception as exc:
            log.warning("Anthropic attack-chain assessment failed, using fallback: %s", exc)
    return _fallback_assessment(paths, remediations)


def _paragraph_text(text: str) -> str:
    return html.escape(text).replace("\n\n", "<br/><br/>").replace("\n", "<br/>")


def build_pdf(db: Session, scan: Scan) -> bytes:
    del db  # report generation only needs the hydrated scan object

    edges = build_edges(scan)
    graph = to_networkx(scan, edges)
    candidate_paths = _build_candidate_paths(scan, graph)
    remediation_candidates = _build_remediation_candidates(candidate_paths)
    analyst_assessment = _analyst_assessment(scan, candidate_paths, remediation_candidates)
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
        ["Critical CVEs (CVSS ≥ 9)", critical_cves],
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
        elems.append(Paragraph(f"Selected path: <b>{html.escape(_path_sentence(primary_path))}</b>", body))
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
                hop.get("rule_id") or "—",
                hop.get("cve_id") or "—",
                f"{hop['cvss']}" if hop.get("cvss") else "—",
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
                f"{hop.get('rule_id') or hop.get('relationship')} — {hop.get('rationale') or 'No rationale recorded.'}"
            )
            elems.append(Paragraph(_paragraph_text(evidence), body))
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
                    f"{cve.cvss_score or '—'}",
                    cve.attack_complexity or "—",
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
