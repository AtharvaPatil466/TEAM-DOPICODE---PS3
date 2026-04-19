"""Breach Impact Simulator.

Computes the financial impact of a breach given the attack path, asset inventory,
and company profile.

Components:
1. Asset Classification
2. Regulatory Exposure Calculator (DPDP Act)
3. Operational Loss Calculator
4. Attack Scenario Matrix
"""
import uuid
from typing import Optional
from backend.db.models import Asset, Scan

COMPANY_SIZES = {
    "small": {"employees": 50, "records_low": 10000, "records_high": 50000, "ir_low": 1500000, "ir_high": 4000000, "hourly_revenue": 10000, "annual_revenue": 80000000},
    "medium": {"employees": 200, "records_low": 50000, "records_high": 500000, "ir_low": 4000000, "ir_high": 15000000, "hourly_revenue": 50000, "annual_revenue": 400000000},
    "large": {"employees": 1000, "records_low": 500000, "records_high": 5000000, "ir_low": 15000000, "ir_high": 80000000, "hourly_revenue": 200000, "annual_revenue": 1600000000},
}

# Impact multipliers for high-risk finding types (per PRD).
# Applied to the base exposure for paths whose route exercises a finding.
FINDING_MULTIPLIERS = {
    "subdomain_takeover": 8.0,
    "public_s3": 6.0,
    "exposed_admin": 5.0,
}


INDUSTRY_MULTIPLIERS = {
    "technology": 1.5,
    "retail": 1.2,
    "financial_services": 2.0,
    "healthcare": 1.8,
    "manufacturing": 0.8,
    "other": 1.0,
}

# DPDP Act Penalities
# Tier 1: Severe (₹250 cr max) - Failure to take reasonable security safeguards
# Tier 2: High (₹200 cr max) - Failure to notify breach
DPDP_MAX = 2500000000  # ₹250 crore
DPDP_MIN = 50000000    # ₹5 crore

def _classify_asset(asset: Asset) -> dict:
    open_ports = {p.port_number for p in asset.ports if p.state == "open"}
    
    classification = "generic_compute"
    tier = 4
    
    if open_ports & {3306, 5432, 27017, 1433}:
        classification = "customer_data_store"
        tier = 1
    elif open_ports & {389, 636}:
        classification = "identity_store"
        tier = 2
    elif open_ports & {6379, 11211}:
        classification = "session_cache"
        tier = 2
    elif open_ports & {445, 139}:
        classification = "document_storage"
        tier = 3
    elif open_ports & {8080, 8443, 80, 443} and asset.asset_type in ("web", "api"):
        classification = "business_logic"
        tier = 2
    
    if asset.asset_type == "storage":
        classification = "document_storage"
        tier = 2
        
    if asset.is_crown_jewel:
        tier = 1
        classification = "crown_jewel"
        
    return {
        "asset_id": asset.id,
        "label": asset.hostname or asset.ip_address or f"asset-{asset.id}",
        "classification": classification,
        "data_sensitivity_tier": tier
    }

def _calculate_regulatory_exposure(size_metrics: dict, max_tier_hit: int, processes_pii: bool) -> dict:
    if not processes_pii or max_tier_hit > 3:
        return {
            "min_inr": 0.0,
            "max_inr": 0.0,
            "min_formatted": "₹0",
            "max_formatted": "₹0",
            "applicable_law": "DPDP Act 2023",
            "penalty_tier": "None",
            "breakdown": {"reason": "No sensitive PII at risk"},
        }

    penalty_tier = "Severe" if max_tier_hit == 1 else "High"
    base_max = DPDP_MAX if max_tier_hit == 1 else 2000000000
    
    # Scale penalty by records
    record_ratio = min(size_metrics["records_high"] / 5000000, 1.0)
    
    max_penalty = min(base_max * max(0.05, record_ratio * 2.0), base_max)
    min_penalty = max(DPDP_MIN, max_penalty * 0.15)
    
    return {
        "min_inr": min_penalty,
        "max_inr": max_penalty,
        "min_formatted": _format_inr(min_penalty),
        "max_formatted": _format_inr(max_penalty),
        "applicable_law": "India DPDP Act 2023",
        "penalty_tier": penalty_tier,
        "breakdown": {
            "max_data_tier_compromised": max_tier_hit,
            "records_at_risk_estimate": f"{size_metrics['records_low']} - {size_metrics['records_high']}",
        }
    }

def _format_inr(amount: float) -> str:
    if amount >= 10000000:
        return f"₹{amount / 10000000:.1f} Cr"
    if amount >= 100000:
        return f"₹{amount / 100000:.1f} L"
    return f"₹{amount:,.0f}"

def _calculate_operational_loss(size_metrics: dict, industry_multiplier: float, max_tier_hit: int, max_cvss: float, asset_count: int, finding_count: int) -> dict:
    # 1. Downtime
    # MTTR scales with max_cvss and findings footprint
    base_mttr = 4 + (max_cvss * 1.5) + (finding_count * 0.5)
    mttr_low, mttr_high = max(4.0, base_mttr), max(12.0, base_mttr * 3.0)
    
    # Asset complexity multiplier
    asset_mult = max(1.0, 1.0 + (asset_count * 0.15))
    
    effective_hourly = size_metrics["hourly_revenue"] * industry_multiplier
    downtime_min = mttr_low * effective_hourly * asset_mult
    downtime_max = mttr_high * effective_hourly * asset_mult
    
    # 2. Incident Response scales with complexity
    ir_complexity = 1.0 + (finding_count * 0.08) + (max_cvss * 0.05)
    ir_min = size_metrics["ir_low"] * ir_complexity
    ir_max = size_metrics["ir_high"] * ir_complexity
    
    # 3. Customer Churn scales slightly with severity
    churn_rate = 0.12 if max_tier_hit == 1 else (0.05 if max_tier_hit == 2 else 0.01)
    churn_severity_mult = 1.0 + (max_cvss / 20.0) + (finding_count * 0.02)
    churn_cost = size_metrics["annual_revenue"] * churn_rate * churn_severity_mult
    churn_min = churn_cost * 0.5
    churn_max = churn_cost * 1.5
    
    total_min = downtime_min + ir_min + churn_min
    total_max = downtime_max + ir_max + churn_max
    
    return {
        "downtime": {
            "min_inr": downtime_min,
            "max_inr": downtime_max,
            "mttr_hours_low": mttr_low,
            "mttr_hours_high": mttr_high,
        },
        "incident_response": {
            "min_inr": ir_min,
            "max_inr": ir_max,
        },
        "customer_churn": {
            "min_inr": churn_min,
            "max_inr": churn_max,
        },
        "total_min_inr": total_min,
        "total_max_inr": total_max,
    }


# Per-rule remediation cost estimates (INR).
# Each maps to a category with a base cost + per-affected-asset marginal cost.
RULE_REMEDIATION_COSTS = {
    "EXP-001": {"category": "Patch Management",       "base": 200000,  "per_asset": 75000,  "hours_base": 8,  "hours_per_asset": 4},
    "EXP-002": {"category": "Patch Management",       "base": 150000,  "per_asset": 60000,  "hours_base": 6,  "hours_per_asset": 3},
    "CRED-001": {"category": "MFA & Auth Hardening",   "base": 500000,  "per_asset": 40000,  "hours_base": 20, "hours_per_asset": 4},
    "CONF-001": {"category": "TLS Certificate Renewal","base": 80000,   "per_asset": 25000,  "hours_base": 4,  "hours_per_asset": 1},
    "NET-001": {"category": "Network Segmentation",    "base": 800000,  "per_asset": 120000, "hours_base": 40, "hours_per_asset": 8},
    "NET-002": {"category": "Perimeter Hardening",     "base": 300000,  "per_asset": 50000,  "hours_base": 12, "hours_per_asset": 3},
    "MISC-001": {"category": "Admin Panel Lockdown",   "base": 150000,  "per_asset": 35000,  "hours_base": 6,  "hours_per_asset": 2},
    "SHADOW-001": {"category": "Asset Inventory & NAC","base": 600000,  "per_asset": 80000,  "hours_base": 30, "hours_per_asset": 6},
    "DATA-001": {"category": "Data Access Controls",   "base": 400000,  "per_asset": 100000, "hours_base": 16, "hours_per_asset": 8},
    "CLOUD-001": {"category": "Bucket ACL Fix",        "base": 100000,  "per_asset": 20000,  "hours_base": 4,  "hours_per_asset": 1},
    "SUPPLY-001": {"category": "Dependency Upgrade",   "base": 250000,  "per_asset": 60000,  "hours_base": 10, "hours_per_asset": 4},
}
_DEFAULT_COST = {"category": "General Hardening", "base": 200000, "per_asset": 50000, "hours_base": 8, "hours_per_asset": 3}


def _estimate_prevention_cost(paths: list[dict]) -> tuple[float, int, str]:
    """Estimate prevention cost from the distinct rule IDs across all paths."""
    rule_assets: dict[str, set] = {}
    for path in paths:
        for hop in path["hops"]:
            rule_id = hop.get("rule_id")
            if rule_id:
                rule_assets.setdefault(rule_id, set()).add(hop.get("target_id", 0))

    total_cost = 0.0
    total_hours = 0
    categories: list[str] = []
    for rule_id, asset_ids in rule_assets.items():
        spec = RULE_REMEDIATION_COSTS.get(rule_id, _DEFAULT_COST)
        cost = spec["base"] + spec["per_asset"] * len(asset_ids)
        hours = spec["hours_base"] + spec["hours_per_asset"] * len(asset_ids)
        total_cost += cost
        total_hours += hours
        if spec["category"] not in categories:
            categories.append(spec["category"])

    summary_parts = categories[:3]
    summary = f"~{total_hours} engineering hours across {', '.join(summary_parts)}"
    if len(categories) > 3:
        summary += f" and {len(categories) - 3} other area(s)"
    summary += "."
    return total_cost, total_hours, summary


def _categorize_paths(paths: list[dict], classifications: dict[int, dict]) -> list[dict]:
    scenarios = {
        "external_rce": {"name": "External RCE", "desc": "Remote code execution from the public internet.", "paths": []},
        "credential_compromise": {"name": "Credential Compromise", "desc": "Login surface bypassed or breached via auth CVE.", "paths": []},
        "supply_chain": {"name": "Supply Chain / 3rd Party", "desc": "Outdated exposed dependency.", "paths": []},
        "data_exfiltration": {"name": "Data Exfiltration", "desc": "Direct path to a Tier 1 or 2 data store.", "paths": []},
        "lateral_movement": {"name": "Lateral Movement", "desc": "Internal pivot chain across subnets.", "paths": []},
        "shadow_device_pivot": {"name": "Shadow Pivot", "desc": "Pivot through an unmanaged device.", "paths": []},
        "admin_takeover": {"name": "Admin Takeover", "desc": "Exposed admin panel leveraged for full control.", "paths": []},
        "cloud_exposure": {"name": "Cloud Exposure", "desc": "Publicly exposed storage or bucket.", "paths": []},
    }
    
    for path in paths:
        path_added = False
        target_id = path["asset_sequence"][-1]
        target_class = classifications.get(target_id, {})

        has_takeover = any(hop.get("rule_id") == "TAKEOVER-001" for hop in path["hops"])
        mult = 1.0
        if has_takeover:
            mult = max(mult, FINDING_MULTIPLIERS["subdomain_takeover"])

        has_rce = any((hop.get("cvss") or 0.0) >= 9.0 and hop.get("attack_vector") == "NETWORK" for hop in path["hops"])
        has_shadow = any(hop.get("rule_id") == "SHADOW-001" for hop in path["hops"])
        has_admin = any(hop.get("rule_id") == "MISC-001" for hop in path["hops"])
        has_bucket = any(hop.get("rule_id") == "CLOUD-001" for hop in path["hops"])
        if has_bucket:
            mult = max(mult, FINDING_MULTIPLIERS["public_s3"])
        if has_admin:
            mult = max(mult, FINDING_MULTIPLIERS["exposed_admin"])
        path["impact_multiplier"] = mult
        has_lateral = any(hop.get("rule_id") == "NET-001" for hop in path["hops"])
        has_supply = any(hop.get("rule_id") == "SUPPLY-001" for hop in path["hops"])
        has_cred = any(hop.get("rule_id") == "CRED-001" for hop in path["hops"])
        
        if target_class.get("data_sensitivity_tier", 4) <= 2:
            scenarios["data_exfiltration"]["paths"].append(path)
            path_added = True
            
        if has_bucket:
            scenarios["cloud_exposure"]["paths"].append(path)
            path_added = True
            
        if has_admin:
            scenarios["admin_takeover"]["paths"].append(path)
            path_added = True
            
        if has_rce:
            scenarios["external_rce"]["paths"].append(path)
            path_added = True
            
        if has_shadow:
            scenarios["shadow_device_pivot"]["paths"].append(path)
            path_added = True
            
        if has_lateral:
            scenarios["lateral_movement"]["paths"].append(path)
            path_added = True
            
        if has_supply:
            scenarios["supply_chain"]["paths"].append(path)
            path_added = True
            
        if has_cred:
            scenarios["credential_compromise"]["paths"].append(path)
            path_added = True
            
    return scenarios

def compute_impact(db, scan) -> Optional[dict]:
    from backend.db.models import ImpactReport
    from backend.intelligence.attack_path import build_candidate_paths
    from backend.intelligence.graph_builder import build_edges, to_networkx
    
    company_size = scan.company_size or "small"
    industry = scan.industry_sector or "technology"
    processes_pii = getattr(scan, "processes_pii", True)
    if processes_pii is None:
        processes_pii = True
        
    size_metrics = COMPANY_SIZES.get(company_size, COMPANY_SIZES["small"])
    ind_mult = INDUSTRY_MULTIPLIERS.get(industry, 1.0)
    
    # 1. Asset Classifications
    classifications = [_classify_asset(a) for a in scan.assets]
    class_by_id = {c["asset_id"]: c for c in classifications}
    
    max_tier_hit = 4
    for asset in scan.assets:
        if asset.exposure == "external" or asset.is_crown_jewel or scan.target_subnet:
            tier = class_by_id.get(asset.id, {}).get("data_sensitivity_tier", 4)
            if tier < max_tier_hit:
                max_tier_hit = tier

    # 2. Paths
    edges = build_edges(scan)
    graph = to_networkx(scan, edges)
    paths = build_candidate_paths(scan, graph, limit=50)
    
    if not paths:
        return None
        
    asset_count = len(scan.assets) or 1
    finding_count = sum(1 for a in scan.assets if getattr(a, 'cves', None) or getattr(a, 'admin_panels', None) or getattr(a, 'is_shadow_device', False) or getattr(a, 'ssl_info', None)) + len(paths)
    
    max_cvss = max((hop.get("cvss") or 0.0 for p in paths for hop in p["hops"]), default=0.0)
    if max_cvss == 0.0:
        max_cvss = max((cve.cvss_score or 0.0 for a in scan.assets for cve in getattr(a, 'cves', [])), default=0.0)

    # 3. Calculators
    reg_exposure = _calculate_regulatory_exposure(size_metrics, max_tier_hit, processes_pii)
    op_loss = _calculate_operational_loss(size_metrics, ind_mult, max_tier_hit, max_cvss, asset_count, finding_count)
    
    tot_min = reg_exposure["min_inr"] + op_loss["total_min_inr"]
    tot_max = reg_exposure["max_inr"] + op_loss["total_max_inr"]

    # 4. Scenarios
    scenarios_data = _categorize_paths(paths, class_by_id)
    out_scenarios = []
    
    for key, data in scenarios_data.items():
        if not data["paths"]:
            continue
        
        path_count = len(data["paths"])
        prevention, eng_hours, prevention_summary = _estimate_prevention_cost(data["paths"])
        
        bucket_mult = max((p.get("impact_multiplier", 1.0) for p in data["paths"]), default=1.0)
        exposure_min = tot_min * (path_count / len(paths)) * bucket_mult
        exposure_max = tot_max * (path_count / len(paths)) * bucket_mult
        average_exposure = (exposure_min + exposure_max) / 2
        
        out_scenarios.append({
            "scenario_id": key,
            "name": data["name"],
            "description": data["desc"],
            "attacker_skill": "apt" if "RCE" in data["name"] or "Pivot" in data["name"] else "criminal",
            "estimated_execution_time": "Less than 24 hours",
            "estimated_dwell_time": "1 - 3 months",
            "data_at_risk": ["Customer PII", "Corporate credentials"] if max_tier_hit <= 2 else ["Internal configs"],
            "path_count": path_count,
            "paths": data["paths"][:5], # Keep top 5 per scenario
            "total_exposure_min_inr": exposure_min,
            "total_exposure_max_inr": exposure_max,
            "prevention_cost_inr": prevention,
            "prevention_summary": prevention_summary,
            "roi_ratio": average_exposure / prevention if prevention > 0 else 0,
        })
        
    out_scenarios.sort(key=lambda x: x["total_exposure_max_inr"], reverse=True)

    report = ImpactReport(
        scan_id=scan.id,
        asset_classifications=classifications,
        regulatory_min_inr=reg_exposure["min_inr"],
        regulatory_max_inr=reg_exposure["max_inr"],
        regulatory_breakdown=reg_exposure["breakdown"],
        downtime_cost_min_inr=op_loss["downtime"]["min_inr"],
        downtime_cost_max_inr=op_loss["downtime"]["max_inr"],
        incident_response_min_inr=op_loss["incident_response"]["min_inr"],
        incident_response_max_inr=op_loss["incident_response"]["max_inr"],
        churn_cost_min_inr=op_loss["customer_churn"]["min_inr"],
        churn_cost_max_inr=op_loss["customer_churn"]["max_inr"],
        operational_breakdown={
            "mttr_low": op_loss["downtime"]["mttr_hours_low"],
            "mttr_high": op_loss["downtime"]["mttr_hours_high"],
        },
        total_exposure_min_inr=tot_min,
        total_exposure_max_inr=tot_max,
        scenario_matrix=out_scenarios,
        executive_advisory=None,
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    # Generate executive advisory via local Ollama (fire-and-forget, non-blocking)
    advisory = _generate_executive_advisory(scan, tot_min, tot_max, out_scenarios, max_tier_hit)
    if advisory:
        report.executive_advisory = advisory
        db.commit()
    
    return {
        "report_id": report.id,
        "total_exposure_min_inr": tot_min,
        "total_exposure_max_inr": tot_max,
        "total_formatted": f"{_format_inr(tot_min)} - {_format_inr(tot_max)}",
        "scenario_count": len(out_scenarios),
        "top_scenario_name": out_scenarios[0]["name"] if out_scenarios else "None",
    }


def _generate_executive_advisory(scan, tot_min: float, tot_max: float,
                                  scenarios: list[dict], max_tier: int) -> Optional[str]:
    """Call local Ollama Llama 3.2 to produce a CISO-level advisory. Returns None on failure."""
    import httpx
    import logging

    log = logging.getLogger(__name__)

    top_scenarios = ", ".join(s["name"] for s in scenarios[:3]) or "None"
    prompt = (
        f"You are the CISO writing a 4-sentence executive advisory for the board.\n"
        f"Domain: {scan.target_domain}. Company size: {scan.company_size or 'unknown'}. "
        f"Industry: {scan.industry_sector or 'unknown'}.\n"
        f"Total breach exposure: {_format_inr(tot_min)} to {_format_inr(tot_max)}.\n"
        f"Top attack scenarios: {top_scenarios}.\n"
        f"Highest data sensitivity tier compromised: Tier {max_tier}.\n"
        f"Lead with the single biggest business risk, then the financial exposure, "
        f"then the most urgent remediation action, and close with a timeline recommendation. "
        f"Be direct, no filler."
    )

    try:
        resp = httpx.post(
            "http://localhost:11434/api/generate",
            json={"model": "llama3.2", "prompt": prompt, "stream": False},
            timeout=30.0,
        )
        if resp.status_code == 200:
            text = resp.json().get("response", "").strip()
            return text if text else None
    except Exception as e:
        log.debug("Ollama advisory generation failed (non-critical): %s", e)
    return None
