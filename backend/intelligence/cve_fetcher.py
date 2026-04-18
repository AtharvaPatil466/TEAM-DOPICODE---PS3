"""NVD CVE lookups with SQLite cache.

Uses the NVD REST API 2.0 — https://services.nvd.nist.gov/rest/json/cves/2.0
Caches by a (product, version) key so we never hit the live API during demo.
"""
import logging
from dataclasses import dataclass
from datetime import datetime

import httpx
from sqlalchemy.orm import Session

from backend.config import NVD_API_KEY
from backend.db.models import CVECache
from backend.intelligence import kev

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT = 3.0
MAX_RESULTS_PER_QUERY = 20


@dataclass
class CVERecord:
    cve_id: str
    description: str
    cvss_score: float | None
    attack_vector: str | None
    attack_complexity: str | None
    remediation: str
    in_kev: bool = False
    kev_ransomware: bool = False
    kev_date_added: str | None = None


def _key(product: str, version: str | None) -> str:
    return f"{(product or '').lower().strip()}:{(version or '').lower().strip()}"


def _remediation_for(product: str, version: str | None) -> str:
    if version:
        return f"Upgrade {product} from {version} to the latest patched release. Review NVD entry for specific guidance."
    return f"Upgrade {product} to the latest patched release. Review NVD entry for specific guidance."


def _parse_nvd_item(item: dict) -> CVERecord | None:
    cve = item.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        return None
    descs = cve.get("descriptions") or []
    description = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
    metrics = cve.get("metrics", {})
    score = None
    vector = None
    complexity = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            data = metrics[key][0].get("cvssData", {})
            score = data.get("baseScore")
            vector = data.get("attackVector") or data.get("accessVector")
            complexity = data.get("attackComplexity") or data.get("accessComplexity")
            break
    return CVERecord(
        cve_id=cve_id,
        description=description,
        cvss_score=float(score) if score is not None else None,
        attack_vector=vector,
        attack_complexity=complexity,
        remediation="",
    )


def _load_cached(db: Session, key: str) -> list[CVERecord]:
    rows = db.query(CVECache).filter(CVECache.service_key == key).all()
    return [
        CVERecord(
            cve_id=r.cve_id,
            description=r.description or "",
            cvss_score=r.cvss_score,
            attack_vector=r.attack_vector,
            attack_complexity=r.attack_complexity,
            remediation=r.remediation or "",
            in_kev=bool(r.in_kev),
            kev_ransomware=bool(r.kev_ransomware),
            kev_date_added=r.kev_date_added,
        )
        for r in rows
    ]


def _store(db: Session, key: str, recs: list[CVERecord]) -> None:
    for r in recs:
        db.add(CVECache(
            service_key=key,
            cve_id=r.cve_id,
            description=r.description,
            cvss_score=r.cvss_score,
            attack_vector=r.attack_vector,
            attack_complexity=r.attack_complexity,
            remediation=r.remediation,
            in_kev=r.in_kev,
            kev_ransomware=r.kev_ransomware,
            kev_date_added=r.kev_date_added,
            cached_at=datetime.utcnow(),
        ))
    db.commit()


def _apply_kev(rec: CVERecord) -> CVERecord:
    info = kev.lookup(rec.cve_id)
    if info is None:
        return rec
    rec.in_kev = True
    rec.kev_ransomware = bool(info.get("kev_ransomware"))
    rec.kev_date_added = info.get("kev_date_added")
    return rec


# Vendor lookup for CPE-based NVD queries. When nmap reports service=redis
# version=5.0.5, keyword search for "redis 5.0.5" returns 0 (NVD matches
# the literal phrase). CPE lookup `cpe:2.3:a:redis:redis:5.0.5` returns 26.
_CPE_VENDORS: dict[str, str] = {
    "redis": "redis",
    "http": "apache",          # nmap labels apache as "http"
    "httpd": "apache",
    "apache": "apache",
    "mysql": "oracle",
    "ssh": "openbsd",
    "openssh": "openbsd",
    "flask": "palletsprojects",
    "werkzeug": "palletsprojects",
    "nginx": "nginx",
    "postgresql": "postgresql",
    "busybox": "busybox",
}

# Some services want a different product slug than nmap's service string.
_CPE_PRODUCTS: dict[str, str] = {
    "http": "http_server",
    "httpd": "http_server",
    "apache": "http_server",
    "ssh": "openssh",
}


def _cpe_string(product: str, version: str) -> str | None:
    prod_lower = (product or "").lower().strip()
    vendor = _CPE_VENDORS.get(prod_lower)
    if not vendor:
        return None
    cpe_product = _CPE_PRODUCTS.get(prod_lower, prod_lower)
    return f"cpe:2.3:a:{vendor}:{cpe_product}:{version}"


async def _nvd_query(params: dict) -> list[dict]:
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        async with httpx.AsyncClient(timeout=NVD_TIMEOUT) as client:
            r = await client.get(NVD_URL, params=params, headers=headers)
            if r.status_code != 200:
                log.warning("NVD %s -> %s", params, r.status_code)
                return []
            return r.json().get("vulnerabilities", []) or []
    except (httpx.HTTPError, ValueError) as e:
        log.warning("NVD fetch failed for %s: %s", params, e)
        return []


async def fetch_cves(db: Session, product: str, version: str | None) -> list[CVERecord]:
    """Look up CVEs for a product/version with caching.

    Lookup strategy (stop at first hit):
      1. CPE virtualMatchString (most precise) when vendor is known
      2. Keyword "product version"
      3. Keyword "product" alone (catches versioned hits NVD refuses to
         match as a literal phrase — e.g. "redis 5.0.5" returns 0 hits,
         but "redis" returns 177)
    """
    key = _key(product, version)
    cached = _load_cached(db, key)
    if cached:
        return cached

    items: list[dict] = []
    if version:
        cpe = _cpe_string(product, version)
        if cpe:
            items = await _nvd_query({"virtualMatchString": cpe, "resultsPerPage": MAX_RESULTS_PER_QUERY})
        if not items:
            items = await _nvd_query({"keywordSearch": f"{product} {version}", "resultsPerPage": MAX_RESULTS_PER_QUERY})
    if not items:
        items = await _nvd_query({"keywordSearch": product, "resultsPerPage": MAX_RESULTS_PER_QUERY})

    recs: list[CVERecord] = []
    for it in items:
        rec = _parse_nvd_item(it)
        if rec is None:
            continue
        rec.remediation = _remediation_for(product, version)
        _apply_kev(rec)
        recs.append(rec)

    # Keep top by (KEV status, CVSS) — KEV-listed entries are always more operationally important.
    recs.sort(key=lambda r: (r.in_kev, r.cvss_score or 0), reverse=True)
    recs = recs[:10]
    _store(db, key, recs)
    return recs
