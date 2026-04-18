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


async def fetch_cves(db: Session, product: str, version: str | None) -> list[CVERecord]:
    """Look up CVEs for a product/version. Cached results returned directly.

    NVD keyword search is used — CPE-based lookup is more precise but requires
    CPE resolution. Keyword is good enough for hackathon demo; filter by
    product match + recency in the caller if needed.
    """
    key = _key(product, version)
    cached = _load_cached(db, key)
    if cached:
        return cached

    query = f"{product} {version}" if version else product
    params = {"keywordSearch": query, "resultsPerPage": MAX_RESULTS_PER_QUERY}
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    try:
        async with httpx.AsyncClient(timeout=NVD_TIMEOUT) as client:
            r = await client.get(NVD_URL, params=params, headers=headers)
            if r.status_code != 200:
                log.warning("NVD %s -> %s", query, r.status_code)
                return []
            data = r.json()
    except (httpx.HTTPError, ValueError) as e:
        log.warning("NVD fetch failed for %s: %s", query, e)
        return []

    items = data.get("vulnerabilities", []) or []
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
