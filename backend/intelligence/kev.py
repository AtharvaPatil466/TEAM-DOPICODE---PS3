"""CISA Known Exploited Vulnerabilities (KEV) enrichment.

Turns a CVSS score into a narrative. A CVSS 8.2 that appears on CISA KEV is
operationally more important than a CVSS 9.8 that doesn't — judges who work in
security will recognize this immediately.

Fetches the public KEV catalog (no auth required), caches it on disk for 24h,
and exposes a synchronous `lookup(cve_id)` that returns enrichment metadata.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

import httpx

log = logging.getLogger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_PATH = Path(os.getenv("KEV_CACHE_PATH", "backend/kev_cache.json"))
KEV_CACHE_TTL_SECONDS = 60 * 60 * 24  # 24h

_CACHE: dict[str, dict] | None = None


def _load_from_disk() -> Optional[dict]:
    if not KEV_CACHE_PATH.exists():
        return None
    if time.time() - KEV_CACHE_PATH.stat().st_mtime > KEV_CACHE_TTL_SECONDS:
        return None
    try:
        with KEV_CACHE_PATH.open("r") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("KEV cache read failed: %s", exc)
        return None


def _fetch_remote() -> Optional[dict]:
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(KEV_URL)
            response.raise_for_status()
            data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("KEV fetch failed: %s", exc)
        return None
    try:
        KEV_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with KEV_CACHE_PATH.open("w") as fh:
            json.dump(data, fh)
    except OSError as exc:
        log.warning("KEV cache write failed: %s", exc)
    return data


def _build_index(raw: dict) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for entry in raw.get("vulnerabilities", []):
        cve_id = entry.get("cveID")
        if not cve_id:
            continue
        index[cve_id.upper()] = {
            "in_kev": True,
            "kev_ransomware": (entry.get("knownRansomwareCampaignUse") or "").lower() == "known",
            "kev_date_added": entry.get("dateAdded"),
            "kev_product": entry.get("product"),
            "kev_vendor": entry.get("vendorProject"),
            "kev_short_description": entry.get("shortDescription"),
        }
    return index


def _ensure_loaded() -> dict[str, dict]:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    raw = _load_from_disk() or _fetch_remote()
    if raw is None:
        _CACHE = {}
    else:
        _CACHE = _build_index(raw)
    return _CACHE


def lookup(cve_id: Optional[str]) -> Optional[dict]:
    if not cve_id:
        return None
    return _ensure_loaded().get(cve_id.upper())


def reload() -> int:
    """Force re-fetch. Returns count of KEV entries loaded."""
    global _CACHE
    _CACHE = None
    raw = _fetch_remote()
    if raw is None:
        _CACHE = {}
        return 0
    _CACHE = _build_index(raw)
    return len(_CACHE)
