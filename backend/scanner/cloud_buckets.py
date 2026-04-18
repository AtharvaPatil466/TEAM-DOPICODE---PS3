"""Generate bucket-name permutations from a target and probe AWS S3 + Azure Blob."""
import asyncio
import logging
import re
from dataclasses import dataclass

import httpx

log = logging.getLogger(__name__)

PROBE_CONCURRENCY = 25
PROBE_TIMEOUT = 6.0

S3_TEMPLATES = [
    "https://{name}.s3.amazonaws.com",
    "https://s3.amazonaws.com/{name}",
]
AZURE_TEMPLATE = "https://{name}.blob.core.windows.net/?comp=list"

SUFFIXES = [
    "", "-assets", "-backup", "-backups", "-static", "-media", "-uploads",
    "-dev", "-staging", "-prod", "-production", "-internal", "-private",
    "-public", "-data", "-logs", "-archive", "-files", "-docs",
]


@dataclass
class BucketHit:
    url: str
    provider: str  # aws|azure
    public: bool
    listing_sample: str | None = None


def _base_names(domain: str) -> list[str]:
    # e.g. "shop.example.com" -> ["shop-example", "example", "shopexample"]
    parts = re.split(r"[.\-]", domain.lower())
    parts = [p for p in parts if p and p not in ("com", "net", "org", "io", "co", "www")]
    if not parts:
        return [domain.replace(".", "-")]
    names = set()
    names.add("-".join(parts))
    names.add("".join(parts))
    if parts:
        names.add(parts[0])
    return sorted(names)


def candidates_for(domain: str) -> list[str]:
    names = _base_names(domain)
    out: list[str] = []
    for n in names:
        for s in SUFFIXES:
            cand = (n + s).strip("-")
            if 3 <= len(cand) <= 63 and re.fullmatch(r"[a-z0-9][a-z0-9\-]*[a-z0-9]", cand):
                out.append(cand)
    return list(dict.fromkeys(out))


def _is_public_listing(body: str, provider: str) -> bool:
    if provider == "aws":
        return "<ListBucketResult" in body or "<Contents>" in body
    if provider == "azure":
        return "<EnumerationResults" in body or "<Blobs>" in body
    return False


async def _probe(client: httpx.AsyncClient, url: str, provider: str) -> BucketHit | None:
    try:
        r = await client.get(url, timeout=PROBE_TIMEOUT)
    except (httpx.HTTPError, OSError):
        return None
    if r.status_code == 404:
        return None
    # 200 with a listing body = public. 403 = bucket exists but not listable.
    if r.status_code == 200 and _is_public_listing(r.text, provider):
        return BucketHit(url=url, provider=provider, public=True, listing_sample=r.text[:500])
    if r.status_code in (403, 401):
        return BucketHit(url=url, provider=provider, public=False)
    return None


async def check_buckets(domain: str) -> list[BucketHit]:
    names = candidates_for(domain)
    sem = asyncio.Semaphore(PROBE_CONCURRENCY)
    hits: list[BucketHit] = []

    async with httpx.AsyncClient() as client:
        async def one(url: str, provider: str) -> None:
            async with sem:
                hit = await _probe(client, url, provider)
                if hit is not None:
                    hits.append(hit)

        tasks = []
        for n in names:
            for tmpl in S3_TEMPLATES:
                tasks.append(one(tmpl.format(name=n), "aws"))
            tasks.append(one(AZURE_TEMPLATE.format(name=n), "azure"))
        await asyncio.gather(*tasks)
    return hits
