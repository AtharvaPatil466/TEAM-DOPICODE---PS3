"""Probe each live host against a curated list of admin/login paths."""
import asyncio
import logging
from dataclasses import dataclass

import httpx

from .live_prober import LiveHost
from .wordlists import ADMIN_PANEL_PATHS

log = logging.getLogger(__name__)

PROBE_CONCURRENCY = 20
PROBE_TIMEOUT = 6.0
INTERESTING = {200, 301, 302, 401, 403}


@dataclass
class AdminHit:
    host: str
    path: str
    status_code: int
    final_url: str
    requires_auth: bool


async def _probe(client: httpx.AsyncClient, live: LiveHost, path: str) -> AdminHit | None:
    url = f"{live.scheme}://{live.host}{path}"
    try:
        r = await client.get(url, follow_redirects=False, timeout=PROBE_TIMEOUT)
    except (httpx.HTTPError, OSError):
        return None
    if r.status_code not in INTERESTING:
        return None
    return AdminHit(
        host=live.host,
        path=path,
        status_code=r.status_code,
        final_url=str(r.url),
        requires_auth=r.status_code in (401, 403),
    )


async def detect_admin_panels(hosts: list[LiveHost], paths: list[str] | None = None) -> list[AdminHit]:
    paths = paths or ADMIN_PANEL_PATHS
    sem = asyncio.Semaphore(PROBE_CONCURRENCY)
    hits: list[AdminHit] = []

    async with httpx.AsyncClient(verify=False) as client:
        async def one(live: LiveHost, path: str) -> None:
            async with sem:
                hit = await _probe(client, live, path)
                if hit is not None:
                    hits.append(hit)

        tasks = [one(h, p) for h in hosts for p in paths]
        await asyncio.gather(*tasks)
    return hits
