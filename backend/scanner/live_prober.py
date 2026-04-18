"""Probe candidate hosts over HTTP and HTTPS; record status, redirects, headers."""
import asyncio
import logging
from dataclasses import dataclass, field

import httpx

log = logging.getLogger(__name__)

PROBE_CONCURRENCY = 30
PROBE_TIMEOUT = 8.0


MAX_BODY_BYTES = 200_000


@dataclass
class LiveHost:
    host: str
    url: str
    status_code: int
    final_url: str
    headers: dict[str, str] = field(default_factory=dict)
    scheme: str = "http"
    body: str = ""

    def is_https(self) -> bool:
        return self.scheme == "https"


async def _probe_one(client: httpx.AsyncClient, host: str, scheme: str) -> LiveHost | None:
    url = f"{scheme}://{host}"
    try:
        r = await client.get(url, follow_redirects=True, timeout=PROBE_TIMEOUT)
    except (httpx.HTTPError, OSError) as e:
        log.debug("probe %s failed: %s", url, e)
        return None
    body = r.text[:MAX_BODY_BYTES] if r.text else ""
    return LiveHost(
        host=host,
        url=url,
        status_code=r.status_code,
        final_url=str(r.url),
        headers={k.lower(): v for k, v in r.headers.items()},
        scheme=scheme,
        body=body,
    )


async def probe_hosts(hosts: list[str]) -> list[LiveHost]:
    """Probe each host over HTTPS first, then HTTP if HTTPS fails."""
    sem = asyncio.Semaphore(PROBE_CONCURRENCY)
    results: list[LiveHost] = []

    async with httpx.AsyncClient(verify=False, http2=False) as client:
        async def one(h: str) -> None:
            async with sem:
                live = await _probe_one(client, h, "https")
                if live is None:
                    live = await _probe_one(client, h, "http")
                if live is not None:
                    results.append(live)

        await asyncio.gather(*(one(h) for h in hosts))
    return results
