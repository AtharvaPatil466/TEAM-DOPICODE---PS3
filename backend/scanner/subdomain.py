"""Subdomain enumeration: DNS brute-force + crt.sh certificate transparency."""
import asyncio
import logging
from typing import Iterable

import httpx
import dns.asyncresolver
import dns.exception

from .wordlists import COMMON_SUBDOMAINS

log = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
DNS_CONCURRENCY = 40
DNS_TIMEOUT = 3.0


async def _resolve(resolver: dns.asyncresolver.Resolver, name: str) -> str | None:
    try:
        answers = await resolver.resolve(name, "A", lifetime=DNS_TIMEOUT)
        if answers:
            return name
    except (dns.exception.DNSException, asyncio.TimeoutError):
        return None
    return None


async def _brute_force(domain: str, words: Iterable[str]) -> set[str]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    sem = asyncio.Semaphore(DNS_CONCURRENCY)

    async def one(w: str) -> str | None:
        async with sem:
            return await _resolve(resolver, f"{w}.{domain}")

    results = await asyncio.gather(*(one(w) for w in words))
    return {r for r in results if r}


async def _crtsh(domain: str) -> set[str]:
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(CRTSH_URL.format(domain=domain))
            if r.status_code != 200:
                return set()
            data = r.json()
    except (httpx.HTTPError, ValueError) as e:
        log.warning("crt.sh failed for %s: %s", domain, e)
        return set()
    found: set[str] = set()
    for row in data:
        name_value = row.get("name_value", "")
        for n in name_value.splitlines():
            n = n.strip().lower().lstrip("*.")
            if n and (n == domain or n.endswith("." + domain)):
                found.add(n)
    return found


async def enumerate_subdomains(domain: str, wordlist: list[str] | None = None) -> list[str]:
    domain = domain.lower().strip().lstrip(".")
    words = wordlist or COMMON_SUBDOMAINS
    brute_task = asyncio.create_task(_brute_force(domain, words))
    crt_task = asyncio.create_task(_crtsh(domain))
    brute, crt = await asyncio.gather(brute_task, crt_task)
    all_subs = brute | crt
    all_subs.add(domain)  # always include apex
    return sorted(all_subs)
