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


async def _subfinder(domain: str, timeout: float = 20.0) -> set[str]:
    """Shell out to subfinder if the binary is available. Silent fallback on miss."""
    import shutil
    if not shutil.which("subfinder"):
        return set()
    try:
        proc = await asyncio.create_subprocess_exec(
            "subfinder", "-silent", "-d", domain, "-all", "-timeout", "10",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, OSError) as e:
        log.warning("subfinder failed for %s: %s", domain, e)
        return set()
    found: set[str] = set()
    for line in stdout.decode("utf-8", errors="ignore").splitlines():
        n = line.strip().lower().lstrip("*.")
        if n and (n == domain or n.endswith("." + domain)):
            found.add(n)
    return found


async def enumerate_subdomains(domain: str, wordlist: list[str] | None = None) -> list[str]:
    domain = domain.lower().strip().lstrip(".")
    words = wordlist or COMMON_SUBDOMAINS
    # Run subfinder, crt.sh, and DNS brute-force in parallel. Subfinder +
    # crt.sh are the primary source; brute-force is a fallback when they return
    # sparse results.
    subfinder_task = asyncio.create_task(_subfinder(domain))
    crt_task = asyncio.create_task(_crtsh(domain))
    brute_task = asyncio.create_task(_brute_force(domain, words))
    sf, crt, brute = await asyncio.gather(subfinder_task, crt_task, brute_task)
    all_subs = sf | crt | brute
    all_subs.add(domain)  # always include apex
    return sorted(all_subs)
