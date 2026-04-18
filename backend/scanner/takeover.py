"""Subdomain-takeover detector.

Checks CNAME targets against known dangling-provider fingerprints and
confirms with an HTTP body match. Returns per-host findings.
"""
import asyncio
import logging
from dataclasses import dataclass
from typing import Iterable

import httpx
import dns.asyncresolver
import dns.exception

log = logging.getLogger(__name__)

# provider: (cname_substrings, body_fingerprints)
FINGERPRINTS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "github_pages": (("github.io",), ("There isn't a GitHub Pages site here.",)),
    "heroku":       (("herokuapp.com", "herokudns.com"), ("No such app", "herokucdn.com/error-pages/no-such-app.html")),
    "netlify":      (("netlify.app", "netlify.com"), ("Not Found - Request ID",)),
    "aws_s3":       (("s3.amazonaws.com", "s3-website"), ("NoSuchBucket", "The specified bucket does not exist")),
    "shopify":      (("myshopify.com",), ("Sorry, this shop is currently unavailable",)),
    "zendesk":      (("zendesk.com",), ("Help Center Closed",)),
    "fastly":       (("fastly.net",), ("Fastly error: unknown domain",)),
    "surge":        (("surge.sh",), ("project not found",)),
}

DNS_TIMEOUT = 3.0
HTTP_TIMEOUT = 5.0


@dataclass
class TakeoverFinding:
    host: str
    provider: str
    cname: str
    status: str  # "confirmed" | "suspected"
    evidence: str


async def _resolve_cname(resolver: dns.asyncresolver.Resolver, host: str) -> str | None:
    try:
        answers = await resolver.resolve(host, "CNAME", lifetime=DNS_TIMEOUT)
        for a in answers:
            return str(a.target).rstrip(".").lower()
    except (dns.exception.DNSException, asyncio.TimeoutError):
        return None
    return None


def _match_provider(cname: str) -> str | None:
    for provider, (needles, _) in FINGERPRINTS.items():
        if any(n in cname for n in needles):
            return provider
    return None


async def _confirm_http(client: httpx.AsyncClient, host: str, provider: str) -> tuple[str, str]:
    _, fingerprints = FINGERPRINTS[provider]
    for scheme in ("https", "http"):
        try:
            r = await client.get(f"{scheme}://{host}", timeout=HTTP_TIMEOUT, follow_redirects=True)
            body = r.text or ""
            for fp in fingerprints:
                if fp in body:
                    return "confirmed", f"fingerprint {fp!r} in body"
            if r.status_code == 404:
                return "suspected", f"HTTP 404 from {provider}"
        except httpx.HTTPError:
            continue
    return "suspected", f"CNAME points at {provider} but no HTTP confirmation"


async def check_takeover(host: str, client: httpx.AsyncClient, resolver: dns.asyncresolver.Resolver) -> TakeoverFinding | None:
    cname = await _resolve_cname(resolver, host)
    if not cname:
        return None
    provider = _match_provider(cname)
    if not provider:
        return None
    status, evidence = await _confirm_http(client, host, provider)
    return TakeoverFinding(host=host, provider=provider, cname=cname, status=status, evidence=evidence)


async def scan_takeovers(hosts: Iterable[str], concurrency: int = 20) -> list[TakeoverFinding]:
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    sem = asyncio.Semaphore(concurrency)
    findings: list[TakeoverFinding] = []
    async with httpx.AsyncClient(verify=False) as client:
        async def one(h: str) -> None:
            async with sem:
                try:
                    f = await check_takeover(h, client, resolver)
                except Exception as e:  # never fail the whole scan on one host
                    log.debug("takeover check failed for %s: %s", h, e)
                    return
                if f:
                    findings.append(f)
        await asyncio.gather(*(one(h) for h in hosts))
    return findings
