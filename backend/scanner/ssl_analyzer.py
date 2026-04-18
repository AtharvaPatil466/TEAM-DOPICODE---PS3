"""SSL/TLS certificate analysis: expiry, hostname match, issuer, self-signed."""
import asyncio
import logging
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

log = logging.getLogger(__name__)

TIMEOUT = 6.0


@dataclass
class SSLInfo:
    host: str
    port: int
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_to_expiry: int | None = None
    hostname_match: bool = False
    self_signed: bool = False
    expired: bool = False
    expiring_soon: bool = False  # within 30 days
    san: list[str] | None = None
    error: str | None = None


def _parse_cert_time(s: str) -> datetime:
    return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def _flatten(field) -> str:
    return ", ".join("=".join(x) for pair in field for x in pair)


def _analyze_sync(host: str, port: int = 443) -> SSLInfo:
    info = SSLInfo(host=host, port=port)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want to inspect even broken certs
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except (socket.gaierror, socket.timeout, ConnectionError, OSError, ssl.SSLError) as e:
        info.error = str(e)
        return info

    if not cert:
        info.error = "no certificate returned"
        return info

    info.subject = _flatten(cert.get("subject", ()))
    info.issuer = _flatten(cert.get("issuer", ()))
    info.self_signed = info.subject == info.issuer
    info.not_before = cert.get("notBefore")
    info.not_after = cert.get("notAfter")
    if info.not_after:
        try:
            exp = _parse_cert_time(info.not_after)
            delta = (exp - datetime.now(timezone.utc)).days
            info.days_to_expiry = delta
            info.expired = delta < 0
            info.expiring_soon = 0 <= delta <= 30
        except ValueError:
            pass

    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    info.san = sans or None

    # Hostname match — accept exact or wildcard one-level match.
    info.hostname_match = _hostname_matches(host, cert)
    return info


def _hostname_matches(host: str, cert: dict) -> bool:
    host = host.lower().rstrip(".")
    names: list[str] = []
    for k, v in cert.get("subjectAltName", ()):
        if k == "DNS":
            names.append(v.lower())
    if not names:
        for pair in cert.get("subject", ()):
            for k, v in pair:
                if k == "commonName":
                    names.append(v.lower())
    for n in names:
        if n == host:
            return True
        if n.startswith("*.") and host.endswith(n[1:]) and host.count(".") == n.count("."):
            return True
    return False


async def analyze(host: str, port: int = 443) -> SSLInfo:
    return await asyncio.to_thread(_analyze_sync, host, port)


async def analyze_batch(hosts: list[str], port: int = 443, concurrency: int = 20) -> list[SSLInfo]:
    sem = asyncio.Semaphore(concurrency)

    async def one(h: str) -> SSLInfo:
        async with sem:
            return await analyze(h, port)

    return await asyncio.gather(*(one(h) for h in hosts))
