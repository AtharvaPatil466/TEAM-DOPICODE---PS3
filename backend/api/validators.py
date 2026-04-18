"""Input validators for public-facing API requests."""
import ipaddress
import re

_INTERNAL_SUFFIXES = ("localhost", ".local", ".internal", ".lan", ".intranet", ".corp", ".home")
_LABEL_RE = re.compile(r"^(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", re.IGNORECASE)


def normalize_domain(raw: str) -> str:
    """Normalize + validate a user-supplied domain.

    Strips scheme, path, port and whitespace. Rejects IPs, localhost, and
    RFC1918/internal suffixes. Raises ValueError with a user-safe message.
    """
    if not raw or not isinstance(raw, str):
        raise ValueError("domain is required")
    d = raw.strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    d = d.split(":", 1)[0]
    d = d.strip(".")
    if not d:
        raise ValueError("domain is empty after normalization")
    if len(d) > 253:
        raise ValueError("domain exceeds 253 chars")

    try:
        ip = ipaddress.ip_address(d)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError("internal / loopback addresses are not scannable")
        raise ValueError("raw IP addresses are not accepted — provide a domain name")
    except ValueError as e:
        if "not scannable" in str(e) or "not accepted" in str(e):
            raise

    if any(d == s.lstrip(".") or d.endswith(s) for s in _INTERNAL_SUFFIXES):
        raise ValueError("internal-network domains are not scannable")

    labels = d.split(".")
    if len(labels) < 2:
        raise ValueError("domain must include a TLD (e.g. example.com)")
    for label in labels:
        if not _LABEL_RE.match(label):
            raise ValueError(f"invalid domain label: {label!r}")
    return d
