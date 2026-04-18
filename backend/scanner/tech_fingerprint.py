"""Lightweight tech stack fingerprinting from HTTP response.
Matches against headers, HTML meta/generator tags, cookie names, and known
script paths. Not Wappalyzer-complete — covers what's useful for risk scoring.
"""
import re
from dataclasses import dataclass, field
from typing import Iterable

from .live_prober import LiveHost


# (label, category, matcher) where matcher is a dict of conditions.
# condition keys: header (name, regex), cookie (name), html (regex), powered_by (regex)
SIGNATURES: list[tuple[str, str, dict]] = [
    ("WordPress", "cms", {"html": r"wp-content|wp-includes|/wp-json/"}),
    ("Drupal", "cms", {"html": r"Drupal\.settings|/sites/default/files/"}),
    ("Joomla", "cms", {"html": r"/media/jui/|joomla!"}),
    ("Django", "framework", {"cookie": "csrftoken"}),
    ("Rails", "framework", {"cookie": "_rails_session"}),
    ("Laravel", "framework", {"cookie": "laravel_session"}),
    ("Express", "framework", {"header": ("x-powered-by", r"express")}),
    ("ASP.NET", "framework", {"header": ("x-powered-by", r"asp\.net")}),
    ("PHP", "language", {"header": ("x-powered-by", r"php")}),
    ("Nginx", "server", {"header": ("server", r"nginx")}),
    ("Apache httpd", "server", {"header": ("server", r"apache")}),
    ("IIS", "server", {"header": ("server", r"microsoft-iis")}),
    ("Cloudflare", "cdn", {"header": ("server", r"cloudflare")}),
    ("Akamai", "cdn", {"header": ("server", r"akamai")}),
    ("AWS CloudFront", "cdn", {"header": ("via", r"cloudfront")}),
    ("Fastly", "cdn", {"header": ("x-served-by", r"fastly|cache-")}),
    ("Next.js", "framework", {"header": ("x-powered-by", r"next\.js")}),
    ("React", "frontend", {"html": r"__NEXT_DATA__|react-dom"}),
    ("Vue", "frontend", {"html": r"vue\.js|__vue__"}),
    ("jQuery", "frontend", {"html": r"jquery(-|\.|/)[\d.]+"}),
    ("Jenkins", "devops", {"header": ("x-jenkins", r".*")}),
    ("Kubernetes Dashboard", "devops", {"html": r"kubernetes-dashboard"}),
    ("phpMyAdmin", "admin", {"html": r"phpmyadmin"}),
    ("Grafana", "monitoring", {"html": r"grafana"}),
]


@dataclass
class TechFingerprint:
    technologies: list[dict] = field(default_factory=list)  # {name, category}
    server: str | None = None
    powered_by: str | None = None

    def names(self) -> list[str]:
        return [t["name"] for t in self.technologies]


def _match(host: LiveHost, body: str, cond: dict) -> bool:
    if "header" in cond:
        hname, hregex = cond["header"]
        v = host.headers.get(hname.lower(), "")
        if v and re.search(hregex, v, re.I):
            return True
        return False
    if "cookie" in cond:
        cookies = host.headers.get("set-cookie", "")
        return cond["cookie"].lower() in cookies.lower()
    if "html" in cond:
        return bool(re.search(cond["html"], body, re.I))
    return False


def fingerprint(host: LiveHost, body: str = "") -> TechFingerprint:
    fp = TechFingerprint(
        server=host.headers.get("server"),
        powered_by=host.headers.get("x-powered-by"),
    )
    seen: set[str] = set()
    for name, category, cond in SIGNATURES:
        if name in seen:
            continue
        if _match(host, body, cond):
            fp.technologies.append({"name": name, "category": category})
            seen.add(name)
    # Extract version suffixes when server header is like "Apache/2.4.49 (Unix)".
    if fp.server:
        m = re.match(r"([A-Za-z][A-Za-z0-9_\-]*)/([0-9][0-9A-Za-z.\-]*)", fp.server)
        if m:
            prod, ver = m.group(1), m.group(2)
            for t in fp.technologies:
                if prod.lower() in t["name"].lower():
                    t["version"] = ver
                    break
    return fp


def fingerprint_batch(hosts_with_bodies: Iterable[tuple[LiveHost, str]]) -> dict[str, TechFingerprint]:
    return {h.host: fingerprint(h, body) for h, body in hosts_with_bodies}
