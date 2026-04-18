"""Test stubs for Asset/CVE so rulebook tests don't touch the DB.

The edge rules only read attributes; duck-typed stubs are enough and keep
the suite fast (no sqlite fixture, no session teardown).
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class StubCVE:
    cve_id: str
    cvss_score: float | None = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    description: str = ""
    in_kev: bool = False
    kev_ransomware: bool = False
    kev_date_added: Optional[str] = None


@dataclass
class StubAsset:
    id: int
    ip_address: str
    hostname: Optional[str] = None
    exposure: str = "internal"
    asset_type: str = "server"
    tech_stack: Optional[dict] = None
    admin_panels: Optional[list] = None
    ssl_info: Optional[dict] = None
    cves: list = field(default_factory=list)
    is_shadow_device: bool = False
    is_crown_jewel: bool = False
    ports: list = field(default_factory=list)


def same_subnet(a: StubAsset, b: StubAsset) -> bool:
    if not a.ip_address or not b.ip_address:
        return False
    return a.ip_address.rsplit(".", 1)[0] == b.ip_address.rsplit(".", 1)[0]


def subnet_of(asset: StubAsset) -> str:
    prefix = asset.ip_address.rsplit(".", 1)[0]
    return f"{prefix}.0/24"


def default_ctx() -> dict:
    return {"scan": None, "same_subnet": same_subnet, "subnet_of": subnet_of}
