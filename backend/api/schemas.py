from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


class ScanStartRequest(BaseModel):
    domain: str
    subnet: Optional[str] = None


class ScanStartResponse(BaseModel):
    scan_id: int
    status: str


class ScanStatusResponse(BaseModel):
    scan_id: int
    status: str
    progress: int
    total_assets: int
    total_cves: int
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


class PortOut(BaseModel):
    port: int
    protocol: str
    service: Optional[str] = None
    version: Optional[str] = None
    state: str


class CVEOut(BaseModel):
    cve_id: str
    description: Optional[str] = None
    cvss: Optional[float] = None
    attack_vector: Optional[str] = None
    remediation: Optional[str] = None


class AssetSummary(BaseModel):
    id: int
    hostname: Optional[str] = None
    ip: Optional[str] = None
    asset_type: Optional[str] = None
    os: Optional[str] = None
    risk_score: float
    is_shadow_device: bool
    is_crown_jewel: bool
    exposure: str
    open_ports: list[int] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    cve_count: int = 0


class AssetDetail(AssetSummary):
    tech_stack: Optional[dict] = None
    admin_panels: Optional[list] = None
    ssl_info: Optional[dict] = None
    ports: list[PortOut] = Field(default_factory=list)
    cves: list[CVEOut] = Field(default_factory=list)
    graph_position: Optional[dict] = None


class GraphNode(BaseModel):
    id: int
    label: str
    risk_level: str  # low|medium|high|critical
    asset_type: Optional[str] = None
    is_crown_jewel: bool = False
    is_shadow_device: bool = False


class GraphEdgeOut(BaseModel):
    source: int
    target: int
    relationship: str


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdgeOut]


class AttackPathHop(BaseModel):
    asset_id: int
    label: str
    vulnerability: Optional[str] = None
    description: Optional[str] = None


class AttackPathResponse(BaseModel):
    hops: list[AttackPathHop]
    total_risk_score: float
    narrative: str


class LiveEvent(BaseModel):
    type: str  # host_discovered|port_open|cve_found|shadow_device_detected|attack_path_computed|scan_started|scan_completed|progress
    timestamp: datetime
    scan_id: Optional[int] = None
    payload: dict[str, Any] = Field(default_factory=dict)
