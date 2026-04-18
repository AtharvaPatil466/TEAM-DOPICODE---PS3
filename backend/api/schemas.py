from datetime import datetime
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field

Persona = Literal["script_kiddie", "criminal", "apt"]


CompanySize = Literal["small", "medium", "large"]
IndustrySector = Literal["technology", "retail", "financial_services", "healthcare", "manufacturing", "other"]


class ScanStartRequest(BaseModel):
    domain: str
    subnet: Optional[str] = None
    company_size: Optional[CompanySize] = None
    industry_sector: Optional[IndustrySector] = None
    processes_pii: Optional[bool] = None


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


class LatestScanResponse(ScanStatusResponse):
    domain: str
    subnet: Optional[str] = None
    internal_scope: bool = False


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
    attack_complexity: Optional[str] = None
    remediation: Optional[str] = None
    in_kev: bool = False
    kev_ransomware: bool = False
    kev_date_added: Optional[str] = None


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
    rule_id: Optional[str] = None
    rationale: Optional[str] = None
    weight: float = 1.0
    attack_techniques: list[str] = Field(default_factory=list)
    evidence: Optional[dict] = None
    verified_at: Optional[datetime] = None
    verification_evidence: Optional[dict] = None


class GraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdgeOut]


class RulebookRuleOut(BaseModel):
    id: str
    name: str
    description: str
    attack_techniques: list[str] = Field(default_factory=list)


class AttackPathHop(BaseModel):
    asset_id: int
    label: str
    vulnerability: Optional[str] = None
    description: Optional[str] = None
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    rationale: Optional[str] = None
    relationship: Optional[str] = None
    cvss: Optional[float] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    estimated_window: Optional[str] = None
    attack_techniques: list[str] = Field(default_factory=list)
    evidence: Optional[dict] = None
    verified_at: Optional[datetime] = None


class HopValidation(BaseModel):
    hostname: str
    port: Optional[int] = None
    success: bool
    latency_ms: float
    rule_id: Optional[str] = None
    error: Optional[str] = None


class PathValidation(BaseModel):
    validated: bool
    confidence: str  # CONFIRMED | PARTIAL | UNVERIFIED
    hop_results: list[HopValidation] = Field(default_factory=list)


class AttackPathCandidate(BaseModel):
    path_id: str
    sequence_labels: list[str]
    total_risk_score: float
    estimated_window: str
    hops: list[AttackPathHop]
    validation: Optional[PathValidation] = None


class RemediationCandidate(BaseModel):
    summary: str
    blocks_paths: int
    path_ids: list[str]
    target_assets: list[str]
    rule_ids: list[str]
    max_cvss: float = 0.0


class AttackPathResponse(BaseModel):
    hops: list[AttackPathHop]
    total_risk_score: float
    narrative: str
    path_id: Optional[str] = None
    estimated_window: Optional[str] = None
    persona: Optional[str] = None
    validation: Optional[PathValidation] = None
    alternates: list[AttackPathCandidate] = Field(default_factory=list)
    remediation_candidates: list[RemediationCandidate] = Field(default_factory=list)


class SimulateRequest(BaseModel):
    patched_asset_ids: list[int] = Field(default_factory=list)
    patched_cve_ids: list[str] = Field(default_factory=list)
    persona: Optional[Persona] = None


class ValidationSummary(BaseModel):
    confirmed: int = 0
    partial: int = 0
    unverified: int = 0
    total: int = 0


class SimulateResponse(BaseModel):
    summary: str
    blocked_path_ids: list[str]
    introduced_path_ids: list[str]
    time_to_breach_delta_minutes: Optional[int] = None
    baseline: Optional[AttackPathResponse] = None
    simulated: Optional[AttackPathResponse] = None
    before: ValidationSummary = Field(default_factory=ValidationSummary)
    after: ValidationSummary = Field(default_factory=ValidationSummary)
    delta_summary: str = ""


class ScanDiffResponse(BaseModel):
    before_id: int
    after_id: int
    summary: str
    assets_added: list[dict]
    assets_removed: list[dict]
    edges_added: list[dict]
    edges_removed: list[dict]
    paths_broken: list[str]
    paths_introduced: list[str]
    risk_delta: float
    time_to_breach_delta_minutes: Optional[int] = None


class LabValidationResult(BaseModel):
    edge_id: int
    source_id: int
    target_id: int
    rule_id: Optional[str] = None
    verified: bool
    probe: Optional[str] = None
    status_code: Optional[int] = None
    snippet: Optional[str] = None
    error: Optional[str] = None


class LabValidateResponse(BaseModel):
    scan_id: int
    probes_run: int
    verified: int
    results: list[LabValidationResult]


class LiveEvent(BaseModel):
    type: str  # host_discovered|port_open|cve_found|shadow_device_detected|attack_path_computed|scan_started|scan_completed|progress
    timestamp: datetime
    scan_id: Optional[int] = None
    payload: dict[str, Any] = Field(default_factory=dict)


class AssetClassification(BaseModel):
    asset_id: int
    label: str
    classification: str
    data_sensitivity_tier: int


class RegulatoryExposure(BaseModel):
    min_inr: float
    max_inr: float
    min_formatted: str
    max_formatted: str
    applicable_law: str
    penalty_tier: str
    breakdown: dict


class OperationalLoss(BaseModel):
    downtime: dict
    incident_response: dict
    customer_churn: dict
    total_min_inr: float
    total_max_inr: float


class AttackScenario(BaseModel):
    scenario_id: str
    name: str
    description: str
    attacker_skill: str
    estimated_execution_time: str
    estimated_dwell_time: str
    data_at_risk: list[str]
    path_count: int
    paths: list[AttackPathCandidate]
    total_exposure_min_inr: float
    total_exposure_max_inr: float
    prevention_cost_inr: float
    prevention_summary: str
    roi_ratio: float


class ImpactResponse(BaseModel):
    scan_id: int
    company_size: str
    industry_sector: str
    asset_classifications: list[AssetClassification]
    regulatory_exposure: RegulatoryExposure
    operational_loss: OperationalLoss
    total_exposure_min_inr: float
    total_exposure_max_inr: float
    total_formatted: str
    executive_advisory: Optional[str] = None


class ScenarioMatrixResponse(BaseModel):
    scan_id: int
    total_paths: int
    total_scenarios: int
    scenarios: list[AttackScenario]


class ComplianceControl(BaseModel):
    control: str
    framework: str
    rule_ids: list[str]
    edge_count: int


class ComplianceSummaryResponse(BaseModel):
    scan_id: int
    total_violations: int
    controls: list[ComplianceControl]

