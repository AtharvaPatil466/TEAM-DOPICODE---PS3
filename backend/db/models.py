from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text, JSON
)
from sqlalchemy.orm import relationship

from .session import Base


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True)
    target_domain = Column(String, nullable=False)
    target_subnet = Column(String, nullable=True)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    status = Column(String, default="pending")  # pending|running|completed|failed
    progress = Column(Integer, default=0)
    total_assets = Column(Integer, default=0)
    total_cves = Column(Integer, default=0)

    company_size = Column(String, nullable=True)      # small|medium|large
    industry_sector = Column(String, nullable=True)    # technology|retail|financial_services|healthcare|manufacturing|other
    processes_pii = Column(Boolean, default=True)      # conservative default

    assets = relationship("Asset", back_populates="scan", cascade="all, delete-orphan")
    edges = relationship("GraphEdge", back_populates="scan", cascade="all, delete-orphan")
    paths = relationship("AttackPath", back_populates="scan", cascade="all, delete-orphan")
    impact_reports = relationship("ImpactReport", back_populates="scan", cascade="all, delete-orphan")


class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    hostname = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    asset_type = Column(String, nullable=True)  # web|db|iot|workstation|router|unknown
    os_guess = Column(String, nullable=True)
    risk_score = Column(Float, default=0.0)
    is_shadow_device = Column(Boolean, default=False)
    is_crown_jewel = Column(Boolean, default=False)
    exposure = Column(String, default="internal")  # external|internal
    tech_stack = Column(JSON, nullable=True)
    admin_panels = Column(JSON, nullable=True)
    ssl_info = Column(JSON, nullable=True)
    discovered_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="assets")
    ports = relationship("Port", back_populates="asset", cascade="all, delete-orphan")
    cves = relationship("CVE", back_populates="asset", cascade="all, delete-orphan")


class Port(Base):
    __tablename__ = "ports"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    port_number = Column(Integer, nullable=False)
    protocol = Column(String, default="tcp")
    service_name = Column(String, nullable=True)
    service_version = Column(String, nullable=True)
    state = Column(String, default="open")

    asset = relationship("Asset", back_populates="ports")


class CVE(Base):
    __tablename__ = "cves"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False)
    cve_id = Column(String, nullable=False, index=True)
    description = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    attack_vector = Column(String, nullable=True)      # NVD AV:N / AV:L / AV:A / AV:P
    attack_complexity = Column(String, nullable=True)  # NVD AC:L / AC:H
    remediation = Column(Text, nullable=True)
    in_kev = Column(Boolean, default=False)             # CISA Known Exploited Vulnerabilities
    kev_ransomware = Column(Boolean, default=False)     # actively exploited in ransomware campaigns
    kev_date_added = Column(String, nullable=True)      # YYYY-MM-DD as published by CISA
    cached_at = Column(DateTime, default=datetime.utcnow)

    asset = relationship("Asset", back_populates="cves")


class CVECache(Base):
    """Standalone NVD cache keyed by service+version to avoid re-fetches."""
    __tablename__ = "cve_cache"
    id = Column(Integer, primary_key=True)
    service_key = Column(String, index=True, nullable=False)  # e.g. "apache httpd:2.4.49"
    cve_id = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    attack_vector = Column(String, nullable=True)
    attack_complexity = Column(String, nullable=True)
    remediation = Column(Text, nullable=True)
    in_kev = Column(Boolean, default=False)
    kev_ransomware = Column(Boolean, default=False)
    kev_date_added = Column(String, nullable=True)
    cached_at = Column(DateTime, default=datetime.utcnow)


class GraphEdge(Base):
    __tablename__ = "graph_edges"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    source_id = Column(Integer, nullable=False)   # 0 reserved for virtual Internet node
    target_id = Column(Integer, nullable=False)
    relationship_type = Column(String, default="reachable")
    weight = Column(Float, default=1.0)
    rule_id = Column(String, index=True, nullable=True)   # edge_rules.py rule that fired
    rationale = Column(Text, nullable=True)               # human-readable evidence
    attack_techniques = Column(JSON, nullable=True)       # list[str] MITRE ATT&CK IDs
    evidence = Column(JSON, nullable=True)                # structured predicate evidence
    verified_at = Column(DateTime, nullable=True)         # live-probe verification timestamp
    verification_evidence = Column(JSON, nullable=True)   # probe type + response snippet

    scan = relationship("Scan", back_populates="edges")


class AttackPath(Base):
    __tablename__ = "attack_paths"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    asset_sequence = Column(JSON, nullable=False)  # list[asset_id]
    total_risk_score = Column(Float, default=0.0)
    narrative = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="paths")


class ImpactReport(Base):
    __tablename__ = "impact_reports"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    
    # Asset classifications
    asset_classifications = Column(JSON)       # list[{asset_id, classification, tier}]
    
    # Regulatory exposure
    regulatory_min_inr = Column(Float)         # minimum penalty ₹
    regulatory_max_inr = Column(Float)         # maximum penalty ₹
    regulatory_breakdown = Column(JSON)        # detailed calculation steps
    
    # Operational losses
    downtime_cost_min_inr = Column(Float)
    downtime_cost_max_inr = Column(Float)
    incident_response_min_inr = Column(Float)
    incident_response_max_inr = Column(Float)
    churn_cost_min_inr = Column(Float)
    churn_cost_max_inr = Column(Float)
    operational_breakdown = Column(JSON)
    
    # Total exposure
    total_exposure_min_inr = Column(Float)
    total_exposure_max_inr = Column(Float)
    
    # Scenario matrix
    scenario_matrix = Column(JSON)             # list[scenario_dict]
    
    # LLM advisory
    executive_advisory = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    scan = relationship("Scan", back_populates="impact_reports")
