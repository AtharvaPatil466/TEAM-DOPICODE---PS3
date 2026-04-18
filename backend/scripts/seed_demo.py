"""Seed the database with a realistic demo scan — runs with NO network access.

Use this when:
  * Demo machine has no internet (judge's laptop, conference wifi is dead)
  * Docker lab isn't running
  * You want a deterministic scan that matches the demo narrative every time

Populates: 4 external assets, 4 internal lab assets, CVEs, graph edges, the
canonical two-hop attack path from exposed Apache -> MySQL crown jewel.

Run:  python -m backend.scripts.seed_demo
"""
from datetime import datetime

from backend.db import SessionLocal, init_db
from backend.db.models import (
    Asset, CVE, GraphEdge, Port, Scan, AttackPath,
)


def _add_port(db, asset, port, service, version=None, protocol="tcp"):
    db.add(Port(
        asset_id=asset.id, port_number=port, protocol=protocol,
        service_name=service, service_version=version, state="open",
    ))


def _add_cve(db, asset, cve_id, cvss, description, remediation, vector="NETWORK"):
    db.add(CVE(
        asset_id=asset.id, cve_id=cve_id, cvss_score=cvss,
        description=description, remediation=remediation,
        attack_vector=vector,
    ))


def seed(domain: str = "democorp.io", subnet: str = "172.28.0.0/24") -> int:
    init_db()
    db = SessionLocal()
    try:
        scan = Scan(
            target_domain=domain,
            target_subnet=subnet,
            status="completed",
            progress=100,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow(),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # --- External assets ---
        ext_www = Asset(
            scan_id=scan.id, hostname=f"www.{domain}", exposure="external",
            asset_type="web", risk_score=42.0,
            tech_stack={"technologies": [
                {"name": "Nginx", "category": "server", "version": "1.24.0"},
                {"name": "React", "category": "frontend"},
            ], "server": "nginx/1.24.0"},
            admin_panels=[],
            ssl_info={"issuer": "Let's Encrypt", "days_to_expiry": 62,
                      "hostname_match": True, "self_signed": False, "expired": False},
        )
        ext_api = Asset(
            scan_id=scan.id, hostname=f"api.{domain}", exposure="external",
            asset_type="web", risk_score=58.0,
            tech_stack={"technologies": [
                {"name": "Express", "category": "framework"},
            ], "server": "nginx/1.24.0", "powered_by": "Express"},
            admin_panels=[],
            ssl_info={"issuer": "Let's Encrypt", "days_to_expiry": 45,
                      "hostname_match": True, "self_signed": False, "expired": False},
        )
        ext_legacy = Asset(
            scan_id=scan.id, hostname=f"legacy.{domain}", exposure="external",
            asset_type="web", risk_score=92.5,
            tech_stack={"technologies": [
                {"name": "Apache httpd", "category": "server", "version": "2.4.49"},
                {"name": "PHP", "category": "language"},
            ], "server": "Apache/2.4.49 (Unix)"},
            admin_panels=[{"path": "/admin", "status": 200, "auth": False}],
            ssl_info={"issuer": "DigiCert", "days_to_expiry": 4,
                      "hostname_match": True, "self_signed": False,
                      "expired": False, "expiring_soon": True},
        )
        ext_ci = Asset(
            scan_id=scan.id, hostname=f"ci.{domain}", exposure="external",
            asset_type="web", risk_score=71.0,
            tech_stack={"technologies": [
                {"name": "Jenkins", "category": "devops"},
            ], "server": "Jetty(9.4.43)"},
            admin_panels=[{"path": "/login", "status": 200, "auth": False},
                          {"path": "/jenkins", "status": 200, "auth": False}],
            ssl_info={"issuer": "Internal CA", "days_to_expiry": 120,
                      "hostname_match": False, "self_signed": True, "expired": False},
        )
        db.add_all([ext_www, ext_api, ext_legacy, ext_ci])
        db.flush()

        _add_cve(db, ext_legacy, "CVE-2021-41773", 9.8,
                 "Apache HTTP Server 2.4.49 path traversal and file disclosure vulnerability.",
                 "Upgrade Apache httpd to 2.4.51 or later immediately.")
        _add_cve(db, ext_legacy, "CVE-2021-42013", 9.8,
                 "Apache 2.4.49/2.4.50 path traversal — follow-on to CVE-2021-41773.",
                 "Upgrade Apache httpd to 2.4.51 or later.")
        _add_cve(db, ext_ci, "CVE-2024-23897", 9.1,
                 "Jenkins CLI arbitrary file read via argument parsing.",
                 "Upgrade Jenkins to 2.442+ / LTS 2.426.3+.")

        # --- Internal (lab) assets ---
        int_apache = Asset(
            scan_id=scan.id, ip_address="172.28.0.10", hostname="shadowlab-apache",
            exposure="internal", asset_type="web", risk_score=95.0,
            os_guess="Linux 5.x", tech_stack=None, admin_panels=None,
        )
        int_mysql = Asset(
            scan_id=scan.id, ip_address="172.28.0.20", hostname="shadowlab-mysql",
            exposure="internal", asset_type="db", risk_score=88.0,
            is_crown_jewel=True, os_guess="Linux 5.x",
        )
        int_iot = Asset(
            scan_id=scan.id, ip_address="172.28.0.30", hostname=None,
            exposure="internal", asset_type="iot", risk_score=48.0,
            is_shadow_device=True, os_guess=None,
        )
        int_rogue = Asset(
            scan_id=scan.id, ip_address="172.28.0.40", hostname=None,
            exposure="internal", asset_type="workstation", risk_score=55.0,
            is_shadow_device=True, os_guess="Alpine Linux",
        )
        db.add_all([int_apache, int_mysql, int_iot, int_rogue])
        db.flush()

        _add_port(db, int_apache, 80, "http", "Apache httpd 2.4.49")
        _add_cve(db, int_apache, "CVE-2021-41773", 9.8,
                 "Apache HTTP Server 2.4.49 path traversal — allows RCE with mod_cgi.",
                 "Upgrade to 2.4.51+. Disable mod_cgi if not required.")

        _add_port(db, int_mysql, 3306, "mysql", "MySQL 5.7.36")
        _add_cve(db, int_mysql, "CVE-2022-21417", 7.2,
                 "MySQL Server privilege escalation in InnoDB.",
                 "Upgrade MySQL to 5.7.38+ or 8.0.28+.")

        _add_port(db, int_iot, 80, "http", "BusyBox httpd 1.36")
        _add_port(db, int_rogue, 22, "ssh", "OpenSSH 9.3")

        # --- Graph edges ---
        edges = [
            GraphEdge(scan_id=scan.id, source_id=0, target_id=ext_legacy.id,
                      relationship_type="internet_reachable", weight=101 - 92.5),
            GraphEdge(scan_id=scan.id, source_id=0, target_id=ext_ci.id,
                      relationship_type="internet_reachable", weight=101 - 71.0),
            GraphEdge(scan_id=scan.id, source_id=0, target_id=ext_api.id,
                      relationship_type="internet_reachable", weight=101 - 58.0),
            GraphEdge(scan_id=scan.id, source_id=0, target_id=ext_www.id,
                      relationship_type="internet_reachable", weight=101 - 42.0),
            GraphEdge(scan_id=scan.id, source_id=ext_legacy.id, target_id=int_apache.id,
                      relationship_type="pivot_internal", weight=101 - 95.0),
            GraphEdge(scan_id=scan.id, source_id=int_apache.id, target_id=int_mysql.id,
                      relationship_type="lateral", weight=101 - 88.0),
            GraphEdge(scan_id=scan.id, source_id=int_apache.id, target_id=int_iot.id,
                      relationship_type="lateral", weight=101 - 48.0),
            GraphEdge(scan_id=scan.id, source_id=int_apache.id, target_id=int_rogue.id,
                      relationship_type="lateral", weight=101 - 55.0),
        ]
        db.add_all(edges)

        # --- Canonical attack path ---
        path = AttackPath(
            scan_id=scan.id,
            asset_sequence=[0, ext_legacy.id, int_apache.id, int_mysql.id],
            total_risk_score=275.5,
            narrative=(
                "Step 1: Attacker starts on the public internet. "
                f"Step 2: Compromise legacy.{domain} (web) via CVE-2021-41773 (CVSS 9.8). "
                "Step 3: Compromise shadowlab-apache (web) via CVE-2021-41773 (CVSS 9.8). "
                "Step 4: Compromise shadowlab-mysql (crown jewel) via CVE-2022-21417 (CVSS 7.2)."
            ),
        )
        db.add(path)

        scan.total_assets = 8
        scan.total_cves = sum(len(a.cves) for a in
                              [ext_www, ext_api, ext_legacy, ext_ci,
                               int_apache, int_mysql, int_iot, int_rogue])
        db.commit()
        return scan.id
    finally:
        db.close()


if __name__ == "__main__":
    scan_id = seed()
    print(f"Seeded demo scan id={scan_id}")
