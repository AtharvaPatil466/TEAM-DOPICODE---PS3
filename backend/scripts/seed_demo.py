"""Seed a deterministic demo scan with a controlled external attack surface."""
from __future__ import annotations

import argparse
from datetime import UTC, datetime

from backend.db import SessionLocal, init_db
from backend.db.models import Asset, CVE, Port, Scan
from backend.intelligence.attack_path import compute_attack_path
from backend.intelligence.graph_builder import build_edges, persist_edges, to_networkx


def _add_port(db, asset, port, service, version=None, protocol="tcp"):
    db.add(Port(
        asset_id=asset.id,
        port_number=port,
        protocol=protocol,
        service_name=service,
        service_version=version,
        state="open",
    ))


def _add_cve(
    db,
    asset,
    cve_id,
    cvss,
    description,
    remediation,
    vector="NETWORK",
    complexity="LOW",
):
    from backend.intelligence import kev as kev_mod
    kev_info = kev_mod.lookup(cve_id) or {}
    db.add(CVE(
        asset_id=asset.id,
        cve_id=cve_id,
        cvss_score=cvss,
        description=description,
        remediation=remediation,
        attack_vector=vector,
        attack_complexity=complexity,
        in_kev=bool(kev_info.get("in_kev")),
        kev_ransomware=bool(kev_info.get("kev_ransomware")),
        kev_date_added=kev_info.get("kev_date_added"),
    ))


def _add_asset(
    db,
    scan,
    *,
    hostname=None,
    ip_address=None,
    exposure,
    asset_type,
    risk_score,
    tech_stack=None,
    admin_panels=None,
    ssl_info=None,
    os_guess=None,
    is_shadow_device=False,
    is_crown_jewel=False,
):
    asset = Asset(
        scan_id=scan.id,
        hostname=hostname,
        ip_address=ip_address,
        exposure=exposure,
        asset_type=asset_type,
        risk_score=risk_score,
        tech_stack=tech_stack,
        admin_panels=admin_panels,
        ssl_info=ssl_info,
        os_guess=os_guess,
        is_shadow_device=is_shadow_device,
        is_crown_jewel=is_crown_jewel,
    )
    db.add(asset)
    db.flush()
    return asset


def _good_tls(days_to_expiry=90):
    return {
        "issuer": "Let's Encrypt",
        "days_to_expiry": days_to_expiry,
        "hostname_match": True,
        "self_signed": False,
        "expired": False,
        "expiring_soon": days_to_expiry <= 14,
    }


def _seed_external_assets(db, scan, domain: str) -> list[Asset]:
    bucket_name = f"{domain.split('.', 1)[0]}-backup"
    assets: list[Asset] = []

    www = _add_asset(
        db,
        scan,
        hostname=f"www.{domain}",
        exposure="external",
        asset_type="web",
        risk_score=82.0,
        tech_stack={
            "technologies": [
                {"name": "WordPress", "category": "cms", "version": "5.8.1"},
                {"name": "PHP", "category": "language", "version": "8.0.30"},
            ],
            "server": "nginx/1.22.1",
            "issue": "outdated_cms",
            "issue_summary": "The production site exposes a known WordPress build with mapped SQL injection risk.",
            "remediation_summary": "Upgrade WordPress core and review plugins for unsupported versions.",
        },
        admin_panels=[{"path": "/wp-admin", "status": 200, "auth": True}],
        ssl_info=_good_tls(73),
    )
    _add_cve(
        db,
        www,
        "CVE-2022-21661",
        8.8,
        "WordPress before 5.8.3 is vulnerable to blind SQL injection through WP_Query parameter handling.",
        "Upgrade WordPress to 5.8.3 or later and remove unsupported plugins.",
    )
    assets.append(www)

    api = _add_asset(
        db,
        scan,
        hostname=f"api.{domain}",
        exposure="external",
        asset_type="api",
        risk_score=62.0,
        tech_stack={
            "technologies": [
                {"name": "Express", "category": "framework", "version": "4.18.2"},
            ],
            "server": "nginx/1.24.0",
            "issue": "public_docs",
            "issue_summary": "Interactive OpenAPI docs are publicly reachable and disclose internal route structure.",
            "remediation_summary": "Restrict API docs and disable verbose discovery routes outside trusted ranges.",
        },
        admin_panels=[{"path": "/docs", "status": 200, "auth": False}],
        ssl_info=_good_tls(64),
    )
    assets.append(api)

    staging = _add_asset(
        db,
        scan,
        hostname=f"staging.{domain}",
        exposure="external",
        asset_type="web",
        risk_score=84.0,
        tech_stack={
            "technologies": [
                {"name": "Next.js", "category": "frontend", "version": "14.1.0"},
            ],
            "server": "Vercel edge",
            "issue": "debug_build",
            "issue_summary": "A public staging build exposes debug tooling and verbose stack traces.",
            "remediation_summary": "Remove public staging exposure and disable debug assets in deployment builds.",
        },
        admin_panels=[{"path": "/debug", "status": 200, "auth": False}],
        ssl_info=_good_tls(51),
    )
    assets.append(staging)

    dev = _add_asset(
        db,
        scan,
        hostname=f"dev.{domain}",
        exposure="external",
        asset_type="web",
        risk_score=74.0,
        tech_stack={
            "technologies": [
                {"name": "Django", "category": "framework", "version": "4.2.11"},
            ],
            "server": "gunicorn/21.2.0",
            "issue": "git_exposure",
            "issue_summary": "Public .git metadata leaks commit history, deployment paths, and environment references.",
            "remediation_summary": "Block VCS metadata and redeploy from a clean artifact without repository content.",
        },
        admin_panels=[],
        ssl_info=_good_tls(33),
    )
    assets.append(dev)

    admin = _add_asset(
        db,
        scan,
        hostname=f"admin.{domain}",
        exposure="external",
        asset_type="web",
        risk_score=90.0,
        tech_stack={
            "technologies": [
                {"name": "Atlassian Confluence", "category": "collaboration", "version": "8.5.1"},
            ],
            "server": "nginx/1.22.1",
            "issue": "exposed_admin",
            "issue_summary": "A public admin portal still exposes a vulnerable Confluence login surface to the internet.",
            "remediation_summary": "Move admin access behind VPN or an allowlist and patch Confluence immediately.",
        },
        admin_panels=[{"path": "/login", "status": 200, "auth": False}],
        ssl_info=_good_tls(19),
    )
    _add_cve(
        db,
        admin,
        "CVE-2023-22515",
        9.8,
        "Broken access control in Confluence Data Center and Server can allow unauthorized administrator creation.",
        "Upgrade Confluence to a fixed release and disable public access to the administration plane.",
    )
    assets.append(admin)

    legacy = _add_asset(
        db,
        scan,
        hostname=f"legacy.{domain}",
        exposure="external",
        asset_type="web",
        risk_score=93.0,
        tech_stack={
            "technologies": [
                {"name": "Apache httpd", "category": "server", "version": "2.4.49"},
                {"name": "PHP", "category": "language", "version": "7.4.33"},
            ],
            "server": "Apache/2.4.49 (Unix)",
            "issue": "critical_cve",
            "issue_summary": "The legacy site is pinned to Apache 2.4.49 with public RCE-grade CVEs.",
            "remediation_summary": "Upgrade Apache immediately and retire the legacy stack from public exposure.",
        },
        admin_panels=[{"path": "/admin", "status": 200, "auth": False}],
        ssl_info={
            "issuer": "DigiCert",
            "days_to_expiry": 4,
            "hostname_match": True,
            "self_signed": False,
            "expired": False,
            "expiring_soon": True,
        },
    )
    _add_cve(
        db,
        legacy,
        "CVE-2021-41773",
        9.8,
        "Apache HTTP Server 2.4.49 path traversal and file disclosure vulnerability with RCE potential when mod_cgi is enabled.",
        "Upgrade Apache httpd to 2.4.51 or later immediately.",
    )
    _add_cve(
        db,
        legacy,
        "CVE-2021-42013",
        9.8,
        "Apache 2.4.49 and 2.4.50 remain vulnerable to path traversal and remote code execution.",
        "Upgrade Apache httpd to 2.4.51 or later and disable mod_cgi if not required.",
    )
    assets.append(legacy)

    backup = _add_asset(
        db,
        scan,
        hostname=f"backup.{domain}",
        exposure="external",
        asset_type="web",
        risk_score=78.0,
        tech_stack={
            "technologies": [
                {"name": "Apache httpd", "category": "server", "version": "2.4.57"},
            ],
            "server": "Apache/2.4.57 (Unix)",
            "issue": "directory_listing",
            "issue_summary": "A backup host exposes downloadable archive listings and stale export bundles.",
            "remediation_summary": "Disable directory listing and move backup artifacts off public infrastructure.",
        },
        admin_panels=[],
        ssl_info=_good_tls(120),
    )
    assets.append(backup)

    mail = _add_asset(
        db,
        scan,
        hostname=f"mail.{domain}",
        exposure="external",
        asset_type="web",
        risk_score=57.0,
        tech_stack={
            "technologies": [
                {"name": "Roundcube", "category": "webmail", "version": "1.6.7"},
            ],
            "server": "Apache/2.4.57 (Unix)",
            "issue": "no_https",
            "issue_summary": "Webmail is reachable over plaintext HTTP with no HSTS enforcement.",
            "remediation_summary": "Force HTTPS, redirect HTTP to TLS, and enforce HSTS for all mail interfaces.",
        },
        admin_panels=[{"path": "/webmail", "status": 200, "auth": True}],
        ssl_info=None,
    )
    assets.append(mail)

    ci = _add_asset(
        db,
        scan,
        hostname=f"ci.{domain}",
        exposure="external",
        asset_type="web",
        risk_score=81.0,
        tech_stack={
            "technologies": [
                {"name": "Jenkins", "category": "devops", "version": "2.441"},
            ],
            "server": "Jetty(10.0.18)",
            "issue": "jenkins_exposure",
            "issue_summary": "The CI server is exposed with a file-read CVE and a self-signed certificate.",
            "remediation_summary": "Patch Jenkins and restrict CI access to trusted operators and networks only.",
        },
        admin_panels=[
            {"path": "/login", "status": 200, "auth": False},
            {"path": "/jenkins", "status": 200, "auth": False},
        ],
        ssl_info={
            "issuer": "Internal CA",
            "days_to_expiry": 118,
            "hostname_match": False,
            "self_signed": True,
            "expired": False,
            "expiring_soon": False,
        },
    )
    _add_cve(
        db,
        ci,
        "CVE-2024-23897",
        9.1,
        "Jenkins CLI argument parsing allows attackers to read arbitrary files from the controller.",
        "Upgrade Jenkins to 2.442 or later, or the fixed LTS line.",
    )
    assets.append(ci)

    internal = _add_asset(
        db,
        scan,
        hostname=f"internal.{domain}",
        exposure="external",
        asset_type="web",
        risk_score=67.0,
        tech_stack={
            "technologies": [
                {"name": "nginx", "category": "server", "version": "1.24.0"},
            ],
            "server": "nginx/1.24.0",
            "issue": "intranet_exposure",
            "issue_summary": "An intranet portal is publicly reachable and presents a self-signed certificate.",
            "remediation_summary": "Remove the portal from the public edge and replace internal trust assumptions.",
        },
        admin_panels=[{"path": "/portal", "status": 200, "auth": True}],
        ssl_info={
            "issuer": "ShadowTrace Internal CA",
            "days_to_expiry": 210,
            "hostname_match": False,
            "self_signed": True,
            "expired": False,
            "expiring_soon": False,
        },
    )
    assets.append(internal)

    bucket = _add_asset(
        db,
        scan,
        hostname=f"{bucket_name}.s3.amazonaws.com",
        exposure="external",
        asset_type="storage",
        risk_score=97.0,
        tech_stack={
            "provider": "aws",
            "bucket_name": bucket_name,
            "url": f"https://{bucket_name}.s3.amazonaws.com",
            "issue": "public_listing",
            "issue_summary": "The backup bucket is publicly listable and exposes convincing internal-looking files.",
            "remediation_summary": "Disable public listing, rotate exposed credentials, and move backups to private storage.",
            "sample_files": [
                "employee-data-2024.csv",
                "db-backup-march.sql",
                "api-keys.txt",
            ],
        },
        admin_panels=[],
        ssl_info=None,
    )
    assets.append(bucket)

    return assets


def _seed_internal_assets(db, scan) -> list[Asset]:
    assets: list[Asset] = []

    int_apache = _add_asset(
        db,
        scan,
        hostname="shadowlab-apache",
        ip_address="172.28.0.10",
        exposure="internal",
        asset_type="web",
        risk_score=95.0,
        os_guess="Linux 5.x",
    )
    _add_port(db, int_apache, 80, "http", "Apache httpd 2.4.49")
    _add_cve(
        db,
        int_apache,
        "CVE-2021-41773",
        9.8,
        "Apache HTTP Server 2.4.49 path traversal allows remote code execution when mod_cgi is enabled.",
        "Upgrade to 2.4.51 or later and disable mod_cgi where possible.",
    )
    assets.append(int_apache)

    int_mysql = _add_asset(
        db,
        scan,
        hostname="shadowlab-mysql",
        ip_address="172.28.0.20",
        exposure="internal",
        asset_type="db",
        risk_score=88.0,
        os_guess="Linux 5.x",
        is_crown_jewel=True,
    )
    _add_port(db, int_mysql, 3306, "mysql", "MySQL 5.7.36")
    _add_cve(
        db,
        int_mysql,
        "CVE-2022-21417",
        7.2,
        "MySQL Server contains a local privilege-escalation flaw in InnoDB.",
        "Upgrade MySQL to 5.7.38 or later, or the equivalent supported 8.0 release.",
        vector="LOCAL",
        complexity="HIGH",
    )
    assets.append(int_mysql)

    int_iot = _add_asset(
        db,
        scan,
        ip_address="172.28.0.30",
        exposure="internal",
        asset_type="iot",
        risk_score=48.0,
        is_shadow_device=True,
    )
    _add_port(db, int_iot, 80, "http", "BusyBox httpd 1.36")
    assets.append(int_iot)

    int_rogue = _add_asset(
        db,
        scan,
        hostname="shadowlab-rogue",
        ip_address="172.28.0.40",
        exposure="internal",
        asset_type="workstation",
        risk_score=55.0,
        os_guess="Alpine Linux",
        is_shadow_device=True,
    )
    _add_port(db, int_rogue, 22, "ssh", "OpenSSH 9.3")
    assets.append(int_rogue)

    return assets


def seed(
    domain: str = "shadowtrace-demo.xyz",
    subnet: str = "172.28.0.0/24",
    include_internal: bool = False,
) -> int:
    init_db()
    db = SessionLocal()
    try:
        scan = Scan(
            target_domain=domain,
            target_subnet=subnet if include_internal else None,
            status="completed",
            progress=100,
            start_time=datetime.now(UTC),
            end_time=datetime.now(UTC),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        external_assets = _seed_external_assets(db, scan, domain)
        internal_assets = _seed_internal_assets(db, scan) if include_internal else []

        scan.total_assets = len(external_assets) + len(internal_assets)
        scan.total_cves = (
            db.query(CVE)
            .join(Asset, CVE.asset_id == Asset.id)
            .filter(Asset.scan_id == scan.id)
            .count()
        )
        db.commit()
        db.refresh(scan)

        edges = build_edges(scan)
        persist_edges(db, scan, edges)
        graph = to_networkx(scan, edges)
        compute_attack_path(db, scan, graph)
        return scan.id
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", default="shadowtrace-demo.xyz", help="Root domain shown in the cached demo.")
    parser.add_argument("--subnet", default="172.28.0.0/24", help="Internal subnet used only when --include-internal is set.")
    parser.add_argument(
        "--include-internal",
        action="store_true",
        help="Include the internal pivot layer after organizer approval.",
    )
    args = parser.parse_args()
    scan_id = seed(domain=args.domain, subnet=args.subnet, include_internal=args.include_internal)
    scope = "external+internal" if args.include_internal else "external-only"
    print(f"Seeded demo scan id={scan_id} scope={scope} domain={args.domain}")


if __name__ == "__main__":
    main()
