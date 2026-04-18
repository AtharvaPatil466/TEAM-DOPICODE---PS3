"""Scan job orchestrator. Runs the pipeline asynchronously and emits events."""
import asyncio
import logging
from datetime import datetime

from backend.db import SessionLocal
from backend.db.models import Scan
from backend.api.events import bus

log = logging.getLogger(__name__)


async def run_scan(scan_id: int, domain: str, subnet: str | None) -> None:
    """Run the full scan pipeline. Stubbed phases emit progress events so the
    frontend has a working contract from day one. Real implementations replace
    each phase in place."""
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = "running"
        db.commit()
        await bus.publish("scan_started", {"domain": domain, "subnet": subnet}, scan_id)

        phases = [
            ("subdomain_enum", 10),
            ("live_prober", 20),
            ("tech_fingerprint", 30),
            ("admin_panel", 40),
            ("cloud_bucket", 50),
            ("ssl_analyzer", 55),
            ("nmap_internal", 70),
            ("cve_lookup", 80),
            ("risk_scoring", 85),
            ("graph_build", 90),
            ("attack_path", 95),
            ("anomaly_classify", 100),
        ]
        for name, pct in phases:
            await asyncio.sleep(0.1)  # placeholder — real phases replace this
            scan.progress = pct
            db.commit()
            await bus.publish("progress", {"phase": name, "percent": pct}, scan_id)

        scan.status = "completed"
        scan.end_time = datetime.utcnow()
        db.commit()
        await bus.publish("scan_completed", {"scan_id": scan_id}, scan_id)
    except Exception as e:
        log.exception("scan failed")
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            db.commit()
        await bus.publish("scan_failed", {"error": str(e)}, scan_id)
    finally:
        db.close()
