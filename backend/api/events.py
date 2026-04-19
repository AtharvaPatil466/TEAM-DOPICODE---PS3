"""WebSocket broadcast hub and in-process event bus for scan progress."""
import asyncio
from datetime import datetime
from typing import Any
from fastapi import WebSocket


class EventBus:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()
        self._history: list[dict] = []  # replay buffer for late joiners
        self._scan_subscribers: dict[int, set[asyncio.Queue]] = {}

    async def connect(self, ws: WebSocket, scan_id: int | None = None) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)
        for evt in self._history[-200:]:
            if scan_id is not None and evt.get("scan_id") != scan_id:
                continue
            try:
                await ws.send_json(evt)
            except Exception:
                break

    async def subscribe_scan(self, ws: WebSocket, scan_id: int) -> None:
        """Accept ws, replay history for this scan, then stream live events in PRD envelope."""
        await ws.accept()
        for evt in list(self._history):
            if evt.get("scan_id") == scan_id:
                try:
                    await ws.send_json(_to_prd_envelope(evt))
                except Exception:
                    return
        filtered: asyncio.Queue = asyncio.Queue()

        async def _sink() -> None:
            while True:
                evt = await filtered.get()
                try:
                    await ws.send_json(_to_prd_envelope(evt))
                except Exception:
                    return

        self._scan_subscribers.setdefault(scan_id, set()).add(filtered)
        sink_task = asyncio.create_task(_sink())
        try:
            while True:
                await ws.receive_text()
        except Exception:
            pass
        finally:
            self._scan_subscribers.get(scan_id, set()).discard(filtered)
            sink_task.cancel()

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def reset_history(self) -> None:
        async with self._lock:
            self._history = []

    async def publish(self, event_type: str, payload: dict[str, Any], scan_id: int | None = None) -> None:
        event = {
            "type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
            "scan_id": scan_id,
            "payload": payload,
        }
        self._history.append(event)
        if len(self._history) > 1000:
            self._history = self._history[-500:]
        dead: list[WebSocket] = []
        async with self._lock:
            clients = list(self._clients)
        for ws in clients:
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._clients.discard(ws)
        if scan_id is not None:
            for q in list(self._scan_subscribers.get(scan_id, set())):
                try:
                    q.put_nowait(event)
                except Exception:
                    pass


_PHASE_MESSAGES = {
    "subdomain_enum": "Enumerating subdomains",
    "live_prober": "Probing live hosts",
    "takeover_check": "Checking for subdomain takeovers",
    "admin_panel": "Hunting exposed admin panels",
    "cloud_bucket": "Searching for public buckets",
    "ssl_analyzer": "Inspecting TLS posture",
    "nmap_host_discovery": "Discovering internal hosts",
    "graph_build": "Building attack graph",
    "attack_path": "Computing kill chains",
    "impact_simulation": "Modeling breach impact",
    "anomaly_classify": "Classifying shadow devices",
}


def _to_prd_envelope(evt: dict) -> dict:
    """Translate internal bus events into the PRD WS contract:
    {event, percent, message, new_finding, scan_id, timestamp}."""
    t = evt.get("type", "")
    payload = evt.get("payload") or {}
    percent = payload.get("percent")
    new_finding = None
    message = t.replace("_", " ")

    if t == "progress":
        phase = payload.get("phase") or ""
        base = _PHASE_MESSAGES.get(phase.split(":", 1)[0], phase or "Working")
        if "found" in payload:
            message = f"{base} — {payload['found']} found"
        elif percent is not None:
            message = f"{base} ({percent}%)"
        else:
            message = base
    elif t == "host_discovered":
        h = payload.get("hostname") or payload.get("ip") or "host"
        message = f"Found host: {h}"
        new_finding = {"kind": "host", **payload}
    elif t == "port_open":
        message = f"Open port {payload.get('port')} ({payload.get('service') or 'unknown'}) on {payload.get('ip')}"
        new_finding = {"kind": "port", **payload}
    elif t == "cve_found":
        message = f"Vulnerability: {payload.get('cve_id')} (CVSS {payload.get('cvss')})"
        new_finding = {"kind": "cve", **payload}
    elif t == "subdomain_takeover_detected":
        message = f"Subdomain takeover {payload.get('status')}: {payload.get('host')} → {payload.get('provider')}"
        new_finding = {"kind": "takeover", **payload}
    elif t == "cloud_bucket_found":
        message = f"Cloud bucket exposed: {payload.get('url')} ({payload.get('provider')})"
        new_finding = {"kind": "bucket", **payload}
    elif t == "shadow_device_detected":
        message = f"Shadow device detected at {payload.get('ip')}"
        new_finding = {"kind": "shadow", **payload}
    elif t == "attack_path_computed":
        vs = payload.get("validation_summary") or {}
        message = f"Attack path modeled — {vs.get('confirmed', 0)}/{vs.get('total', 0)} hops confirmed"
        new_finding = {"kind": "path", **payload}
    elif t == "impact_computed":
        message = f"Breach impact modeled — top scenario: {payload.get('top_scenario')}"
        new_finding = {"kind": "impact", **payload}
    elif t == "scan_started":
        message = f"Scan started on {payload.get('domain')}"
    elif t == "scan_completed":
        message = f"Scan complete — {payload.get('assets')} assets, {payload.get('cves')} CVEs"
        percent = 100
    elif t == "scan_failed":
        message = f"Scan failed: {payload.get('error')}"

    return {
        "event": t,
        "percent": percent,
        "message": message,
        "new_finding": new_finding,
        "scan_id": evt.get("scan_id"),
        "timestamp": evt.get("timestamp"),
    }


bus = EventBus()
