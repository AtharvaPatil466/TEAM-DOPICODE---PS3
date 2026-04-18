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

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)
        for evt in self._history[-200:]:
            try:
                await ws.send_json(evt)
            except Exception:
                break

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

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


bus = EventBus()
