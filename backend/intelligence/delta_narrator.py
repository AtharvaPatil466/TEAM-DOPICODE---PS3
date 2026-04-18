"""One-line narrator for patch simulation deltas.

Receives only the validation before/after summary plus the patched target
labels — a small payload kept off the demo critical path. Falls back to a
deterministic sentence when the Anthropic API is unavailable.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Iterable, Optional

from backend.config import ANTHROPIC_API_KEY

log = logging.getLogger(__name__)

_MODEL = "claude-sonnet-4-6"
_MAX_TOKENS = 120
_TIMEOUT_S = 4.0


def _deterministic(
    patched_labels: list[str],
    patched_cves: list[str],
    before: dict,
    after: dict,
    blocked_path_ids: list[str],
) -> str:
    target = (
        ", ".join(patched_labels)
        if patched_labels
        else (", ".join(patched_cves) if patched_cves else "the selected remediation")
    )
    delta_paths = max(0, before.get("total", 0) - after.get("total", 0))
    delta_confirmed = max(0, before.get("confirmed", 0) - after.get("confirmed", 0))
    return (
        f"Patching {target} removes {delta_paths} path"
        f"{'' if delta_paths == 1 else 's'} and "
        f"{delta_confirmed} confirmed route"
        f"{'' if delta_confirmed == 1 else 's'}."
    )


async def narrate_simulation_delta(
    patched_labels: Iterable[str],
    patched_cves: Iterable[str],
    before: dict,
    after: dict,
    blocked_path_ids: Optional[list[str]] = None,
) -> str:
    patched_labels = list(patched_labels or [])
    patched_cves = list(patched_cves or [])
    blocked_path_ids = list(blocked_path_ids or [])

    fallback = _deterministic(patched_labels, patched_cves, before, after, blocked_path_ids)
    if not ANTHROPIC_API_KEY:
        return fallback

    payload = {
        "patched_assets": patched_labels,
        "patched_cves": patched_cves,
        "before": before,
        "after": after,
        "blocked_path_ids": blocked_path_ids,
    }
    prompt = (
        "You are a concise security analyst. Write ONE sentence (max 28 words) "
        "describing the impact of the proposed remediation. "
        "Quote the number of confirmed paths removed. "
        "If confirmed paths dropped to zero, say so explicitly. "
        "Do not use bullet points or emojis. "
        "Input:\n" + json.dumps(payload)
    )

    def _call() -> Optional[str]:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            msg = client.messages.create(
                model=_MODEL,
                max_tokens=_MAX_TOKENS,
                messages=[{"role": "user", "content": prompt}],
            )
            parts = [b.text for b in msg.content if getattr(b, "type", "") == "text"]
            return ("".join(parts)).strip() or None
        except Exception as exc:
            log.warning("delta narrator LLM call failed: %s", exc)
            return None

    try:
        text = await asyncio.wait_for(asyncio.to_thread(_call), timeout=_TIMEOUT_S)
    except asyncio.TimeoutError:
        log.warning("delta narrator timed out")
        text = None
    return text or fallback
