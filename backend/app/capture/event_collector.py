"""
Unified event collector for TraceCTF.

Every capture source (terminal, filesystem, screenshot, browser extension
later) calls EventCollector.handle_event() with a plain dict matching the
Event columns. This collector:
  1. Persists the raw event to SQLite immediately (source of truth).
  2. Pushes a lightweight reference onto the analysis queue for the
     background AI pipeline to pick up later — decoupled, never blocking.

This is the concrete implementation of the "capture never waits on AI"
principle from the architecture (NFR-2, NFR-3).
"""

from __future__ import annotations

import asyncio
import datetime
from typing import Optional

from app.db.database import AsyncSessionLocal
from app.db.models import Event


# ---------------------------------------------------------------------------
# Analysis queue — the background pipeline worker (queue_worker.py, next)
# consumes from this. Bounded size is intentional: if the pipeline falls
# far behind, we'd rather apply backpressure logging than grow unbounded.
# ---------------------------------------------------------------------------
analysis_queue: "asyncio.Queue[int]" = asyncio.Queue(maxsize=1000)


def _parse_timestamp(value: str) -> datetime.datetime:
    try:
        return datetime.datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return datetime.datetime.utcnow()


class EventCollector:
    """
    Single entry point all capture sources push events through.
    Instantiate once per session and pass `.handle_event` as the
    `on_event` callback to PTY wrappers, filesystem watcher, and
    screenshot capturer.
    """

    def __init__(self, session_id: int):
        self.session_id = session_id

    async def handle_event(self, event: dict) -> None:
        """
        event: dict with keys matching Event model columns.
        Required: session_id, source, timestamp.
        All other fields optional depending on source type.
        """
        async with AsyncSessionLocal() as db:
            db_event = Event(
                session_id=event.get("session_id", self.session_id),
                source=event["source"],
                timestamp=_parse_timestamp(event["timestamp"]),
                command=event.get("command"),
                stdout=event.get("stdout"),
                stderr=event.get("stderr"),
                cwd=event.get("cwd"),
                url=event.get("url"),
                http_method=event.get("http_method"),
                http_status=event.get("http_status"),
                file_path=event.get("file_path"),
                file_action=event.get("file_action"),
                screenshot_path=event.get("screenshot_path"),
                raw_metadata=event.get("raw_metadata"),
            )
            db.add(db_event)
            await db.commit()
            await db.refresh(db_event)

        await self._enqueue_for_analysis(db_event.id)

    async def _enqueue_for_analysis(self, event_id: int) -> None:
        """
        Non-blocking hand-off to the AI pipeline. If the queue is full
        (pipeline badly backed up), we drop the enqueue rather than
        block capture — the event is still safely in SQLite and can be
        picked up by a periodic "catch-up" sweep in the worker later.
        """
        try:
            analysis_queue.put_nowait(event_id)
        except asyncio.QueueFull:
            # Event is already persisted; only the "process me now" signal
            # is lost. The queue_worker's catch-up sweep (next files)
            # handles any events missed this way.
            pass