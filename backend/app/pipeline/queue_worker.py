"""
Background queue worker for TraceCTF's AI pipeline.

Consumes event IDs pushed by EventCollector, batches them according to
settings.analysis_batch_interval_seconds / analysis_batch_size, and runs
each through: finding_extractor -> evidence_linker.

Also runs a periodic "catch-up sweep" that finds any terminal events with
no linked finding yet (e.g., dropped from the queue during a rush per
event_collector.py's backpressure handling) and reprocesses them — this
guarantees no event is permanently skipped, only delayed.

NOTE ON GROUPING: v1 processes events individually (one event -> zero or
one finding). Multi-event correlation (e.g., grouping an nmap scan with a
follow-up curl into one finding) is listed as future pipeline enhancement
in the SRS — flagging here so the simplification is explicit, not silent.
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select, and_, not_, exists

from app.config import settings
from app.db.database import AsyncSessionLocal
from app.db.models import Event, Finding, FindingEvidence
from app.capture.event_collector import analysis_queue
from app.pipeline.llm_client import OllamaClient
from app.pipeline.finding_extractor import extract_finding_from_events
from app.pipeline.evidence_linker import persist_finding

logger = logging.getLogger("tracectf.queue_worker")

_llm_client = OllamaClient()


class QueueWorker:
    """
    Owns the background asyncio tasks for batch processing and catch-up
    sweeping. Start once at FastAPI startup, stop at shutdown.
    """

    def __init__(self):
        self._running = False
        self._batch_task: asyncio.Task | None = None
        self._sweep_task: asyncio.Task | None = None

    def start(self) -> None:
        self._running = True
        self._batch_task = asyncio.create_task(self._batch_loop())
        self._sweep_task = asyncio.create_task(self._catchup_sweep_loop())
        logger.info("QueueWorker started")

    async def stop(self) -> None:
        self._running = False
        for task in (self._batch_task, self._sweep_task):
            if task:
                task.cancel()
        logger.info("QueueWorker stopped")

    # -----------------------------------------------------------------
    # Main batch loop — drains the queue at a fixed interval
    # -----------------------------------------------------------------
    async def _batch_loop(self) -> None:
        while self._running:
            await asyncio.sleep(settings.analysis_batch_interval_seconds)
            try:
                event_ids = self._drain_queue(settings.analysis_batch_size)
                if event_ids:
                    await self._process_event_ids(event_ids)
            except Exception:
                logger.exception("Error during batch processing — continuing")

    def _drain_queue(self, max_items: int) -> list[int]:
        drained = []
        while len(drained) < max_items:
            try:
                drained.append(analysis_queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return drained

    # -----------------------------------------------------------------
    # Catch-up sweep — finds terminal events with no finding yet
    # -----------------------------------------------------------------
    async def _catchup_sweep_loop(self) -> None:
        # Runs less frequently than the batch loop; purely a safety net
        sweep_interval = max(settings.analysis_batch_interval_seconds * 5, 30)
        while self._running:
            await asyncio.sleep(sweep_interval)
            try:
                await self._sweep_unprocessed_events()
            except Exception:
                logger.exception("Error during catch-up sweep — continuing")

    async def _sweep_unprocessed_events(self) -> None:
        async with AsyncSessionLocal() as db:
            # Events with source='terminal' that have no row in finding_evidence
            has_evidence = exists().where(FindingEvidence.event_id == Event.id)
            stmt = select(Event.id).where(
                and_(Event.source == "terminal", not_(has_evidence))
            ).limit(settings.analysis_batch_size)

            result = await db.execute(stmt)
            missed_ids = [row[0] for row in result.all()]

        if missed_ids:
            logger.info(f"Catch-up sweep found {len(missed_ids)} unprocessed events")
            await self._process_event_ids(missed_ids)

    # -----------------------------------------------------------------
    # Core processing: event IDs -> Event rows -> finding -> persisted
    # -----------------------------------------------------------------
    async def _process_event_ids(self, event_ids: list[int]) -> None:
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Event).where(Event.id.in_(event_ids)))
            events = result.scalars().all()

        # v1: process one event at a time (see module docstring note on grouping)
        for event in events:
            if event.source != "terminal" or not event.command:
                continue  # only terminal commands produce findings in v1

            finding_dict = await extract_finding_from_events([event], llm_client=_llm_client)
            if finding_dict is None:
                continue  # not a meaningful finding — nothing to persist

            async with AsyncSessionLocal() as db:
                # Re-fetch session_id fresh per write to avoid stale detached state
                session_id = event.session_id
                await persist_finding(db, session_id=session_id, finding_dict=finding_dict)


# Module-level singleton, imported by main.py startup/shutdown handlers
queue_worker = QueueWorker()