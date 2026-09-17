"""
Background queue worker for TraceCTF's AI pipeline.

Consumes event IDs pushed by EventCollector, batches them, and runs each
through: finding_extractor -> evidence_linker.

Every event that gets analyzed — whether or not it produces a finding —
is recorded in ProcessedEvent. This is what the catch-up sweep checks,
NOT the presence of a finding, since "analyzed, no finding" and "never
analyzed" are different states that must not be conflated (a command
like `echo hello` should be analyzed once and left alone, not retried
forever).
"""

from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select, and_, not_, exists
from sqlalchemy.exc import IntegrityError

from app.config import settings
from app.db.database import AsyncSessionLocal
from app.db.models import Event, ProcessedEvent
from app.capture.event_collector import analysis_queue
from app.pipeline.llm_client import OllamaClient
from app.pipeline.finding_extractor import extract_finding_from_events
from app.pipeline.evidence_linker import persist_finding, PIPELINE_VERSION

logger = logging.getLogger("tracectf.queue_worker")

_llm_client = OllamaClient()


class QueueWorker:
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

    async def _catchup_sweep_loop(self) -> None:
        sweep_interval = max(settings.analysis_batch_interval_seconds * 5, 30)
        while self._running:
            await asyncio.sleep(sweep_interval)
            try:
                await self._sweep_unprocessed_events()
            except Exception:
                logger.exception("Error during catch-up sweep — continuing")

    async def _sweep_unprocessed_events(self) -> None:
        async with AsyncSessionLocal() as db:
            # Events with no row in processed_events — meaning they were
            # never analyzed at all (not "analyzed with no finding").
            already_processed = exists().where(ProcessedEvent.event_id == Event.id)
            stmt = select(Event.id).where(
                and_(Event.source == "terminal", not_(already_processed))
            ).limit(settings.analysis_batch_size)

            result = await db.execute(stmt)
            missed_ids = [row[0] for row in result.all()]

        if missed_ids:
            logger.info(f"Catch-up sweep found {len(missed_ids)} unprocessed events")
            await self._process_event_ids(missed_ids)

    async def _process_event_ids(self, event_ids: list[int]) -> None:
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Event).where(Event.id.in_(event_ids)))
            events = result.scalars().all()

        for event in events:
            if event.source != "terminal" or not event.command:
                await self._mark_processed(event.id)
                continue

            finding_dict = await extract_finding_from_events([event], llm_client=_llm_client)

            async with AsyncSessionLocal() as db:
                db.add(ProcessedEvent(event_id=event.id, pipeline_version=PIPELINE_VERSION))
                try:
                    if finding_dict is not None:
                        # persist_finding commits internally, which also
                        # commits the ProcessedEvent row added above —
                        # both succeed or fail together, atomically.
                        await persist_finding(db, session_id=event.session_id, finding_dict=finding_dict)
                    else:
                        await db.commit()
                except IntegrityError:
                    # Rare race: this event was already marked processed
                    # by an overlapping batch/sweep cycle. Safe to ignore.
                    await db.rollback()

    async def _mark_processed(self, event_id: int) -> None:
        async with AsyncSessionLocal() as db:
            db.add(ProcessedEvent(event_id=event_id, pipeline_version=PIPELINE_VERSION))
            try:
                await db.commit()
            except IntegrityError:
                await db.rollback()


queue_worker = QueueWorker()