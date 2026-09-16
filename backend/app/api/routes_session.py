"""
Session management API for TraceCTF.

Handles the full lifecycle of a recording session:
  - POST /sessions            -> create + start capture
  - POST /sessions/{id}/stop  -> stop capture, mark session completed
  - POST /sessions/{id}/pause / /resume
  - GET  /sessions/{id}       -> session status
  - GET  /sessions            -> list all sessions

Active in-memory capture objects (PTY session, fs watcher, screenshot
capturer) are tracked in a module-level dict keyed by session_id, since
they're runtime objects (threads/subprocesses) that can't be stored in
the DB — only their lifecycle events are persisted.
"""

from __future__ import annotations

import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Session as SessionModel
from app.capture.event_collector import EventCollector
from app.capture.pty_wrapper import create_pty_session
from app.capture.fs_watcher import FilesystemWatcher
from app.capture.screenshot import PeriodicScreenshotCapturer

router = APIRouter(prefix="/sessions", tags=["sessions"])


# ---------------------------------------------------------------------------
# Request/response schemas
# ---------------------------------------------------------------------------
class StartSessionRequest(BaseModel):
    name: str
    challenge_name: Optional[str] = None
    backend: str  # "windows" or "docker"
    container_name: Optional[str] = None   # required if backend == "docker"
    watch_directory: Optional[str] = None  # optional filesystem watch
    enable_screenshots: bool = True


class SessionResponse(BaseModel):
    id: int
    name: str
    challenge_name: Optional[str]
    status: str
    started_at: datetime.datetime
    ended_at: Optional[datetime.datetime]

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# In-memory registry of active capture runtime objects, keyed by session_id.
# These are NOT persisted — they're process/thread handles that only exist
# while the FastAPI server process is alive.
# ---------------------------------------------------------------------------
class _ActiveCapture:
    def __init__(self, pty_session, fs_watcher: Optional[FilesystemWatcher], screenshot_capturer: Optional[PeriodicScreenshotCapturer]):
        self.pty_session = pty_session
        self.fs_watcher = fs_watcher
        self.screenshot_capturer = screenshot_capturer


_active_captures: dict[int, _ActiveCapture] = {}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@router.post("", response_model=SessionResponse)
async def start_session(req: StartSessionRequest, db: AsyncSession = Depends(get_db)):
    if req.backend not in ("windows", "docker"):
        raise HTTPException(400, "backend must be 'windows' or 'docker'")
    if req.backend == "docker" and not req.container_name:
        raise HTTPException(400, "container_name is required when backend='docker'")

    session = SessionModel(
        name=req.name,
        challenge_name=req.challenge_name,
        started_at=datetime.datetime.utcnow(),
        status="active",
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)

    collector = EventCollector(session_id=session.id)

    # ---- Start terminal capture ----
    pty_session = create_pty_session(
        session_id=session.id,
        on_event=collector.handle_event,
        backend=req.backend,
        container_name=req.container_name,
    )
    await pty_session.start()

    # ---- Optionally start filesystem watcher ----
    fs_watcher = None
    if req.watch_directory:
        fs_watcher = FilesystemWatcher(
            session_id=session.id,
            on_event=collector.handle_event,
            watch_directory=req.watch_directory,
        )
        try:
            fs_watcher.start()
        except FileNotFoundError as e:
            # Don't fail the whole session start over a bad watch path —
            # log-equivalent behavior: degrade gracefully (NFR-4 spirit).
            fs_watcher = None

    # ---- Optionally start periodic screenshot capture ----
    screenshot_capturer = None
    if req.enable_screenshots:
        screenshot_capturer = PeriodicScreenshotCapturer(
            session_id=session.id,
            on_event=collector.handle_event,
        )
        screenshot_capturer.start()

    _active_captures[session.id] = _ActiveCapture(
        pty_session=pty_session,
        fs_watcher=fs_watcher,
        screenshot_capturer=screenshot_capturer,
    )

    return session


@router.post("/{session_id}/stop", response_model=SessionResponse)
async def stop_session(session_id: int, db: AsyncSession = Depends(get_db)):
    session = await _get_session_or_404(db, session_id)

    active = _active_captures.pop(session_id, None)
    if active:
        await active.pty_session.stop()
        if active.fs_watcher:
            active.fs_watcher.stop()
        if active.screenshot_capturer:
            active.screenshot_capturer.stop()

    session.status = "completed"
    session.ended_at = datetime.datetime.utcnow()
    await db.commit()
    await db.refresh(session)
    return session


@router.post("/{session_id}/pause", response_model=SessionResponse)
async def pause_session(session_id: int, db: AsyncSession = Depends(get_db)):
    session = await _get_session_or_404(db, session_id)
    active = _active_captures.get(session_id)
    if active and active.screenshot_capturer:
        active.screenshot_capturer.stop()
    session.status = "paused"
    await db.commit()
    await db.refresh(session)
    return session


@router.post("/{session_id}/resume", response_model=SessionResponse)
async def resume_session(session_id: int, db: AsyncSession = Depends(get_db)):
    session = await _get_session_or_404(db, session_id)
    active = _active_captures.get(session_id)
    if active and active.screenshot_capturer:
        active.screenshot_capturer.start()
    session.status = "active"
    await db.commit()
    await db.refresh(session)
    return session


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(session_id: int, db: AsyncSession = Depends(get_db)):
    return await _get_session_or_404(db, session_id)


@router.get("", response_model=list[SessionResponse])
async def list_sessions(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SessionModel).order_by(SessionModel.started_at.desc()))
    return result.scalars().all()


async def _get_session_or_404(db: AsyncSession, session_id: int) -> SessionModel:
    result = await db.execute(select(SessionModel).where(SessionModel.id == session_id))
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(404, f"Session {session_id} not found")
    return session