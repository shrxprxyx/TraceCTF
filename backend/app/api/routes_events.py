"""
Event API for TraceCTF.

  - POST /sessions/{id}/command  -> send a command into the active PTY session
  - GET  /sessions/{id}/events   -> list recorded events for a session
  - GET  /events/{event_id}      -> get a single event by ID

The command endpoint relies on the same in-memory _active_captures
registry from routes_session.py — a session must be actively running
(not stopped) for a command to be sent.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.models import Event
from app.api.routes_session import _active_captures

router = APIRouter(tags=["events"])


# Schemas
class SendCommandRequest(BaseModel):
    command: str
    cwd_hint: str = ""


class EventResponse(BaseModel):
    id: int
    session_id: int
    source: str
    timestamp: str
    command: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    cwd: Optional[str] = None
    url: Optional[str] = None
    http_method: Optional[str] = None
    http_status: Optional[int] = None
    file_path: Optional[str] = None
    file_action: Optional[str] = None
    screenshot_path: Optional[str] = None

    class Config:
        from_attributes = True



# Routes
@router.post("/sessions/{session_id}/command")
async def send_command(session_id: int, req: SendCommandRequest):
    active = _active_captures.get(session_id)
    if active is None:
        raise HTTPException(
            404,
            f"No active capture session for session_id={session_id}. "
            "Has it been started, or was it already stopped?",
        )

    active.pty_session.send_command(req.command, cwd_hint=req.cwd_hint)
    return {"status": "sent", "command": req.command}


@router.get("/sessions/{session_id}/events", response_model=list[EventResponse])
async def list_events(
    session_id: int,
    source: Optional[str] = None,
    limit: int = 200,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Event).where(Event.session_id == session_id)
    if source:
        stmt = stmt.where(Event.source == source)
    stmt = stmt.order_by(Event.timestamp.desc()).limit(limit)

    result = await db.execute(stmt)
    events = result.scalars().all()
    return [_serialize_event(e) for e in events]


@router.get("/events/{event_id}", response_model=EventResponse)
async def get_event(event_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Event).where(Event.id == event_id))
    event = result.scalar_one_or_none()
    if event is None:
        raise HTTPException(404, f"Event {event_id} not found")
    return _serialize_event(event)


def _serialize_event(e: Event) -> EventResponse:
    return EventResponse(
        id=e.id,
        session_id=e.session_id,
        source=e.source,
        timestamp=e.timestamp.isoformat(),
        command=e.command,
        stdout=e.stdout,
        stderr=e.stderr,
        cwd=e.cwd,
        url=e.url,
        http_method=e.http_method,
        http_status=e.http_status,
        file_path=e.file_path,
        file_action=e.file_action,
        screenshot_path=e.screenshot_path,
    )