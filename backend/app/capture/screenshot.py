"""
Screenshot capture for TraceCTF.

Supports:
  - Manual, on-demand capture (triggered via API, e.g., a hotkey or
    dashboard button)
  - Periodic auto-capture, at an interval configured in settings

Screenshots are saved to disk under settings.screenshots_dir, named with
session ID + timestamp so they sort naturally and never collide across
sessions. Only the file path is stored in the event — not the image
bytes — keeping the SQLite DB small.
"""

from __future__ import annotations

import asyncio
import datetime
from pathlib import Path
from typing import Callable, Awaitable, Optional

import mss
import mss.tools

from app.config import settings


def _capture_to_file(session_id: int) -> str:
    """
    Synchronous capture of the primary monitor to a PNG file.
    Runs inside a thread executor since mss is a blocking library.
    """
    settings.screenshots_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
    filename = f"session{session_id}_{timestamp}.png"
    filepath = settings.screenshots_dir / filename

    with mss.mss() as sct:
        monitor = sct.monitors[1]  # index 0 is "all monitors combined"; 1 is primary
        shot = sct.grab(monitor)
        mss.tools.to_png(shot.rgb, shot.size, output=str(filepath))

    return str(filepath)


async def capture_screenshot(
    session_id: int,
    on_event: Callable[[dict], Awaitable[None]],
) -> str:
    """
    Takes a single screenshot immediately and emits an event.
    Call this from an API route for manual/on-demand capture.
    """
    loop = asyncio.get_event_loop()
    filepath = await loop.run_in_executor(None, _capture_to_file, session_id)

    event = {
        "session_id": session_id,
        "source": "screenshot",
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "screenshot_path": filepath,
    }
    await on_event(event)
    return filepath


class PeriodicScreenshotCapturer:
    """
    Runs a background loop that takes a screenshot every N seconds,
    as configured by settings.screenshot_auto_interval_seconds.
    Set that value to 0 to disable auto-capture entirely.
    """

    def __init__(
        self,
        session_id: int,
        on_event: Callable[[dict], Awaitable[None]],
        interval_seconds: Optional[int] = None,
    ):
        self.session_id = session_id
        self.on_event = on_event
        self.interval_seconds = (
            interval_seconds
            if interval_seconds is not None
            else settings.screenshot_auto_interval_seconds
        )
        self._task: Optional[asyncio.Task] = None
        self._running = False

    def start(self) -> None:
        if self.interval_seconds <= 0:
            return  # auto-capture disabled
        self._running = True
        self._task = asyncio.create_task(self._loop())

    def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            self._task = None

    async def _loop(self) -> None:
        while self._running:
            await asyncio.sleep(self.interval_seconds)
            if not self._running:
                break
            try:
                await capture_screenshot(self.session_id, self.on_event)
            except Exception:
                # Never let a single failed screenshot kill the loop —
                # capture must stay resilient (NFR-4 style reliability).
                pass