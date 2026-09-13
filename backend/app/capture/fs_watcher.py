"""
Filesystem watcher for TraceCTF.

Monitors a working directory (e.g., where the user downloads exploits,
saves loot, or finds a flag file) and emits an event for every
created/modified/deleted file. Runs on watchdog's own background thread
and bridges callbacks into the asyncio event loop safely.
"""

from __future__ import annotations

import asyncio
import datetime
from pathlib import Path
from typing import Callable, Awaitable, Optional

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
from watchdog.observers.api import BaseObserver


class _Handler(FileSystemEventHandler):
    """
    Bridges watchdog's synchronous, thread-based callbacks into the
    asyncio event loop where the rest of TraceCTF's async pipeline lives.
    """

    def __init__(
        self,
        session_id: int,
        on_event: Callable[[dict], Awaitable[None]],
        loop: asyncio.AbstractEventLoop,
    ):
        self.session_id = session_id
        self.on_event = on_event
        self.loop = loop

    def _schedule(self, file_path: str, action: str) -> None:
        event = {
            "session_id": self.session_id,
            "source": "filesystem",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "file_path": file_path,
            "file_action": action,
        }
        # watchdog callbacks run on a background thread, not the asyncio
        # loop — this safely schedules the coroutine onto the main loop.
        asyncio.run_coroutine_threadsafe(self.on_event(event), self.loop)

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._schedule(event.src_path, "created")

    def on_modified(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._schedule(event.src_path, "modified")

    def on_deleted(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._schedule(event.src_path, "deleted")

class FilesystemWatcher:
    """
    Wraps a watchdog Observer for a single session's working directory.
    """

    def __init__(
        self,
        session_id: int,
        on_event: Callable[[dict], Awaitable[None]],
        watch_directory: str,
        recursive: bool = True,
    ):
        self.session_id = session_id
        self.watch_directory = watch_directory
        self.recursive = recursive
        self._observer: Optional[BaseObserver] = None
        self._on_event = on_event

    def start(self) -> None:
        path = Path(self.watch_directory)
        if not path.exists():
            raise FileNotFoundError(f"Watch directory does not exist: {self.watch_directory}")

        loop = asyncio.get_event_loop()
        handler = _Handler(session_id=self.session_id, on_event=self._on_event, loop=loop)

        self._observer = Observer()
        self._observer.schedule(handler, str(path), recursive=self.recursive)
        self._observer.start()

    def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None