"""
Terminal capture wrapper for TraceCTF.

Supports two backends, auto-selected per session:
  - "windows": wraps native PowerShell/cmd using pywinpty (ConPTY)
  - "docker":  wraps a shell inside a running Docker container (e.g., Kali),
               added in the next file — see DockerPtySession below (Part 2)

Every command typed by the user is captured along with its output, cwd,
and timestamp, then handed to the event collector for storage. Capture
NEVER blocks on AI analysis — it only writes raw events.
"""

from __future__ import annotations

import asyncio
import datetime
import re
from typing import Optional, Callable, Awaitable

import winpty  # from pywinpty

from app.config import settings


# ---------------------------------------------------------------------------
# Sensitive data masking (applied before anything is stored)
# ---------------------------------------------------------------------------
_MASK_REGEXES = [re.compile(p, re.IGNORECASE) for p in settings.mask_patterns]


def mask_sensitive(text: Optional[str]) -> Optional[str]:
    if not text or not settings.enable_masking:
        return text
    masked = text
    for pattern in _MASK_REGEXES:
        masked = pattern.sub("[MASKED]", masked)
    return masked


# ---------------------------------------------------------------------------
# Windows-native PTY session (ConPTY via pywinpty)
# ---------------------------------------------------------------------------
class WindowsPtySession:
    """
    Wraps a native PowerShell process using ConPTY.
    Reads output continuously in the background and detects command
    boundaries using a sentinel marker injected after each command,
    so we know when one command's output has ended.
    """

    SENTINEL = "__TRACECTF_CMD_DONE__"

    def __init__(
        self,
        session_id: int,
        on_event: Callable[[dict], Awaitable[None]],
        shell_cmd: str = "powershell.exe -NoLogo",
        cols: int = 120,
        rows: int = 30,
    ):
        self.session_id = session_id
        self.on_event = on_event
        self._proc = winpty.PtyProcess.spawn(shell_cmd, dimensions=(rows, cols))
        self._buffer = ""
        self._current_command: Optional[str] = None
        self._current_cwd: str = ""
        self._running = False

    async def start(self) -> None:
        self._running = True
        asyncio.create_task(self._read_loop())

    async def stop(self) -> None:
        self._running = False
        if self._proc.isalive():
            self._proc.terminate(force=True)

    def send_command(self, command: str, cwd_hint: str = "") -> None:
        """
        Called when the user types a command (via the CLI wrapper's stdin relay).
        Injects the command plus a sentinel so we can detect completion.
        """
        self._current_command = command
        self._current_cwd = cwd_hint
        full_line = f"{command}; Write-Output '{self.SENTINEL}'\r\n"
        self._proc.write(full_line)

    async def _read_loop(self) -> None:
        loop = asyncio.get_event_loop()
        while self._running and self._proc.isalive():
            try:
                chunk = await loop.run_in_executor(None, self._proc.read, 1024)
            except EOFError:
                break
            if not chunk:
                await asyncio.sleep(0.05)
                continue

            self._buffer += chunk

            if self.SENTINEL in self._buffer:
                output, _, remainder = self._buffer.partition(self.SENTINEL)
                self._buffer = remainder
                await self._emit_event(output)

    async def _emit_event(self, raw_output: str) -> None:
        if self._current_command is None:
            return  # output before first command (banner, etc.) — ignored

        event = {
            "session_id": self.session_id,
            "source": "terminal",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "command": mask_sensitive(self._current_command),
            "stdout": mask_sensitive(raw_output.strip()),
            "stderr": None,  # PowerShell interleaves stderr into the same stream via ConPTY
            "cwd": self._current_cwd,
        }
        await self.on_event(event)
        self._current_command = None
# ---------------------------------------------------------------------------
# Docker container PTY session (for your Kali/Linux attack container)
# ---------------------------------------------------------------------------
class DockerPtySession:
    """
    Wraps a shell running inside an already-running Docker container by
    attaching via `docker exec -it <container> <shell>` and driving it
    as a subprocess with pipes. This avoids needing WSL2 on the host —
    Docker Desktop itself handles the Linux side.

    Command boundary detection uses the same sentinel-marker technique
    as WindowsPtySession, since we're talking to a real Linux shell
    (bash/sh), which supports the same trick natively.
    """

    SENTINEL = "__TRACECTF_CMD_DONE__"

    def __init__(
        self,
        session_id: int,
        on_event: Callable[[dict], Awaitable[None]],
        container_name: str,
        shell_cmd: str = "/bin/bash",
    ):
        self.session_id = session_id
        self.on_event = on_event
        self.container_name = container_name
        self.shell_cmd = shell_cmd
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._buffer = ""
        self._current_command: Optional[str] = None
        self._current_cwd: str = ""
        self._running = False

    async def start(self) -> None:
        """
        Launches `docker exec -it <container> <shell>` as a subprocess,
        piping stdin/stdout so we can inject commands and read output.
        """
        self._proc = await asyncio.create_subprocess_exec(
            "docker", "exec", "-i", self.container_name, self.shell_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,  # merge stderr into stdout stream
        )
        self._running = True
        asyncio.create_task(self._read_loop())

    async def stop(self) -> None:
        self._running = False
        if self._proc and self._proc.returncode is None:
            self._proc.terminate()
            await self._proc.wait()

    def send_command(self, command: str, cwd_hint: str = "") -> None:
        if not self._proc or not self._proc.stdin:
            raise RuntimeError("DockerPtySession not started")

        self._current_command = command
        self._current_cwd = cwd_hint
        full_line = f"{command}; echo {self.SENTINEL}\n"
        self._proc.stdin.write(full_line.encode("utf-8"))
        # fire-and-forget drain; caller doesn't need to await this
        asyncio.create_task(self._proc.stdin.drain())

    async def _read_loop(self) -> None:
        if not self._proc or not self._proc.stdout:
            return

        while self._running and self._proc.returncode is None:
            try:
                chunk_bytes = await self._proc.stdout.read(1024)
            except Exception:
                break
            if not chunk_bytes:
                await asyncio.sleep(0.05)
                continue

            chunk = chunk_bytes.decode("utf-8", errors="replace")
            self._buffer += chunk

            if self.SENTINEL in self._buffer:
                output, _, remainder = self._buffer.partition(self.SENTINEL)
                self._buffer = remainder
                await self._emit_event(output)

    async def _emit_event(self, raw_output: str) -> None:
        if self._current_command is None:
            return

        event = {
            "session_id": self.session_id,
            "source": "terminal",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "command": mask_sensitive(self._current_command),
            "stdout": mask_sensitive(raw_output.strip()),
            "stderr": None,  # merged into stdout above via STDOUT redirect
            "cwd": self._current_cwd,
        }
        await self.on_event(event)
        self._current_command = None


# ---------------------------------------------------------------------------
# Factory — picks the right backend based on where the user wants to work
# ---------------------------------------------------------------------------
def create_pty_session(
    session_id: int,
    on_event: Callable[[dict], Awaitable[None]],
    backend: str,
    container_name: Optional[str] = None,
):
    """
    backend: "windows" or "docker"
    container_name: required if backend == "docker"
    """
    if backend == "windows":
        return WindowsPtySession(session_id=session_id, on_event=on_event)
    elif backend == "docker":
        if not container_name:
            raise ValueError("container_name is required for docker backend")
        return DockerPtySession(session_id=session_id, on_event=on_event, container_name=container_name)
    else:
        raise ValueError(f"Unknown PTY backend: {backend}")