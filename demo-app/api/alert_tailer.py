from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Callable, Awaitable

from watchfiles import awatch

from models import Alert, Engine
from parsers import parse_alert_csv_line
from typing import Optional as _Opt

logger = logging.getLogger("alert-tailer")

# Max queued alerts before we start dropping (logged at WARNING)
_QUEUE_MAXSIZE = 50_000


class AlertTailer:
    """
    Tails a Snort alert_csv file using watchfiles (inotify) and parses new lines
    into Alert objects, feeding them into an asyncio.Queue for WS broadcast.

    Usage:
        tailer = AlertTailer(path, engine, on_alert)
        task = asyncio.create_task(tailer.run())
        # ... later ...
        task.cancel()
    """

    def __init__(
        self,
        file_path: Path,
        engine: "_Opt[Engine]",
        on_alert: Callable[[Alert], Awaitable[None]],
    ) -> None:
        self._path = file_path
        self._engine = engine  # None = combined mode, GID-based routing in parser
        self._on_alert = on_alert
        self._offset = 0
        self._queue: asyncio.Queue[Alert] = asyncio.Queue(maxsize=_QUEUE_MAXSIZE)
        self._dropped = 0

    async def run(self) -> None:
        """Main loop: watch for file changes, parse new lines, enqueue alerts."""
        # Drain broadcaster and file reader concurrently
        async with asyncio.TaskGroup() as tg:
            tg.create_task(self._watch_loop())
            tg.create_task(self._broadcast_loop())

    # ── private ───────────────────────────────────────────────────────────────

    async def _watch_loop(self) -> None:
        """Wait for inotify events, then read all new bytes."""
        # Wait for the file to exist before starting awatch
        for _ in range(50):  # up to 5s
            if self._path.exists():
                break
            await asyncio.sleep(0.1)

        if not self._path.exists():
            logger.warning("alert_csv not found after 5s: %s", self._path)
            return

        # Read any lines already present on start
        self._read_new_lines()

        async for _ in awatch(self._path):
            self._read_new_lines()

    def _read_new_lines(self) -> None:
        """Read bytes appended since last offset, parse each line."""
        try:
            with open(self._path, "rb") as fh:
                fh.seek(self._offset)
                new_bytes = fh.read()
                self._offset += len(new_bytes)

            if not new_bytes:
                return

            text = new_bytes.decode("utf-8", errors="replace")
            for raw_line in text.splitlines():
                alert = parse_alert_csv_line(raw_line, self._engine)
                if alert is None:
                    continue
                try:
                    self._queue.put_nowait(alert)
                except asyncio.QueueFull:
                    self._dropped += 1
                    if self._dropped == 1 or self._dropped % 1000 == 0:
                        logger.warning(
                            "alert queue full — dropped %d alerts so far (engine=%s)",
                            self._dropped,
                            self._engine,
                        )
        except Exception as exc:
            logger.error("error reading %s: %s", self._path, exc)

    async def _broadcast_loop(self) -> None:
        """Pull alerts from queue and call on_alert callback."""
        while True:
            alert = await self._queue.get()
            try:
                await self._on_alert(alert)
            except Exception as exc:
                logger.error("on_alert callback error: %s", exc)
            finally:
                self._queue.task_done()
