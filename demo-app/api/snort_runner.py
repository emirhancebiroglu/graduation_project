from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import uuid
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger("snort-runner")

# ── Paths ─────────────────────────────────────────────────────────────────────

_HOME = Path.home()
_SNORT_CWD = "/usr/local/etc/snort"
_COMBINED_CONFIG = str(_HOME / "bitirme/configs/snort_combined.lua")
_COMBINED_PLUGIN = str(_HOME / "bitirme/plugins/combined_plugins")
_RUN_ROOT = Path("/tmp/demo-runs")

# PCAP duration fallbacks (seconds) used when capinfos is unavailable
_PCAP_DURATION_FALLBACK: dict[str, float] = {
    "normal_2min": 120.0,
    "dos_hulk_2min": 120.0,
    "full_wednesday": 28800.0,
}

# Actual wall-clock replay time at disk speed — used for progress bar accuracy.
# Short PCAPs replay in ~1.5-3s regardless of PCAP content duration.
PCAP_REPLAY_WALL_CLOCK: dict[str, float] = {
    "normal_2min": 3.0,
    "dos_hulk_2min": 3.0,
    "full_wednesday": 180.0,
}


# ── State types ───────────────────────────────────────────────────────────────

class RunStatus(str, Enum):
    idle = "idle"
    running = "running"
    stopped = "stopped"
    errored = "errored"


@dataclass
class RunState:
    run_id: str
    pcap_path: str
    pcap_name: str
    run_dir: str
    started_at: datetime
    status: RunStatus
    pcap_duration_s: float
    error: str | None = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _xgboost_env() -> dict[str, str]:
    xgb_root = Path(os.environ.get("XGBOOST_ROOT", str(_HOME / "snort_src/xgboost")))
    xgb_lib = str(xgb_root / "lib")
    existing = os.environ.get("LD_LIBRARY_PATH", "")
    return {
        **os.environ,
        "LD_LIBRARY_PATH": f"{xgb_lib}:{existing}" if existing else xgb_lib,
    }


def _get_pcap_duration(pcap_path: str, pcap_name: str) -> float:
    return _PCAP_DURATION_FALLBACK.get(pcap_name, 120.0)


# ── SnortRunner ───────────────────────────────────────────────────────────────

class SnortRunner:
    def __init__(self) -> None:
        self._state: RunState | None = None
        self._proc: subprocess.Popen | None = None
        self._log_handles: list = []

    # ── public interface ──────────────────────────────────────────────────────

    @property
    def state(self) -> RunState | None:
        return self._state

    def is_running(self) -> bool:
        return self._state is not None and self._state.status == RunStatus.running

    def pcap_progress(self) -> float:
        if self._state is None or self._state.status != RunStatus.running:
            return 0.0
        # If snort process exited naturally, progress is complete
        if self._proc is not None and self._proc.poll() is not None:
            return 1.0
        elapsed = (datetime.now(timezone.utc) - self._state.started_at).total_seconds()
        wall_clock = PCAP_REPLAY_WALL_CLOCK.get(self._state.pcap_name, self._state.pcap_duration_s)
        # Cap at 99% while still processing — final jump to 100% happens on exit
        return min(elapsed / wall_clock, 0.99)

    async def start(
        self,
        pcap_name: str,
        pcap_path: str,
        run_id: str,
        on_launched: "Coroutine[Any, Any, None] | None" = None,
        on_launched_with_dir: "Callable[[str], Coroutine[Any, Any, None]] | None" = None,
    ) -> RunState:
        if self.is_running():
            raise AlreadyRunningError("A replay is already in progress")

        duration = await asyncio.to_thread(_get_pcap_duration, pcap_path, pcap_name)

        run_dir = _RUN_ROOT / run_id
        combined_dir = run_dir / "combined"
        # Legacy paths kept so alert_tailer and main.py can find files
        xgb_dir = run_dir / "xgboost"
        comm_dir = run_dir / "community"
        combined_dir.mkdir(parents=True, exist_ok=True)
        xgb_dir.mkdir(parents=True, exist_ok=True)
        comm_dir.mkdir(parents=True, exist_ok=True)

        self._state = RunState(
            run_id=run_id,
            pcap_path=pcap_path,
            pcap_name=pcap_name,
            run_dir=str(run_dir),
            started_at=datetime.now(timezone.utc),
            status=RunStatus.running,
            pcap_duration_s=duration,
        )

        try:
            self._proc = self._launch_combined(pcap_path, str(combined_dir))
        except Exception as exc:
            self._state.status = RunStatus.errored
            self._state.error = f"Failed to launch Snort: {exc}"
            logger.error("Snort launch failed: %s", exc)
            return self._state

        # Immediately notify callers that Snort is running (don't wait for 1s poll loop)
        if on_launched is not None:
            try:
                await on_launched
            except Exception as exc:
                logger.warning("on_launched callback error (ignored): %s", exc)
        if on_launched_with_dir is not None:
            try:
                await on_launched_with_dir(str(run_dir))
            except Exception as exc:
                logger.warning("on_launched_with_dir callback error (ignored): %s", exc)

        # Check immediately for launch errors (non-zero exit within ms of launch = config error).
        # Normal PCAP completion is handled by _status_broadcaster's check_natural_exit().
        await asyncio.sleep(0.5)

        if self._state.status != RunStatus.running:
            return self._state

        if self._proc is not None:
            rc = self._proc.poll()
            if rc is not None and rc != 0:
                self._state.status = RunStatus.errored
                self._state.error = f"Snort exited with error (exit {rc})"
                logger.error("Launch error: %s", self._state.error)
                await self.stop()

        return self._state

    async def stop(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            logger.info("Sending SIGTERM to snort (pid=%d)", self._proc.pid)
            self._proc.terminate()
            try:
                await asyncio.wait_for(asyncio.to_thread(self._proc.wait), timeout=3.0)
            except asyncio.TimeoutError:
                logger.warning("snort did not exit; sending SIGKILL")
                self._proc.kill()
                await asyncio.to_thread(self._proc.wait)

        self._close_log_handles()
        self._proc = None

        if self._state and self._state.status == RunStatus.running:
            self._state.status = RunStatus.stopped
        logger.info("SnortRunner stopped (run_id=%s)", self._state.run_id if self._state else "?")

    async def cleanup(self) -> None:
        try:
            await self.stop()
        except Exception as exc:
            logger.warning("cleanup error (ignored): %s", exc)

    def check_natural_exit(self) -> bool:
        """Return True if the combined process has exited naturally (PCAP fully replayed)."""
        if self._proc is None:
            return False
        return self._proc.poll() is not None

    # ── private ───────────────────────────────────────────────────────────────

    def _launch_combined(self, pcap_path: str, out_dir: str) -> subprocess.Popen:
        env = _xgboost_env()

        stdout_fh = open(f"{out_dir}/snort_stdout.log", "wb")
        stderr_fh = open(f"{out_dir}/snort_stderr.log", "wb")
        self._log_handles = [stdout_fh, stderr_fh]

        cmd = [
            "snort",
            "-c", _COMBINED_CONFIG,
            "--plugin-path", _COMBINED_PLUGIN,
            "-r", pcap_path,
            "-A", "alert_csv",
            "-l", out_dir,
            "--warn-all",
        ]

        logger.info("Launching combined Snort: %s", " ".join(cmd))
        proc = subprocess.Popen(
            cmd,
            cwd=_SNORT_CWD,
            env=env,
            stdout=stdout_fh,
            stderr=stderr_fh,
        )
        logger.info("Combined Snort launched (pid=%d)", proc.pid)
        return proc

    def _close_log_handles(self) -> None:
        for fh in self._log_handles:
            try:
                fh.close()
            except Exception:
                pass
        self._log_handles = []


class AlreadyRunningError(Exception):
    pass
