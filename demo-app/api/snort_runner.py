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
_XGB_CONFIG = str(_HOME / "bitirme/configs/snort_xgb.lua")
_XGB_PLUGIN = str(_HOME / "bitirme/plugins/xgb_inspector/build")
_COMMUNITY_CONFIG = str(_HOME / "bitirme/configs/snort_community.lua")
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
    fallback = _PCAP_DURATION_FALLBACK.get(pcap_name, 120.0)
    try:
        result = subprocess.run(
            ["capinfos", "-c", "-u", pcap_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
        for line in result.stdout.splitlines():
            if "Capture duration" in line:
                # "Capture duration:    119.996614 seconds"
                parts = line.split(":")
                if len(parts) >= 2:
                    duration = float(parts[1].strip().split()[0])
                    logger.info("capinfos duration for %s: %.1fs", pcap_name, duration)
                    return duration
    except Exception as exc:
        logger.warning("capinfos failed (%s), using fallback %.0fs: %s", pcap_name, fallback, exc)
    return fallback


# ── SnortRunner ───────────────────────────────────────────────────────────────

class SnortRunner:
    def __init__(self) -> None:
        self._state: RunState | None = None
        self._xgb_proc: subprocess.Popen | None = None
        self._comm_proc: subprocess.Popen | None = None
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
        elapsed = (datetime.now(timezone.utc) - self._state.started_at).total_seconds()
        wall_clock = PCAP_REPLAY_WALL_CLOCK.get(self._state.pcap_name, self._state.pcap_duration_s)
        return min(elapsed / wall_clock, 1.0)

    async def start(
        self,
        pcap_name: str,
        pcap_path: str,
        on_launched: "Coroutine[Any, Any, None] | None" = None,
        on_launched_with_dir: "Callable[[str], Coroutine[Any, Any, None]] | None" = None,
    ) -> RunState:
        if self.is_running():
            raise AlreadyRunningError("A replay is already in progress")

        duration = await asyncio.to_thread(_get_pcap_duration, pcap_path, pcap_name)

        run_id = str(uuid.uuid4())
        run_dir = _RUN_ROOT / run_id
        xgb_dir = run_dir / "xgboost"
        comm_dir = run_dir / "community"
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
            self._xgb_proc, self._comm_proc = self._launch_both(
                pcap_path, str(xgb_dir), str(comm_dir)
            )
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

        bad: list[str] = []
        for proc, name in [(self._xgb_proc, "xgboost"), (self._comm_proc, "community")]:
            if proc is None:
                continue
            rc = proc.poll()
            if rc is not None and rc != 0:
                bad.append(f"{name} (exit {rc})")

        if bad:
            self._state.status = RunStatus.errored
            self._state.error = f"Subprocess exited with error: {', '.join(bad)}"
            logger.error("Launch error: %s", self._state.error)
            await self.stop()

        return self._state

    async def stop(self) -> None:
        for proc, name in [
            (self._xgb_proc, "xgboost"),
            (self._comm_proc, "community"),
        ]:
            if proc is None:
                continue
            if proc.poll() is None:
                logger.info("Sending SIGTERM to %s (pid=%d)", name, proc.pid)
                proc.terminate()

        # Wait up to 3s for graceful exit
        deadline = asyncio.get_event_loop().time() + 3.0
        for proc, name in [
            (self._xgb_proc, "xgboost"),
            (self._comm_proc, "community"),
        ]:
            if proc is None:
                continue
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining > 0:
                try:
                    await asyncio.wait_for(
                        asyncio.to_thread(proc.wait), timeout=remaining
                    )
                except asyncio.TimeoutError:
                    logger.warning("%s did not exit; sending SIGKILL", name)
                    proc.kill()
                    await asyncio.to_thread(proc.wait)

        self._close_log_handles()
        self._xgb_proc = None
        self._comm_proc = None

        if self._state and self._state.status == RunStatus.running:
            self._state.status = RunStatus.stopped
        logger.info("SnortRunner stopped (run_id=%s)", self._state.run_id if self._state else "?")

    async def cleanup(self) -> None:
        try:
            await self.stop()
        except Exception as exc:
            logger.warning("cleanup error (ignored): %s", exc)

    def check_natural_exit(self) -> bool:
        """Return True if both processes have exited naturally (PCAP fully replayed)."""
        if self._xgb_proc is None and self._comm_proc is None:
            return False
        xgb_done = self._xgb_proc is None or self._xgb_proc.poll() is not None
        comm_done = self._comm_proc is None or self._comm_proc.poll() is not None
        return xgb_done and comm_done

    # ── private ───────────────────────────────────────────────────────────────

    def _launch_both(
        self, pcap_path: str, xgb_dir: str, comm_dir: str
    ) -> tuple[subprocess.Popen, subprocess.Popen]:
        xgb_env = _xgboost_env()

        xgb_stdout = open(f"{xgb_dir}/snort_stdout.log", "wb")
        xgb_stderr = open(f"{xgb_dir}/snort_stderr.log", "wb")
        comm_stdout = open(f"{comm_dir}/snort_stdout.log", "wb")
        comm_stderr = open(f"{comm_dir}/snort_stderr.log", "wb")
        self._log_handles = [xgb_stdout, xgb_stderr, comm_stdout, comm_stderr]

        cmd_xgb = [
            "snort",
            "-c", _XGB_CONFIG,
            "--plugin-path", _XGB_PLUGIN,
            "-r", pcap_path,
            "-A", "alert_csv",
            "-l", xgb_dir,
            "--warn-all", "-q",
        ]
        cmd_community = [
            "snort",
            "-c", _COMMUNITY_CONFIG,
            "-r", pcap_path,
            "-A", "alert_csv",
            "-l", comm_dir,
            "--warn-all", "-q",
        ]

        logger.info("Launching XGBoost Snort: %s", " ".join(cmd_xgb))
        xgb_proc = subprocess.Popen(
            cmd_xgb,
            cwd=_SNORT_CWD,
            env=xgb_env,
            stdout=xgb_stdout,
            stderr=xgb_stderr,
        )

        logger.info("Launching Community Snort: %s", " ".join(cmd_community))
        comm_proc = subprocess.Popen(
            cmd_community,
            cwd=_SNORT_CWD,
            stdout=comm_stdout,
            stderr=comm_stderr,
        )

        logger.info(
            "Both processes launched (xgb pid=%d, comm pid=%d)",
            xgb_proc.pid,
            comm_proc.pid,
        )
        return xgb_proc, comm_proc

    def _close_log_handles(self) -> None:
        for fh in self._log_handles:
            try:
                fh.close()
            except Exception:
                pass
        self._log_handles = []


class AlreadyRunningError(Exception):
    pass
