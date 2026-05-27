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
# NOTE: _ensure_combined_plugins() is called at the bottom of this module, after
# all symbols are defined, to create symlinks in combined_plugins/ on first run.

_HOME = Path.home()
_SNORT_CWD = "/usr/local/etc/snort"
_COMBINED_CONFIG = str(_HOME / "bitirme/configs/snort_combined.lua")
_COMBINED_PLUGIN = str(_HOME / "bitirme/plugins/combined_plugins")
_RUN_ROOT = Path("/tmp/demo-runs")

# Plugin .so files to symlink into combined_plugins/ (relative to plugins/)
_PLUGIN_SOURCES: list[str] = [
    "dos_inspector/build/dos_inspector.so",
    "portscan_inspector/build/portscan_inspector.so",
    "dos_aggregator/build/dos_aggregator.so",
    "ddos_aggregator/build/ddos_aggregator.so",
    "bot_client_inspector/build/bot_client_inspector.so",
    "bruteforce_inspector/build/bruteforce_inspector.so",
]


def _ensure_combined_plugins() -> None:
    """Create combined_plugins/ and symlink all plugin .so files into it.

    Runs at import time so every API restart self-heals the plugin directory.
    Safe to call repeatedly — only re-symlinks if dst is missing or dangling.
    """
    plugins_root = _HOME / "bitirme/plugins"
    combined = Path(_COMBINED_PLUGIN)
    combined.mkdir(parents=True, exist_ok=True)
    for rel_src in _PLUGIN_SOURCES:
        src = plugins_root / rel_src
        dst = combined / src.name
        # Re-symlink if dst is absent OR is a dangling symlink
        needs_link = not dst.exists() or (dst.is_symlink() and not dst.resolve().exists())
        if needs_link:
            if src.exists():
                if dst.is_symlink():
                    dst.unlink()
                dst.symlink_to(src)
                logger.info("combined_plugins: linked %s", src.name)
            else:
                logger.warning("combined_plugins: source missing, skip: %s", src)

# PCAP duration fallbacks (seconds).
_PCAP_DURATION_FALLBACK: dict[str, float] = {
    "normal_2min": 120.0,
    "dos_hulk_2min": 120.0,
    "full_wednesday": 28800.0,
    "scenario_dos": 120.0,
    "scenario_ddos": 80.0,
    "scenario_portscan": 75.0,
    "scenario_bruteforce": 135.0,
    "scenario_bot": 335.0,
}

# tcpreplay PPS per scenario.
# PCAPs include benign padding so window-level inspectors have time to fire inference.
# dos: 270K pkts / 30s ≈ 9000 pps (flow-level, no window concern)
# ddos: 735K pkts (335K attack + 400K benign) / 9600 pps ≈ 77s > 60s window ✓
# portscan: 178K pkts (98K attack + 80K benign) / 2425 pps ≈ 73s > 60s window ✓
# bruteforce: 2429K pkts (829K attack + 1600K benign) / 18400 pps ≈ 132s > 120s window ✓
# bot: 2162K pkts (262K attack + 1900K benign) / 6550 pps ≈ 330s > 300s window ✓
_TCPREPLAY_PPS: dict[str, int] = {
    "scenario_dos": 9000,
    "scenario_ddos": 9600,
    "scenario_portscan": 2425,
    "scenario_bruteforce": 18400,
    "scenario_bot": 6550,
}

# Wall-clock seconds for progress bar (padded PCAP sizes ÷ PPS).
PCAP_REPLAY_WALL_CLOCK: dict[str, float] = {
    "normal_2min": 3.0,
    "dos_hulk_2min": 3.0,
    "full_wednesday": 180.0,
    "scenario_dos": 32.0,
    "scenario_ddos": 80.0,
    "scenario_portscan": 75.0,
    "scenario_bruteforce": 135.0,
    "scenario_bot": 335.0,
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
        self._proc: subprocess.Popen | None = None        # snort process (or file-replay snort)
        self._replay_proc: subprocess.Popen | None = None  # tcpreplay process (live mode only)
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
        # In live mode: tcpreplay done means replay complete
        if self._replay_proc is not None and self._replay_proc.poll() is not None:
            return 1.0
        # In file mode: snort done means replay complete
        if self._replay_proc is None and self._proc is not None and self._proc.poll() is not None:
            return 1.0
        elapsed = (datetime.now(timezone.utc) - self._state.started_at).total_seconds()
        wall_clock = PCAP_REPLAY_WALL_CLOCK.get(self._state.pcap_name, self._state.pcap_duration_s)
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

        pps = _TCPREPLAY_PPS.get(pcap_name)
        use_live = pps is not None

        try:
            if use_live:
                snort_proc = self._launch_snort_live(str(combined_dir))
                self._proc = snort_proc
                self._replay_proc = None
                # Notify callers (start alert tailer, broadcast status) before injecting traffic
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
                # Give snort time to initialize its listener before injecting packets
                await asyncio.sleep(1.5)
                self._replay_proc = self._launch_tcpreplay(pcap_path, str(combined_dir), pps)
            else:
                self._proc = self._launch_combined(pcap_path, str(combined_dir))
                self._replay_proc = None
        except Exception as exc:
            self._state.status = RunStatus.errored
            self._state.error = f"Failed to launch Snort: {exc}"
            logger.error("Snort launch failed: %s", exc)
            return self._state

        # For file-mode only: fire callbacks after launch
        if not use_live:
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

        await asyncio.sleep(0.5)

        if self._state.status != RunStatus.running:
            return self._state

        # In live mode, snort stays alive; only check for immediate crash
        check_proc = self._proc
        if check_proc is not None:
            rc = check_proc.poll()
            if rc is not None and rc != 0:
                self._state.status = RunStatus.errored
                self._state.error = f"Snort exited with error (exit {rc})"
                logger.error("Launch error: %s", self._state.error)
                await self.stop()

        return self._state

    async def stop(self) -> None:
        # Stop tcpreplay first (stops packet injection)
        if self._replay_proc is not None and self._replay_proc.poll() is None:
            logger.info("Sending SIGTERM to tcpreplay (pid=%d)", self._replay_proc.pid)
            self._replay_proc.terminate()
            try:
                await asyncio.wait_for(asyncio.to_thread(self._replay_proc.wait), timeout=3.0)
            except asyncio.TimeoutError:
                self._replay_proc.kill()
                await asyncio.to_thread(self._replay_proc.wait)
        self._replay_proc = None

        # Then stop snort
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
        """Return True when the replay is done.

        Live mode: tcpreplay process has exited (all packets sent).
        File mode: snort process has exited (PCAP fully consumed).
        """
        if self._replay_proc is not None:
            # Live capture mode — done when tcpreplay finishes
            return self._replay_proc.poll() is not None
        if self._proc is None:
            return False
        return self._proc.poll() is not None

    # ── private ───────────────────────────────────────────────────────────────

    def _launch_combined(self, pcap_path: str, out_dir: str) -> subprocess.Popen:
        """File-replay mode: snort reads PCAP directly."""
        env = _xgboost_env()

        stdout_fh = open(f"{out_dir}/snort_stdout.log", "wb")
        stderr_fh = open(f"{out_dir}/snort_stderr.log", "wb")
        self._log_handles = [stdout_fh, stderr_fh]

        cmd = [
            "stdbuf", "-oL",
            "snort",
            "-c", _COMBINED_CONFIG,
            "--plugin-path", _COMBINED_PLUGIN,
            "-r", pcap_path,
            "-A", "alert_csv",
            "-l", out_dir,
            "--warn-all",
        ]

        logger.info("Launching combined Snort (file mode): %s", " ".join(cmd))
        proc = subprocess.Popen(
            cmd,
            cwd=_SNORT_CWD,
            env=env,
            stdout=stdout_fh,
            stderr=stderr_fh,
        )
        logger.info("Combined Snort launched (pid=%d)", proc.pid)
        return proc

    def _launch_snort_live(self, out_dir: str) -> subprocess.Popen:
        """Start snort listening on lo interface (live capture mode)."""
        env = _xgboost_env()

        snort_stdout_fh = open(f"{out_dir}/snort_stdout.log", "wb")
        snort_stderr_fh = open(f"{out_dir}/snort_stderr.log", "wb")
        # Reserve slots 0-1 for snort; tcpreplay handles added in _launch_tcpreplay
        self._log_handles = [snort_stdout_fh, snort_stderr_fh]

        snort_cmd = [
            "stdbuf", "-oL",
            "snort",
            "-c", _COMBINED_CONFIG,
            "--plugin-path", _COMBINED_PLUGIN,
            "-i", "lo",
            "-A", "alert_csv",
            "-l", out_dir,
            "--warn-all",
        ]

        logger.info("Launching Snort (live mode, iface=lo): %s", " ".join(snort_cmd))
        proc = subprocess.Popen(
            snort_cmd,
            cwd=_SNORT_CWD,
            env=env,
            stdout=snort_stdout_fh,
            stderr=snort_stderr_fh,
        )
        logger.info("Snort live launched (pid=%d)", proc.pid)
        return proc

    def _launch_tcpreplay(self, pcap_path: str, out_dir: str, pps: int) -> subprocess.Popen:
        """Start tcpreplay injecting pcap_path onto lo at pps packets/second."""
        replay_stdout_fh = open(f"{out_dir}/tcpreplay_stdout.log", "wb")
        replay_stderr_fh = open(f"{out_dir}/tcpreplay_stderr.log", "wb")
        self._log_handles.extend([replay_stdout_fh, replay_stderr_fh])

        replay_cmd = [
            "tcpreplay",
            f"--pps={pps}",
            "--loop=1",
            "-i", "lo",
            pcap_path,
        ]

        logger.info("Launching tcpreplay: %s", " ".join(replay_cmd))
        proc = subprocess.Popen(
            replay_cmd,
            stdout=replay_stdout_fh,
            stderr=replay_stderr_fh,
        )
        logger.info("tcpreplay launched (pid=%d)", proc.pid)
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


# Ensure combined_plugins/ dir + symlinks exist at import time
_ensure_combined_plugins()
