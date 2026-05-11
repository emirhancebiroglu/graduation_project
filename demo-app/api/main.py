from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from models import (
    Alert,
    AlertCountsPayload,
    Engine,
    HealthResponse,
    ReplayRequest,
    ReplayStartResponse,
    StatusPayload,
    WsAlertCountsMessage,
    WsAlertMessage,
    WsStatusMessage,
)
from alert_tailer import AlertTailer
from snort_runner import AlreadyRunningError, SnortRunner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("demo-api")

# ── Paths ─────────────────────────────────────────────────────────────────────

_PCAP_DIR = Path.home() / "bitirme/demo-app/api/pcaps"

# ── In-memory state ───────────────────────────────────────────────────────────

_history: list[Alert] = []
_HISTORY_MAX = 1000

_counters: dict[Engine, dict[str, Any]] = {
    Engine.xgboost: {"total": 0, "unique_src": set(), "flows": 0},
    Engine.community: {"total": 0, "unique_src": set(), "flows": 0},
}

_FROZEN_CONFIG: dict[str, Any] = {
    "threshold": 0.90,
    "max_packets": 2,
    "rule3_suppressed_ports": [53, 137, 389],
    "model": "fine_tuned_xgb_model.json",
    "metrics": {
        "TP": 252610,
        "TN": 432318,
        "FP": 7713,
        "FN": 62,
        "Acc": 0.9888,
        "Prec": 0.9704,
        "Rec": 0.9998,
        "F1": 0.9848,
        "FPR": 0.0175,
    },
}

# ── Connection manager ────────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.append(ws)
        logger.info("WS client connected (total=%d)", len(self._connections))

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self._connections:
            self._connections.remove(ws)
        logger.info("WS client disconnected (total=%d)", len(self._connections))

    async def broadcast(self, payload: str) -> None:
        dead: list[WebSocket] = []
        for ws in list(self._connections):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in self._connections:
                self._connections.remove(ws)


manager = ConnectionManager()
runner = SnortRunner()

# Active tailer tasks — cancelled when replay stops
_tailer_tasks: list[asyncio.Task] = []

# Track current run_dir for file-based line counts
_current_run_dir: Path | None = None


def _count_alert_lines(path: Path) -> int:
    try:
        with open(path, "rb") as fh:
            return sum(1 for _ in fh)
    except Exception:
        return 0

# ── Alert ingestion ───────────────────────────────────────────────────────────

async def ingest_alert(alert: Alert) -> None:
    _history.append(alert)
    if len(_history) > _HISTORY_MAX:
        _history.pop(0)

    c = _counters[alert.engine]
    c["total"] += 1
    c["unique_src"].add(alert.src_ip)
    c["flows"] += 1

    await manager.broadcast(WsAlertMessage(engine=alert.engine, data=alert).model_dump_json())


def _start_tailers(run_dir: str) -> None:
    """Create and register two AlertTailer tasks for a run directory."""
    global _tailer_tasks, _current_run_dir
    _cancel_tailers()
    _current_run_dir = Path(run_dir)

    for engine, subdir in [(Engine.xgboost, "xgboost"), (Engine.community, "community")]:
        path = Path(run_dir) / subdir / "alert_csv.txt"
        tailer = AlertTailer(path, engine, ingest_alert)
        task = asyncio.create_task(tailer.run(), name=f"tailer-{subdir}")
        _tailer_tasks.append(task)
    logger.info("Alert tailers started for run_dir=%s", run_dir)


def _cancel_tailers() -> None:
    global _tailer_tasks
    for task in _tailer_tasks:
        if not task.done():
            task.cancel()
    _tailer_tasks = []


# ── Background tasks ──────────────────────────────────────────────────────────

async def _status_broadcaster() -> None:
    """Broadcasts Snort status every 1s; detects natural process exit."""
    while True:
        await asyncio.sleep(1.0)
        state = runner.state
        if state is not None and runner.is_running() and runner.check_natural_exit():
            logger.info("Both Snort processes exited naturally (run_id=%s)", state.run_id)
            await runner.stop()
            # Give tailers time to drain the remaining lines before cancelling
            await asyncio.sleep(1.0)
            _cancel_tailers()

        current_state = runner.state
        msg = WsStatusMessage(
            data=StatusPayload(
                snort_running=runner.is_running(),
                pcap_progress=runner.pcap_progress(),
                error=current_state.error if current_state else None,
            )
        )
        await manager.broadcast(msg.model_dump_json())

        if _current_run_dir is not None:
            xgb_count = await asyncio.to_thread(
                _count_alert_lines, _current_run_dir / "xgboost" / "alert_csv.txt"
            )
            comm_count = await asyncio.to_thread(
                _count_alert_lines, _current_run_dir / "community" / "alert_csv.txt"
            )
            counts_msg = WsAlertCountsMessage(
                data=AlertCountsPayload(
                    xgboost_file_count=xgb_count,
                    community_file_count=comm_count,
                )
            )
            await manager.broadcast(counts_msg.model_dump_json())


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    status_task = asyncio.create_task(_status_broadcaster())
    logger.info("Status broadcaster started")

    yield

    status_task.cancel()
    try:
        await status_task
    except asyncio.CancelledError:
        pass

    _cancel_tailers()
    await runner.cleanup()
    logger.info("Shutdown complete")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="Bitirme Demo API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── REST endpoints ────────────────────────────────────────────────────────────

@app.get("/api/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse()


@app.get("/api/config")
async def config() -> dict[str, Any]:
    return _FROZEN_CONFIG


@app.get("/api/history")
async def history() -> list[Alert]:
    return list(_history)


@app.post("/api/replay/start", response_model=ReplayStartResponse)
async def replay_start(body: ReplayRequest) -> ReplayStartResponse:
    pcap_path = _PCAP_DIR / f"{body.pcap.value}.pcap"
    if not pcap_path.exists():
        raise HTTPException(status_code=400, detail=f"PCAP not found: {pcap_path}")

    async def _on_launched(run_dir: str) -> None:
        # Reset per-run state so previous replay counts don't bleed into this run
        global _history
        _history = []
        for eng in _counters:
            _counters[eng] = {"total": 0, "unique_src": set(), "flows": 0}

        # Broadcast running status AND start tailers immediately at launch time,
        # not after the 2s early-exit check. This ensures alerts written during
        # fast PCAP replay are captured even if Snort exits before start() returns.
        msg = WsStatusMessage(
            data=StatusPayload(snort_running=True, pcap_progress=0.0, error=None)
        )
        await manager.broadcast(msg.model_dump_json())
        _start_tailers(run_dir)
        # Yield so tailers execute their initial _read_new_lines()
        await asyncio.sleep(0.1)

    try:
        state = await runner.start(
            pcap_name=body.pcap.value,
            pcap_path=str(pcap_path),
            on_launched_with_dir=_on_launched,
        )
    except AlreadyRunningError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    logger.info("replay/start: pcap=%s run_id=%s status=%s", body.pcap, state.run_id, state.status)
    return ReplayStartResponse(run_id=state.run_id)


@app.post("/api/replay/stop")
async def replay_stop() -> dict[str, bool]:
    _cancel_tailers()
    await runner.stop()
    logger.info("replay/stop: done")
    return {"ok": True}


# ── WebSocket endpoint ────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await manager.connect(ws)

    state = runner.state
    await ws.send_text(
        WsStatusMessage(
            data=StatusPayload(
                snort_running=runner.is_running(),
                pcap_progress=runner.pcap_progress(),
                error=state.error if state else None,
            )
        ).model_dump_json()
    )

    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)
