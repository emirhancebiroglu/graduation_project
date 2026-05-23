from __future__ import annotations

import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from models import (
    Alert,
    AlertCountsPayload,
    Engine,
    EngineEvaluation,
    EvaluationPayload,
    HealthResponse,
    ReplayRequest,
    ReplayStartResponse,
    StatusPayload,
    WsAlertCountsMessage,
    WsAlertMessage,
    WsEvaluationMessage,
    WsStatusMessage,
)
from alert_tailer import AlertTailer
from ground_truth import get_ground_truth_loader
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
    "max_packets": 8,
    "rule3_suppressed_ports": [53, 137, 389],
    "model": "dos_fpr_opt_v3b.json",
    "metrics": {
        "TP": 252657,
        "TN": 432638,
        "FP": 7393,
        "FN": 15,
        "Acc": 0.9893,
        "Prec": 0.9716,
        "Rec": 0.9999,
        "F1": 0.9856,
        "FPR": 0.0168,
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
_gt_loader = get_ground_truth_loader()

# Active tailer tasks — cancelled when replay stops
_tailer_tasks: list[asyncio.Task] = []

# Track current run_dir for file-based line counts
_current_run_dir: Path | None = None
_active_run_id: str | None = None


def _count_alert_lines(path: Path) -> int:
    try:
        with open(path, "rb") as fh:
            return sum(1 for _ in fh)
    except Exception:
        return 0


async def _compute_and_broadcast_evaluation(run_dir: Path) -> None:
    """Read alert CSVs, compute confusion matrix for both engines, broadcast result."""
    from ground_truth import extract_flow_ids_from_alert_csv

    logger.info("Computing evaluation for run_dir=%s", run_dir)

    _gt_loader.ensure_loaded()
    stats = _gt_loader.stats()
    total_flows = stats["total"]

    results = {}
    for engine, subdir in [("xgboost", "xgboost"), ("community", "community")]:
        alert_path = run_dir / subdir / "alert_csv.txt"
        if not alert_path.exists():
            logger.warning("Alert CSV not found for %s: %s", engine, alert_path)
            continue

        flow_ids, _, _ = extract_flow_ids_from_alert_csv(alert_path)
        conf = _gt_loader.compute_confusion(flow_ids)

        if "error" in conf:
            logger.error("Evaluation error for %s: %s", engine, conf["error"])
            continue

        results[engine] = EngineEvaluation(
            TP=conf["TP"],
            TN=conf["TN"],
            FP=conf["FP"],
            FN=conf["FN"],
            accuracy=round(conf["accuracy"], 4),
            precision=round(conf["precision"], 4),
            recall=round(conf["recall"], 4),
            f1=round(conf["f1"], 4),
            fpr=round(conf["fpr"], 4),
        )
        logger.info(
            "%s evaluation: TP=%d, FP=%d, TN=%d, FN=%d, FPR=%.4f",
            engine, conf["TP"], conf["FP"], conf["TN"], conf["FN"], conf["fpr"],
        )

    if "xgboost" in results and "community" in results:
        payload = EvaluationPayload(
            xgboost=results["xgboost"],
            community=results["community"],
            total_flows=total_flows,
        )
        await manager.broadcast(WsEvaluationMessage(data=payload).model_dump_json())
        logger.info("Evaluation broadcast complete")
    else:
        logger.error("Missing results for one or both engines, not broadcasting")

# ── IF enrichment ────────────────────────────────────────────────────────────

import sys as _sys
_sys.path.insert(0, str(Path.home() / "bitirme/scripts"))
# Ensure ML packages (numpy, sklearn, xgboost, shap) are findable
# demo-app .venv is minimal (no ML deps) — point to user site-packages
_sys.path.insert(0, str(Path.home() / ".local/lib/python3.12/site-packages"))
# System dist-packages needed for dateutil (used by pandas → shap)
_sys.path.insert(0, "/usr/lib/python3/dist-packages")
try:
    from if_score_alert import score as _if_score
    _IF_AVAILABLE = True
except Exception as _e:
    logger.warning("IF scorer unavailable: %s", _e)
    _IF_AVAILABLE = False

# Per-run XGB alert counter — used for sequential log line matching
_xgb_alert_seq: int = 0
_xgb_log_features: list[list[float]] = []  # populated by log tailer


def _parse_log_features(line: str) -> list[float] | None:
    """Extract raw feature vector from dos_inspector LogMessage line.

    v3b format (15 features, swin/dwin removed):
      [dos_inspector] s1-high pkts=8 score=0.9902 | dur=0.0000 sp=2 dp=0 sb=116 db=0 smsz=58 dmsz=0 si=0.0479 di=0.0000 fwd=58 bwd=0 fin=0 ack=2 syn=1 biat=0.0 sid=1
    Returns 15 floats or None.
    """
    if "[dos_inspector]" not in line or "sid=" not in line:
        return None
    try:
        def _val(key: str) -> float:
            idx = line.index(key + "=")
            start = idx + len(key) + 1
            end = line.find(" ", start)
            return float(line[start:] if end == -1 else line[start:end])
        return [
            _val("dur"), _val("sp"), _val("dp"),
            _val("sb"), _val("db"), _val("smsz"), _val("dmsz"),
            _val("si"), _val("di"),
            _val("fwd"), _val("bwd"),
            _val("fin"), _val("ack"), _val("syn"), _val("biat"),
        ]
    except (ValueError, IndexError):
        return None


def _read_next_log_feature(run_dir: Path, alert_idx: int) -> list[float] | None:
    """Read the Nth feature vector from snort_stdout.log (0-indexed, matching alert_csv order).

    Retries briefly since Snort may still be writing when first alert arrives.
    """
    import time
    log_path = run_dir / "xgboost" / "snort_stdout.log"
    for attempt in range(10):
        if not log_path.exists():
            time.sleep(0.2)
            continue
        try:
            count = 0
            with open(log_path) as f:
                for line in f:
                    fv = _parse_log_features(line)
                    if fv is not None:
                        if count == alert_idx:
                            return fv
                        count += 1
            # Entry not yet written — wait briefly and retry
            if count <= alert_idx:
                time.sleep(0.2)
                continue
        except Exception as exc:
            logger.warning("log feature read error (idx=%d): %s", alert_idx, exc)
            return None
    return None


# ── Alert ingestion ───────────────────────────────────────────────────────────

async def ingest_alert(alert: Alert) -> None:
    global _xgb_alert_seq, _xgb_log_features

    _gt_loader.ensure_loaded()
    label = _gt_loader.lookup(alert.src_ip, alert.src_port, alert.dst_ip, alert.dst_port, alert.proto.value)
    alert.ground_truth = label

    # IF + SHAP enrichment for XGBoost alerts only
    if alert.engine == Engine.xgboost and _current_run_dir is not None:
        fv = await asyncio.to_thread(_read_next_log_feature, _current_run_dir, _xgb_alert_seq)
        if fv is not None:
            alert.raw_features = fv
            if _IF_AVAILABLE:
                try:
                    result = await asyncio.to_thread(_if_score, fv)
                    alert.if_score = result["if_score"]
                    alert.if_label = result["label"]
                except Exception as exc:
                    logger.warning("IF score error (alert %d): %s", _xgb_alert_seq, exc)
        else:
            logger.warning("XGB alert #%d: no feature vector found in snort_stdout.log", _xgb_alert_seq)
        _xgb_alert_seq += 1

    _history.append(alert)
    if len(_history) > _HISTORY_MAX:
        _history.pop(0)

    c = _counters[alert.engine]
    c["total"] += 1
    c["unique_src"].add(alert.src_ip)
    c["flows"] += 1

    # Exclude raw_features from WS broadcast (internal only, used by /api/explain)
    alert_for_ws = alert.model_copy(update={"raw_features": None})
    await manager.broadcast(WsAlertMessage(engine=alert.engine, data=alert_for_ws).model_dump_json())


def _start_tailers(run_dir: str, run_id: str) -> None:
    """Create and register two AlertTailer tasks for a run directory."""
    global _tailer_tasks, _current_run_dir, _active_run_id, _xgb_alert_seq, _xgb_log_features
    _cancel_tailers()
    _current_run_dir = Path(run_dir)
    _active_run_id = run_id
    _xgb_alert_seq = 0
    _xgb_log_features = []

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
        is_this_run = state is not None and state.run_id == _active_run_id

        if is_this_run and runner.check_natural_exit():
            logger.info("Both Snort processes exited (run_id=%s)", state.run_id)
            await _force_evaluation()
            continue

        msg = WsStatusMessage(
            data=StatusPayload(
                snort_running=runner.is_running(),
                pcap_progress=runner.pcap_progress(),
                error=state.error if state else None,
            )
        )
        await manager.broadcast(msg.model_dump_json())

        if _current_run_dir is not None and is_this_run:
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


async def _force_evaluation() -> None:
    """Stop processes, drain tailers, compute and broadcast evaluation."""
    global _active_run_id
    try:
        await runner.stop()
    except Exception as exc:
        logger.warning("runner.stop() error (ignored): %s", exc)
    # Give tailers time to drain remaining lines — IF enrichment adds ~0.2s per alert
    # 27 alerts × 0.2s retry = 5.4s worst case; use 8s to be safe
    await asyncio.sleep(8.0)
    _cancel_tailers()
    if _current_run_dir is not None:
        await _compute_and_broadcast_evaluation(_current_run_dir)
    else:
        logger.warning("_current_run_dir is None — cannot compute evaluation")
    _active_run_id = None


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-load ground truth CSV so first replay has no latency
    logger.info("Pre-loading ground truth CSV (this takes ~30s)...")
    _gt_loader.ensure_loaded()
    logger.info("Ground truth loaded: %s", _gt_loader.stats())

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
    return [a.model_copy(update={"raw_features": None}) for a in _history]


@app.post("/api/replay/start", response_model=ReplayStartResponse)
async def replay_start(body: ReplayRequest) -> ReplayStartResponse:
    pcap_path = _PCAP_DIR / f"{body.pcap.value}.pcap"
    if not pcap_path.exists():
        raise HTTPException(status_code=400, detail=f"PCAP not found: {pcap_path}")

    async def _on_launched(run_dir: str) -> None:
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
        _start_tailers(run_dir, _active_run_id)
        # Yield so tailers execute their initial _read_new_lines()
        await asyncio.sleep(0.1)

    _active_run_id = str(uuid.uuid4())

    try:
        state = await runner.start(
            pcap_name=body.pcap.value,
            pcap_path=str(pcap_path),
            run_id=_active_run_id,
            on_launched_with_dir=_on_launched,
        )
    except AlreadyRunningError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    logger.info("replay/start: pcap=%s run_id=%s status=%s", body.pcap, state.run_id, state.status)
    return ReplayStartResponse(run_id=state.run_id)


@app.get("/api/explain/{alert_id}")
async def explain_alert(alert_id: str) -> list[dict]:
    alert = next((a for a in _history if a.id == alert_id), None)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found in history")
    if alert.engine != Engine.xgboost:
        raise HTTPException(status_code=400, detail="SHAP explain only available for XGBoost alerts")
    if alert.raw_features is None:
        raise HTTPException(status_code=400, detail="Feature vector not available for this alert")
    try:
        from shap_explain_alert import explain as _shap_explain
        result = await asyncio.to_thread(_shap_explain, alert.raw_features)
        return result
    except Exception as exc:
        logger.error("SHAP explain error (alert_id=%s): %s", alert_id, exc)
        raise HTTPException(status_code=500, detail=f"SHAP error: {exc}")


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
