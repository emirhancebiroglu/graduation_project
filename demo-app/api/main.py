from __future__ import annotations

import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

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
from ground_truth import get_ground_truth_loader, get_ground_truth_loader_for_pcap
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
    # Community Snort3 rules baseline (CIC Wednesday replay — fixed reference)
    "community_baseline": {
        "FP": 36633,
        "fp_gap": 29240,  # community FP - xgb FP (36633 - 7393)
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
_gt_loader = get_ground_truth_loader()  # default wednesday; swapped on replay start

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
    """Read alert CSVs, compute confusion matrix for all engines, broadcast result."""
    from ground_truth import extract_flow_ids_from_alert_csv, extract_src_ips_from_alert_csv

    logger.info("Computing evaluation for run_dir=%s", run_dir)

    _gt_loader.ensure_loaded()
    stats = _gt_loader.stats()
    total_flows = stats["total"]

    combined_path = run_dir / "combined" / "alert_csv.txt"
    if not combined_path.exists():
        logger.warning("Combined alert CSV not found: %s", combined_path)
        return

    # Engine → GID mapping + evaluation mode
    # Per-flow engines use flow ID matching; cross-flow engines use IP-level matching
    ENGINE_CONFIG = [
        ("xgboost",    {301}, "flow"),   # dos_inspector
        ("portscan",   {302}, "ip"),     # portscan_inspector
        ("dos_agg",    {303}, "ip"),     # dos_aggregator
        ("bot",        {306}, "ip"),     # bot_client_inspector
        ("bruteforce", {307}, "ip"),     # bruteforce_inspector
        ("ddos",       {304}, "ip"),     # ddos_aggregator
        ("community",  {1},   "flow"),   # community rules
    ]

    results: dict[str, EngineEvaluation | None] = {}

    for engine, gid_set, mode in ENGINE_CONFIG:
        if mode == "flow":
            flow_ids, _, _ = extract_flow_ids_from_alert_csv(combined_path, gid_filter=gid_set)
            conf = _gt_loader.compute_confusion(flow_ids)
        else:
            src_ips = extract_src_ips_from_alert_csv(combined_path, gid_filter=gid_set)
            conf = _gt_loader.compute_ip_confusion(src_ips)

        if "error" in conf:
            logger.warning("Evaluation error for %s: %s", engine, conf["error"])
            results[engine] = None
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
        ip_tag = " [IP-level]" if mode == "ip" else ""
        logger.info(
            "%s evaluation%s: TP=%d, FP=%d, TN=%d, FN=%d, FPR=%.4f",
            engine, ip_tag, conf["TP"], conf["FP"], conf["TN"], conf["FN"], conf["fpr"],
        )

    xgb_result = results.get("xgboost")
    comm_result = results.get("community")
    if xgb_result is None or comm_result is None:
        logger.error("Missing results for xgboost or community, not broadcasting")
        return

    payload = EvaluationPayload(
        xgboost=xgb_result,
        portscan=results.get("portscan"),
        dos_agg=results.get("dos_agg"),
        bot=results.get("bot"),
        bruteforce=results.get("bruteforce"),
        ddos=results.get("ddos"),
        community=comm_result,
        total_flows=total_flows,
    )
    await manager.broadcast(WsEvaluationMessage(data=payload).model_dump_json())
    logger.info("Evaluation broadcast complete")

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


def _parse_log_entry(line: str) -> tuple[list[float], float | None] | None:
    """Extract (feature_vector, score) from dos_inspector LogMessage line.

    v3b format:
      [dos_inspector] s1-high pkts=8 score=0.9902 | dur=0.0000 sp=2 dp=0 ...
    Returns (features, score) or None if line is not a dos_inspector entry.
    """
    if "[dos_inspector]" not in line or "sid=" not in line:
        return None
    try:
        def _val(key: str) -> float:
            idx = line.index(key + "=")
            start = idx + len(key) + 1
            end = line.find(" ", start)
            return float(line[start:] if end == -1 else line[start:end])

        score: float | None = None
        if "score=" in line:
            try:
                score = _val("score")
            except (ValueError, IndexError):
                pass

        features = [
            _val("dur"), _val("sp"), _val("dp"),
            _val("sb"), _val("db"), _val("smsz"), _val("dmsz"),
            _val("si"), _val("di"),
            _val("fwd"), _val("bwd"),
            _val("fin"), _val("ack"), _val("syn"), _val("biat"),
        ]
        return (features, score)
    except (ValueError, IndexError):
        return None


def _read_next_log_entry(run_dir: Path, alert_idx: int) -> tuple[list[float], float | None] | None:
    """Read the Nth (features, score) from snort_stdout.log (0-indexed).

    Retries briefly since Snort may still be writing when first alert arrives.
    """
    import time
    log_path = run_dir / "combined" / "snort_stdout.log"
    for attempt in range(10):
        if not log_path.exists():
            time.sleep(0.2)
            continue
        try:
            count = 0
            with open(log_path) as f:
                for line in f:
                    entry = _parse_log_entry(line)
                    if entry is not None:
                        if count == alert_idx:
                            return entry
                        count += 1
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
        entry = await asyncio.to_thread(_read_next_log_entry, _current_run_dir, _xgb_alert_seq)
        if entry is not None:
            fv, score = entry
            alert.raw_features = fv
            if score is not None:
                alert.score = score
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

    if alert.engine not in _counters:
        _counters[alert.engine] = {"total": 0, "unique_src": set(), "flows": 0}
    c = _counters[alert.engine]
    c["total"] += 1
    c["unique_src"].add(alert.src_ip)
    c["flows"] += 1

    # Exclude raw_features from WS broadcast (internal only, used by /api/explain)
    alert_for_ws = alert.model_copy(update={"raw_features": None})
    await manager.broadcast(WsAlertMessage(engine=alert.engine, data=alert_for_ws).model_dump_json())


def _start_tailers(run_dir: str, run_id: str) -> None:
    """Create and register one AlertTailer task for the combined run directory."""
    global _tailer_tasks, _current_run_dir, _active_run_id, _xgb_alert_seq, _xgb_log_features
    _cancel_tailers()
    _current_run_dir = Path(run_dir)
    _active_run_id = run_id
    _xgb_alert_seq = 0
    _xgb_log_features = []

    # Combined mode: single alert_csv.txt, engine resolved per-alert by GID
    path = Path(run_dir) / "combined" / "alert_csv.txt"
    tailer = AlertTailer(path, None, ingest_alert)
    task = asyncio.create_task(tailer.run(), name="tailer-combined")
    _tailer_tasks.append(task)
    logger.info("Alert tailer started for run_dir=%s (combined)", run_dir)


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
            logger.info("Snort process exited (run_id=%s)", state.run_id)
            # First broadcast draining phase with progress=100%
            await manager.broadcast(
                WsStatusMessage(
                    data=StatusPayload(
                        snort_running=True,
                        pcap_progress=1.0,
                        phase="draining",
                    )
                ).model_dump_json()
            )
            await _force_evaluation()
            continue

        phase: Literal["processing", "draining", "complete"] = "processing"
        if state is not None and not runner.is_running() and _active_run_id is None:
            phase = "complete"
        elif state is not None and not runner.is_running():
            phase = "draining"

        msg = WsStatusMessage(
            data=StatusPayload(
                snort_running=runner.is_running(),
                pcap_progress=runner.pcap_progress(),
                phase=phase,
                error=state.error if state else None,
            )
        )
        await manager.broadcast(msg.model_dump_json())

        if _current_run_dir is not None and is_this_run:
            combined_count = await asyncio.to_thread(
                _count_alert_lines, _current_run_dir / "combined" / "alert_csv.txt"
            )
            counts_msg = WsAlertCountsMessage(
                data=AlertCountsPayload(
                    xgboost_file_count=combined_count,
                    community_file_count=0,
                )
            )
            await manager.broadcast(counts_msg.model_dump_json())


async def _force_evaluation() -> None:
    """Stop processes, cancel tailers, compute and broadcast evaluation."""
    global _active_run_id
    try:
        await runner.stop()
    except Exception as exc:
        logger.warning("runner.stop() error (ignored): %s", exc)
    # Cancel tailers immediately — no new alerts enter the pipeline
    _cancel_tailers()
    # Give enrichment tasks time to finish — IF adds ~0.2s per alert
    await asyncio.sleep(8.0)
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
    global _gt_loader
    pcap_path = _PCAP_DIR / f"{body.pcap.value}.pcap"
    if not pcap_path.exists():
        raise HTTPException(status_code=400, detail=f"PCAP not found: {pcap_path}")

    _gt_loader = get_ground_truth_loader_for_pcap(body.pcap.value)
    _gt_loader.ensure_loaded()

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
async def explain_alert(alert_id: str) -> dict:
    alert = next((a for a in _history if a.id == alert_id), None)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found in history")
    if alert.engine != Engine.xgboost:
        raise HTTPException(status_code=400, detail="SHAP explain only available for XGBoost alerts")
    if alert.raw_features is None:
        raise HTTPException(status_code=400, detail="Feature vector not available for this alert")
    try:
        from shap_explain_alert import explain as _shap_explain, shap_to_narrative as _narrative
        contributions = await asyncio.to_thread(_shap_explain, alert.raw_features)
        narrative = _narrative(contributions)
        return {"contributions": contributions, "narrative": narrative}
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
