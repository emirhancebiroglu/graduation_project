from __future__ import annotations

import asyncio
import json
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
    PcapName,
    ReplayRequest,
    ReplayStartResponse,
    ScenarioKey,
    ScenariosListResponse,
    ScenarioPayload,
    StatusPayload,
    WsAlertCountsMessage,
    WsAlertMessage,
    WsEvaluationMessage,
    WsStatusMessage,
)
from alert_tailer import AlertTailer
from ground_truth import get_ground_truth_loader, get_ground_truth_loader_for_pcap
from scenarios import (
    DEFAULT_SCENARIO,
    SCENARIO_REGISTRY,
    all_scenarios,
    pcap_path_for,
    resolve_scenario,
)
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
_window_alerts: list[Alert] = []  # window-level alerts kept forever for score patching

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
    # Community baseline measured from snort_combined.lua on full Wednesday PCAP
    "community_baseline": {
        "FP": 36633,
        "fp_gap": 29240,  # 36633 - 7393
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
_active_scenario: ScenarioKey | None = None  # tracks current scenario picker selection

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
# api/ first so shap_explain_*.py in api/ takes priority over scripts/ equivalents
_sys.path.insert(0, str(Path(__file__).parent))
_sys.path.insert(0, str(Path.home() / "bitirme/scripts"))
# Ensure ML packages (numpy, sklearn, xgboost, shap) are findable
# demo-app .venv is minimal (no ML deps) — point to user site-packages
_sys.path.insert(0, str(Path.home() / ".local/lib/python3.12/site-packages"))
# System dist-packages needed for dateutil (used by pandas → shap)
_sys.path.insert(0, "/usr/lib/python3/dist-packages")
_IF_SCORERS: dict[str, Any] = {}
_IF_AVAILABLE = False

def _load_if_scorers() -> None:
    global _IF_AVAILABLE
    from if_score_alert import score as _dos_if
    from if_score_portscan import score as _ps_if
    from if_score_dos_agg import score as _agg_if
    from if_score_bot_client import score as _bot_if
    from if_score_bruteforce import score as _bfc_if
    _IF_SCORERS["xgboost"]    = _dos_if
    _IF_SCORERS["portscan"]   = _ps_if
    _IF_SCORERS["dos_agg"]    = _agg_if
    _IF_SCORERS["bot"]        = _bot_if
    _IF_SCORERS["bruteforce"] = _bfc_if
    _IF_AVAILABLE = True

try:
    _load_if_scorers()
except Exception as _e:
    logger.warning("IF scorer(s) unavailable: %s", _e)

# Per-run XGB alert counter — used for sequential log line matching
_xgb_alert_seq: int = 0
_xgb_log_features: list[list[float]] = []  # populated by log tailer

# Window-level engine: src_ip → {score, features} from aegis_scores.jsonl
_WindowEntry = dict  # {"score": float, "features": list[float] | None}

def _load_window_data(run_dir: "Path", want_ip: str | None = None) -> dict[str, _WindowEntry]:
    """Read /tmp/aegis_scores.jsonl written by C++ plugins with fflush.

    Each line: {"engine":"dos_agg","src_ip":"1.2.3.4","score":0.982,"features":[...]}
    If want_ip given, retries up to 10× (0.2s apart) until IP appears.
    """
    import time
    score_path = Path("/tmp/aegis_scores.jsonl")

    def _scan() -> dict[str, _WindowEntry]:
        data: dict[str, _WindowEntry] = {}
        if not score_path.exists():
            return data
        try:
            with open(score_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        data[obj["src_ip"]] = {
                            "score":    float(obj["score"]),
                            "features": obj.get("features"),
                        }
                    except Exception:
                        pass
        except Exception:
            pass
        return data

    for attempt in range(10):
        data = _scan()
        if want_ip is None or want_ip in data:
            return data
        time.sleep(0.2)
    return data


# Backward-compat shim used only by _load_window_scores callers that only need score
def _load_window_scores(run_dir: "Path", want_ip: str | None = None) -> dict[str, float]:
    return {ip: e["score"] for ip, e in _load_window_data(run_dir, want_ip).items()}


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
    global _xgb_alert_seq, _xgb_log_features, _window_alerts

    _gt_loader.ensure_loaded()
    _WINDOW_ENGINES = {Engine.dos_agg, Engine.portscan, Engine.bruteforce, Engine.bot}
    if alert.engine in _WINDOW_ENGINES:
        # Window-level engines classify per src_ip, not per flow — use IP-level GT
        label = _gt_loader.lookup_ip(alert.src_ip)
    else:
        label = _gt_loader.lookup(alert.src_ip, alert.src_port, alert.dst_ip, alert.dst_port, alert.proto.value)
    alert.ground_truth = label

    # Score + feature enrichment for window-level engines (dos_agg, portscan, bruteforce, bot)
    if alert.engine in _WINDOW_ENGINES and _current_run_dir is not None:
        window_data = await asyncio.to_thread(_load_window_data, _current_run_dir, alert.src_ip)
        entry = window_data.get(alert.src_ip)
        if entry:
            alert.score = entry["score"]
            if entry.get("features"):
                alert.raw_features = entry["features"]
                if _IF_AVAILABLE:
                    engine_key = alert.engine.value  # e.g. "dos_agg", "portscan"
                    scorer = _IF_SCORERS.get(engine_key)
                    if scorer:
                        try:
                            result = await asyncio.to_thread(scorer, alert.raw_features)
                            alert.if_score = result["if_score"]
                            alert.if_label = result["label"]
                        except Exception as exc:
                            logger.warning("IF score error (%s %s): %s", engine_key, alert.src_ip, exc)

    # IF + SHAP enrichment for XGBoost per-flow alerts
    if alert.engine == Engine.xgboost and _current_run_dir is not None:
        entry = await asyncio.to_thread(_read_next_log_entry, _current_run_dir, _xgb_alert_seq)
        if entry is not None:
            fv, score = entry
            alert.raw_features = fv
            if score is not None:
                alert.score = score
            if _IF_AVAILABLE:
                scorer = _IF_SCORERS.get("xgboost")
                if scorer:
                    try:
                        result = await asyncio.to_thread(scorer, fv)
                        alert.if_score = result["if_score"]
                        alert.if_label = result["label"]
                    except Exception as exc:
                        logger.warning("IF score error (xgb alert %d): %s", _xgb_alert_seq, exc)
        else:
            logger.warning("XGB alert #%d: no feature vector found in snort_stdout.log", _xgb_alert_seq)
        _xgb_alert_seq += 1

    _history.append(alert)
    if len(_history) > _HISTORY_MAX:
        _history.pop(0)

    _WINDOW_ENGINES_SET = {Engine.dos_agg, Engine.portscan, Engine.bruteforce, Engine.bot}
    if alert.engine in _WINDOW_ENGINES_SET:
        _window_alerts.append(alert)

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
    logger.info("_force_evaluation: sleep done, run_dir=%s history=%d", _current_run_dir, len(_history))
    if _current_run_dir is not None:
        # Retroactively patch scores + features for window-level alerts (log fully flushed now)
        window_data = await asyncio.to_thread(_load_window_data, _current_run_dir)
        logger.info("_force_evaluation: window_data keys=%s", list(window_data.keys()))
        if window_data:
            patched = 0
            for a in _window_alerts:
                entry = window_data.get(a.src_ip)
                if not entry:
                    continue
                changed = False
                if a.score is None:
                    a.score = entry["score"]; changed = True
                if a.raw_features is None and entry.get("features"):
                    a.raw_features = entry["features"]
                    # Run IF retroactively if not already done
                    if _IF_AVAILABLE and a.if_score is None:
                        engine_key = a.engine.value
                        scorer = _IF_SCORERS.get(engine_key)
                        if scorer:
                            try:
                                r = scorer(a.raw_features)
                                a.if_score = r["if_score"]
                                a.if_label = r["label"]
                                changed = True
                            except Exception as exc:
                                logger.warning("retroactive IF error (%s %s): %s", engine_key, a.src_ip, exc)
                if changed:
                    patched += 1
            logger.info("_force_evaluation: patched=%d window alerts", patched)
            if patched:
                await manager.broadcast(json.dumps({"type": "alerts_updated", "data": [a.model_dump() for a in _window_alerts]}))
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
async def config(scenario: ScenarioKey | None = None) -> dict[str, Any]:
    payload = resolve_scenario(scenario)
    base = dict(_FROZEN_CONFIG)
    # Override the metric block + community baseline with scenario-specific values.
    base["scenario"] = payload.model_dump()
    base["default_scenario"] = DEFAULT_SCENARIO.value
    return base


@app.get("/api/config/scenarios", response_model=ScenariosListResponse)
async def config_scenarios() -> ScenariosListResponse:
    return ScenariosListResponse(scenarios=all_scenarios(), default=DEFAULT_SCENARIO)


@app.get("/api/history")
async def history() -> list[Alert]:
    return [a.model_copy(update={"raw_features": None}) for a in _history]


@app.post("/api/replay/start", response_model=ReplayStartResponse)
async def replay_start(body: ReplayRequest) -> ReplayStartResponse:
    global _gt_loader, _active_scenario

    if body.scenario is not None:
        scenario_payload = resolve_scenario(body.scenario)
        pcap_value = scenario_payload.pcap_name.value
        _active_scenario = body.scenario
    elif body.pcap is not None:
        pcap_value = body.pcap.value
        _active_scenario = None
    else:
        # Default to current default scenario
        scenario_payload = resolve_scenario(DEFAULT_SCENARIO)
        pcap_value = scenario_payload.pcap_name.value
        _active_scenario = DEFAULT_SCENARIO

    pcap_path = _PCAP_DIR / f"{pcap_value}.pcap"
    if not pcap_path.exists():
        raise HTTPException(status_code=400, detail=f"PCAP not found: {pcap_path}")

    _gt_loader = get_ground_truth_loader_for_pcap(pcap_value)
    _gt_loader.ensure_loaded()

    # Apply per-scenario PCAP-slice universe so confusion math reflects only
    # flows/IPs that actually appear in the slice — not the full day.
    if _active_scenario is not None:
        from scenarios import slice_universe_for
        universe = slice_universe_for(_active_scenario)
        _gt_loader.set_slice_universe(universe)
        logger.info("Slice universe applied for %s: %s", _active_scenario.value, universe)
    else:
        _gt_loader.set_slice_universe(None)

    async def _on_launched(run_dir: str) -> None:
        global _history, _window_alerts
        _history = []
        _window_alerts = []
        Path("/tmp/aegis_scores.jsonl").unlink(missing_ok=True)
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
            pcap_name=pcap_value,
            pcap_path=str(pcap_path),
            run_id=_active_run_id,
            on_launched_with_dir=_on_launched,
        )
    except AlreadyRunningError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    logger.info(
        "replay/start: scenario=%s pcap=%s run_id=%s status=%s",
        _active_scenario, pcap_value, state.run_id, state.status,
    )
    return ReplayStartResponse(run_id=state.run_id)


# Absolute paths to api/ SHAP modules — bypasses sys.modules cache pollution from scripts/
_API_DIR = Path(__file__).parent
_SHAP_FILES: dict[str, Path] = {
    "xgboost":    _API_DIR / "shap_explain_alert.py",
    "portscan":   _API_DIR / "shap_explain_portscan.py",
    "dos_agg":    _API_DIR / "shap_explain_dos_agg.py",
    "bot":        _API_DIR / "shap_explain_bot.py",
    "bruteforce": _API_DIR / "shap_explain_bruteforce.py",
}
_shap_cache: dict[str, Any] = {}  # engine_key → loaded module

def _load_shap_module(engine_key: str):
    if engine_key in _shap_cache:
        return _shap_cache[engine_key]
    import importlib.util
    spec = importlib.util.spec_from_file_location(f"_aegis_shap_{engine_key}", _SHAP_FILES[engine_key])
    mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    _shap_cache[engine_key] = mod
    return mod

@app.get("/api/explain/{alert_id}")
async def explain_alert(alert_id: str) -> dict:
    alert = next((a for a in _history if a.id == alert_id), None)
    if alert is None:
        # _history is capped — also search _window_alerts (unbounded, never evicted)
        alert = next((a for a in _window_alerts if a.id == alert_id), None)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found in history")
    engine_key = alert.engine.value
    if engine_key not in _SHAP_FILES:
        raise HTTPException(status_code=400, detail=f"SHAP explain not supported for engine: {engine_key}")
    if alert.raw_features is None:
        raise HTTPException(status_code=400, detail="Feature vector not available for this alert")
    try:
        mod = _load_shap_module(engine_key)
        contributions = await asyncio.to_thread(mod.explain, alert.raw_features)
        narrative = mod.shap_to_narrative(contributions)
        return {"contributions": contributions, "narrative": narrative}
    except Exception as exc:
        logger.error("SHAP explain error (alert_id=%s engine=%s): %s", alert_id, engine_key, exc)
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
