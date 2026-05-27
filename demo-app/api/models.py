from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal, Union
from uuid import uuid4

from pydantic import BaseModel, Field


class Engine(str, Enum):
    xgboost = "xgboost"       # GID:301 dos_inspector
    community = "community"   # GID:1   community rules
    portscan = "portscan"     # GID:302 portscan_inspector
    dos_agg = "dos_agg"       # GID:303 dos_aggregator
    ddos = "ddos"             # GID:304 ddos_aggregator
    bot = "bot"               # GID:306 bot_client_inspector
    bruteforce = "bruteforce" # GID:307 bruteforce_inspector


class PcapName(str, Enum):
    normal_2min = "normal_2min"
    dos_hulk_2min = "dos_hulk_2min"
    full_wednesday = "full_wednesday"
    scenario_dos = "scenario_dos"
    scenario_portscan = "scenario_portscan"
    scenario_bruteforce = "scenario_bruteforce"
    scenario_bot = "scenario_bot"
    scenario_ddos = "scenario_ddos"


class ScenarioKey(str, Enum):
    dos = "dos"
    portscan = "portscan"
    bruteforce = "bruteforce"
    bot = "bot"
    ddos = "ddos"


class Proto(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"


# ── Alert ────────────────────────────────────────────────────────────────────

class Alert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    ts: str                          # ISO-8601
    engine: Engine
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: Proto
    gid: int                         # 301 = xgboost, 1000+ = community
    sid: int
    msg: str
    score: float | None = None       # xgboost only, 0..1
    ground_truth: str | None = None   # "attack" | "benign" | None
    if_score: float | None = None    # IsolationForest anomaly score (more negative = more anomalous)
    if_label: str | None = None      # "anomaly_candidate" | "known_pattern" | None
    raw_features: list[float] | None = None  # 15 raw feature values for SHAP explain (v3b schema, not sent to frontend)
    mitre_technique: str | None = None  # e.g. "T1499"
    mitre_tactic: str | None = None     # e.g. "TA0040"


# ── Metrics ──────────────────────────────────────────────────────────────────

class Metrics(BaseModel):
    total_alerts: int
    alerts_per_sec: float
    unique_attackers: int
    flagged_flows: int


# ── ComparisonSnapshot ───────────────────────────────────────────────────────

class EngineSnapshot(BaseModel):
    alerts: int
    first_alert_ms: int | None


class ComparisonSnapshot(BaseModel):
    xgboost: EngineSnapshot
    community: EngineSnapshot
    pcap_elapsed_ms: int


# ── Status ───────────────────────────────────────────────────────────────────

class StatusPayload(BaseModel):
    snort_running: bool
    pcap_progress: float             # 0.0..1.0
    phase: Literal["processing", "draining", "complete"] = "processing"
    error: str | None = None


# ── WsMessage discriminated union ────────────────────────────────────────────

class WsAlertMessage(BaseModel):
    type: Literal["alert"] = "alert"
    engine: Engine
    data: Alert


class WsMetricMessage(BaseModel):
    type: Literal["metric"] = "metric"
    engine: Engine
    data: Metrics


class WsStatusMessage(BaseModel):
    type: Literal["status"] = "status"
    data: StatusPayload


class WsComparisonMessage(BaseModel):
    type: Literal["comparison"] = "comparison"
    data: ComparisonSnapshot


class AlertCountsPayload(BaseModel):
    xgboost_file_count: int
    community_file_count: int


class WsAlertCountsMessage(BaseModel):
    type: Literal["alert_counts"] = "alert_counts"
    data: AlertCountsPayload


class EngineEvaluation(BaseModel):
    TP: int
    TN: int
    FP: int
    FN: int
    accuracy: float
    precision: float
    recall: float
    f1: float
    fpr: float


class EvaluationPayload(BaseModel):
    xgboost: EngineEvaluation
    portscan: EngineEvaluation | None = None
    dos_agg: EngineEvaluation | None = None
    bot: EngineEvaluation | None = None
    bruteforce: EngineEvaluation | None = None
    ddos: EngineEvaluation | None = None
    community: EngineEvaluation
    total_flows: int


class WsEvaluationMessage(BaseModel):
    type: Literal["evaluation"] = "evaluation"
    data: EvaluationPayload


WsMessage = Annotated[
    Union[WsAlertMessage, WsMetricMessage, WsStatusMessage, WsComparisonMessage, WsAlertCountsMessage, WsEvaluationMessage],
    Field(discriminator="type"),
]


# ── REST request/response shapes ─────────────────────────────────────────────

class ReplayRequest(BaseModel):
    pcap: PcapName | None = None
    scenario: ScenarioKey | None = None


class ReplayStartResponse(BaseModel):
    ok: bool = True
    run_id: str


# ── Scenario registry payloads ────────────────────────────────────────────────

MetricLevel = Literal["flow", "window"]


class ScenarioConfusion(BaseModel):
    TP: int | None = None
    FP: int | None = None
    FN: int | None = None
    TN: int | None = None
    TP_windows: int | None = None
    FP_windows: int | None = None
    FN_windows: int | None = None
    TN_windows: int | None = None


class ScenarioMlBlock(BaseModel):
    alerts: int
    confusion: ScenarioConfusion
    accuracy: float | None = None
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None
    fpr: float | None = None
    avg_score: float | None = None
    attacker_ips_detected: str | None = None
    window_recall: float | None = None
    syn_coverage: float | None = None
    target: str | None = None
    dedup_seconds: int | None = None
    attacker_ip_list: list[str] | None = None
    windows_per_ip_range: str | None = None
    score_range: list[float] | None = None


class ScenarioCommunityBlock(BaseModel):
    alerts_total_day: int
    alerts_on_attackers: int
    fpr: float
    confusion: ScenarioConfusion | None = None


class ScenarioDisplay(BaseModel):
    title_key: str
    attack_label: str
    dataset_label: str
    generalization_chip: str


class ScenarioPayload(BaseModel):
    key: ScenarioKey
    pcap_name: PcapName
    active_engine: Engine
    metric_level: MetricLevel
    gt_loader_day: str
    ml: ScenarioMlBlock
    community: ScenarioCommunityBlock
    display: ScenarioDisplay


class ScenariosListResponse(BaseModel):
    scenarios: list[ScenarioPayload]
    default: ScenarioKey


class HealthResponse(BaseModel):
    ok: bool = True
