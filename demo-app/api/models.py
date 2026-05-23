from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal, Union
from uuid import uuid4

from pydantic import BaseModel, Field


class Engine(str, Enum):
    xgboost = "xgboost"
    community = "community"


class PcapName(str, Enum):
    normal_2min = "normal_2min"
    dos_hulk_2min = "dos_hulk_2min"
    full_wednesday = "full_wednesday"


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
    pcap: PcapName


class ReplayStartResponse(BaseModel):
    ok: bool = True
    run_id: str


class HealthResponse(BaseModel):
    ok: bool = True
