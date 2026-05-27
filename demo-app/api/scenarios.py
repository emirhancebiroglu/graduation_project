"""Scenario registry: maps ScenarioKey → frozen baselines + display metadata.

Loaded at import time from scenario_baselines.json. Each scenario points to a
sliced PCAP under demo-app/api/pcaps/scenario_<key>.pcap and pins the active
inspector that the UI should foreground.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from models import (
    Engine,
    PcapName,
    ScenarioCommunityBlock,
    ScenarioConfusion,
    ScenarioDisplay,
    ScenarioKey,
    ScenarioMlBlock,
    ScenarioPayload,
)

logger = logging.getLogger("scenarios")

_BASELINES_PATH = Path(__file__).parent / "scenario_baselines.json"
_PCAP_DIR = Path.home() / "bitirme/demo-app/api/pcaps"
DEFAULT_SCENARIO = ScenarioKey.dos


_ENGINE_FOR_KEY: dict[str, Engine] = {
    "dos": Engine.xgboost,
    "portscan": Engine.portscan,
    "bruteforce": Engine.bruteforce,
    "bot": Engine.bot,
    "ddos": Engine.dos_agg,
}


def _engine_for(key: str) -> Engine:
    return _ENGINE_FOR_KEY[key]


# Per-scenario inspector GID set used by main.py for window-level alert filtering.
SCENARIO_ENGINE_GIDS: dict[ScenarioKey, set[int]] = {
    ScenarioKey.dos: {301},        # dos_inspector
    ScenarioKey.portscan: {302},   # portscan_inspector
    ScenarioKey.bruteforce: {307},
    ScenarioKey.bot: {306},
    ScenarioKey.ddos: {303},       # dos_aggregator (IP-level, GID:303)
}

COMMUNITY_GID: set[int] = {1}


def _build_payload(key: str, raw: dict) -> ScenarioPayload:
    ml = raw["ml"]
    confusion = ScenarioConfusion(**ml.get("confusion", {}))

    ml_block = ScenarioMlBlock(
        alerts=ml["alerts"],
        confusion=confusion,
        accuracy=ml.get("accuracy"),
        precision=ml.get("precision"),
        recall=ml.get("recall"),
        f1=ml.get("f1"),
        fpr=ml.get("fpr"),
        avg_score=ml.get("avg_score"),
        attacker_ips_detected=ml.get("attacker_ips_detected"),
        window_recall=ml.get("window_recall"),
        syn_coverage=ml.get("syn_coverage"),
        target=ml.get("target"),
        dedup_seconds=ml.get("dedup_seconds"),
        attacker_ip_list=ml.get("attacker_ip_list"),
        windows_per_ip_range=ml.get("windows_per_ip_range"),
        score_range=ml.get("score_range"),
    )

    comm = raw["community"]
    comm_block = ScenarioCommunityBlock(
        alerts_total_day=comm["alerts_total_day"],
        alerts_on_attackers=comm["alerts_on_attackers"],
        fpr=comm["fpr"],
        confusion=ScenarioConfusion(**comm["confusion"]) if "confusion" in comm else None,
    )

    display = ScenarioDisplay(**raw["display"])

    return ScenarioPayload(
        key=ScenarioKey(key),
        pcap_name=PcapName(raw["pcap_name"]),
        active_engine=_engine_for(key),
        metric_level=raw["metric_level"],
        gt_loader_day=raw["gt_loader_day"],
        ml=ml_block,
        community=comm_block,
        display=display,
    )


def _load_registry() -> tuple[dict[ScenarioKey, ScenarioPayload], dict[ScenarioKey, dict]]:
    if not _BASELINES_PATH.exists():
        raise RuntimeError(f"Missing scenario baselines file: {_BASELINES_PATH}")
    with open(_BASELINES_PATH, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    registry: dict[ScenarioKey, ScenarioPayload] = {}
    universes: dict[ScenarioKey, dict] = {}
    for key, blob in raw.items():
        if key.startswith("_"):
            continue
        try:
            sk = ScenarioKey(key)
            registry[sk] = _build_payload(key, blob)
            if "slice_universe" in blob:
                universes[sk] = blob["slice_universe"]
        except Exception as exc:
            logger.error("Failed to parse scenario %s: %s", key, exc)
            raise
    return registry, universes


SCENARIO_REGISTRY, _SLICE_UNIVERSES = _load_registry()


def slice_universe_for(scenario: ScenarioKey) -> dict | None:
    """Return precomputed PCAP-slice GT universe for confusion math, or None."""
    return _SLICE_UNIVERSES.get(scenario)


def pcap_path_for(scenario: ScenarioKey) -> Path:
    payload = SCENARIO_REGISTRY[scenario]
    return _PCAP_DIR / f"{payload.pcap_name.value}.pcap"


def resolve_scenario(key: ScenarioKey | None) -> ScenarioPayload:
    if key is None:
        return SCENARIO_REGISTRY[DEFAULT_SCENARIO]
    return SCENARIO_REGISTRY[key]


def all_scenarios() -> list[ScenarioPayload]:
    return list(SCENARIO_REGISTRY.values())
