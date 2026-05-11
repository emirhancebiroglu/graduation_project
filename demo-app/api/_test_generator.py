"""Fake alert generator — used only during development (tasks 01-03).

Sends one alert per second to all connected WebSocket clients by calling the
`ingest_alert` callback supplied by main.py.  Alternates between xgboost and
community engines.  Replaced in task 05 by the real alert tailer.
"""
from __future__ import annotations

import asyncio
import logging
import random
from datetime import datetime, timezone
from typing import Awaitable, Callable

from models import Alert, Engine, Proto

logger = logging.getLogger("fake-generator")

_ATTACKER_POOL = [f"192.168.10.{i}" for i in range(5, 20)]
_VICTIM_POOL = [f"172.16.0.{i}" for i in range(1, 10)]

_XGB_MSGS = [
    "XGBoost: DoS Hulk detected",
    "XGBoost: Brute-force suspected",
    "XGBoost: Anomalous flow score",
]
_COMMUNITY_MSGS = [
    "Community: ET SCAN Nmap TCP",
    "Community: GPL ATTACK_RESPONSE id check returned root",
    "Community: ET DOS Excessive POST",
]


def _random_alert(engine: Engine, counter: int) -> Alert:
    src = random.choice(_ATTACKER_POOL)
    dst = random.choice(_VICTIM_POOL)
    proto = random.choice(list(Proto))

    if engine == Engine.xgboost:
        return Alert(
            ts=datetime.now(timezone.utc).isoformat(),
            engine=engine,
            src_ip=src,
            src_port=random.randint(1024, 65535),
            dst_ip=dst,
            dst_port=random.choice([80, 443, 8080, 22]),
            proto=proto,
            gid=301,
            sid=1000 + counter,
            msg=random.choice(_XGB_MSGS),
            score=round(random.uniform(0.90, 0.999), 4),
        )
    else:
        return Alert(
            ts=datetime.now(timezone.utc).isoformat(),
            engine=engine,
            src_ip=src,
            src_port=random.randint(1024, 65535),
            dst_ip=dst,
            dst_port=random.choice([80, 443, 8080, 22]),
            proto=proto,
            gid=1,
            sid=2000000 + counter,
            msg=random.choice(_COMMUNITY_MSGS),
            score=None,
        )


async def fake_alert_loop(
    ingest: Callable[[Alert], Awaitable[None]],
    interval: float = 1.0,
) -> None:
    counter = 0
    engines = [Engine.xgboost, Engine.community]
    while True:
        engine = engines[counter % 2]
        alert = _random_alert(engine, counter)
        try:
            await ingest(alert)
            logger.debug("fake alert sent: engine=%s id=%s", engine, alert.id)
        except Exception as exc:
            logger.warning("ingest error: %s", exc)
        counter += 1
        await asyncio.sleep(interval)
