from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from models import Alert, Engine, Proto

logger = logging.getLogger("parsers")

# Snort alert_csv field indices (Snort 3, default alert_csv output)
# timestamp, pkt_num, proto, service, pkt_len, direction, src_ip:port, dst_ip:port, gid:sid:rev, action
_F_TS = 0
_F_PROTO = 2
_F_SRC = 6
_F_DST = 7
_F_GID_SID_REV = 8


def _split_addr(field: str) -> tuple[str, int] | None:
    """Split 'ip:port' using rfind so IPv4 works. Returns None for unresolvable."""
    field = field.strip()
    sep = field.rfind(":")
    if sep == -1:
        return None
    ip = field[:sep]
    port_str = field[sep + 1:]
    # Reject IPv6 (multiple colons in the ip portion)
    if ":" in ip:
        return None
    # ':0' appears for UNK-direction packets (non-IP traffic)
    if not ip or ip == "":
        return None
    try:
        return ip, int(port_str)
    except ValueError:
        return None


def _parse_proto(raw: str) -> Proto:
    upper = raw.strip().upper()
    if upper in ("TCP", "UDP", "ICMP"):
        return Proto(upper)
    return Proto.TCP  # default for unknown (eth, raw, etc.)


def parse_alert_csv_line(line: str, engine: Engine) -> Optional[Alert]:
    """Parse one Snort 3 alert_csv line into an Alert. Returns None on any parse failure."""
    line = line.strip()
    if not line:
        return None

    parts = [p.strip() for p in line.split(",")]
    if len(parts) < 9:
        logger.debug("too few fields (%d): %s", len(parts), line[:80])
        return None

    # Parse src / dst — skip non-IP rows (UNK direction with ':0')
    src = _split_addr(parts[_F_SRC])
    dst = _split_addr(parts[_F_DST])
    if src is None or dst is None:
        logger.debug("unparseable addr: %s | %s", parts[_F_SRC], parts[_F_DST])
        return None

    # Parse gid:sid:rev
    gid_sid = parts[_F_GID_SID_REV].split(":")
    if len(gid_sid) < 2:
        logger.debug("bad gid:sid:rev: %s", parts[_F_GID_SID_REV])
        return None
    try:
        gid = int(gid_sid[0])
        sid = int(gid_sid[1])
    except ValueError:
        logger.debug("non-int gid/sid: %s", parts[_F_GID_SID_REV])
        return None

    # Timestamp: Snort uses 'MM/DD-HH:MM:SS.ffffff' without year — use current year
    ts_raw = parts[_F_TS].strip()
    try:
        now = datetime.now(timezone.utc)
        ts = datetime.strptime(f"{now.year}/{ts_raw}", "%Y/%m/%d-%H:%M:%S.%f")
        ts = ts.replace(tzinfo=timezone.utc)
        ts_iso = ts.isoformat()
    except ValueError:
        ts_iso = datetime.now(timezone.utc).isoformat()

    # Build msg from gid/sid (Option B — no score from csv)
    msg = f"GID={gid} SID={sid}"
    if engine == Engine.xgboost:
        msg = f"XGBoost anomaly detected (sid={sid})"
    else:
        msg = f"Community rule {gid}:{sid}"

    return Alert(
        id=str(uuid.uuid4()),
        ts=ts_iso,
        engine=engine,
        src_ip=src[0],
        src_port=src[1],
        dst_ip=dst[0],
        dst_port=dst[1],
        proto=_parse_proto(parts[_F_PROTO]),
        gid=gid,
        sid=sid,
        msg=msg,
        score=None,  # Option B: score added in task 11
    )
