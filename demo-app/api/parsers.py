from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from models import Alert, Engine, Proto

logger = logging.getLogger("parsers")

_alert_seq = 0

# GID → Engine routing
_GID_ENGINE: dict[int, Engine] = {
    301: Engine.xgboost,
    302: Engine.portscan,
    303: Engine.dos_agg,
    304: Engine.ddos,
    306: Engine.bot,
    307: Engine.bruteforce,
    1:   Engine.community,
}

# MITRE ATT&CK mapping keyed by GID
_MITRE_MAP: dict[int, tuple[str, str]] = {
    301: ("T1499", "TA0040"),  # Endpoint Denial of Service
    303: ("T1498", "TA0040"),  # Network Denial of Service
    304: ("T1498", "TA0040"),  # Network Denial of Service (DDoS aggregator)
    302: ("T1046", "TA0043"),  # Network Service Discovery
    307: ("T1110", "TA0006"),  # Brute Force
    306: ("T1071", "TA0011"),  # Application Layer Protocol (C2)
    1:   ("T1190", "TA0001"),  # Exploit Public-Facing Application
}

_GID_MSG: dict[int, str] = {
    301: "DoS detected (per-flow)",
    302: "Port scan detected",
    303: "DoS flood detected",
    304: "DDoS HTTP flood detected",
    306: "Bot client detected",
    307: "Brute force detected",
}

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


def parse_alert_csv_line(line: str, engine: Engine | None = None) -> Optional[Alert]:
    """Parse one Snort 3 alert_csv line into an Alert.

    engine: if None, derived from GID via _GID_ENGINE (combined mode).
            if provided, used as-is (legacy single-engine mode).
    Returns None on any parse failure.
    """
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

    # Resolve engine: GID-based routing in combined mode
    resolved_engine = engine if engine is not None else _GID_ENGINE.get(gid, Engine.community)

    # Timestamp: current time with monotonically increasing microsecond offset
    # so alerts parsed in the same second get unique, ordered timestamps
    global _alert_seq
    now = datetime.now(timezone.utc)
    ts = now.replace(microsecond=(now.microsecond + _alert_seq) % 1000000)
    _alert_seq += 1
    ts_iso = ts.isoformat()

    msg = _GID_MSG.get(gid, f"Community rule {gid}:{sid}")

    mitre = _MITRE_MAP.get(gid)
    return Alert(
        id=str(uuid.uuid4()),
        ts=ts_iso,
        engine=resolved_engine,
        src_ip=src[0],
        src_port=src[1],
        dst_ip=dst[0],
        dst_port=dst[1],
        proto=_parse_proto(parts[_F_PROTO]),
        gid=gid,
        sid=sid,
        msg=msg,
        score=None,
        mitre_technique=mitre[0] if mitre else None,
        mitre_tactic=mitre[1] if mitre else None,
    )
