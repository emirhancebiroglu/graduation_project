from __future__ import annotations

import csv
import logging
import threading
from pathlib import Path

logger = logging.getLogger("ground_truth")

PROTO_MAP = {
    "TCP": 6,
    "UDP": 17,
    "ICMP": 1,
    "tcp": 6,
    "udp": 17,
    "icmp": 1,
}

IP_MAP = {
    "192.168.10.51": "172.16.0.1",
}

WEDNESDAY_CSV_NAME = "Wednesday-workingHours.pcap_ISCX.csv"

DEFAULT_CSV_DIR = Path.home() / "bitirme/data/raw/cicids2017"


def _is_valid_ip(ip: str) -> bool:
    if not ip:
        return False
    if ip.startswith("224.") or ip.startswith("239."):
        return False
    if ip == "255.255.255.255":
        return False
    if ":" in ip:
        return False
    return True


def _map_ip(ip: str) -> str:
    return IP_MAP.get(ip, ip)


def _make_flow_ids(
    src_ip: str, src_port: int,
    dst_ip: str, dst_port: int,
    proto: int,
) -> list[str]:
    """Build flow IDs matching GT CSV format: srcIP-dstIP-srcPort-dstPort-proto.

    NOTE: Alert CSV has src_ip:src_port_field as source and dst_ip:dst_port_field as
    destination. GT CSV uses the SAME field order (srcIP-dstIP-srcPort-dstPort).
    When extracting from alert CSV, alert_csv[6] = src_ip:src_port (attacker client),
    alert_csv[7] = dst_ip:dst_port (victim server). So the flow ID fields map as:
      src_ip_field (alert[6]) → GT_srcIP
      dst_ip_field (alert[7]) → GT_dstIP
      dst_port_field (alert[7]) → GT_srcPort  ← SWAPPED
      src_port_field (alert[6]) → GT_dstPort  ← SWAPPED
    """
    fids = []

    orig_fid1 = f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{proto}"
    orig_fid2 = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}"
    fids.append(orig_fid1)
    fids.append(orig_fid2)

    mapped_src = _map_ip(src_ip)
    mapped_dst = _map_ip(dst_ip)
    if mapped_src != src_ip or mapped_dst != dst_ip:
        fids.append(f"{mapped_dst}-{mapped_src}-{dst_port}-{src_port}-{proto}")
        fids.append(f"{mapped_src}-{mapped_dst}-{src_port}-{dst_port}-{proto}")

    return fids


class GroundTruthLoader:
    _instance: GroundTruthLoader | None = None
    _lock = threading.Lock()

    def __init__(self, csv_dir: Path | None = None):
        self.csv_dir = csv_dir or DEFAULT_CSV_DIR
        self._flow_data: dict[str, dict] = {}
        self._total_rows: int = 0
        self._attack_count: int = 0
        self._benign_count: int = 0
        self._loaded: bool = False
        self._load_error: str | None = None

    @classmethod
    def get_instance(cls, csv_dir: Path | None = None) -> GroundTruthLoader:
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(csv_dir)
            return cls._instance

    def ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._load()

    def _load(self) -> None:
        csv_path = self.csv_dir / WEDNESDAY_CSV_NAME
        if not csv_path.exists():
            self._load_error = f"Wednesday CSV not found: {csv_path}"
            logger.error(self._load_error)
            self._loaded = True
            return

        logger.info(f"Loading ground truth CSV: {csv_path}")
        skipped = 0

        try:
            with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    raw_flow_id = row.get("Flow ID", "").strip()
                    raw_label = row.get(" Label", "").strip()
                    flow_id = raw_flow_id.strip("\r\n")
                    label = raw_label.strip("\r\n")
                    if not flow_id:
                        skipped += 1
                        continue
                    self._total_rows += 1
                    is_attack = label != "BENIGN"
                    if is_attack:
                        self._attack_count += 1
                    else:
                        self._benign_count += 1
                    if flow_id not in self._flow_data:
                        self._flow_data[flow_id] = {"attack_rows": 0, "benign_rows": 0}
                    if is_attack:
                        self._flow_data[flow_id]["attack_rows"] += 1
                    else:
                        self._flow_data[flow_id]["benign_rows"] += 1
        except Exception as exc:
            self._load_error = f"Failed to read CSV: {exc}"
            logger.error(self._load_error)
            self._loaded = True
            return

        if skipped > 0:
            logger.warning(f"  Skipped {skipped:,} rows with missing Flow ID")

        logger.info(
            f"  Ground truth loaded: {self._total_rows:,} rows, "
            f"{self._attack_count:,} attack rows, {self._benign_count:,} benign rows"
        )
        logger.info(f"  Flow lookup table built: {len(self._flow_data):,} unique flow IDs")
        self._loaded = True

    def lookup(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto_str: str) -> str | None:
        """Look up ground truth for a flow. Returns 'attack', 'benign', or None."""
        if not self._loaded:
            self._load()

        if self._load_error:
            return None

        if not _is_valid_ip(src_ip) or not _is_valid_ip(dst_ip):
            return None

        if src_port == 0 or dst_port == 0:
            return None

        proto_num = PROTO_MAP.get(proto_str.upper(), 0)
        if proto_num == 0:
            return None

        flow_ids = _make_flow_ids(src_ip, src_port, dst_ip, dst_port, proto_num)

        for fid in flow_ids:
            if fid in self._flow_data:
                fd = self._flow_data[fid]
                return "attack" if fd["attack_rows"] > 0 else "benign"

        return None

    def stats(self) -> dict:
        return {
            "total": self._total_rows,
            "attacks": self._attack_count,
            "benign": self._benign_count,
            "flow_entries": len(self._flow_data),
            "loaded": self._loaded,
            "error": self._load_error,
        }

    def compute_confusion(self, alert_flow_ids: set[str]) -> dict:
        """Compute confusion matrix metrics given a set of alerted flow IDs.
        
        Matches alert flow IDs against GT flow IDs (unique flow IDs, not rows).
        TP = total attack rows across matched flows.
        FP = total benign rows across matched flows.
        """
        if not self._loaded:
            self._load()

        if self._load_error:
            return {"error": self._load_error}

        if not self._flow_data:
            return {"error": "No ground truth loaded"}

        matched_attack_rows = 0
        matched_benign_rows = 0

        for flow_id, fd in self._flow_data.items():
            if flow_id in alert_flow_ids:
                matched_attack_rows += fd["attack_rows"]
                matched_benign_rows += fd["benign_rows"]

        true_positives = matched_attack_rows
        false_positives = matched_benign_rows
        true_negatives = self._benign_count - false_positives
        false_negatives = self._attack_count - true_positives
        total = true_positives + true_negatives + false_positives + false_negatives

        accuracy   = (true_positives + true_negatives) / total if total > 0 else 0
        precision  = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
        recall     = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
        f1         = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        fpr        = false_positives / (false_positives + true_negatives) if (false_positives + true_negatives) > 0 else 0

        return {
            "TP": true_positives,
            "TN": true_negatives,
            "FP": false_positives,
            "FN": false_negatives,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "fpr": fpr,
            "total": total,
        }


def get_ground_truth_loader(csv_dir: Path | None = None) -> GroundTruthLoader:
    return GroundTruthLoader.get_instance(csv_dir)


def extract_flow_ids_from_alert_csv(
    alert_path: Path,
) -> tuple[set[str], int, int]:
    """Extract unique flow IDs from a Snort alert_csv.txt file.

    Returns (flow_ids, total_lines, filtered_lines).
    Uses the EXACT same logic as xgb_flowid_confusion_wednesday.py.
    """
    flow_ids: set[str] = set()
    total = 0
    filtered = 0

    if not alert_path.exists():
        logger.warning(f"Alert file not found: {alert_path}")
        return flow_ids, 0, 0

    with open(alert_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            total += 1

            parts = line.split(",")
            if len(parts) < 8:
                filtered += 1
                continue

            try:
                proto_str = parts[2].strip()

                src_field = parts[6].strip()
                dst_field = parts[7].strip()

                src_sep = src_field.rfind(":")
                dst_sep = dst_field.rfind(":")
                if src_sep == -1 or dst_sep == -1:
                    filtered += 1
                    continue

                src_ip = src_field[:src_sep]
                src_port_str = src_field[src_sep + 1:]
                dst_ip = dst_field[:dst_sep]
                dst_port_str = dst_field[dst_sep + 1:]

                if ":" in src_ip or ":" in dst_ip:
                    filtered += 1
                    continue

                try:
                    src_port = int(src_port_str)
                    dst_port = int(dst_port_str)
                except ValueError:
                    filtered += 1
                    continue

                if not _is_valid_ip(src_ip) or not _is_valid_ip(dst_ip):
                    filtered += 1
                    continue

                if src_port == 0 or dst_port == 0:
                    filtered += 1
                    continue

                proto_num = PROTO_MAP.get(proto_str.upper(), 0)
                if proto_num == 0:
                    filtered += 1
                    continue

                mapped_src = _map_ip(src_ip)
                mapped_dst = _map_ip(dst_ip)

                fids = _make_flow_ids(src_ip, src_port, dst_ip, dst_port, proto_num)
                if mapped_src != src_ip or mapped_dst != dst_ip:
                    mapped_fids = _make_flow_ids(mapped_src, src_port, mapped_dst, dst_port, proto_num)
                    fids.extend(mapped_fids)

                for fid in fids:
                    flow_ids.add(fid)

            except (IndexError, ValueError):
                filtered += 1
                continue

    return flow_ids, total, filtered