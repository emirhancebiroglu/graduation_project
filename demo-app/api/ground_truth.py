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

DAILY_CSVS: dict[str, list[str]] = {
    "monday":    ["Monday-WorkingHours.pcap_ISCX.csv"],
    "tuesday":   ["Tuesday-WorkingHours.pcap_ISCX.csv"],
    "wednesday": ["Wednesday-workingHours.pcap_ISCX.csv"],
    "thursday":  [
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    ],
    "friday":    [
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    ],
}

# Legacy — kept for backward compat
WEDNESDAY_CSV_NAME = "Wednesday-workingHours.pcap_ISCX.csv"

DEFAULT_CSV_DIR = Path.home() / "bitirme/data/raw/cicids2017"


def _day_from_pcap(pcap_path: str) -> str:
    """Infer day key from PCAP filename (case-insensitive)."""
    name = pcap_path.lower()
    for day in DAILY_CSVS:
        if day in name:
            return day
    return "wednesday"


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
    _instances: dict[str, GroundTruthLoader] = {}
    _lock = threading.Lock()

    def __init__(self, day: str = "wednesday", csv_dir: Path | None = None):
        self.day = day
        self.csv_dir = csv_dir or DEFAULT_CSV_DIR
        self._flow_data: dict[str, dict] = {}
        self._ip_data: dict[str, str] = {}
        self._total_rows: int = 0
        self._attack_count: int = 0
        self._benign_count: int = 0
        self._loaded: bool = False
        self._load_error: str | None = None

    @classmethod
    def get_instance(cls, day: str = "wednesday", csv_dir: Path | None = None) -> GroundTruthLoader:
        with cls._lock:
            if day not in cls._instances:
                cls._instances[day] = cls(day, csv_dir)
            return cls._instances[day]

    @classmethod
    def get_instance_for_pcap(cls, pcap_path: str, csv_dir: Path | None = None) -> GroundTruthLoader:
        day = _day_from_pcap(pcap_path)
        return cls.get_instance(day, csv_dir)

    @classmethod
    def reset(cls) -> None:
        with cls._lock:
            cls._instances.clear()

    def ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._load()

    def _load_one_csv(self, csv_path: Path, skipped_ref: list[int]) -> None:
        logger.info(f"Loading ground truth CSV: {csv_path}")
        try:
            with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    raw_flow_id = row.get("Flow ID", "").strip()
                    raw_label = row.get(" Label", "").strip()
                    flow_id = raw_flow_id.strip("\r\n")
                    label = raw_label.strip("\r\n")
                    if not flow_id:
                        skipped_ref[0] += 1
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
            self._load_error = f"Failed to read CSV {csv_path}: {exc}"
            logger.error(self._load_error)

    def _load(self) -> None:
        csv_names = DAILY_CSVS.get(self.day, DAILY_CSVS["wednesday"])
        skipped_ref = [0]
        found_any = False

        for csv_name in csv_names:
            csv_path = self.csv_dir / csv_name
            if not csv_path.exists():
                logger.warning(f"GT CSV not found (skipping): {csv_path}")
                continue
            found_any = True
            self._load_one_csv(csv_path, skipped_ref)
            if self._load_error:
                self._loaded = True
                return

        if not found_any:
            self._load_error = f"No GT CSVs found for day '{self.day}' in {self.csv_dir}"
            logger.error(self._load_error)
            self._loaded = True
            return

        if skipped_ref[0] > 0:
            logger.warning(f"  Skipped {skipped_ref[0]:,} rows with missing Flow ID")

        logger.info(
            f"  Ground truth loaded ({self.day}): {self._total_rows:,} rows, "
            f"{self._attack_count:,} attack rows, {self._benign_count:,} benign rows"
        )
        logger.info(f"  Flow lookup table built: {len(self._flow_data):,} unique flow IDs")

        self._build_ip_index()

        self._loaded = True

    def _build_ip_index(self) -> None:
        """Build src_ip → label index from flow data for cross-flow evaluation."""
        ip_labels: dict[str, set[str]] = {}
        for flow_id, fd in self._flow_data.items():
            parts = flow_id.split("-")
            if len(parts) < 2:
                continue
            src_ip = parts[0]
            if not _is_valid_ip(src_ip):
                continue
            if fd["attack_rows"] > 0:
                ip_labels.setdefault(src_ip, set()).add("attack")
            if fd["benign_rows"] > 0:
                ip_labels.setdefault(src_ip, set()).add("benign")

        self._ip_data = {}
        for ip, labels in ip_labels.items():
            if "attack" in labels:
                self._ip_data[ip] = "attack"
            else:
                self._ip_data[ip] = "benign"

        logger.info(
            f"  IP index built ({self.day}): {len(self._ip_data):,} unique IPs, "
            f"{sum(1 for v in self._ip_data.values() if v == 'attack')} attack, "
            f"{sum(1 for v in self._ip_data.values() if v == 'benign')} benign"
        )

    def lookup(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto_str: str) -> str | None:
        """Look up ground truth for a flow. Returns 'attack', 'benign', or None."""
        if not self._loaded:
            self._load()

        if self._load_error:
            return None

        if not _is_valid_ip(src_ip) or not _is_valid_ip(dst_ip):
            return None

        proto_num = PROTO_MAP.get(proto_str.upper(), 0)

        # ICMP has no ports (type/code appear as 0) — skip port filter
        if proto_num != 1 and (src_port == 0 or dst_port == 0):
            return None
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

    def lookup_ip(self, src_ip: str) -> str | None:
        """IP-level ground truth lookup for cross-flow inspectors."""
        if not self._loaded:
            self._load()
        if self._load_error:
            return None
        return self._ip_data.get(src_ip)

    def compute_ip_confusion(self, alert_src_ips: set[str]) -> dict:
        """IP-level confusion matrix for cross-flow inspectors.

        TP = alerted src_ip whose GT label is "attack"
        FP = alerted src_ip whose GT label is "benign"
        FN = GT "attack" IPs that were NOT alerted
        TN = GT "benign" IPs that were NOT alerted
        """
        if not self._loaded:
            self._load()

        if self._load_error:
            return {"error": self._load_error}

        if not self._ip_data:
            return {"error": "No IP ground truth loaded"}

        alerted = alert_src_ips & set(self._ip_data.keys())
        non_alerted = set(self._ip_data.keys()) - alert_src_ips

        ip_tp = sum(1 for ip in alerted if self._ip_data[ip] == "attack")
        ip_fp = sum(1 for ip in alerted if self._ip_data[ip] == "benign")
        ip_fn = sum(1 for ip in non_alerted if self._ip_data[ip] == "attack")
        ip_tn = sum(1 for ip in non_alerted if self._ip_data[ip] == "benign")

        total = ip_tp + ip_tn + ip_fp + ip_fn
        accuracy = (ip_tp + ip_tn) / total if total > 0 else 0
        precision = ip_tp / (ip_tp + ip_fp) if (ip_tp + ip_fp) > 0 else 0
        recall = ip_tp / (ip_tp + ip_fn) if (ip_tp + ip_fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        fpr = ip_fp / (ip_fp + ip_tn) if (ip_fp + ip_tn) > 0 else 0

        logger.info(
            f"  IP-level confusion: TP={ip_tp} FP={ip_fp} FN={ip_fn} TN={ip_tn} "
            f"Recall={recall:.4f} Prec={precision:.4f} F1={f1:.4f} FPR={fpr:.4f}"
        )

        return {
            "TP": ip_tp,
            "TN": ip_tn,
            "FP": ip_fp,
            "FN": ip_fn,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "fpr": fpr,
            "total": total,
            "ip_level": True,
        }


def get_ground_truth_loader(day: str = "wednesday", csv_dir: Path | None = None) -> GroundTruthLoader:
    return GroundTruthLoader.get_instance(day, csv_dir)


def get_ground_truth_loader_for_pcap(pcap_path: str, csv_dir: Path | None = None) -> GroundTruthLoader:
    return GroundTruthLoader.get_instance_for_pcap(pcap_path, csv_dir)


def extract_flow_ids_from_alert_csv(
    alert_path: Path,
    gid_filter: set[int] | None = None,
) -> tuple[set[str], int, int]:
    """Extract unique flow IDs from a Snort alert_csv.txt file.

    gid_filter: if provided, only include lines where GID is in this set.
    Returns (flow_ids, total_lines, filtered_lines).
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
            if len(parts) < 9:
                filtered += 1
                continue

            try:
                # GID filter check — field 8 is gid:sid:rev
                if gid_filter is not None:
                    gid_str = parts[8].strip().split(":")[0]
                    try:
                        if int(gid_str) not in gid_filter:
                            filtered += 1
                            continue
                    except ValueError:
                        filtered += 1
                        continue

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


def extract_src_ips_from_alert_csv(
    alert_path: Path,
    gid_filter: set[int] | None = None,
) -> set[str]:
    """Extract unique src IPs from a Snort alert_csv.txt file.

    Used for cross-flow inspector evaluation (portscan, dos_agg, bot, bruteforce).
    gid_filter: if provided, only include lines where GID is in this set.
    Returns set of unique src IPs.
    """
    src_ips: set[str] = set()

    if not alert_path.exists():
        logger.warning(f"Alert file not found: {alert_path}")
        return src_ips

    with open(alert_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split(",")
            if len(parts) < 9:
                continue

            try:
                # GID filter check — field 8 is gid:sid:rev
                if gid_filter is not None:
                    gid_str = parts[8].strip().split(":")[0]
                    try:
                        if int(gid_str) not in gid_filter:
                            continue
                    except ValueError:
                        continue

                src_field = parts[6].strip()
                src_sep = src_field.rfind(":")
                if src_sep == -1:
                    continue

                src_ip = src_field[:src_sep]
                if ":" in src_ip or not _is_valid_ip(src_ip):
                    continue

                mapped_src = _map_ip(src_ip)
                src_ips.add(mapped_src)

            except (IndexError, ValueError):
                continue

    return src_ips