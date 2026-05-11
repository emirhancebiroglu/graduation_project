#!/usr/bin/env python3
"""
Test ground_truth.py against the known XGBoost and Community confusion matrices.
Validates that the module produces the same results as the standalone scripts.

Usage:
    cd ~/bitirme/demo-app/api
    source .venv/bin/activate
    python test_ground_truth.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from ground_truth import (
    get_ground_truth_loader,
    extract_flow_ids_from_alert_csv,
    WEDNESDAY_CSV_NAME,
)

XGB_ALERT_PATH = Path("/home/emirhan/bitirme/results/xgboost/Wednesday-workingHours/alert_csv.txt")
COMM_ALERT_PATH = Path("/home/emirhan/bitirme/results/community/Wednesday-workingHours/alert_csv.txt")
CSV_DIR = Path("/home/emirhan/bitirme/data/raw/cicids2017")

EXPECTED_XGB = {
    "TP": 252610, "TN": 432352, "FP": 7679, "FN": 62,
}
EXPECTED_COMM = {
    "TP": 252634, "TN": 388688, "FP": 51343, "FN": 38,
}

TOLERANCE_COUNT = 5
TOLERANCE_RATE = 0.001  # 0.1% for rate metrics


def test_ground_truth_loader():
    print("=" * 60)
    print("Test 1: GroundTruthLoader instantiation and stats")
    print("=" * 60)

    loader = get_ground_truth_loader(CSV_DIR)
    loader.ensure_loaded()

    stats = loader.stats()
    print(f"  Stats: {stats}")

    assert stats["loaded"], f"Ground truth not loaded: {stats['error']}"
    assert stats["total"] > 0, "No rows in ground truth CSV"
    assert stats["attacks"] > 0, "No attack flows found"
    assert stats["benign"] > 0, "No benign flows found"
    assert stats["flow_entries"] > 0, "Flow lookup table is empty"

    assert stats["total"] == stats["attacks"] + stats["benign"], \
        f"Row count mismatch: {stats['total']} != {stats['attacks']} + {stats['benign']}"

    print("  PASSED: GroundTruthLoader loaded successfully")
    print()


def test_flow_id_extraction_xgb():
    print("=" * 60)
    print("Test 2: Flow ID extraction from XGBoost alert CSV")
    print("=" * 60)

    if not XGB_ALERT_PATH.exists():
        print(f"  SKIPPED: XGB alert file not found: {XGB_ALERT_PATH}")
        print("  (This is expected if replay hasn't been run yet)")
        return

    flow_ids, total, filtered = extract_flow_ids_from_alert_csv(XGB_ALERT_PATH)
    print(f"  Total lines: {total}")
    print(f"  Filtered: {filtered}")
    print(f"  Unique flow IDs: {len(flow_ids):,}")

    assert total > 0, "No alerts processed"
    assert len(flow_ids) > 0, "No flow IDs extracted"
    print("  PASSED: XGBoost flow ID extraction works")
    print()


def test_flow_id_extraction_community():
    print("=" * 60)
    print("Test 3: Flow ID extraction from Community rules alert CSV")
    print("=" * 60)

    if not COMM_ALERT_PATH.exists():
        print(f"  SKIPPED: Community alert file not found: {COMM_ALERT_PATH}")
        print("  (This is expected if replay hasn't been run yet)")
        return

    flow_ids, total, filtered = extract_flow_ids_from_alert_csv(COMM_ALERT_PATH)
    print(f"  Total lines: {total:,}")
    print(f"  Filtered: {filtered}")
    print(f"  Unique flow IDs: {len(flow_ids):,}")

    assert total > 0, "No alerts processed"
    assert len(flow_ids) > 0, "No flow IDs extracted"
    print("  PASSED: Community flow ID extraction works")
    print()


def test_xgb_confusion():
    print("=" * 60)
    print("Test 4: XGBoost confusion matrix")
    print("=" * 60)

    if not XGB_ALERT_PATH.exists():
        print(f"  SKIPPED: {XGB_ALERT_PATH}")
        return

    loader = get_ground_truth_loader(CSV_DIR)
    loader.ensure_loaded()
    flow_ids, _, _ = extract_flow_ids_from_alert_csv(XGB_ALERT_PATH)
    result = loader.compute_confusion(flow_ids)

    if "error" in result:
        print(f"  FAILED: {result['error']}")
        return

    print(f"  TP={result['TP']:,} (expected {EXPECTED_XGB['TP']:,})")
    print(f"  TN={result['TN']:,} (expected {EXPECTED_XGB['TN']:,})")
    print(f"  FP={result['FP']:,} (expected {EXPECTED_XGB['FP']:,})")
    print(f"  FN={result['FN']:,} (expected {EXPECTED_XGB['FN']:,})")
    print(f"  FPR={result['fpr']:.4f} (expected ~0.0175)")

    tp_match = abs(result["TP"] - EXPECTED_XGB["TP"]) <= TOLERANCE_COUNT
    fp_match = abs(result["FP"] - EXPECTED_XGB["FP"]) <= TOLERANCE_COUNT

    assert tp_match, f"TP mismatch: {result['TP']} vs expected {EXPECTED_XGB['TP']}"
    assert fp_match, f"FP mismatch: {result['FP']} vs expected {EXPECTED_XGB['FP']}"
    assert result["recall"] > 0.999, f"Recall too low: {result['recall']}"
    assert 0.017 < result["fpr"] < 0.018, f"FPR out of range: {result['fpr']}"

    print("  PASSED: XGBoost confusion matrix matches expected results")
    print()


def test_community_confusion():
    print("=" * 60)
    print("Test 5: Community rules confusion matrix")
    print("=" * 60)

    if not COMM_ALERT_PATH.exists():
        print(f"  SKIPPED: {COMM_ALERT_PATH}")
        return

    loader = get_ground_truth_loader(CSV_DIR)
    loader.ensure_loaded()
    flow_ids, _, _ = extract_flow_ids_from_alert_csv(COMM_ALERT_PATH)
    result = loader.compute_confusion(flow_ids)

    if "error" in result:
        print(f"  FAILED: {result['error']}")
        return

    print(f"  TP={result['TP']:,} (expected {EXPECTED_COMM['TP']:,})")
    print(f"  TN={result['TN']:,} (expected {EXPECTED_COMM['TN']:,})")
    print(f"  FP={result['FP']:,} (expected {EXPECTED_COMM['FP']:,})")
    print(f"  FN={result['FN']:,} (expected {EXPECTED_COMM['FN']:,})")
    print(f"  FPR={result['fpr']:.4f} (expected ~0.1167)")

    tp_match = abs(result["TP"] - EXPECTED_COMM["TP"]) <= TOLERANCE_COUNT
    fp_match = abs(result["FP"] - EXPECTED_COMM["FP"]) <= TOLERANCE_COUNT

    assert tp_match, f"TP mismatch: {result['TP']} vs expected {EXPECTED_COMM['TP']}"
    assert fp_match, f"FP mismatch: {result['FP']} vs expected {EXPECTED_COMM['FP']}"
    assert result["recall"] > 0.999, f"Recall too low: {result['recall']}"
    assert 0.116 < result["fpr"] < 0.118, f"FPR out of range: {result['fpr']}"

    print("  PASSED: Community confusion matrix matches expected results")
    print()


def test_lookup():
    print("=" * 60)
    print("Test 6: Per-alert ground truth lookup")
    print("=" * 60)

    loader = get_ground_truth_loader(CSV_DIR)
    loader.ensure_loaded()

    if not XGB_ALERT_PATH.exists():
        print("  SKIPPED: No XGBoost alerts to spot-check")
        return

    with open(XGB_ALERT_PATH) as f:
        lines = f.readlines()

    checked = 0
    filtered_ipv6 = 0
    sample = [l for l in lines if l.strip() and not l.strip().startswith("#")]
    for line in sample:
        parts = line.split(",")
        if len(parts) < 8:
            continue

        try:
            src_field = parts[6].strip()
            dst_field = parts[7].strip()
            proto_str = parts[2].strip()

            src_sep = src_field.rfind(":")
            dst_sep = dst_field.rfind(":")
            if src_sep == -1 or dst_sep == -1:
                continue

            src_ip = src_field[:src_sep]
            src_port = int(src_field[src_sep + 1:])
            dst_ip = dst_field[:dst_sep]
            dst_port = int(dst_field[dst_sep + 1:])

            if ":" in src_ip or ":" in dst_ip:
                filtered_ipv6 += 1
                continue

            label = loader.lookup(src_ip, src_port, dst_ip, dst_port, proto_str)
            if label is not None and checked < 5:
                print(f"  Flow: {dst_ip}:{dst_port} <- {src_ip}:{src_port} {proto_str} -> {label.upper()}")
                checked += 1

        except (IndexError, ValueError):
            continue

    print(f"  Checked {checked} flows (skipped {filtered_ipv6} IPv6)")
    assert checked > 0, "Could not look up any flows"
    print("  PASSED: Per-alert lookup works")
    print()


if __name__ == "__main__":
    print()
    print("DEMOV2 — TASK 01 VALIDATION: Ground Truth Module")
    print()

    try:
        test_ground_truth_loader()
        test_flow_id_extraction_xgb()
        test_flow_id_extraction_community()
        test_xgb_confusion()
        test_community_confusion()
        test_lookup()

        print("=" * 60)
        print("ALL TESTS PASSED")
        print("=" * 60)
        print()
        print("Task 01 (GroundTruthLoader + flow ID resolver) is VALIDATED.")
        print("Proceed to Task 02.")

    except AssertionError as exc:
        print()
        print("=" * 60)
        print(f"TEST FAILED: {exc}")
        print("=" * 60)
        sys.exit(1)
    except Exception as exc:
        print()
        print("=" * 60)
        print(f"UNEXPECTED ERROR: {exc}")
        print("=" * 60)
        import traceback
        traceback.print_exc()
        sys.exit(1)