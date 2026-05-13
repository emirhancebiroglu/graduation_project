#!/bin/bash
# launch_loop.sh — Start the fully autonomous PortScan optimization loop
# Run from: ~/bitirme/portscan-optimizer

echo "=========================================="
echo "  PortScan Autonomous Optimization Loop"
echo "  Targets: Recall>=0.99, Prec>=0.98,"
echo "           F1>=0.98, FPR<=0.01"
echo "  Evaluation: ONLINE (Snort PCAP replay)"
echo "  Max iterations: 20"
echo "=========================================="

cd "$(dirname "$0")"

opencode run \
  --agent planner \
  --dangerously-skip-permissions \
  "Start the PortScan classifier optimization loop.
Check results/portscan/metrics.json first (if absent, this is iteration 0).
Follow LOOP PROTOCOL exactly — all 4 pipeline steps per iteration.
Invoke @executor for each iteration.
Targets must be hit in ONLINE Snort metrics, not offline sklearn.
Run fully autonomously until targets hit or 20 iterations reached."