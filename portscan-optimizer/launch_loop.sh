#!/bin/bash
# launch_loop.sh
# Run this once. The planner+executor loop runs fully autonomously.
# Check results/metrics.json for progress. Check results/DONE.txt for completion.

echo "=========================================="
echo "  PortScan Classifier Autonomous Loop"
echo "=========================================="
echo "Targets: Recall>=0.99, Precision>=0.98, F1>=0.98, FPR<=0.01"
echo "Max iterations: 20"
echo "Starting..."
echo ""

opencode run \
  --agent planner \
  --dangerously-skip-permissions \
  --model "opencode/minimax-m2-5" \
  "Start the PortScan classifier optimization loop.

Read results/metrics.json if it exists (if not, iteration 0 baseline).
Follow your LOOP PROTOCOL exactly.
Invoke @executor for each experiment.
Continue until ALL 4 targets are hit or 20 iterations are reached.
Do not ask for confirmation at any step. Run fully autonomously."