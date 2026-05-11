#!/usr/bin/env bash
set -e
cd ~/bitirme/demo-app/api
source .venv/bin/activate

# Start a dos_hulk replay
RESP=$(curl -s -X POST http://localhost:8000/api/replay/start \
  -H "Content-Type: application/json" -d '{"pcap":"dos_hulk_2min"}')
echo "start: $RESP"
RUN_ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['run_id'])")
echo "run_id=$RUN_ID"

ALERT_FILE="/tmp/demo-runs/$RUN_ID/xgboost/alert_csv.txt"
echo "target: $ALERT_FILE"

# Wait for file to appear (Snort creates it on first alert)
for i in $(seq 1 20); do
  [ -f "$ALERT_FILE" ] && break
  sleep 0.1
done
echo "file exists: $([ -f "$ALERT_FILE" ] && echo yes || echo NO)"

# Run watchfiles for up to 5 seconds and count events
python3 - "$ALERT_FILE" <<'PYEOF'
import asyncio, sys, signal
from watchfiles import awatch

async def main():
    path = sys.argv[1]
    print(f"awatch started on: {path}", flush=True)
    event_count = 0
    try:
        async for changes in awatch(path):
            event_count += len(changes)
            print(f"  EVENT: {changes}", flush=True)
            if event_count >= 5:
                break
    except Exception as e:
        print(f"  error: {e}", flush=True)
    print(f"Total inotify events: {event_count}", flush=True)

asyncio.run(asyncio.wait_for(main(), timeout=5.0))
PYEOF
echo "watchfiles exit=$?"
