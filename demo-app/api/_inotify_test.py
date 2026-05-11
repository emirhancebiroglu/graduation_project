"""Inotify smoke test. Run: python3 _inotify_test.py /path/to/file"""
import asyncio
import sys
from pathlib import Path
from watchfiles import awatch

async def main():
    path = sys.argv[1]
    print(f"awatch on: {path}", flush=True)
    event_count = 0
    async for changes in awatch(path):
        event_count += len(changes)
        print(f"EVENT #{event_count}: {changes}", flush=True)
        if event_count >= 3:
            break
    print(f"Total events: {event_count}", flush=True)

asyncio.run(main())
