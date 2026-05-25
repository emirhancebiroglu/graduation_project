"""End-to-end smoke test: open WS first, start replay, capture real alerts."""
import asyncio
import json
import urllib.request

import websockets

API = "http://localhost:8000"
WS = "ws://localhost:8000/ws"


def post(path: str, body: dict) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{API}{path}", data=data,
        headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


async def main() -> None:
    real: list[dict] = []
    fake: list[dict] = []

    async with websockets.connect(WS) as ws:
        print("WS connected. Starting full_wednesday replay...")
        resp = post("/api/replay/start", {"pcap": "full_wednesday"})
        print(f"  run_id={resp['run_id']}")

        print("Collecting WS messages for 5s...")
        try:
            async with asyncio.timeout(5.0):
                while True:
                    msg = json.loads(await ws.recv())
                    if msg["type"] != "alert":
                        continue
                    a = msg["data"]
                    # Real (parsed) alerts have msg containing "XGBoost anomaly" or "Community rule"
                    # Fake (generator) alerts have msg like "XGBoost: DoS Hulk detected"
                    if "anomaly detected" in a.get("msg", "") or "Community rule" in a.get("msg", ""):
                        real.append(a)
                    else:
                        fake.append(a)
        except TimeoutError:
            pass

    print(f"\nResults:")
    print(f"  Real (parsed from Snort) alerts : {len(real)}")
    print(f"  Fake (generator) alerts         : {len(fake)}")

    if real:
        print("\nSample real alert:")
        a = real[0]
        print(f"  engine={a['engine']} src={a['src_ip']}:{a['src_port']} "
              f"dst={a['dst_ip']}:{a['dst_port']} gid={a['gid']} sid={a['sid']} msg={a['msg']!r}")
        print("\nPASS: real alerts flowing over WebSocket")
    else:
        print("\nFAIL: no real alerts received")

    post("/api/replay/stop", {})


asyncio.run(main())
