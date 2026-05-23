#!/usr/bin/env python3
import numpy as np
scores = {"bot": [], "fp": [], "other": []}
bot_ips = {3232238085, 3232238088, 3232238089, 3232238092, 3232238094, 3232238095, 3232238097}
fp_ips = {3232238096, 3232238099, 3232238105, 3232238131, 2886729745}
with open("/tmp/botcl_train_data.txt") as f:
    for line in f:
        if line.startswith("#"): continue
        parts = line.strip().split()
        if len(parts) < 14: continue
        ip = int(parts[-1])
        score = float(parts[-2])
        if ip in bot_ips:
            scores["bot"].append(score)
        elif ip in fp_ips:
            scores["fp"].append(score)
        else:
            scores["other"].append(score)
for k in ["bot","fp","other"]:
    v = scores[k]
    if v:
        print(f"{k}: n={len(v)} mean={np.mean(v):.4f} min={min(v):.4f} max={max(v):.4f}")
    else:
        print(f"{k}: n=0")
# Print some FP window details
with open("/tmp/botcl_train_data.txt") as f:
    for line in f:
        if line.startswith("#"): continue
        parts = line.strip().split()
        if len(parts) < 14: continue
        ip = int(parts[-1])
        if ip in fp_ips:
            print(f"FP ip={ip} f0={parts[1]} f1={parts[2]} f7={parts[8]} f8={parts[9]} f9={parts[10]} score={parts[-2]}")
