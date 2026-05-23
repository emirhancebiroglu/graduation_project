#!/usr/bin/env python3
print("Parsing /tmp/botcl_train_data.txt ...")
bot_ips = {3232238085, 3232238088, 3232238089, 3232238092, 3232238094, 3232238095, 3232238097}
fp_ips = {3232238096, 3232238099, 3232238105, 3232238131, 2886729729}

fps = []
bots = []
count = 0
with open("/tmp/botcl_train_data.txt") as f:
    for line in f:
        if line.startswith("#"): continue
        parts = line.strip().split()
        if len(parts) < 3: continue
        ip = int(parts[-1])
        score = float(parts[-2])
        if ip in bot_ips:
            bots.append(score)
        elif ip in fp_ips:
            fps.append((ip, parts[1], parts[8], parts[9], parts[10], score))
        count += 1
print(f"Total lines parsed: {count}")
print(f"BOT windows: n={len(bots)} min={min(bots):.4f} max={max(bots):.4f}")
if fps:
    scores_only = [float(x[5]) for x in fps]
    print(f"FP windows: n={len(fps)} min={min(scores_only):.4f} max={max(scores_only):.4f}")
    print("\nFP windows:")
    for ip, syn, ic, ir, ie, sc in fps:
        ip_str = ".".join(str((ip >> (8*i)) & 0xFF) for i in range(3, -1, -1))
        print(f"  {ip_str} syn={syn} ip_conc={ic} ip_ratio={ir} ip_ent={ie} score={sc}")
else:
    print("FP windows: n=0")
