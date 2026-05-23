lines = open('/tmp/botcl_train_data.txt').readlines()
count = 0
for line in lines[1:]:
    parts = line.strip().split()
    if len(parts) >= 20:
        src_ip_int = int(parts[19])
        if src_ip_int == 3232238096:
            inc_r = float(parts[15])
            syn_cnt = float(parts[1])
            print(f"inc_r={inc_r:.6f} syn_cnt={syn_cnt:.0f}")
            count += 1
            if count >= 5:
                break
