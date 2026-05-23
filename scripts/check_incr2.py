lines = open('/tmp/botcl_train_data.txt').readlines()
for line in lines[1:]:
    parts = line.strip().split()
    if len(parts) >= 20:
        inc_r = float(parts[15])
        src_ip_int = int(parts[19])
        src_ip = f'{(src_ip_int>>24)&255}.{(src_ip_int>>16)&255}.{(src_ip_int>>8)&255}.{src_ip_int&255}'
        if src_ip in ['192.168.10.16','192.168.10.19']:
            if inc_r > 0.001:
                print(f'{src_ip}: inc_ratio={inc_r:.6f}')
