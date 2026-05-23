# Read C++ training dump, show inc_ratio for each IP
import re
lines = open('/tmp/botcl_train_data.txt').readlines()
for line in lines[1:]:  # skip header
    parts = line.strip().split()
    if len(parts) >= 20:
        inc_r = parts[15]  # 0-indexed: column 15 = inc_ratio
        score = parts[18]
        src_ip_int = int(parts[19])
        src_ip = f'{(src_ip_int>>24)&255}.{(src_ip_int>>16)&255}.{(src_ip_int>>8)&255}.{src_ip_int&255}'
        if src_ip in ['172.16.0.1','192.168.10.16','192.168.10.19','192.168.10.25','192.168.10.51','192.168.10.3']:
            print(f'{src_ip}: inc_ratio={inc_r} score={score}')
