from scapy.all import PcapReader, IP, TCP
from collections import Counter

dst_ports = Counter()
dst_ips = Counter()
count = 0
with PcapReader('/home/emirhan/bitirme/pcaps/Wednesday-workingHours.pcap') as r:
    for pkt in r:
        try:
            if IP in pkt and TCP in pkt:
                if pkt[IP].src == '172.16.0.1' and (pkt[TCP].flags & 0x02) and not (pkt[TCP].flags & 0x10):
                    dst_ports[pkt[TCP].dport] += 1
                    dst_ips[pkt[IP].dst] += 1
                    count += 1
        except:
            pass

print(f'Total SYNs: {count}')
print(f'Unique dst ports: {len(dst_ports)}')
print(f'Unique dst IPs: {len(dst_ips)}')
print('Top 10 ports:')
for p, c in dst_ports.most_common(10):
    print(f'  port {p}: {c}')
print('Top 5 IPs:')
for ip, c in dst_ips.most_common(5):
    print(f'  {ip}: {c}')
