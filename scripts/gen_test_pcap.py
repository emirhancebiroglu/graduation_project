#!/usr/bin/env python3
"""
gen_test_pcap.py — ml_inspector stub testi için minimal TCP PCAP üretir.
Tek bir TCP flow: 100 paket (50 client→server, 50 server→client)
max_packets=100 eşiğine ulaşınca inference tetiklenir.
"""
from scapy.all import *

pkts = []
src_ip, dst_ip = "192.168.1.10", "192.168.1.20"
sport, dport   = 54321, 80

# SYN
pkts.append(IP(src=src_ip, dst=dst_ip) /
            TCP(sport=sport, dport=dport, flags="S", window=65535, seq=1000))

# SYN-ACK
pkts.append(IP(src=dst_ip, dst=src_ip) /
            TCP(sport=dport, dport=sport, flags="SA", window=65535, seq=2000, ack=1001))

# ACK
pkts.append(IP(src=src_ip, dst=dst_ip) /
            TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001))

# Veri paketleri — toplam 97 paket daha (3 handshake + 97 = 100)
seq_c, seq_s = 1001, 2001
for i in range(49):
    payload = ("X" * 100).encode()
    pkts.append(IP(src=src_ip, dst=dst_ip) /
                TCP(sport=sport, dport=dport, flags="PA", seq=seq_c, ack=seq_s) /
                Raw(load=payload))
    seq_c += 100

    pkts.append(IP(src=dst_ip, dst=src_ip) /
                TCP(sport=dport, dport=sport, flags="PA", seq=seq_s, ack=seq_c) /
                Raw(load=payload))
    seq_s += 100

# FIN
pkts.append(IP(src=src_ip, dst=dst_ip) /
            TCP(sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s))

out = os.path.expanduser("~/bitirme/pcaps/test_stub.pcap")
wrpcap(out, pkts)
print(f"Yazıldı: {out}  ({len(pkts)} paket)")
