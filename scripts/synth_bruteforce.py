#!/usr/bin/env python3
"""Generate synthetic bruteforce PCAPs simulating different tools.

Features:
- Patator-style: constant rate, low IAT variation
- Hydra-style: moderate rate, moderate IAT variation, retry delays
- Medusa-style: low rate, high IAT variation
- Ncrack-style: burst mode (fast bursts with pauses)
- Custom-style: random human-like timing

Each PCAP includes:
- TCP SYN packets from attacker (10.0.0.1) to target (192.168.1.100)
- SYN-ACK responses from target (simulates port open)
- RST from attacker (simulates auth failure → connection teardown)
"""
import os, sys, time, random, json
from scapy.all import *
from scapy.layers.inet import IP, TCP

random.seed(42)

ATTACKER_IP = "10.0.0.1"
TARGET_IP = "192.168.1.100"
TARGET_PORT = 22  # SSH
OUTDIR = os.path.expanduser("~/bitirme/pcaps/synthetic_bruteforce")
os.makedirs(OUTDIR, exist_ok=True)

def make_syn(seq, src, dst, sport, dport, ts):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq)
    pkt.time = ts
    return pkt

def make_syn_ack(seq, ack, src, dst, sport, dport, ts):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="SA", seq=seq, ack=ack)
    pkt.time = ts
    return pkt

def make_rst(seq, ack, src, dst, sport, dport, ts):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="R", seq=seq, ack=ack)
    pkt.time = ts
    return pkt

def generate_tool_pcap(name, syn_schedule, total_duration, description):
    """Generate a PCAP with SYN attempts and SYN-ACK+RST responses.
    
    syn_schedule: list of (timestamp, src_port) tuples
    total_duration: seconds the PCAP covers
    """
    packets = []
    seq = 1000
    src_port_base = 40000

    for i, (ts, sport) in enumerate(syn_schedule):
        if ts > total_duration:
            break
        # SYN from attacker
        syn_seq = seq + i * 1000
        packets.append(make_syn(syn_seq, ATTACKER_IP, TARGET_IP, sport, TARGET_PORT, ts))
        
        # SYN-ACK from target (port is open)
        sa_delay = 0.001 + random.random() * 0.005  # 1-6ms response time
        packets.append(make_syn_ack(seq + i * 500, syn_seq + 1, TARGET_IP, ATTACKER_IP, TARGET_PORT, sport, ts + sa_delay))
        
        # RST from attacker (auth failure, close immediately)
        rst_delay = 0.05 + random.random() * 0.15  # 50-200ms, represents auth attempt
        packets.append(make_rst(syn_seq + 1, seq + i * 500 + 1, ATTACKER_IP, TARGET_IP, sport, TARGET_PORT, ts + rst_delay))

    packets.sort(key=lambda p: p.time)
    
    pcap_path = os.path.join(OUTDIR, f"{name}.pcap")
    wrpcap(pcap_path, packets)
    
    # Stats
    syns = sum(1 for p in packets if p.haslayer(TCP) and p[TCP].flags == 0x02)
    syn_acks = sum(1 for p in packets if p.haslayer(TCP) and p[TCP].flags == 0x12)
    rsts = sum(1 for p in packets if p.haslayer(TCP) and p[TCP].flags == 0x04)
    total_time = packets[-1].time - packets[0].time if packets else 0
    rate = syns / total_time * 60 if total_time > 0 else 0
    
    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"  {description}")
    print(f"{'='*60}")
    print(f"  Packets: {len(packets)} ({syns} SYNs, {syn_acks} SYN-ACKs, {rsts} RSTs)")
    print(f"  Duration: {total_time:.1f}s, Rate: {rate:.1f} SYN/min")
    print(f"  Saved: {pcap_path}")
    return pcap_path

# ─── Tool 1: Patator (constant rate, rapid) ──────────────────────────
# Simulates SSH-Patator: 60 attempts/min, constant 1s interval
syn_schedule = []
for i in range(300):  # 5 minutes of attack
    ts = i * 1.0  # 1 SYN per second = 60/min
    syn_schedule.append((ts, 40000 + i))
generate_tool_pcap("patator_fast", syn_schedule, 600, "Patator-style: 60/min constant rate, SSH port 22")

# ─── Tool 2: Patator (slow) ──────────────────────────────────────────
syn_schedule = []
for i in range(150):  # 5 minutes
    ts = i * 2.0  # 1 SYN per 2 seconds = 30/min
    syn_schedule.append((ts, 41000 + i))
generate_tool_pcap("patator_slow", syn_schedule, 600, "Patator-style: 30/min constant rate, SSH port 22")

# ─── Tool 3: Hydra (moderate rate, IAT variation) ────────────────────
# Hydra adds jitter and retry delays
syn_schedule = []
t = 0.0
for i in range(200):
    # Base interval 1.5s + random jitter
    interval = 1.5 + random.gauss(0, 0.3)  # mean 1.5s, std 0.3s
    if random.random() < 0.1:  # 10% chance of retry delay
        interval += 3.0  # extra 3s delay on retry
    interval = max(0.3, min(5.0, interval))  # clamp
    t += interval
    syn_schedule.append((t, 42000 + i))
generate_tool_pcap("hydra_moderate", syn_schedule, 600, "Hydra-style: ~40/min with IAT jitter and retry delays")

# ─── Tool 4: Hydra (fast) ────────────────────────────────────────────
syn_schedule = []
t = 0.0
for i in range(300):
    interval = 0.8 + random.gauss(0, 0.2)
    interval = max(0.2, min(3.0, interval))
    t += interval
    syn_schedule.append((t, 43000 + i))
generate_tool_pcap("hydra_fast", syn_schedule, 600, "Hydra-style: ~75/min with moderate IAT jitter")

# ─── Tool 5: Medusa (slow, high IAT variation) ───────────────────────
# Medusa is deliberate: 1 attempt per 5-15 seconds
syn_schedule = []
t = 0.0
for i in range(60):  # 60 attempts
    interval = 5.0 + random.random() * 10.0  # 5-15s between attempts
    t += interval
    syn_schedule.append((t, 44000 + i))
generate_tool_pcap("medusa_slow", syn_schedule, 900, "Medusa-style: ~6/min, high IAT variation (5-15s intervals)")

# ─── Tool 6: Ncrack (burst mode) ─────────────────────────────────────
# Ncrack does fast bursts of 5-10 attempts, then pauses
syn_schedule = []
t = 0.0
burst_num = 0
while t < 600:
    burst_size = random.randint(5, 15)
    for i in range(burst_size):
        interval = 0.2 + random.random() * 0.3  # fast 200-500ms within burst
        t += interval
        syn_schedule.append((t, 45000 + burst_num * 100 + i))
    pause = 5.0 + random.random() * 15.0  # pause 5-20s between bursts
    t += pause
    burst_num += 1
generate_tool_pcap("ncrack_burst", syn_schedule, 700, "Ncrack-style: fast bursts of 5-15, then 5-20s pause")

# ─── Tool 7: Custom Script (erratic human-like) ──────────────────────
syn_schedule = []
t = 0.0
attempts = 0
while t < 600:
    # Human would type a few commands, wait, try another
    if attempts > 0 and random.random() < 0.15:  # 15% chance of thinking pause
        t += random.uniform(10, 30)  # 10-30s think time
    interval = 2.0 + random.random() * 8.0  # 2-10s between attempts
    t += interval
    syn_schedule.append((t, 46000 + attempts))
    attempts += 1
    if attempts > 100:
        break
generate_tool_pcap("custom_erratic", syn_schedule, 700, "Custom script: erratic human-like timing, 2-30s intervals")

# ─── Tool 8: Distributed brute (3 IPs → 1 target) ───────────────────
# 3 different attacker IPs slowly brute forcing same target
syn_schedule = []
attackers = ["10.0.0.2", "10.0.0.3", "10.0.0.4"]
for aidx, attacker in enumerate(attackers):
    t = 0.0
    for i in range(30):  # 30 attempts each
        interval = 1.0 + random.random() * 4.0  # 1-5s per IP
        t += interval
        seq_base = aidx * 50000 + i * 1000
        sport = 47000 + aidx * 100 + i
        # SYN
        pkt = IP(src=attacker, dst=TARGET_IP) / TCP(sport=sport, dport=TARGET_PORT, flags="S", seq=seq_base)
        pkt.time = t
        syn_schedule.append(("pkt", attacker, pkt))
        
        # SYN-ACK from target
        pkt2 = IP(src=TARGET_IP, dst=attacker) / TCP(sport=TARGET_PORT, dport=sport, flags="SA", seq=seq_base + 500, ack=seq_base + 1)
        pkt2.time = t + 0.002
        syn_schedule.append(("pkt", attacker, pkt2))
        
        # RST from attacker
        pkt3 = IP(src=attacker, dst=TARGET_IP) / TCP(sport=sport, dport=TARGET_PORT, flags="R", seq=seq_base + 1, ack=seq_base + 500 + 1)
        pkt3.time = t + 0.08
        syn_schedule.append(("pkt", attacker, pkt3))

packets = [item[2] for item in syn_schedule if item[0] == "pkt"]
packets.sort(key=lambda p: p.time)
pcap_path = os.path.join(OUTDIR, "distributed_brute.pcap")
wrpcap(pcap_path, packets)
syns = sum(1 for p in packets if p.haslayer(TCP) and p[TCP].flags == 0x02)
print(f"\n{'='*60}")
print(f"  distributed_brute")
print(f"  3 IPs → 1 target (SSH:22), each ~30 attempts")
print(f"{'='*60}")
print(f"  Packets: {len(packets)} ({syns} SYNs)")
print(f"  Saved: {pcap_path}")

# ─── Tool 9: Extra fast (120/min) ────────────────────────────────────
syn_schedule = []
for i in range(400):
    ts = i * 0.5  # 120/min
    syn_schedule.append((ts, 48000 + i))
generate_tool_pcap("extra_fast", syn_schedule, 400, "Extra fast: 120/min, tests window boundary limits")

# ─── Tool 10: Very slow (just above min_syns) ───────────────────────
syn_schedule = []
t = 0.0
for i in range(30):  # Only 30 attempts total
    interval = 10.0 + random.random() * 5.0  # 10-15s intervals = 4-6/min
    t += interval
    syn_schedule.append((t, 49000 + i))
generate_tool_pcap("very_slow", syn_schedule, 600, "Very slow: 4-6/min, just above min_syns=5 threshold")

# ─── Summary ────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print(f"  GENERATION COMPLETE")
print(f"{'='*60}")
print(f"  Output: {OUTDIR}/")
for f in sorted(os.listdir(OUTDIR)):
    if f.endswith(".pcap"):
        size = os.path.getsize(os.path.join(OUTDIR, f))
        print(f"  {f:30s} {size:>8,} bytes")
