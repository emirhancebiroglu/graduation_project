#!/usr/bin/env python3
"""Check what features the masscan window would have."""
import math

# From debug: syn=555267, uports=5
# Reconstruct what features Snort computed
# Features: total_syns, unique_dst_ports, unique_dst_ips, dst_port_entropy, src_port_range, unique_port_ratio, syn_rate

# We know: syn=555267, uports=5
# From tshark: 39 unique dst IPs in Cupid (different PCAP)
# masscan.pcapng: 1 src IP, ~561K SYNs, 65s, scans many IPs, few ports

# Estimate masscan features:
# total_syns ~ 555267 (confirmed from debug)
# unique_dst_ports ~ 5 (confirmed)
# unique_dst_ips ~ many (masscan scans internet)
# dst_port_entropy ~ log2(5) ~ 2.32 (very low, concentrated on few ports)
# src_port_range ~ 65000 (masscan uses random high src ports)
# unique_port_ratio ~ 5/555267 ~ 0.000009 (very low)
# syn_rate ~ 555267/65 ~ 8543/s

# After log1p + RobustScaler from portscan_aggregator_model_v4d_scaler.json:
# median: [2.0794, 1.0986, 1.0986, 0.5940, 1.7918, 0.2877, 0.1103]
# iqr:    [2.5649, 0.6931, 1.0986, 0.8633, 7.7916, 0.3054, 0.5664]

median = [2.0794, 1.0986, 1.0986, 0.5940, 1.7918, 0.2877, 0.1103]
iqr    = [2.5649, 0.6931, 1.0986, 0.8633, 7.7916, 0.3054, 0.5664]

# Estimated raw features for masscan
raw = [
    555267,     # total_syns
    5,          # unique_dst_ports
    5000,       # unique_dst_ips (masscan scans many IPs)
    2.32,       # dst_port_entropy (low — few ports)
    60000,      # src_port_range (masscan uses random src ports)
    5/555267,   # unique_port_ratio (very low)
    8543,       # syn_rate (very high)
]

log1p_features = [math.log1p(x) for x in raw]
scaled = [(log1p_features[i] - median[i]) / iqr[i] for i in range(7)]

feature_names = ['total_syns', 'unique_dst_ports', 'unique_dst_ips', 'dst_port_entropy', 'src_port_range', 'unique_port_ratio', 'syn_rate']
print("Feature | raw | log1p | scaled")
for i, name in enumerate(feature_names):
    print(f"  {name:22s}: raw={raw[i]:.4f} log1p={log1p_features[i]:.4f} scaled={scaled[i]:.4f}")

print("\nKey insight: unique_dst_ports=5 → very low port diversity → model unsure")
print("CIC scanner: uports=997 → high diversity → model confident (score=0.997)")
print("masscan: uports=5, but unique_dst_ips=5000 → different attack profile")
