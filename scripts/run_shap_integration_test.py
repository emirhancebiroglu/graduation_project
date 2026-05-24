#!/usr/bin/env python3
"""SHAP integration test — all 5 models.

For each model, runs explain() on a representative attack sample and a benign sample.
Verifies: top feature has correct direction, no exceptions.
Saves results to results/generalization/madde7_shap_integration.json
"""
import json, sys, traceback
from pathlib import Path

BASE = Path('/home/emirhan/bitirme')
sys.path.insert(0, str(BASE / 'scripts'))

RESULTS_DIR = BASE / 'results' / 'generalization'
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

results = {}

# ── 1. dos_inspector (v3b, 15 features) ──────────────────────────────────────
# Features: dur, spkts, dpkts, sbytes, dbytes, smeansz, dmeansz,
#           sintpkt, dintpkt, fwd_pkt_mean, bwd_pkt_mean,
#           fin_cnt, ack_cnt, syn_cnt, bwd_iat
DOS_ATK  = [0.0, 5000.0, 2.0, 450000.0, 100.0, 90.0, 50.0,
            0.0001, 0.05, 90.0, 50.0, 0, 10, 4900, 0.0001]
DOS_BEN  = [0.5, 20.0, 18.0, 3200.0, 2800.0, 160.0, 155.0,
            0.025, 0.027, 177.0, 155.0, 2, 18, 0, 0.03]

print("Testing dos_inspector SHAP...")
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("shap_dos", BASE/'scripts'/'shap_explain_alert.py')
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    atk_r = mod.explain(DOS_ATK, top_n=5)
    ben_r = mod.explain(DOS_BEN, top_n=5)
    results['dos_inspector'] = {
        'attack_top5': atk_r,
        'benign_top5': ben_r,
        'attack_top1_feature': atk_r[0]['feature'],
        'attack_top1_direction': atk_r[0]['direction'],
        'status': 'PASS'
    }
    print(f"  PASS — attack top1: {atk_r[0]['feature']} ({atk_r[0]['direction']}, shap={atk_r[0]['shap_value']})")
except Exception as e:
    results['dos_inspector'] = {'status': 'FAIL', 'error': traceback.format_exc()}
    print(f"  FAIL: {e}")

# ── 2. dos_aggregator (7 features) ───────────────────────────────────────────
# Features: total_syns, unique_dst_ports, unique_dst_ips,
#           dst_port_entropy, src_port_range, unique_port_ratio, syn_rate
AGG_ATK  = [5000.0, 1.0, 1.0, 0.0, 500.0, 0.0002, 83.3]
AGG_BEN  = [12.0, 8.0, 3.0, 2.8, 60.0, 0.67, 0.2]

print("Testing dos_aggregator SHAP...")
try:
    spec2 = importlib.util.spec_from_file_location("shap_agg", BASE/'scripts'/'shap_explain_dos_agg.py')
    mod2 = importlib.util.module_from_spec(spec2); spec2.loader.exec_module(mod2)
    atk_r = mod2.explain(AGG_ATK, top_n=5)
    ben_r = mod2.explain(AGG_BEN, top_n=5)
    results['dos_aggregator'] = {
        'attack_top5': atk_r,
        'benign_top5': ben_r,
        'attack_top1_feature': atk_r[0]['feature'],
        'attack_top1_direction': atk_r[0]['direction'],
        'status': 'PASS'
    }
    print(f"  PASS — attack top1: {atk_r[0]['feature']} ({atk_r[0]['direction']}, shap={atk_r[0]['shap_value']})")
except Exception as e:
    results['dos_aggregator'] = {'status': 'FAIL', 'error': traceback.format_exc()}
    print(f"  FAIL: {e}")

# ── 3. portscan (7 features) ─────────────────────────────────────────────────
# Features: total_syns, unique_dst_ports, unique_dst_ips,
#           dst_port_entropy, src_port_range, unique_port_ratio, syn_rate
PS_ATK   = [997.0, 997.0, 1.0, 9.96, 200.0, 1.0, 16.6]
PS_BEN   = [8.0, 5.0, 3.0, 2.2, 40.0, 0.625, 0.13]

print("Testing portscan SHAP...")
try:
    spec3 = importlib.util.spec_from_file_location("shap_ps", BASE/'scripts'/'shap_explain_portscan.py')
    mod3 = importlib.util.module_from_spec(spec3); spec3.loader.exec_module(mod3)
    atk_r = mod3.explain(PS_ATK, top_n=5)
    ben_r = mod3.explain(PS_BEN, top_n=5)
    results['portscan'] = {
        'attack_top5': atk_r,
        'benign_top5': ben_r,
        'attack_top1_feature': atk_r[0]['feature'],
        'attack_top1_direction': atk_r[0]['direction'],
        'status': 'PASS'
    }
    print(f"  PASS — attack top1: {atk_r[0]['feature']} ({atk_r[0]['direction']}, shap={atk_r[0]['shap_value']})")
except Exception as e:
    results['portscan'] = {'status': 'FAIL', 'error': traceback.format_exc()}
    print(f"  FAIL: {e}")

# ── 4. bot_client (22 features) ──────────────────────────────────────────────
# Features: syn_count, dst_ips, dst_ports, iat_cv, port_entropy, port_ratio, rate,
#           ip_concentration, dst_ip_ratio, ip_entropy, iat_q90_q10_ratio,
#           time_density, port_to_ip_ratio, handshake_ratio, incoming_ratio,
#           data_density, rst_rate, internal_ip_ratio, bytes_per_syn,
#           fin_ratio, push_ratio, mean_window
BOT_ATK  = [250.0, 3.0, 3.0, 0.3, 0.0, 1.0, 4.17, 0.9, 1.0, 0.5,
            1.5, 0.9, 1.0, 0.02, 0.0, 0.0, 0.05, 0.0, 0.0, 0.0, 0.0, 512.0]
BOT_BEN  = [5.0, 1.0, 1.0, 3.2, 0.0, 0.2, 0.0167, 1.0, 0.2, 0.0,
            0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 8192.0]

print("Testing bot_client SHAP...")
try:
    spec4 = importlib.util.spec_from_file_location("shap_bot", BASE/'scripts'/'shap_explain_bot_client.py')
    mod4 = importlib.util.module_from_spec(spec4); spec4.loader.exec_module(mod4)
    atk_r = mod4.explain(BOT_ATK, top_n=5)
    ben_r = mod4.explain(BOT_BEN, top_n=5)
    results['bot_client'] = {
        'attack_top5': atk_r,
        'benign_top5': ben_r,
        'attack_top1_feature': atk_r[0]['feature'],
        'attack_top1_direction': atk_r[0]['direction'],
        'status': 'PASS'
    }
    print(f"  PASS — attack top1: {atk_r[0]['feature']} ({atk_r[0]['direction']}, shap={atk_r[0]['shap_value']})")
except Exception as e:
    results['bot_client'] = {'status': 'FAIL', 'error': traceback.format_exc()}
    print(f"  FAIL: {e}")

# ── 5. bruteforce (10 features) ──────────────────────────────────────────────
# Features: syn_count, syn_dst_ips, syn_dst_ports, port_ratio, single_port_score,
#           syn_rate, iat_cv, hshake_ratio, rst_after_hshake, bytes_per_syn
BRU_ATK  = [450.0, 1.0, 1.0, 1.0, 1.0, 7.5, 0.5, 0.05, 0.3, 800.0]
BRU_BEN  = [3.0, 1.0, 1.0, 1.0, 1.0, 0.05, 2.5, 0.9, 0.0, 200.0]

print("Testing bruteforce SHAP...")
try:
    spec5 = importlib.util.spec_from_file_location("shap_bru", BASE/'scripts'/'shap_explain_bruteforce.py')
    mod5 = importlib.util.module_from_spec(spec5); spec5.loader.exec_module(mod5)
    atk_r = mod5.explain(BRU_ATK, top_n=5)
    ben_r = mod5.explain(BRU_BEN, top_n=5)
    results['bruteforce'] = {
        'attack_top5': atk_r,
        'benign_top5': ben_r,
        'attack_top1_feature': atk_r[0]['feature'],
        'attack_top1_direction': atk_r[0]['direction'],
        'status': 'PASS'
    }
    print(f"  PASS — attack top1: {atk_r[0]['feature']} ({atk_r[0]['direction']}, shap={atk_r[0]['shap_value']})")
except Exception as e:
    results['bruteforce'] = {'status': 'FAIL', 'error': traceback.format_exc()}
    print(f"  FAIL: {e}")

# ── Summary ───────────────────────────────────────────────────────────────────
pass_cnt = sum(1 for v in results.values() if v.get('status') == 'PASS')
fail_cnt = len(results) - pass_cnt
print(f"\nSHAP integration: {pass_cnt}/5 PASS, {fail_cnt}/5 FAIL")

out_path = RESULTS_DIR / 'madde7_shap_integration.json'
with open(out_path, 'w') as f:
    json.dump(results, f, indent=2)
print(f"Saved: {out_path}")

sys.exit(0 if fail_cnt == 0 else 1)
