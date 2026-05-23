import re
from collections import defaultdict

alerts = {}
pat = re.compile(r'\[botcl\] ALERT: ([\d.]+) score=([\d.]+)')
for line in open('/home/emirhan/bitirme/results/bot_client/Friday_v5/snort_output.log'):
    m = pat.search(line)
    if m:
        ip = m.group(1)
        score = float(m.group(2))
        if ip not in alerts or score > alerts[ip]:
            alerts[ip] = score

BOT_IPS = {'192.168.10.5','192.168.10.8','192.168.10.9','192.168.10.12',
           '192.168.10.14','192.168.10.15','192.168.10.17'}

print('Threshold scan (C++ 17-feature model on Friday_v5):')
print(f"{'thr':<8} {'prec':<8} {'rec':<8} {'f1':<8} {'tp':<4} {'fp':<4} {'fn':<4}")
for thr_int in range(0, 100):
    thr = thr_int / 100.0
    tp = sum(1 for ip, sc in alerts.items() if ip in BOT_IPS and sc >= thr)
    fp = sum(1 for ip, sc in alerts.items() if ip not in BOT_IPS and sc >= thr)
    fn = sum(1 for ip in BOT_IPS if alerts.get(ip, 0) < thr)
    prec = tp / (tp + fp) if tp + fp > 0 else 0
    rec = tp / len(BOT_IPS)
    f1 = 2 * prec * rec / (prec + rec) if prec + rec > 0 else 0
    if tp + fp > 0 and (prec >= 0.50 or fn == 0):
        print(f'{thr:<8.2f} {prec:<8.4f} {rec:<8.4f} {f1:<8.4f} {tp:<4} {fp:<4} {fn:<4}')
