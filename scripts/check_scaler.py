import json
with open('/home/emirhan/bitirme/models/bot_client_model_scaler.json') as f:
    s = json.load(f)
print('Median:', s['median'])
print('IQR:', s['iqr'])
feat = ['syn_count','dst_ips','dst_ports','iat_cv','entropy','port_ratio','rate']
print()
for i, (m, iq) in enumerate(zip(s['median'], s['iqr'])):
    raw_median = m
    raw_iqr = iq
    print(f'{feat[i]}: log1p-median={raw_median:.4f} log1p-iqr={raw_iqr:.4f}')
