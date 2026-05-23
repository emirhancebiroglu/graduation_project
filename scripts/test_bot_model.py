import json
import numpy as np
import xgboost as xgb

model_path = '/home/emirhan/bitirme/models/bot_client_model.json'
scaler_path = '/home/emirhan/bitirme/models/bot_client_model_scaler.json'

with open(scaler_path) as f:
    scaler = json.load(f)

median = np.array(scaler['median'])
iqr = np.array(scaler['iqr'])

model = xgb.Booster()
model.load_model(model_path)

# Test cases matching real PCAP observations
test_cases = [
    ("Normal (1 syn to 1 dst)", [1, 1, 1, 0.0, 0.0, 1.0, 1/300]),
    ("NetSupport-like (79 syns, 32 dsts)", [79, 32, 8, 2.505, 0.5, 8/79, 79/300]),
    ("Lumma-like (133 syns, 52 dsts)", [133, 52, 8, 2.683, 0.5, 8/133, 133/300]),
    ("Heavy scanning (1000 syns, 500 dsts)", [1000, 500, 100, 1.5, 3.0, 100/1000, 1000/300]),
    ("Moderate (50 syns, 20 dsts)", [50, 20, 10, 1.8, 1.5, 10/50, 50/300]),
    ("CICIDS bot-like (200 syns, 150 dsts)", [200, 150, 30, 1.2, 2.5, 30/200, 200/300]),
]

print(f"{'Case':<40} {'Raw features':<50} {'Score':<10}")
print("="*100)
for name, raw in test_cases:
    raw_arr = np.array(raw, dtype=np.float64)
    log_transformed = np.log1p(raw_arr)
    scaled = (log_transformed - median) / iqr
    dmat = xgb.DMatrix(scaled.reshape(1, -1))
    score = model.predict(dmat)[0]
    print(f"{name:<40} syns={raw[0]:<6.0f} dsts={raw[1]:<6.0f} ports={raw[2]:<6.0f} rate={raw[6]:<8.6f}  {score:<10.6f}")

# Also check CICIDS-bot ground truth by examining the training data
print("\n--- What does the model consider 'bot-like'? ---")
# Search for boundary: what features give score >= 0.50?
import itertools
for syns, dsts in [(10,5), (20,10), (50,20), (100,50), (200,100), (500,200), (1000,500)]:
    raw = [syns, dsts, dsts//2, 1.5, 2.0, 0.3, syns/300]
    raw_arr = np.array(raw, dtype=np.float64)
    log_transformed = np.log1p(raw_arr)
    scaled = (log_transformed - median) / iqr
    dmat = xgb.DMatrix(scaled.reshape(1, -1))
    score = model.predict(dmat)[0]
    print(f"  syns={syns:<5} dsts={dsts:<5} -> score={score:.6f}")
