import json, os
path = "/home/emirhan/bitirme/models/bot_client_model.json"
dot = path.rfind('.')
sp = path[:dot] + "_scaler.json"
print(f"Computed path: {sp}")
print(f"File exists: {os.path.exists(sp)}")
if os.path.exists(sp):
    with open(sp) as f:
        j = json.load(f)
        print(f"Keys: {list(j.keys())}")
        print(f"Median len: {len(j['median'])}")
        print(f"IQR len: {len(j['iqr'])}")
