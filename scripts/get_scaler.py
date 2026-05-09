# Eğitim datasından yeniden fit et
import json
import numpy as np
from sklearn.preprocessing import RobustScaler

X_train = np.load("data/processed/dos_specialist/mp_2/X_train.npy")

scaler = RobustScaler()
scaler.fit(X_train)

params = {
    "median": scaler.center_.tolist(),
    "iqr":    scaler.scale_.tolist()
}

with open("models/dos_specialist/mp_2_scaler.json", "w") as f:
    json.dump(params, f, indent=2)

print("Feature sayısı:", len(params["median"]))
print("İlk 3 median:", params["median"][:3])
print("İlk 3 iqr:",    params["iqr"][:3])