import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
import pickle

test_path = "./UNSW_NB15_testing-set.csv"

df_test = pd.read_csv(test_path)

df_test['binary_label'] = df_test['label'].apply(lambda x: 0 if x == 0 else 1)

with open("encoders.pkl", "rb") as f:
    encoders = pickle.load(f)

with open("scaler.pkl", "rb") as f:
    scaler = pickle.load(f)

categorical_cols = ['proto', 'service', 'state']

for col in categorical_cols:
    le = encoders[col]
    df_test[col] = df_test[col].apply(lambda x: x if x in le.classes_ else 'UNK')
    
    if 'UNK' not in le.classes_:
        le.classes_ = np.append(le.classes_, 'UNK')
    
    df_test[col] = le.transform(df_test[col])

drop_cols = ['id', 'attack_cat', 'label']
X_test = df_test.drop(columns=drop_cols + ['binary_label'])
y_test = df_test['binary_label'].values

X_test_scaled = scaler.transform(X_test)

np.save("X_test.npy", X_test_scaled)
np.save("y_test.npy", y_test)

print("Test dataset hazır. Kaydedildi: X_test.npy, y_test.npy")
print(f"X_test shape: {X_test_scaled.shape}, y_test shape: {y_test.shape}")