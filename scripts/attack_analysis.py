import pandas as pd
import numpy as np
import tensorflow as tf
import warnings, os
warnings.filterwarnings('ignore')

HOME = os.path.expanduser('~')

median = np.array([0.0157434195, 2.5649493575, 2.5649493575, 7.2936977206,
                   7.5071410797, 73.0, 89.0, 255.0, 255.0, 0.3841277437, 0.3471507323])
iqr    = np.array([0.1934837207, 2.7080502011, 2.6625878270, 2.7622745192,
                   4.4213950593, 72.0, 496.0, 255.0, 255.0, 2.1157851784, 1.9696133626])

CSV_DIR = f'{HOME}/bitirme/data/raw/cicids2017'
MODEL   = f'{HOME}/bitirme/models/fine_tuned_lstm_model_v3.tflite'

interpreter = tf.lite.Interpreter(model_path=MODEL)
interpreter.allocate_tensors()
inp_det = interpreter.get_input_details()[0]
out_det = interpreter.get_output_details()[0]

def predict_batch(X):
    scores = np.zeros(len(X), dtype=np.float32)
    Xf = X.astype(np.float32).reshape(-1, 1, 11)
    for i in range(len(Xf)):
        interpreter.set_tensor(inp_det['index'], Xf[i:i+1])
        interpreter.invoke()
        scores[i] = interpreter.get_tensor(out_det['index'])[0][0]
    return scores

def gc(df, names):
    for n in names:
        if n in df.columns: return df[n]
    return pd.Series(0.0, index=df.index)

def preprocess(df):
    dur  = gc(df, ['Flow Duration',' Flow Duration']) / 1e6
    sint = gc(df, ['Fwd IAT Mean',' Fwd IAT Mean']) / 1000
    dint = gc(df, ['Bwd IAT Mean',' Bwd IAT Mean']) / 1000
    features = pd.DataFrame({
        'dur':     dur,
        'spkts':   gc(df, ['Total Fwd Packets',' Total Fwd Packets']),
        'dpkts':   gc(df, ['Total Backward Packets',' Total Backward Packets']),
        'sbytes':  gc(df, ['Total Length of Fwd Packets',' Total Length of Fwd Packets']),
        'dbytes':  gc(df, ['Total Length of Bwd Packets',' Total Length of Bwd Packets']),
        'smeansz': gc(df, ['Fwd Packet Length Mean',' Fwd Packet Length Mean']),
        'dmeansz': gc(df, ['Bwd Packet Length Mean',' Bwd Packet Length Mean']),
        'swin':    gc(df, ['Init_Win_bytes_forward',' Init_Win_bytes_forward']).clip(upper=1020),
        'dwin':    gc(df, ['Init_Win_bytes_backward',' Init_Win_bytes_backward']).clip(upper=1020),
        'sintpkt': sint,
        'dintpkt': dint,
    })
    log_cols = ['dur','spkts','dpkts','sbytes','dbytes','sintpkt','dintpkt']
    features[log_cols] = np.log1p(features[log_cols].clip(lower=0))
    X = ((features.values - median) / iqr).astype(np.float32)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    return X

# Tüm CSV'leri oku, attack_type → scores topla
all_results = {}   # attack_type → list of scores
all_benign  = []

for csv_file in sorted(os.listdir(CSV_DIR)):
    if not csv_file.endswith('.csv'): continue
    path = os.path.join(CSV_DIR, csv_file)
    print(f"  İşleniyor: {csv_file} ...", flush=True)
    try:
        df = pd.read_csv(path, low_memory=False, on_bad_lines='skip',
                         encoding_errors='replace')
        df.columns = df.columns.str.strip()
        if 'Label' not in df.columns: continue
        df['Label'] = df['Label'].str.strip()
    except Exception as e:
        print(f"  HATA okuma: {e}")
        continue

    try:
        X = preprocess(df)
        scores = predict_batch(X)
    except Exception as e:
        print(f"  HATA inference: {e}")
        continue

    benign_mask = df['Label'] == 'BENIGN'
    all_benign.extend(scores[benign_mask].tolist())

    for attack in df[~benign_mask]['Label'].unique():
        mask = df['Label'] == attack
        if mask.sum() == 0: continue
        if attack not in all_results:
            all_results[attack] = []
        all_results[attack].extend(scores[mask].tolist())

print()
print("=" * 78)
print("LSTM Model — CIC-IDS2017 Saldırı Türü Bazında Score Analizi (Tam)")
print("=" * 78)
print(f"{'Saldırı Türü':<30} {'N':>7} {'Min':>6} {'Med':>6} {'Max':>6} {'R@0.55':>8} {'P@0.55':>8} {'Durum'}")
print("-" * 78)

ben = np.array(all_benign)
fp55_count = (ben > 0.55).sum()

# Sırala: recall'a göre azalan
sorted_attacks = sorted(all_results.items(),
                        key=lambda x: np.mean(np.array(x[1]) > 0.55), reverse=True)

for attack, score_list in sorted_attacks:
    s = np.array(score_list)
    n = len(s)
    if n == 0: continue
    tp55   = (s > 0.55).sum()
    fp55   = fp55_count
    recall = tp55 / n
    prec   = tp55 / (tp55 + fp55) if (tp55 + fp55) > 0 else 0.0

    if recall >= 0.5:
        status = "✓ İYİ"
    elif recall >= 0.1:
        status = "~ ORTA"
    else:
        status = "✗ KÖTÜ"

    print(f"{attack:<30} {n:>7} {s.min():>6.3f} {np.median(s):>6.3f} "
          f"{s.max():>6.3f} {recall:>8.4f} {prec:>8.4f}  {status}")

print("-" * 78)
print(f"{'BENIGN':<30} {len(ben):>7} {ben.min():>6.3f} {np.median(ben):>6.3f} "
      f"{ben.max():>6.3f} {'FPR:':>8} {(ben>0.55).mean():>8.4f}")
print()

# Özet: kaç saldırı türü hangi kategoride
good  = [(a,s) for a,s in sorted_attacks if np.mean(np.array(s)>0.55) >= 0.5]
mid   = [(a,s) for a,s in sorted_attacks if 0.1 <= np.mean(np.array(s)>0.55) < 0.5]
bad   = [(a,s) for a,s in sorted_attacks if np.mean(np.array(s)>0.55) < 0.1]

print(f"✓ İYİ  ({len(good)}): {[a for a,_ in good]}")
print(f"~ ORTA ({len(mid)}):  {[a for a,_ in mid]}")
print(f"✗ KÖTÜ ({len(bad)}):  {[a for a,_ in bad]}")