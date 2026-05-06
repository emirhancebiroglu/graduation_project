import pandas as pd
import numpy as np
import os, warnings
warnings.filterwarnings('ignore')

HOME = os.path.expanduser('~')
CSV_DIR = f'{HOME}/bitirme/data/raw/cicids2017'

def gc(df, names):
    for n in names:
        if n in df.columns: return df[n]
    return pd.Series(0.0, index=df.index)

def get_features(df):
    return pd.DataFrame({
        'dur_sec':  gc(df, ['Flow Duration',' Flow Duration']) / 1e6,
        'spkts':    gc(df, ['Total Fwd Packets',' Total Fwd Packets']),
        'dpkts':    gc(df, ['Total Backward Packets',' Total Backward Packets']),
        'sbytes':   gc(df, ['Total Length of Fwd Packets',' Total Length of Fwd Packets']),
        'dbytes':   gc(df, ['Total Length of Bwd Packets',' Total Length of Bwd Packets']),
        'swin':     gc(df, ['Init_Win_bytes_forward',' Init_Win_bytes_forward']),
        'dwin':     gc(df, ['Init_Win_bytes_backward',' Init_Win_bytes_backward']),
        'sintpkt':  gc(df, ['Fwd IAT Mean',' Fwd IAT Mean']) / 1000,
        'dintpkt':  gc(df, ['Bwd IAT Mean',' Bwd IAT Mean']) / 1000,
    })

# Tüm attack type verilerini topla
all_data = {}
for csv_file in sorted(os.listdir(CSV_DIR)):
    if not csv_file.endswith('.csv'): continue
    path = os.path.join(CSV_DIR, csv_file)
    df = pd.read_csv(path, low_memory=False, on_bad_lines='skip', encoding_errors='replace')
    df.columns = df.columns.str.strip()
    if 'Label' not in df.columns: continue
    df['Label'] = df['Label'].str.strip()
    df = df[df['Label'].notna() & df['Label'].apply(lambda x: isinstance(x, str))]
    feats = get_features(df)
    feats['Label'] = df['Label'].values
    for label in df['Label'].unique():
        mask = df['Label'] == label
        if label not in all_data:
            all_data[label] = []
        all_data[label].append(feats[mask])

# Birleştir
combined = {}
for label, dfs in all_data.items():
    combined[label] = pd.concat(dfs, ignore_index=True)

# Analiz: KÖTÜ kategoriler vs BENIGN karşılaştırması
bad_attacks  = ['FTP-Patator','SSH-Patator','Bot','Infiltration',
                'Web Attack','Heartbleed']
good_attacks = ['PortScan','DDoS','DoS Hulk','DoS Slowhttptest']
mid_attacks  = ['DoS slowloris','DoS GoldenEye']

features = ['dur_sec','spkts','dpkts','sbytes','dbytes','swin','sintpkt']

print("=" * 90)
print("Feature Medyan Karşılaştırması — BENIGN vs Saldırı Türleri")
print("=" * 90)
print(f"{'Label':<28} {'dur_s':>7} {'spkts':>6} {'dpkts':>6} {'sbytes':>7} {'dbytes':>7} {'swin':>7} {'sintpkt':>8} {'N':>7}")
print("-" * 90)

ben = combined.get('BENIGN', pd.DataFrame())
if len(ben):
    b = ben[features].median()
    print(f"{'BENIGN':<28} {b['dur_sec']:>7.2f} {b['spkts']:>6.1f} {b['dpkts']:>6.1f} "
          f"{b['sbytes']:>7.1f} {b['dbytes']:>7.1f} {b['swin']:>7.0f} {b['sintpkt']:>8.1f} {len(ben):>7}")
print()

for group_name, attacks in [("✓ İYİ", good_attacks), ("~ ORTA", mid_attacks), ("✗ KÖTÜ", bad_attacks)]:
    print(f"--- {group_name} ---")
    for attack in attacks:
        # Fuzzy match (encoding sorunu için)
        key = None
        for k in combined.keys():
            if not isinstance(k, str): continue
            if attack.lower().replace(' ','') in k.lower().replace(' ','') or                k.lower().replace(' ','') in attack.lower().replace(' ',''):
                key = k
                break
        if key is None or len(combined[key]) == 0:
            continue
        d = combined[key]
        m = d[features].median()
        print(f"{key:<28} {m['dur_sec']:>7.2f} {m['spkts']:>6.1f} {m['dpkts']:>6.1f} "
              f"{m['sbytes']:>7.1f} {m['dbytes']:>7.1f} {m['swin']:>7.0f} {m['sintpkt']:>8.1f} {len(d):>7}")
    print()

# UNSW-NB15'teki benzer kategoriler var mı?
print("=" * 90)
print("UNSW-NB15 Eğitim Seti — Attack Category Dağılımı")
print("=" * 90)
# UNSW-NB15 CSV'lerinde header yok
# Sütun 47 = attack_cat, sütun 48 = label (0=normal, 1=attack)
unsw_path = f'{HOME}/bitirme/data/unsw'
unsw_cats = {}
unsw_total = 0
for f in sorted(os.listdir(unsw_path)):
    if not f.endswith('.csv') or 'zone' in f.lower(): continue
    path = os.path.join(unsw_path, f)
    try:
        df_unsw = pd.read_csv(path, low_memory=False, header=None,
                              on_bad_lines='skip', encoding_errors='replace')
        if df_unsw.shape[1] < 49: continue
        cats = df_unsw.iloc[:, 47].value_counts()
        for cat, cnt in cats.items():
            if pd.isna(cat): continue
            cat = str(cat).strip()
            unsw_cats[cat] = unsw_cats.get(cat, 0) + int(cnt)
        unsw_total += len(df_unsw)
        print(f"  {f}: {len(df_unsw):,} satır")
    except Exception as e:
        print(f"  HATA {f}: {e}")

print()
print(f"Toplam: {unsw_total:,} satır")
print()
print("UNSW Attack Kategorileri:")
for cat, cnt in sorted(unsw_cats.items(), key=lambda x: -x[1]):
    print(f"  {cat:<20} {cnt:>8,}")

print()
print("=" * 90)
print("CIC-IDS2017 ↔ UNSW-NB15 Eşleştirme Analizi")
print("=" * 90)

# Mapping tablosu — hangisi UNSW'de var, hangisi yok
mapping = [
    ("DoS Hulk",                "DoS",          "✓ UNSW'de VAR"),
    ("DoS GoldenEye",           "DoS",          "✓ UNSW'de VAR"),
    ("DoS slowloris",           "DoS",          "✓ UNSW'de VAR"),
    ("DoS Slowhttptest",        "DoS",          "✓ UNSW'de VAR"),
    ("DDoS",                    "DoS/Generic",  "~ Kısmi (farklı profil)"),
    ("PortScan",                "Reconnaissance","✓ UNSW'de VAR (Recon)"),
    ("FTP-Patator",             "-",            "✗ UNSW'de YOK"),
    ("SSH-Patator",             "-",            "✗ UNSW'de YOK"),
    ("Bot",                     "Backdoors",    "~ Kısmi (farklı profil)"),
    ("Web Attack BruteForce",   "Exploits",     "~ Kısmi"),
    ("Web Attack XSS",          "Exploits",     "~ Kısmi"),
    ("Web Attack SQLi",         "Exploits",     "~ Kısmi"),
    ("Infiltration",            "Backdoors",    "~ Kısmi"),
    ("Heartbleed",              "Exploits",     "~ Kısmi"),
]

print(f"{'CIC-IDS2017':<28} {'UNSW Karşılığı':<20} {'Durum'}")
print("-" * 70)
for cic, unsw, status in mapping:
    print(f"{cic:<28} {unsw:<20} {status}")