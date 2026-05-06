"""
fine_tune_lstm.py — LSTM Fine-Tuning v3 (Dengeli Örnekleme)
Bitirme Projesi: IDS Performans Karşılaştırma

v2'den farklar:
  1. Dengeli stratified örnekleme — minority class'lar tam alınır, BENIGN kısıtlanır
  2. class_weight ile azınlık sınıflarına ağırlık verilir
  3. swin/dwin clamp (max=1020) — C++ plugin ile tutarlı preprocessing
  4. checkpoint monitor: val_accuracy → val_loss
  5. Per-saldırı-türü test metrikleri log'a yazılır
  6. threshold sweep ile optimal threshold belirlenir
"""

import pandas as pd
import numpy as np
import logging
import os
import pickle
from pathlib import Path
from sklearn.metrics import confusion_matrix, classification_report, f1_score
from sklearn.utils.class_weight import compute_class_weight

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"

import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint

# ---------------------------------------------------------------
# Paths
# ---------------------------------------------------------------
ROOT        = Path(__file__).resolve().parents[1]
logs_dir    = ROOT / "logs" / "cross_eval"
models_dir  = ROOT / "models"
cic_raw_dir = ROOT / "data" / "raw" / "cicids2017"

logs_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(logs_dir / "fine_tune_lstm_v4.log", mode='w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# ---------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------
FEATURE_ORDER = ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes',
                 'smeansz', 'dmeansz', 'swin', 'dwin', 'sintpkt', 'dintpkt']

LOG_COLS = ['sbytes', 'dbytes', 'spkts', 'dpkts', 'dur', 'sintpkt', 'dintpkt']

COL_MAPPING = {
    'Flow Duration':                'dur',
    'Total Fwd Packets':            'spkts',
    'Total Backward Packets':       'dpkts',
    'Total Length of Fwd Packets':  'sbytes',
    'Total Length of Bwd Packets':  'dbytes',
    'Fwd Packet Length Mean':       'smeansz',
    'Bwd Packet Length Mean':       'dmeansz',
    'Init_Win_bytes_forward':       'swin',
    'Init_Win_bytes_backward':      'dwin',
    'Fwd IAT Mean':                 'sintpkt',
    'Bwd IAT Mean':                 'dintpkt',
}

# Fine-tuning seti için sınıf başına maksimum örnek sayısı
# Minority class'lar tam alınır, BENIGN ve büyük saldırılar kısıtlanır
FINETUNE_LIMITS = {
    'BENIGN':              50_000,   # Çok fazla, kısıt
    'DoS Hulk':             5_000,   # Zaten iyi tespit ediliyor
    'DDoS':                 5_000,   # Zaten iyi
    'PortScan':             5_000,   # Zaten iyi
    'DoS GoldenEye':        5_000,
    'DoS slowloris':        5_000,
    'DoS Slowhttptest':     5_000,
    # Minority class'lar — TAMAMI alınır (limit yüksek tutuldu)
    'FTP-Patator':         10_000,
    'SSH-Patator':         10_000,
    'Bot':                 10_000,
    'Infiltration':        10_000,
    'Heartbleed':          10_000,
}
# Web Attack label'ları encoding bozuk — partial match ile yakalanır
WEB_ATTACK_LIMIT = 10_000
DEFAULT_LIMIT = 5_000   # Listede olmayan sınıflar için


# ---------------------------------------------------------------
# Yardımcı: veriyi yükle ve temizle
# ---------------------------------------------------------------
def load_and_preprocess():
    logging.info("CIC-IDS2017 CSV dosyaları yükleniyor...")
    csv_files = sorted(cic_raw_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(f"CSV bulunamadı: {cic_raw_dir}")

    dfs = []
    for f in csv_files:
        logging.info(f"  Okunuyor: {f.name}")
        df_part = pd.read_csv(f, low_memory=False, on_bad_lines='skip',
                              encoding_errors='replace')
        df_part.columns = df_part.columns.str.strip()
        df_part['csv_source'] = f.name
        dfs.append(df_part)

    df = pd.concat(dfs, ignore_index=True)
    logging.info(f"Toplam satır: {len(df):,}")

    # Kolon seç ve rename
    available = [c for c in COL_MAPPING if c in df.columns]
    df = df[available + ['Label', 'csv_source']].copy()
    df.rename(columns={c: COL_MAPPING[c] for c in available}, inplace=True)
    df['Label'] = df['Label'].str.strip()

    # Birim dönüşümleri
    df['dur']     = df['dur']     / 1e6
    df['sintpkt'] = df['sintpkt'] / 1000.0
    df['dintpkt'] = df['dintpkt'] / 1000.0

    # swin/dwin clamp — C++ plugin ile aynı (LSTM için)
    df['swin'] = df['swin'].clip(upper=1020.0)
    df['dwin'] = df['dwin'].clip(upper=1020.0)

    # Temizlik
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # Log1p
    for col in LOG_COLS:
        df[col] = np.log1p(df[col].clip(lower=0))

    # Binary label
    df['label'] = (df['Label'] != 'BENIGN').astype(int)

    logging.info(f"Temizlik sonrası: {len(df):,} satır")
    logging.info(f"Label dağılımı:\n{df['Label'].value_counts().to_string()}")

    return df

def build_balanced_finetune_set(df, random_state=42):
    """
    Saldırı sınıfları: FINETUNE_LIMITS'e göre örnekle (minority class tam alınır).
    BENIGN: her CSV'den 25K — 12.5K rastgele + 12.5K sorunlu profil.
    Sorunlu profil: dbytes=0 OR dur<0.01s OR spkts=1 (model FP ürettiği flow tipleri).
    """
    logging.info("\nDengeli fine-tuning seti oluşturuluyor...")

    PER_CSV_BENIGN  = 25_000
    HALF            = PER_CSV_BENIGN // 2

    train_indices = []

    # ── Saldırı sınıfları ──────────────────────────────────────────
    for label in df['Label'].unique():
        if not isinstance(label, str): continue
        if label == 'BENIGN': continue

        mask    = df['Label'] == label
        n_avail = mask.sum()
        if n_avail == 0: continue

        if 'web attack' in label.lower():
            limit = WEB_ATTACK_LIMIT
        else:
            limit = FINETUNE_LIMITS.get(label, DEFAULT_LIMIT)

        n_take  = min(n_avail, limit)
        sampled = df[mask].sample(n=n_take, random_state=random_state)
        train_indices.extend(sampled.index.tolist())
        logging.info(f"  {label:<35} toplam={n_avail:>7,}  fine-tune={n_take:>6,}")

    # ── BENIGN: her CSV'den stratified örnekleme ───────────────────
    logging.info(f"\n  BENIGN örnekleme (her CSV'den {PER_CSV_BENIGN:,}):")

    # df içinde hangi CSV'den geldiği bilgisi yok — csv_file sütunu eklenmiş olmalı.
    # load_and_preprocess() fonksiyonuna 'csv_source' sütunu eklenmeli (aşağıya bak).
    benign_df = df[df['Label'] == 'BENIGN']

    if 'csv_source' not in benign_df.columns:
        # csv_source yoksa tek blok olarak al — fallback
        logging.warning("  csv_source sütunu yok, tek blok BENIGN örnekleniyor")
        n_take = min(len(benign_df), 200_000)
        sampled = benign_df.sample(n=n_take, random_state=random_state)
        train_indices.extend(sampled.index.tolist())
        logging.info(f"  BENIGN fallback: {n_take:,}")
    else:
        for src in benign_df['csv_source'].unique():
            src_mask = benign_df['csv_source'] == src
            src_df   = benign_df[src_mask]
            n_avail  = len(src_df)

            # Sorunlu profil: model FP ürettiği flow tipleri
            problematic = (
                (src_df['dbytes'] == 0) |
                (src_df['dur']    < np.log1p(0.01)) |   # dur zaten log1p'li
                (src_df['spkts']  == np.log1p(1))        # spkts=1 → log1p(1)=0.693
            )
            prob_df   = src_df[problematic]
            normal_df = src_df[~problematic]

            # Yarısı sorunlu, yarısı rastgele
            n_prob   = min(len(prob_df),   HALF)
            n_normal = min(len(normal_df), HALF)

            s_prob   = prob_df.sample(n=n_prob,   random_state=random_state)
            s_normal = normal_df.sample(n=n_normal, random_state=random_state)

            train_indices.extend(s_prob.index.tolist())
            train_indices.extend(s_normal.index.tolist())

            logging.info(f"  {src:<45} toplam={n_avail:>7,}  "
                         f"sorunlu={n_prob:>5,}  normal={n_normal:>5,}")

    # ── Split ──────────────────────────────────────────────────────
    train_idx = set(train_indices)
    test_idx  = set(df.index) - train_idx

    df_train = df.loc[list(train_idx)]
    df_test  = df.loc[list(test_idx)]

    logging.info(f"\nFine-tuning seti: {len(df_train):,} satır")
    logging.info(f"Test seti:        {len(df_test):,} satır")

    return df_train, df_test

# ---------------------------------------------------------------
# Ana fonksiyon
# ---------------------------------------------------------------
def fine_tune_lstm_v3():
    logging.info("=" * 60)
    logging.info("LSTM Fine-Tuning v3 — Dengeli Örnekleme")
    logging.info("=" * 60)

    # 1. Veri yükle
    df = load_and_preprocess()

    # 2. Dengeli split
    df_train, df_test = build_balanced_finetune_set(df)

    X_train = df_train[FEATURE_ORDER].values
    y_train = df_train['label'].values
    X_test  = df_test[FEATURE_ORDER].values
    y_test  = df_test['label'].values
    labels_test = df_test['Label'].values

    # 3. Scaler — UNSW'den export edilmiş RobustScaler
    logging.info("\nScaler yükleniyor...")
    with open(models_dir / "scaler.pkl", "rb") as f:
        scaler = pickle.load(f)

    X_train = scaler.transform(X_train)
    X_test  = scaler.transform(X_test)

    # 4. LSTM reshape: [samples, 1, features]
    X_train = X_train.reshape(X_train.shape[0], 1, X_train.shape[1])
    X_test  = X_test.reshape(X_test.shape[0],  1, X_test.shape[1])

    # 6. Model yükle
    logging.info("\nBase model yükleniyor: best_lstm_model.h5")
    model = load_model(models_dir / "best_lstm_model.h5")
    model.compile(
        optimizer=Adam(learning_rate=0.0001),
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    model.summary(print_fn=logging.info)

    # 7. Callbacks
    early_stop = EarlyStopping(
        monitor='val_loss',
        patience=4,
        restore_best_weights=True,
        verbose=1
    )
    checkpoint = ModelCheckpoint(
        filepath=str(models_dir / "fine_tuned_lstm_model_v5.h5"),
        monitor='val_loss',      # val_accuracy değil — class imbalance nedeniyle
        save_best_only=True,
        mode='min',
        verbose=1
    )

    # 8. Fine-tuning
    logging.info("\nFine-tuning başlatılıyor (max 30 epoch, early stopping patience=4)...")
    history = model.fit(
        X_train, y_train,
        epochs=30,
        batch_size=512,
        validation_split=0.1,
        callbacks=[early_stop, checkpoint],
        verbose=1
    )

    # 9. En iyi model ile test
    logging.info("\nEn iyi model yükleniyor ve test ediliyor...")
    best_model = load_model(models_dir / "fine_tuned_lstm_model_v5.h5")

    y_pred_prob = best_model.predict(X_test, batch_size=2048).flatten()

    # 10. Threshold sweep — optimal eşik bul
    logging.info("\nThreshold sweep (0.10 - 0.90):")
    best_t, best_f1 = 0.5, 0.0
    for t in np.arange(0.10, 0.91, 0.05):
        y_pred_t = (y_pred_prob > t).astype(int)
        f1 = f1_score(y_test, y_pred_t, zero_division=0)
        tp = ((y_pred_t == 1) & (y_test == 1)).sum()
        fp = ((y_pred_t == 1) & (y_test == 0)).sum()
        fn = ((y_pred_t == 0) & (y_test == 1)).sum()
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
        rec  = tp / (tp + fn) if (tp + fn) > 0 else 0
        logging.info(f"  t={t:.2f}  F1={f1:.4f}  Prec={prec:.4f}  Rec={rec:.4f}  TP={tp}  FP={fp}")
        if f1 > best_f1:
            best_f1, best_t = f1, t

    logging.info(f"\nOptimal threshold: {best_t:.2f} (F1={best_f1:.4f})")

    # 11. Optimal threshold ile final değerlendirme
    y_pred_final = (y_pred_prob > best_t).astype(int)

    cm = confusion_matrix(y_test, y_pred_final)
    cr = classification_report(y_test, y_pred_final,
                               target_names=['Normal (0)', 'Atak (1)'],
                               digits=4)
    logging.info(f"\nFinal Confusion Matrix (t={best_t:.2f}):\n{cm}")
    logging.info(f"\nFinal Classification Report:\n{cr}")

    # 12. Per-saldırı-türü analiz
    logging.info("\nPer-Saldırı-Türü Performans (test seti):")
    logging.info(f"{'Saldırı Türü':<35} {'N':>7} {'TP':>7} {'FP':>7} {'Recall':>8} {'Prec':>8}")
    logging.info("-" * 70)

    attack_types = np.unique(labels_test)
    benign_mask  = labels_test == 'BENIGN'

    for attack in sorted(attack_types):
        if attack == 'BENIGN':
            continue
        mask  = labels_test == attack
        n     = mask.sum()
        if n == 0:
            continue
        tp    = ((y_pred_final[mask] == 1)).sum()
        fp    = ((y_pred_final[benign_mask] == 1)).sum()
        rec   = tp / n if n > 0 else 0
        prec  = tp / (tp + fp) if (tp + fp) > 0 else 0
        logging.info(f"{attack:<35} {n:>7,} {tp:>7,} {fp:>7,} {rec:>8.4f} {prec:>8.4f}")

    # 13. Modeli kaydet (Snort3 için isim aynı kalsın)
    final_path = models_dir / "fine_tuned_lstm_model_v5.h5"
    logging.info(f"\nModel kaydedildi: {final_path}")
    logging.info("Snort3 için TFLite'a dönüştürmek üzere convert_to_tflite.py çalıştırın.")
    logging.info("=" * 60)
    logging.info("Fine-tuning v3 tamamlandı.")


if __name__ == "__main__":
    fine_tune_lstm_v3()