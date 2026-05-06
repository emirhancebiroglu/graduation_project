import pandas as pd
import numpy as np
import logging
import os
import pickle
from pathlib import Path

# Uyarıları gizleme
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report

# 1. Klasör Yolları ve Loglama
ROOT = Path(__file__).resolve().parents[2]
logs_dir = ROOT / "logs" / "cross_eval"
models_dir = ROOT / "models"
cic_raw_dir = ROOT / "data" / "raw" / "cicids2017"

logs_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(logs_dir / "fine_tune_xgb.log", mode='w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def fine_tune_and_evaluate():
    logging.info("--- XGBoost Transfer Learning (İnce Ayar) Süreci Başlıyor ---")

    # 2. Dosyaları Bulma ve Birleştirme
    csv_files = list(cic_raw_dir.glob("*.csv"))
    if not csv_files:
        logging.error(f"'{cic_raw_dir}' dizininde CSV dosyası bulunamadı!")
        return

    df_list = []
    for file in csv_files:
        df_part = pd.read_csv(file, low_memory=False, on_bad_lines='skip')
        df_list.append(df_part)

    logging.info("CIC-IDS2017 Verileri birleştiriliyor...")
    df = pd.concat(df_list, ignore_index=True)
    df.columns = df.columns.str.strip()

    # 3. Özellik Haritalama
    mapping = {
        'Flow Duration': 'dur', 'Total Fwd Packets': 'spkts', 'Total Backward Packets': 'dpkts',
        'Total Length of Fwd Packets': 'sbytes', 'Total Length of Bwd Packets': 'dbytes',
        'Fwd Packet Length Mean': 'smeansz', 'Bwd Packet Length Mean': 'dmeansz',
        'Init_Win_bytes_forward': 'swin', 'Init_Win_bytes_backward': 'dwin',
        'Fwd IAT Mean': 'sintpkt', 'Bwd IAT Mean': 'dintpkt'
    }

    required_cic_cols = list(mapping.keys()) + ['Label']
    df = df[required_cic_cols].copy()
    df.rename(columns=mapping, inplace=True)

    # 4. Birim Dönüşümleri ve Temizlik
    df['dur'] = df['dur'] / 1e6
    df['sintpkt'] = df['sintpkt'] / 1000.0
    df['dintpkt'] = df['dintpkt'] / 1000.0

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    df['label'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
    df.drop(columns=['Label'], inplace=True)

    # 5. Logaritmik Dönüşüm (Eğitim setiyle aynı standart)
    logging.info("Log1p dönüşümü uygulanıyor...")
    log_cols = ['sbytes', 'dbytes', 'spkts', 'dpkts', 'dur', 'sintpkt', 'dintpkt']
    for col in log_cols:
        df[col] = np.log1p(df[col])

    feature_order = ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 
                     'smeansz', 'dmeansz', 'swin', 'dwin', 'sintpkt', 'dintpkt']
    
    X = df[feature_order].values
    y = df['label'].values

    # 6. Train/Test Bölünmesi (%10 İnce Ayar için, %90 Test için)
    logging.info("Veri %10 Fine-Tuning (Eğitim), %90 Test olacak şekilde bölünüyor...")
    X_train_ft, X_test, y_train_ft, y_test = train_test_split(X, y, test_size=0.90, random_state=42, stratify=y)
    
    logging.info(f"İnce Ayar (Eğitim) Seti Boyutu: {X_train_ft.shape}")
    logging.info(f"Devasa Test Seti Boyutu: {X_test.shape}")

    # 7. UNSW Scaler'ı ile Ölçeklendirme
    logging.info("Mevcut RobustScaler yükleniyor ve veriler ölçeklendiriliyor...")
    with open(models_dir / "scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
    
    X_train_ft_scaled = scaler.transform(X_train_ft)
    X_test_scaled = scaler.transform(X_test)

    # ================= TRANSFER LEARNING KISMI =================
    logging.info("--- Model İnce Ayarı (Fine-Tuning) Başlıyor ---")
    
    # Eski modeli baz alarak yeni bir classifier oluşturuyoruz.
    # Öğrenme oranını (learning_rate) düşük tutuyoruz ki eski bilgilerini tamamen silmesin.
    xgb_ft_model = xgb.XGBClassifier(
        n_estimators=50,       # Sadece 50 yeni ağaç ekleyerek kalibre edeceğiz
        learning_rate=0.05,    # Eski bilgiyi korumak için düşük hız
        random_state=42
    )
    
    # xgb_model parametresi ile eski modeli "başlangıç noktası" olarak gösteriyoruz
    old_model_path = models_dir / "best_xgb_model.json"
    xgb_ft_model.fit(X_train_ft_scaled, y_train_ft, xgb_model=old_model_path)
    
    logging.info("İnce ayar tamamlandı! Yeni model test ediliyor...")
    
    # ================= EVALUATION KISMI =================
    y_pred = xgb_ft_model.predict(X_test_scaled)
    
    cm = confusion_matrix(y_test, y_pred)
    cr = classification_report(y_test, y_pred, target_names=['Normal (0)', 'Atak (1)'])
    
    logging.info(f"Fine-Tuned XGBoost Confusion Matrix:\n{cm}")
    logging.info(f"Fine-Tuned XGBoost Raporu:\n{cr}")

    # Güncellenmiş modeli kaydetme
    ft_model_path = models_dir / "fine_tuned_xgb_model.json"
    xgb_ft_model.save_model(ft_model_path)
    logging.info(f"Yeni kalibre edilmiş model kaydedildi: {ft_model_path}")
    logging.info("--- Süreç Tamamlandı ---")

if __name__ == "__main__":
    fine_tune_and_evaluate()