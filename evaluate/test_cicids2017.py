import pandas as pd
import numpy as np
import logging
import os
import pickle
from pathlib import Path

# Uyarıları gizleme (İsteğe bağlı temiz görünüm için)
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
import xgboost as xgb
from tensorflow.keras.models import load_model
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
        logging.FileHandler(logs_dir / "cicids2017_eval.log", mode='w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def evaluate_on_cicids():
    logging.info("CIC-IDS2017 Çapraz Veri Seti (Cross-Dataset) Testi Başlatılıyor...")

    # 2. Dosyaları Bulma ve Birleştirme
    csv_files = list(cic_raw_dir.glob("*.csv"))
    if not csv_files:
        logging.error(f"'{cic_raw_dir}' dizininde CSV dosyası bulunamadı!")
        return

    df_list = []
    for file in csv_files:
        logging.info(f"Yükleniyor: {file.name}")
        # CIC-IDS2017 dosyalarında bazen bozuk satırlar olabiliyor, error_bad_lines atlıyoruz
        df_part = pd.read_csv(file, low_memory=False, on_bad_lines='skip')
        df_list.append(df_part)

    logging.info("Dosyalar birleştiriliyor...")
    df = pd.concat(df_list, ignore_index=True)
    
    # Kolon isimlerindeki baştaki/sondaki boşlukları temizleme
    df.columns = df.columns.str.strip()
    logging.info(f"Orijinal CIC-IDS2017 Boyutu: {df.shape}")

    # 3. Özellik Haritalama (Feature Mapping)
    mapping = {
        'Flow Duration': 'dur',
        'Total Fwd Packets': 'spkts',
        'Total Backward Packets': 'dpkts',
        'Total Length of Fwd Packets': 'sbytes',
        'Total Length of Bwd Packets': 'dbytes',
        'Fwd Packet Length Mean': 'smeansz',
        'Bwd Packet Length Mean': 'dmeansz',
        'Init_Win_bytes_forward': 'swin',
        'Init_Win_bytes_backward': 'dwin',
        'Fwd IAT Mean': 'sintpkt',
        'Bwd IAT Mean': 'dintpkt'
    }

    # Sadece bize lazım olan 11 kolon ve Label kolonunu alıyoruz
    required_cic_cols = list(mapping.keys()) + ['Label']
    
    # Eksik kolon var mı kontrolü
    missing = [c for c in required_cic_cols if c not in df.columns]
    if missing:
        logging.error(f"Şu kolonlar CIC-IDS veri setinde bulunamadı: {missing}")
        return

    df = df[required_cic_cols].copy()
    df.rename(columns=mapping, inplace=True)

    # 4. Birim Dönüşümleri (Çok Kritik!)
    logging.info("Mikrosaniye (Microseconds) değerleri Saniye ve Milisaniyeye dönüştürülüyor...")
    # Flow Duration (Microseconds) -> Seconds
    df['dur'] = df['dur'] / 1e6
    # IAT Mean (Microseconds) -> Milliseconds
    df['sintpkt'] = df['sintpkt'] / 1000.0
    # CIC-IDS setinde Bwd IAT Mean var, UNSW'ye göre milisaniyeye çeviriyoruz
    df['dintpkt'] = df['dintpkt'] / 1000.0

    # 5. NaN ve Infinity Değerleri Temizleme
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # 6. Etiketleri Binary'e Çevirme (BENIGN -> 0, Diğer her şey -> 1)
    df['label'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
    df.drop(columns=['Label'], inplace=True)

    # ===== YENİ EKLENEN KISIM: EĞİTİM SETİYLE UYUMLU LOGARİTMİK DÖNÜŞÜM =====
    logging.info("Aşırı büyük değerli kolonlara Logaritmik Dönüşüm (Log1p) uygulanıyor...")
    log_cols = ['sbytes', 'dbytes', 'spkts', 'dpkts', 'dur', 'sintpkt', 'dintpkt']
    for col in log_cols:
        df[col] = np.log1p(df[col])
    # ========================================================================

    # Modelin eğitildiği spesifik özellik sırası (Scaler bu sırayı bekliyor)
    feature_order = ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 
                     'smeansz', 'dmeansz', 'swin', 'dwin', 'sintpkt', 'dintpkt']
    
    X_cic = df[feature_order].values
    y_cic = df['label'].values

    logging.info(f"Temizlenmiş Test Seti Boyutu: {X_cic.shape}")
    logging.info(f"Dağılım -> Normal (0): {(y_cic==0).sum()}, Atak (1): {(y_cic==1).sum()}")

    # 7. UNSW Scaler'ı ile Ölçeklendirme
    logging.info("UNSW-NB15 Scaler'ı yükleniyor ve veri ölçeklendiriliyor...")
    with open(models_dir / "scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
    
    X_cic_scaled = scaler.transform(X_cic)

    # XGBoost modelini teşhis aşaması için erkenden yüklüyoruz
    xgb_model = xgb.XGBClassifier()
    xgb_model.load_model(models_dir / "fine_tuned_xgb_model.json")

    # ================= TEŞHİS (DIAGNOSTIC) BLOĞU BAŞLANGICI =================
    logging.info("--- ÇAPRAZ TEST VERİ ANALİZİ BAŞLIYOR ---")
    
    df_raw_diag = pd.DataFrame(X_cic, columns=feature_order)
    logging.info("1. CIC-IDS2017 Ham Veri İstatistikleri (Log1p Sonrası, Scaler Öncesi):")
    raw_stats = df_raw_diag.describe().T[['mean', 'std', 'min', 'max']]
    logging.info(f"\n{raw_stats.to_string()}")
    
    df_scaled_diag = pd.DataFrame(X_cic_scaled, columns=feature_order)
    logging.info("2. Ölçeklenmiş Veri İstatistikleri (RobustScaler Sonrası):")
    scaled_stats = df_scaled_diag.describe().T[['mean', 'std', 'min', 'max']]
    logging.info(f"\n{scaled_stats.to_string()}")
    
    logging.info("3. XGBoost Feature Importances (Model hangi kolonlara güveniyor?):")
    importances = xgb_model.feature_importances_
    feat_imp = pd.DataFrame({'Feature': feature_order, 'Importance': importances}).sort_values(by='Importance', ascending=False)
    logging.info(f"\n{feat_imp.to_string(index=False)}")
    
    logging.info("4. Atak Olasılık Dağılımı (Model Atak derken ne kadar emin?):")
    y_proba = xgb_model.predict_proba(X_cic_scaled)[:, 1] 
    gercek_atak_idx = (y_cic == 1) 
    atak_olasiliklari = y_proba[gercek_atak_idx]
    
    logging.info(f"Gerçek Atak verilerinde modelin ortalama Atak deme olasılığı: {np.mean(atak_olasiliklari):.4f}")
    logging.info(f"Gerçek Atak verilerinde olasılık Medyanı: {np.median(atak_olasiliklari):.4f}")
    
    percentiles = np.percentile(atak_olasiliklari, [10, 25, 50, 75, 90])
    logging.info(f"Gerçek Atakların olasılık dağılımı (10%, 25%, 50%, 75%, 90%): {percentiles}")
    logging.info("--- ÇAPRAZ TEST VERİ ANALİZİ BİTTİ ---")
    # ================= TEŞHİS BLOĞU SONU =================

    # ================= EVALUATION KISMI =================

    # 8. XGBoost Testi
    logging.info("--- XGBoost Modeli Test Ediliyor ---")
    y_pred_xgb = xgb_model.predict(X_cic_scaled)
    
    cm_xgb = confusion_matrix(y_cic, y_pred_xgb)
    cr_xgb = classification_report(y_cic, y_pred_xgb, target_names=['Normal (0)', 'Atak (1)'])
    logging.info(f"XGBoost Confusion Matrix:\n{cm_xgb}")
    logging.info(f"XGBoost Raporu:\n{cr_xgb}")

    # 9. LSTM Testi
    logging.info("--- LSTM Modeli Test Ediliyor ---")
    lstm_model = load_model(models_dir / "fine_tuned_lstm_model.h5")
    
    # LSTM reshape
    X_cic_scaled_lstm = np.reshape(X_cic_scaled, (X_cic_scaled.shape[0], 1, X_cic_scaled.shape[1]))
    y_pred_prob_lstm = lstm_model.predict(X_cic_scaled_lstm, batch_size=1024)
    y_pred_lstm = (y_pred_prob_lstm > 0.5).astype(int).flatten()

    cm_lstm = confusion_matrix(y_cic, y_pred_lstm)
    cr_lstm = classification_report(y_cic, y_pred_lstm, target_names=['Normal (0)', 'Atak (1)'])
    logging.info(f"LSTM Confusion Matrix:\n{cm_lstm}")
    logging.info(f"LSTM Raporu:\n{cr_lstm}")

    logging.info("Test Süreci Tamamlandı.")

if __name__ == "__main__":
    evaluate_on_cicids()