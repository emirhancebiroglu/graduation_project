import pandas as pd
import numpy as np
from sklearn.preprocessing import RobustScaler
from sklearn.model_selection import train_test_split
import pickle
import logging
import os
from pathlib import Path

# Kök dizini belirleme (src/data_prep/ içinden çalıştırıldığı varsayımıyla)
ROOT = Path(__file__).resolve().parents[2]
    
# Klasör Yolları
logs_dir = ROOT / "logs" / "lstm"
raw_dir = ROOT / "data" / "raw"
processed_dir = ROOT / "data" / "processed"
models_dir = ROOT / "models"

# Çıktı klasörleri yoksa oluştur
logs_dir.mkdir(parents=True, exist_ok=True)
processed_dir.mkdir(parents=True, exist_ok=True)
models_dir.mkdir(parents=True, exist_ok=True)

# 1. Loglama Yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler(logs_dir / "dataset_prep.log", mode='w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def prepare_data():
    logging.info("Veri ön işleme süreci başlatıldı (Ham veriler birleştiriliyor).")

    # Okunacak 4 ana raw dosya
    raw_files = [
        raw_dir / "UNSW-NB15_1.csv",
        raw_dir / "UNSW-NB15_2.csv",
        raw_dir / "UNSW-NB15_3.csv",
        raw_dir / "UNSW-NB15_4.csv"
    ]
    
    # Raw dosyalarda başlık (header) olmadığı için 49 kolonu manuel tanımlıyoruz
    columns = [
        'srcip', 'sport', 'dstip', 'dsport', 'proto', 'state', 'dur', 'sbytes', 'dbytes',
        'sttl', 'dttl', 'sloss', 'dloss', 'service', 'sload', 'dload', 'spkts', 'dpkts',
        'swin', 'dwin', 'stcpb', 'dtcpb', 'smeansz', 'dmeansz', 'trans_depth', 'res_bdy_len',
        'sjit', 'djit', 'stime', 'ltime', 'sintpkt', 'dintpkt', 'tcprtt', 'synack', 'ackdat',
        'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd', 'is_ftp_login', 'ct_ftp_cmd',
        'ct_srv_src', 'ct_srv_dst', 'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm',
        'ct_dst_sport_ltm', 'ct_dst_src_ltm', 'attack_cat', 'label'
    ]

    # Hedeflediğimiz 11 ortak kolon
    selected_features = [
        'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 
        'smeansz', 'dmeansz', 'swin', 'dwin', 'sintpkt', 'dintpkt'
    ]
    target_col = 'label'

    df_list = []
    
    # 2. Dosyaları Okuma ve Birleştirme
    for file in raw_files:
        if not os.path.exists(file):
            logging.error(f"{file} bulunamadı! Lütfen dosya yolunu kontrol et.")
            return
            
        logging.info(f"{file} yükleniyor...")
        # Header olmadığını varsayarak okuyoruz (low_memory=False RAM uyarılarını kapatır)
        df_part = pd.read_csv(file, header=None, low_memory=False)
        
        # Eğer dosyanın ilk satırı başlık satırı içeriyorsa ('srcip' gibi), o satırı atla
        if str(df_part.iloc[0, 0]).strip().lower() == 'srcip':
            df_part = df_part.iloc[1:]
            
        df_part.columns = columns
        df_list.append(df_part)

    logging.info("4 Parça birleştiriliyor...")
    df_full = pd.concat(df_list, ignore_index=True)
    logging.info(f"Birleştirilmiş Ham Veri Seti Boyutu: {df_full.shape}")

    # 3. Özellik Filtreleme ve NaN Temizliği
    df_filtered = df_full[selected_features + [target_col]].copy()

    # Bazı kolonlar string formatında gelmiş olabilir, float/int'e çeviriyoruz
    df_filtered = df_filtered.apply(pd.to_numeric, errors='coerce')

    if df_filtered.isnull().values.any():
        logging.warning("Veri setinde eksik/hatalı (NaN) değerler var. Bu satırlar atılıyor...")
        df_filtered.dropna(inplace=True)
    
    logging.info(f"Temizlenmiş Veri Seti Boyutu: {df_filtered.shape}")

    # ===== YENİ EKLENEN KISIM: LOGARİTMİK DÖNÜŞÜM =====
    logging.info("Aşırı büyük değerli kolonlara (byte ve paket sayıları) Logaritmik Dönüşüm (Log1p) uygulanıyor...")
    
    # Genelde byte, paket sayıları ve sürelerde devasa dalgalanmalar olur. 
    # Bu kolonları logaritmadan geçiriyoruz ki model büyük rakamları ezberlemesin.
    log_cols = ['sbytes', 'dbytes', 'spkts', 'dpkts', 'dur', 'sintpkt', 'dintpkt']
    
    for col in log_cols:
        # np.log1p (log(1+x)) kullanıyoruz ki x=0 durumunda log(0) yani -sonsuz hatası almayalım.
        df_filtered[col] = np.log1p(df_filtered[col])
        
    # ===================================================

    X = df_filtered[selected_features].values
    y = df_filtered[target_col].values.astype(int)

    # 4. Train-Test Bölünmesi (%80 Eğitim, %20 Test)
    logging.info("Veri %80 Eğitim, %20 Test olacak şekilde bölünüyor (Train-Test Split)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=42, stratify=y)

    logging.info(f"X_train boyutu: {X_train.shape}")
    logging.info(f"X_test boyutu: {X_test.shape}")
    
    train_normal_count = (y_train == 0).sum()
    train_attack_count = (y_train == 1).sum()
    logging.info(f"Eğitim Seti Sınıf Dağılımı -> Normal (0): {train_normal_count}, Atak (1): {train_attack_count}")

    # 5. Ölçeklendirme (Scaling) - ROBUSTSCALER'A GEÇİŞ
    logging.info("RobustScaler ile veriler ölçeklendiriliyor (Outlier'lara karşı dayanıklılık için)...")
    
    # StandardScaler yerine RobustScaler kullanıyoruz.
    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    logging.info("Ölçeklendirme tamamlandı.")

    # 6. Dosyaları Kaydetme
    logging.info("İşlenmiş numpy dizileri ve scaler nesnesi diske kaydediliyor...")
    np.save(processed_dir / "X_train.npy", X_train_scaled)
    np.save(processed_dir / "y_train.npy", y_train)
    np.save(processed_dir / "X_test.npy", X_test_scaled)
    np.save(processed_dir / "y_test.npy", y_test)
    
    with open(models_dir / "scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    logging.info(f"Kayıt işlemi başarılı!\nVeriler: {processed_dir}\nScaler: {models_dir}")

if __name__ == "__main__":
    prepare_data()