import numpy as np
import logging
import xgboost as xgb
from pathlib import Path

# Kök dizin ve dosya yolları
ROOT = Path(__file__).resolve().parents[2]
logs_dir = ROOT / "logs" / "xgboost"
processed_dir = ROOT / "data" / "processed"
models_dir = ROOT / "models"

logs_dir.mkdir(parents=True, exist_ok=True)
models_dir.mkdir(parents=True, exist_ok=True)

# Loglama Yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler(logs_dir / "train_xgboost.log", mode='w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def train_xgboost():
    logging.info("XGBoost Eğitim süreci başlatılıyor...")

    # 1. Verileri Yükleme
    try:
        X_train = np.load(processed_dir / "X_train.npy")
        y_train = np.load(processed_dir / "y_train.npy")
        # XGBoost validasyon seti kullanarak erken durdurma (early stopping) yapabilir
        X_test = np.load(processed_dir / "X_test.npy") 
        y_test = np.load(processed_dir / "y_test.npy")
        logging.info(f"Veriler yüklendi. X_train shape: {X_train.shape}")
    except FileNotFoundError:
        logging.error("Numpy dosyaları bulunamadı! Lütfen prepare_dataset.py betiğini kontrol edin.")
        return

    # Not: LSTM'den farklı olarak XGBoost veriyi 3D değil, standart 2D (satır, sütun) olarak bekler.
    # Numpy dizilerimiz zaten 2D olarak kaydedilmişti, reshape yapmamıza gerek yok.

    # 2. XGBoost Modelini Tanımlama
    logging.info("XGBoost sınıflandırıcısı (classifier) oluşturuluyor...")
    
    model = xgb.XGBClassifier(
        n_estimators=200,          # Ağaç sayısı
        max_depth=6,               # Ağaç derinliği (overfitting'i kontrol etmek için)
        learning_rate=0.1,         # Öğrenme katsayısı
        objective='binary:logistic',
        tree_method='hist',        # Büyük veri setlerinde CPU üzerinde çok daha hızlı eğitim için 'hist' kullanıyoruz
        eval_metric='logloss',
        random_state=42,
        n_jobs=-1                  # Tüm CPU çekirdeklerini kullan
    )

    # 3. Modeli Eğitme (Early Stopping ile)
    logging.info("Eğitim başlatılıyor. Bu işlem CPU gücünüze bağlı olarak biraz sürebilir...")
    
    model.fit(
        X_train, y_train,
        eval_set=[(X_train, y_train), (X_test, y_test)],
        verbose=10 # Her 10 ağaçta bir log bas
    )

    # 4. Modeli Kaydetme
    # İleride Snort3 C++ (libml) entegrasyonu için en uygun format JSON formatıdır.
    model_save_path = models_dir / "best_xgb_model.json"
    model.save_model(model_save_path)
    
    logging.info(f"Eğitim tamamlandı! Model C++ uyumlu formatta kaydedildi: {model_save_path}")

if __name__ == "__main__":
    train_xgboost()