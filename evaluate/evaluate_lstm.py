import numpy as np
import logging
import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
from tensorflow.keras.models import load_model
from sklearn.metrics import confusion_matrix, classification_report
from pathlib import Path

# Kök dizin ve dosya yolları
ROOT = Path(__file__).resolve().parents[2]
logs_dir = ROOT / "logs" / "lstm"
processed_dir = ROOT / "data" / "processed"
models_dir = ROOT / "models"

logs_dir.mkdir(parents=True, exist_ok=True)

# Loglama Yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler(logs_dir / "evaluate_lstm.log", mode='w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def evaluate_model():
    logging.info("LSTM Model Değerlendirme (Evaluation) süreci başlatılıyor...")

    # 1. Verileri ve Modeli Yükleme
    try:
        X_test = np.load(processed_dir / "X_test.npy")
        y_test = np.load(processed_dir / "y_test.npy")
        logging.info(f"Test verisi yüklendi. X_test shape: {X_test.shape}")
        
        # Modeli yükleme
        model_path = models_dir / "best_lstm_model.h5"
        model = load_model(model_path)
        logging.info(f"Model başarıyla yüklendi: {model_path}")
    except Exception as e:
        logging.error(f"Dosya yükleme hatası: {e}")
        return

    # 2. Reshape İşlemi (LSTM için)
    X_test = np.reshape(X_test, (X_test.shape[0], 1, X_test.shape[1]))

    # 3. Tahmin (Prediction) Yapma
    logging.info("Test verisi üzerinde tahminler yapılıyor...")
    y_pred_prob = model.predict(X_test, batch_size=512)
    
    # Sigmoid çıktısını (0.0 - 1.0) binary sınıflara (0 veya 1) dönüştürme
    y_pred = (y_pred_prob > 0.5).astype(int).flatten()

    # 4. Metrikleri Hesaplama
    logging.info("Performans metrikleri hesaplanıyor...\n")
    
    cm = confusion_matrix(y_test, y_pred)
    cr = classification_report(y_test, y_pred, target_names=['Normal (0)', 'Atak (1)'])

    # Matrix formatını düzgün yazdırma
    cm_text = (
        f"Confusion Matrix:\n"
        f"                 Tahmin Edilen Normal (0) | Tahmin Edilen Atak (1)\n"
        f"Gerçek Normal (0) | {cm[0][0]:<24} | {cm[0][1]:<22}\n"
        f"Gerçek Atak (1)   | {cm[1][0]:<24} | {cm[1][1]:<22}\n"
    )

    logging.info(f"\n{cm_text}")
    logging.info(f"\nClassification Report:\n{cr}")

if __name__ == "__main__":
    evaluate_model()