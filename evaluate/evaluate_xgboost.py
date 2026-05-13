import numpy as np
import logging
import xgboost as xgb
from sklearn.metrics import confusion_matrix, classification_report
from pathlib import Path

# Kök dizin ve dosya yolları
ROOT = Path(__file__).resolve().parents[2]
logs_dir = ROOT / "logs" / "xgboost"
processed_dir = ROOT / "data" / "processed"
models_dir = ROOT / "models"

logs_dir.mkdir(parents=True, exist_ok=True)

# Loglama Yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler(logs_dir / "evaluate_xgboost.log", mode='w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def evaluate_xgboost():
    logging.info("XGBoost Model Değerlendirme süreci başlatılıyor...")

    try:
        X_test = np.load(processed_dir / "X_test.npy")
        y_test = np.load(processed_dir / "y_test.npy")
        logging.info(f"Test verisi yüklendi. X_test shape: {X_test.shape}")
        
        # Modeli C++ uyumlu JSON formatından yükleme
        model_path = models_dir / "best_xgb_model.json"
        model = xgb.XGBClassifier()
        model.load_model(model_path)
        logging.info(f"Model başarıyla yüklendi: {model_path}")
    except Exception as e:
        logging.error(f"Hata oluştu: {e}")
        return

    logging.info("Tahminler yapılıyor...")
    y_pred = model.predict(X_test)

    logging.info("Performans metrikleri hesaplanıyor...\n")
    cm = confusion_matrix(y_test, y_pred)
    cr = classification_report(y_test, y_pred, target_names=['Normal (0)', 'Atak (1)'])

    cm_text = (
        f"XGBoost Confusion Matrix:\n"
        f"                 Tahmin Edilen Normal (0) | Tahmin Edilen Atak (1)\n"
        f"Gerçek Normal (0) | {cm[0][0]:<24} | {cm[0][1]:<22}\n"
        f"Gerçek Atak (1)   | {cm[1][0]:<24} | {cm[1][1]:<22}\n"
    )

    logging.info(f"\n{cm_text}")
    logging.info(f"\nClassification Report:\n{cr}")

if __name__ == "__main__":
    evaluate_xgboost()