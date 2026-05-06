#!/usr/bin/env python3
"""
verify_xgb_model.py — XGBoost model doğrulama ve dönüştürme

Kontroller:
  1. Model dosyası okunabiliyor mu?
  2. Doğru feature sayısı (11) bekliyor mu?
  3. Dummy inference çalışıyor mu?
  4. .pkl ise .json'a dönüştür

Kullanım:
    python verify_xgb_model.py --model ~/bitirme/models/fine_tuned_xgb_model.json
    python verify_xgb_model.py --model ~/bitirme/models/xgb_model.pkl --export-json
"""

import argparse
import numpy as np
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="XGBoost model doğrulama")
    parser.add_argument('--model', type=str, required=True,
                        help="Model dosyası (.json, .ubj, .pkl, .bin)")
    parser.add_argument('--export-json', action='store_true',
                        help=".pkl modelini .json olarak dışa aktar")
    args = parser.parse_args()

    model_path = Path(args.model)
    if not model_path.exists():
        print(f"❌ Dosya bulunamadı: {model_path}")
        return

    import xgboost as xgb
    print(f"XGBoost sürümü: {xgb.__version__}")
    print(f"Model dosyası:  {model_path}")
    print(f"Dosya boyutu:   {model_path.stat().st_size / 1024:.1f} KB")
    print()

    # Model yükle
    try:
        if model_path.suffix == '.pkl':
            import pickle
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            print("✅ Pickle model yüklendi")
        else:
            model = xgb.XGBClassifier()
            model.load_model(str(model_path))
            print("✅ XGBoost model yüklendi")
    except Exception as e:
        print(f"❌ Model yüklenemedi: {e}")
        return

    # Booster bilgileri
    booster = model.get_booster() if hasattr(model, 'get_booster') else model
    config = booster.save_config()
    print(f"Ağaç sayısı:    {booster.num_boosted_rounds()}")

    # Feature sayısı kontrolü
    try:
        n_features = booster.num_features()
        print(f"Feature sayısı: {n_features}")
        if n_features != 11:
            print(f"⚠️  UYARI: Beklenen 11 feature, bulunan {n_features}")
        else:
            print("✅ Feature sayısı doğru (11)")
    except Exception:
        print("ℹ️  Feature sayısı alınamadı (normal olabilir)")

    # Dummy inference
    print("\nDummy inference testi...")
    dummy = np.zeros((1, 11), dtype=np.float32)
    try:
        if hasattr(model, 'predict_proba'):
            proba = model.predict_proba(dummy)
            score = proba[0][1]  # Class 1 probability
        else:
            import xgboost as xgb
            dmat = xgb.DMatrix(dummy)
            score = booster.predict(dmat)[0]
        print(f"✅ Dummy score: {score:.6f}")
        print(f"   (Sıfır feature → {'Normal' if score < 0.5 else 'Atak'} sınıflandırması)")
    except Exception as e:
        print(f"❌ Inference hatası: {e}")
        return

    # Scaler uyumluluğu testi
    print("\nPreprocessed dummy inference (LSTM ile aynı scaler)...")
    # log1p + RobustScaler sonrası sıfır vektörü nasıl görünür:
    # log1p(0) = 0, (0 - median) / iqr → negatif değerler
    medians = [0.0157, 2.5649, 2.5649, 7.2937, 7.5071,
               73.0, 89.0, 255.0, 255.0, 0.3841, 0.3472]
    iqrs    = [0.1935, 2.7081, 2.6626, 2.7623, 4.4214,
               72.0, 496.0, 255.0, 255.0, 2.1158, 1.9696]
    scaled = np.array([(-m / q) if q != 0 else 0 for m, q in zip(medians, iqrs)],
                      dtype=np.float32).reshape(1, -1)
    try:
        if hasattr(model, 'predict_proba'):
            proba = model.predict_proba(scaled)
            score = proba[0][1]
        else:
            dmat = xgb.DMatrix(scaled)
            score = booster.predict(dmat)[0]
        print(f"✅ Scaled dummy score: {score:.6f}")
    except Exception as e:
        print(f"❌ Scaled inference hatası: {e}")

    # JSON export
    if args.export_json:
        json_path = model_path.with_suffix('.json')
        print(f"\nJSON export: {json_path}")
        try:
            if hasattr(model, 'save_model'):
                model.save_model(str(json_path))
            else:
                booster.save_model(str(json_path))
            print(f"✅ Kaydedildi: {json_path} ({json_path.stat().st_size / 1024:.1f} KB)")
        except Exception as e:
            print(f"❌ Export hatası: {e}")

    print("\n✅ Doğrulama tamamlandı.")


if __name__ == "__main__":
    main()
