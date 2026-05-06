import numpy as np
import logging
import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout, Input
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
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
logging.getLogger("tensorflow").setLevel(logging.ERROR)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler(logs_dir / "train_lstm.log", mode='w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def build_and_train_model():
    logging.info("LSTM Eğitim süreci başlatılıyor...")

    # 2. İşlenmiş Verileri Yükleme
    try:
        X_train = np.load(processed_dir / "X_train.npy")
        y_train = np.load(processed_dir / "y_train.npy")
        X_test = np.load(processed_dir / "X_test.npy")
        y_test = np.load(processed_dir / "y_test.npy")
        logging.info(f"Veriler başarıyla yüklendi. X_train shape: {X_train.shape}")
    except FileNotFoundError as e:
        logging.error("Numpy dosyaları bulunamadı! Lütfen önce prepare_dataset.py betiğini çalıştırın.")
        return

    # 3. LSTM için Veriyi Yeniden Şekillendirme (Reshape)
    # LSTM giriş formatı: [samples, timesteps, features]
    # Bizim durumumuzda timesteps = 1, features = 11
    X_train = np.reshape(X_train, (X_train.shape[0], 1, X_train.shape[1]))
    X_test = np.reshape(X_test, (X_test.shape[0], 1, X_test.shape[1]))
    logging.info(f"LSTM için Reshape işlemi tamamlandı. Yeni X_train shape: {X_train.shape}")

    # 4. LSTM Model Mimarisi
    logging.info("Model mimarisi oluşturuluyor...")
    model = Sequential(
        [
            Input(shape=(X_train.shape[1], X_train.shape[2])),
            LSTM(64, return_sequences=True),
            Dropout(0.2),
            LSTM(32),
            Dropout(0.2),
            Dense(1, activation='sigmoid')
        ]
    )
    
    # Modeli Derleme (Compile)
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
    logging.info("Model derlendi. Özeti (Summary) aşağıdadır:")
    model.summary(print_fn=logging.info)

    # 5. Callbacks (Erken Durdurma ve En İyi Modeli Kaydetme)
    # Validation loss 3 epoch boyunca düşmezse eğitimi durdur.
    early_stop = EarlyStopping(monitor='val_loss', patience=3, restore_best_weights=True, verbose=1)
    
    # Sadece en iyi modeli (val_loss'u en düşük olanı) kaydet
    checkpoint = ModelCheckpoint(models_dir / "best_lstm_model.h5", monitor='val_loss', save_best_only=True, verbose=1)

    # 6. Eğitimi Başlatma
    logging.info("Model eğitimi başlatılıyor...")
    history = model.fit(
        X_train, y_train,
        epochs=15, # Deneme amaçlı 15 tuttum, EarlyStopping zaten gerekirse erken kesecek.
        batch_size=256, # Veri seti büyükse batch_size artırılabilir (örn: 512, 1024)
        validation_data=(X_test, y_test),
        callbacks=[early_stop, checkpoint]
    )

    logging.info("Eğitim süreci başarıyla tamamlandı. En iyi model 'best_lstm_model.h5' olarak kaydedildi.")

if __name__ == "__main__":
    build_and_train_model()