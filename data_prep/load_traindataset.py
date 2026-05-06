import pandas as pd

# Eğitim seti dosya yolu
train_path = "./UNSW_NB15_training-set.csv"

# CSV'yi oku
df_train = pd.read_csv(train_path)

# İlk 5 satırı kontrol et
print(df_train.head())

# Veri boyutunu kontrol et
print(f"Shape of dataset: {df_train.shape}")

# Sütun isimlerini listele
print(df_train.columns.tolist())