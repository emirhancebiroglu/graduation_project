import pandas as pd
f = '/home/emirhan/bitirme/data/raw/cicids2017/Friday-WorkingHours-Morning.pcap_ISCX.csv'
df = pd.read_csv(f, nrows=2)
for i, c in enumerate(df.columns):
    print(f'{i}: [{c}]')
