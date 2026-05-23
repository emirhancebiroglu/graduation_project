import pandas as pd, traceback
path = '/home/emirhan/bitirme/data/raw/ctu13_binetflow/ctu13_all_merged.binetflow.csv'
for i, chunk in enumerate(pd.read_csv(path, usecols=['StartTime','Proto','SrcAddr','Sport','DstAddr','Dport','Label'], dtype=str, chunksize=500000)):
    bot_mask = chunk['Label'].astype(str).str.contains('Botnet', na=False)
    bot = chunk[bot_mask]
    bg = chunk[~bot_mask]
    print(f'chunk {i}: total={len(chunk)} botnet={len(bot)} bg={len(bg)}')
    if len(bot) > 0:
        r = bot.iloc[0]
        try:
            ts = pd.to_datetime(r['StartTime']).timestamp()
            print(f'  sample OK: ts={ts}')
        except Exception as e:
            print(f'  parse error: {e}')
            break
    if i >= 4: break
print('DONE')
