import pandas as pd
f = "/home/emirhan/bitirme/data/raw/cicids2017/Friday-WorkingHours-Morning.pcap_ISCX.csv"
df = pd.read_csv(f, low_memory=False, usecols=[" Destination IP", " Label", " Timestamp", " Source IP"])
bot = df[df[" Label"]=="Bot"]
print("Bot flows:", len(bot))
print("Unique dst IPs:", bot[" Destination IP"].nunique())
for ip in sorted(bot[" Destination IP"].unique()):
    count = (bot[" Destination IP"]==ip).sum()
    srcs = bot[bot[" Destination IP"]==ip][" Source IP"].nunique()
    print(f"  {ip}: {count} flows, {srcs} src IPs")
print("Unique src IPs:", bot[" Source IP"].nunique())
print("\nAll unique src IPs:", sorted(bot[" Source IP"].unique()))
