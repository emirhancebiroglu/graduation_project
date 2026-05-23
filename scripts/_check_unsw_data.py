import numpy as np
X = np.load("/home/emirhan/bitirme/data/processed/X_test.npy")
feature_names = ["dur","spkts","dpkts","sbytes","dbytes","smeansz","dmeansz","swin","dwin","sintpkt","dintpkt"]
print("Shape:", X.shape)
print()
for i, name in enumerate(feature_names):
    vals = X[:, i]
    neg = (vals < 0).sum()
    zero = (vals == 0).sum()
    print(f"f{i:>2}({name:>8}): min={vals.min():>12.4f}  median={np.median(vals):>12.4f}  max={vals.max():>12.4f}  neg={neg:>6}  zero={zero:>6}")
