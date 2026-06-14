"""
Builds balanced train/val split manifests from the DFD dataset.
Subsamples fake videos to match real count, then splits 80/20.
Output: train.csv, val.csv  (path, label)
"""

import os, random, csv
from pathlib import Path

random.seed(42)

ARCHIVE = Path(r"D:\archive")
REAL_DIR  = ARCHIVE / "DFD_original sequences"
FAKE_DIR  = ARCHIVE / "DFD_manipulated_sequences"
OUT_DIR   = ARCHIVE / "dataset_split"
VAL_FRAC  = 0.2

real_videos = sorted(REAL_DIR.rglob("*.mp4"))
fake_videos = sorted(FAKE_DIR.rglob("*.mp4"))

print(f"Real videos found : {len(real_videos)}")
print(f"Fake videos found : {len(fake_videos)}")

# subsample fake to match real count
n = len(real_videos)
fake_sampled = random.sample(fake_videos, min(n, len(fake_videos)))

print(f"Fake videos kept  : {len(fake_sampled)}  (subsampled to match real)")

all_samples = [(str(p), 0) for p in real_videos] + \
              [(str(p), 1) for p in fake_sampled]

random.shuffle(all_samples)

split = int(len(all_samples) * (1 - VAL_FRAC))
train, val = all_samples[:split], all_samples[split:]

print(f"Train samples     : {len(train)}  (real={sum(1 for _,l in train if l==0)}, fake={sum(1 for _,l in train if l==1)})")
print(f"Val   samples     : {len(val)}    (real={sum(1 for _,l in val   if l==0)}, fake={sum(1 for _,l in val   if l==1)})")

for name, rows in [("train.csv", train), ("val.csv", val)]:
    with open(OUT_DIR / name, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["path", "label"])
        w.writerows(rows)
    print(f"Written: {OUT_DIR / name}")
