"""
Step 3 — Fine-tune EfficientNet-B4 for binary deepfake detection.
Input : D:/archive/faces/{real,fake}/*.jpg
Output: D:/archive/checkpoints/best_model.pth + training_log.csv

Classes: 0 = real, 1 = fake
"""

import torch, timm, csv, time
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader, random_split, WeightedRandomSampler
from torchvision import transforms
from PIL import Image
from pathlib import Path
from collections import Counter

# ── config ──────────────────────────────────────────────────────────────────
FACE_DIR   = Path(r"D:\archive\faces")
CKPT_DIR   = Path(r"D:\archive\checkpoints")
CKPT_DIR.mkdir(parents=True, exist_ok=True)

EPOCHS     = 10
BATCH      = 32
LR         = 3e-4
VAL_FRAC   = 0.2
NUM_WORKERS= 0   # must be 0 on Windows without if __name__=='__main__' guard
SEED       = 42

torch.manual_seed(SEED)
device = "cuda" if torch.cuda.is_available() else "cpu"
print(f"Device: {device}  ({torch.cuda.get_device_name(0) if device=='cuda' else 'CPU'})")

# ── dataset ──────────────────────────────────────────────────────────────────
class FaceDataset(Dataset):
    def __init__(self, samples, transform):
        self.samples = samples      # list of (path_str, label)
        self.transform = transform

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        path, label = self.samples[idx]
        img = Image.open(path).convert("RGB")
        return self.transform(img), label

train_tf = transforms.Compose([
    transforms.RandomHorizontalFlip(),
    transforms.ColorJitter(brightness=0.2, contrast=0.2),
    transforms.RandomRotation(10),
    transforms.ToTensor(),
    transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225]),
])
val_tf = transforms.Compose([
    transforms.ToTensor(),
    transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225]),
])

all_samples = []
for label, name in [(0, "real"), (1, "fake")]:
    for p in (FACE_DIR / name).glob("*.jpg"):
        all_samples.append((str(p), label))

print(f"Total face crops: {len(all_samples)}")

n_val   = int(len(all_samples) * VAL_FRAC)
n_train = len(all_samples) - n_val
train_samples, val_samples = random_split(all_samples, [n_train, n_val],
                                          generator=torch.Generator().manual_seed(SEED))
train_samples = list(train_samples)
val_samples   = list(val_samples)

# weighted sampler to handle any remaining class imbalance
label_counts = Counter(l for _, l in train_samples)
weights      = [1.0 / label_counts[l] for _, l in train_samples]
sampler      = WeightedRandomSampler(weights, num_samples=len(weights), replacement=True)

train_ds = FaceDataset(train_samples, train_tf)
val_ds   = FaceDataset(val_samples,   val_tf)

train_loader = DataLoader(train_ds, batch_size=BATCH, sampler=sampler,
                          num_workers=NUM_WORKERS, pin_memory=True)
val_loader   = DataLoader(val_ds,   batch_size=BATCH, shuffle=False,
                          num_workers=NUM_WORKERS, pin_memory=True)

print(f"Train: {len(train_ds)}  Val: {len(val_ds)}")

# ── model ────────────────────────────────────────────────────────────────────
model = timm.create_model("efficientnet_b4", pretrained=True, num_classes=2)
model = model.to(device)

criterion  = nn.CrossEntropyLoss()
optimizer  = torch.optim.AdamW(model.parameters(), lr=LR, weight_decay=1e-4)
scheduler  = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=EPOCHS)

# ── training loop ────────────────────────────────────────────────────────────
log_path  = CKPT_DIR / "training_log.csv"
best_val  = 0.0

with open(log_path, "w", newline="") as f:
    csv.writer(f).writerow(["epoch", "train_loss", "train_acc", "val_loss", "val_acc", "lr"])

def run_epoch(loader, train=True):
    model.train(train)
    total_loss, correct, n = 0.0, 0, 0
    ctx = torch.enable_grad() if train else torch.no_grad()
    with ctx:
        for imgs, labels in loader:
            imgs, labels = imgs.to(device), labels.to(device)
            if train:
                optimizer.zero_grad()
            out  = model(imgs)
            loss = criterion(out, labels)
            if train:
                loss.backward()
                optimizer.step()
            total_loss += loss.item() * len(labels)
            correct    += (out.argmax(1) == labels).sum().item()
            n          += len(labels)
    return total_loss / n, correct / n

print(f"\n{'Epoch':>5}  {'Train Loss':>10}  {'Train Acc':>9}  {'Val Loss':>8}  {'Val Acc':>7}  {'LR':>8}")
print("-" * 62)

for epoch in range(1, EPOCHS + 1):
    t0 = time.time()
    tr_loss, tr_acc = run_epoch(train_loader, train=True)
    vl_loss, vl_acc = run_epoch(val_loader,   train=False)
    scheduler.step()
    lr = scheduler.get_last_lr()[0]
    elapsed = time.time() - t0

    print(f"{epoch:>5}  {tr_loss:>10.4f}  {tr_acc:>9.4f}  {vl_loss:>8.4f}  {vl_acc:>7.4f}  {lr:>8.2e}  ({elapsed:.0f}s)")

    with open(log_path, "a", newline="") as f:
        csv.writer(f).writerow([epoch, tr_loss, tr_acc, vl_loss, vl_acc, lr])

    if vl_acc > best_val:
        best_val = vl_acc
        torch.save(model.state_dict(), CKPT_DIR / "best_model.pth")
        print(f"         ** saved best model (val_acc={best_val:.4f})")

print(f"\nTraining complete. Best val acc: {best_val:.4f}")
print(f"Model saved to: {CKPT_DIR / 'best_model.pth'}")
