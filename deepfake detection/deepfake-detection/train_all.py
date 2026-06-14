#!/usr/bin/env python
"""
Deepfake Detection Master Orchestrator (train_all.py)

This script allows you to run all parts of the Deepfake Detection training pipeline
together or selectively, including:
  Step 0: Build balanced splits from original videos.
  Step 1: Extract frames from split videos.
  Step 2: Crop faces using MTCNN.
  Step 3: Train multiple CNN/ViT architectures sequentially and compare their performance.

Usage:
    # Run the entire pipeline (Steps 0, 1, 2, 3) for efficientnet_b4 and resnet50:
    python train_all.py --steps all --models efficientnet_b4,resnet50

    # Run only training for a custom list of models:
    python train_all.py --steps 3 --models efficientnet_b4,resnet50,mobilenetv3_large_100 --epochs 5
"""

import os
import sys
import csv
import time
import random
import argparse
import zipfile
from pathlib import Path
from collections import Counter

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader, random_split, WeightedRandomSampler
from torchvision import transforms
from PIL import Image
from tqdm import tqdm

# Attempt imports for optional libraries or notify the user
try:
    import cv2
except ImportError:
    print("Warning: opencv-python is not installed. Step 1 (frame extraction) will fail.")
try:
    from facenet_pytorch import MTCNN
except ImportError:
    print("Warning: facenet-pytorch is not installed. Step 2 (face cropping) will fail.")
try:
    import timm
except ImportError:
    print("Warning: timm is not installed. Step 3 (training) will fail.")


# ─────────────────────────────────────────────────────────────────────────────
# Helper: Reconstruct best_model.pth if needed
# ─────────────────────────────────────────────────────────────────────────────
def check_and_reconstruct_checkpoint(project_root: Path):
    best_model_dir = project_root / "best_model"
    output_pth = project_root / "best_model.pth"
    if output_pth.exists():
        return
    if best_model_dir.exists() and best_model_dir.is_dir():
        print("-> Found unzipped 'best_model' folder. Re-compiling into 'best_model.pth'...")
        try:
            with zipfile.ZipFile(output_pth, 'w', zipfile.ZIP_DEFLATED) as z:
                for file_path in best_model_dir.rglob('*'):
                    if file_path.is_file():
                        rel_path = file_path.relative_to(best_model_dir)
                        z.write(file_path, arcname=Path("archive") / rel_path)
            print(f"-> Successfully compiled 'best_model.pth' at {output_pth}")
        except Exception as e:
            print(f"Warning: Failed to compile 'best_model.pth': {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Step 0: Build Dataset Splits
# ─────────────────────────────────────────────────────────────────────────────
def run_build_splits(archive_dir: Path, val_frac: float, seed: int):
    print("\n" + "="*80)
    print(" [Step 0] Building balanced train/val split manifests")
    print("="*80)
    
    random.seed(seed)
    
    real_dir = archive_dir / "DFD_original sequences"
    fake_dir = archive_dir / "DFD_manipulated_sequences"
    out_dir  = archive_dir / "dataset_split"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    real_videos = sorted(real_dir.rglob("*.mp4"))
    fake_videos = sorted(fake_dir.rglob("*.mp4"))
    
    print(f"Real videos found : {len(real_videos)}")
    print(f"Fake videos found : {len(fake_videos)}")
    
    if not real_videos and not fake_videos:
        print(f"Error: No videos found in {real_dir} or {fake_dir}.")
        print("Please check your --archive-dir parameter or folder setup.")
        sys.exit(1)
        
    n = len(real_videos)
    fake_sampled = random.sample(fake_videos, min(n, len(fake_videos)))
    print(f"Fake videos kept  : {len(fake_sampled)} (subsampled to match real count)")
    
    all_samples = [(str(p), 0) for p in real_videos] + [(str(p), 1) for p in fake_sampled]
    random.shuffle(all_samples)
    
    split = int(len(all_samples) * (1 - val_frac))
    train, val = all_samples[:split], all_samples[split:]
    
    print(f"Train samples     : {len(train)} (real={sum(1 for _, l in train if l==0)}, fake={sum(1 for _, l in train if l==1)})")
    print(f"Val samples       : {len(val)} (real={sum(1 for _, l in val if l==0)}, fake={sum(1 for _, l in val if l==1)})")
    
    for name, rows in [("train.csv", train), ("val.csv", val)]:
        out_file = out_dir / name
        with open(out_file, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["path", "label"])
            w.writerows(rows)
        print(f"Written: {out_file}")


# ─────────────────────────────────────────────────────────────────────────────
# Step 1: Extract Frames
# ─────────────────────────────────────────────────────────────────────────────
def run_extract_frames(archive_dir: Path, fps_sample: int, max_frames: int):
    print("\n" + "="*80)
    print(" [Step 1] Extracting frames from videos")
    print("="*80)
    
    split_dir = archive_dir / "dataset_split"
    frame_dir = archive_dir / "frames"
    
    label_dirs = {0: frame_dir / "real", 1: frame_dir / "fake"}
    for d in label_dirs.values():
        d.mkdir(parents=True, exist_ok=True)
        
    def extract_video(video_path: str, label: int):
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            return 0
        src_fps = cap.get(cv2.CAP_PROP_FPS) or 25
        interval = max(1, int(src_fps / fps_sample))
        stem = Path(video_path).stem
        out_dir = label_dirs[label]
        
        saved = 0
        frame_idx = 0
        while saved < max_frames:
            ret, frame = cap.read()
            if not ret:
                break
            if frame_idx % interval == 0:
                out_path = out_dir / f"{stem}_f{frame_idx:05d}.jpg"
                if not out_path.exists():
                    cv2.imwrite(str(out_path), frame, [cv2.IMWRITE_JPEG_QUALITY, 90])
                saved += 1
            frame_idx += 1
        cap.release()
        return saved

    all_rows = []
    for split_file in [split_dir / "train.csv", split_dir / "val.csv"]:
        if not split_file.exists():
            print(f"Error: Split file {split_file} not found. Please run Step 0 first.")
            sys.exit(1)
        with open(split_file) as f:
            all_rows.extend(list(csv.DictReader(f)))
            
    print(f"Videos to process: {len(all_rows)}")
    total_frames = 0
    for row in tqdm(all_rows, desc="Extracting frames"):
        n = extract_video(row["path"], int(row["label"]))
        total_frames += n
        
    real_count = len(list((frame_dir / "real").glob("*.jpg")))
    fake_count = len(list((frame_dir / "fake").glob("*.jpg")))
    print(f"Done. Frames saved -> real: {real_count}  fake: {fake_count}  total: {real_count + fake_count}")


# ─────────────────────────────────────────────────────────────────────────────
# Step 2: Crop Faces
# ─────────────────────────────────────────────────────────────────────────────
def run_crop_faces(archive_dir: Path, face_size: int, margin: int, device: str):
    print("\n" + "="*80)
    print(" [Step 2] Detecting and cropping faces using MTCNN")
    print("="*80)
    
    frame_dir = archive_dir / "frames"
    face_dir  = archive_dir / "faces"
    
    mtcnn = MTCNN(
        image_size=face_size,
        margin=margin,
        min_face_size=40,
        keep_all=False,     # largest face only
        device=device,
        post_process=False, # return uint8 PIL image
    )
    
    for label_dir in ["real", "fake"]:
        src = frame_dir / label_dir
        dst = face_dir  / label_dir
        dst.mkdir(parents=True, exist_ok=True)
        
        if not src.exists():
            print(f"Warning: Frames directory {src} does not exist. Skipping.")
            continue
            
        frames = sorted(src.glob("*.jpg"))
        skipped = 0
        
        for fp in tqdm(frames, desc=f"Cropping {label_dir}"):
            out_path = dst / fp.name
            if out_path.exists():
                continue
            try:
                img = Image.open(fp).convert("RGB")
                face = mtcnn(img)
                if face is None:
                    skipped += 1
                    continue
                face_img = Image.fromarray(face.permute(1, 2, 0).byte().numpy())
                face_img.save(str(out_path), quality=92)
            except Exception:
                skipped += 1
                
        found = len(list(dst.glob("*.jpg")))
        print(f"  {label_dir}: {found} faces saved, {skipped} frames skipped (no face)")
        
    real = len(list((face_dir / "real").glob("*.jpg")))
    fake = len(list((face_dir / "fake").glob("*.jpg")))
    print(f"\nTotal faces -> real: {real}  fake: {fake}")


# ─────────────────────────────────────────────────────────────────────────────
# Step 3: Train Multiple Models
# ─────────────────────────────────────────────────────────────────────────────
class FaceDataset(Dataset):
    def __init__(self, samples, transform):
        self.samples = samples
        self.transform = transform

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        path, label = self.samples[idx]
        img = Image.open(path).convert("RGB")
        return self.transform(img), label


def run_train_models(archive_dir: Path, model_list: list, epochs: int, batch_size: int,
                     lr: float, val_frac: float, seed: int, device: str):
    print("\n" + "="*80)
    print(" [Step 3] Training Deepfake Detection models")
    print("="*80)
    
    face_dir = archive_dir / "faces"
    ckpt_dir = archive_dir / "checkpoints"
    ckpt_dir.mkdir(parents=True, exist_ok=True)
    
    torch.manual_seed(seed)
    
    # Check dataset
    all_samples = []
    for label, name in [(0, "real"), (1, "fake")]:
        d = face_dir / name
        if d.exists():
            for p in d.glob("*.jpg"):
                all_samples.append((str(p), label))
                
    print(f"Total face crops available: {len(all_samples)}")
    if not all_samples:
        print(f"Error: No face crops found in {face_dir}.")
        print("Please run Steps 1 and 2 first to prepare face crops.")
        sys.exit(1)
        
    # Splitting
    n_val   = int(len(all_samples) * val_frac)
    n_train = len(all_samples) - n_val
    train_samples, val_samples = random_split(
        all_samples, [n_train, n_val],
        generator=torch.Generator().manual_seed(seed)
    )
    train_samples = list(train_samples)
    val_samples   = list(val_samples)
    
    # Weighted sampler to handle any remaining class imbalance
    label_counts = Counter(l for _, l in train_samples)
    weights      = [1.0 / label_counts[l] for _, l in train_samples]
    sampler      = WeightedRandomSampler(weights, num_samples=len(weights), replacement=True)
    
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
    
    train_ds = FaceDataset(train_samples, train_tf)
    val_ds   = FaceDataset(val_samples, val_tf)
    
    train_loader = DataLoader(train_ds, batch_size=batch_size, sampler=sampler,
                              num_workers=0, pin_memory=True)
    val_loader   = DataLoader(val_ds,   batch_size=batch_size, shuffle=False,
                              num_workers=0, pin_memory=True)
    
    print(f"Train Dataset Size: {len(train_ds)}  |  Val Dataset Size: {len(val_ds)}")
    
    summary_results = []
    
    for model_name in model_list:
        print("\n" + "-"*50)
        print(f" Training Model Architecture: {model_name}")
        print("-"*50)
        
        try:
            model = timm.create_model(model_name, pretrained=True, num_classes=2)
        except Exception as e:
            print(f"Error creating model '{model_name}' from timm: {e}")
            print("Skipping to next model...")
            continue
            
        model = model.to(device)
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
        
        log_path  = ckpt_dir / f"training_log_{model_name}.csv"
        best_val  = 0.0
        best_epoch = 0
        best_loss = 0.0
        
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

        print(f"{'Epoch':>5}  {'Train Loss':>10}  {'Train Acc':>9}  {'Val Loss':>8}  {'Val Acc':>7}  {'LR':>8}  {'Time':>5}")
        print("-" * 68)
        
        start_time = time.time()
        for epoch in range(1, epochs + 1):
            t0 = time.time()
            tr_loss, tr_acc = run_epoch(train_loader, train=True)
            vl_loss, vl_acc = run_epoch(val_loader,   train=False)
            scheduler.step()
            current_lr = scheduler.get_last_lr()[0]
            elapsed = time.time() - t0
            
            print(f"{epoch:>5}  {tr_loss:>10.4f}  {tr_acc:>9.4f}  {vl_loss:>8.4f}  {vl_acc:>7.4f}  {current_lr:>8.2e}  {elapsed:>5.0f}s")
            
            with open(log_path, "a", newline="") as f:
                csv.writer(f).writerow([epoch, tr_loss, tr_acc, vl_loss, vl_acc, current_lr])
                
            if vl_acc > best_val:
                best_val = vl_acc
                best_epoch = epoch
                best_loss = tr_loss
                ckpt_path = ckpt_dir / f"best_model_{model_name}.pth"
                torch.save(model.state_dict(), ckpt_path)
                print(f"         ** saved best model checkpoint to {ckpt_path.name}")
                
        total_time = time.time() - start_time
        print(f"Training of {model_name} completed in {total_time/60:.2f} mins. Best Val Acc: {best_val:.4f} at epoch {best_epoch}.")
        
        summary_results.append({
            "model": model_name,
            "best_epoch": best_epoch,
            "best_val_acc": best_val,
            "train_loss": best_loss,
            "total_time_min": total_time / 60
        })
        
    # Print Comparison Table
    print("\n" + "="*80)
    print(" OVERALL MULTI-MODEL PERFORMANCE SUMMARY")
    print("="*80)
    print(f"{'Model Architecture':<30} | {'Best Epoch':<10} | {'Best Val Acc':<12} | {'Train Loss':<10} | {'Train Time':<12}")
    print("-"*80)
    for r in summary_results:
        print(f"{r['model']:<30} | {r['best_epoch']:<10} | {r['best_val_acc']:<12.2%} | {r['train_loss']:<10.4f} | {r['total_time_min']:<10.2f} min")
    print("="*80 + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main orchestrator
# ─────────────────────────────────────────────────────────────────────────────
def main():
    project_root = Path(__file__).resolve().parent
    
    # Auto-reconstruct best_model.pth if user uploaded it as an unzipped folder
    check_and_reconstruct_checkpoint(project_root)
    
    parser = argparse.ArgumentParser(description="Deepfake Detection Pipeline and Multi-Model Trainer")
    parser.add_argument("--archive-dir", type=str, default=r"D:\archive",
                        help="Path to archive root containing datasets, frames, and checkpoints")
    parser.add_argument("--steps", type=str, default="3",
                        help="Comma-separated step numbers to run: 0 (splits), 1 (frames), 2 (crops), 3 (training), or 'all'")
    parser.add_argument("--models", type=str, default="efficientnet_b4,resnet50",
                        help="Comma-separated timm model names to train sequentially in Step 3")
    parser.add_argument("--epochs", type=int, default=10, help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size for training/validation")
    parser.add_argument("--lr", type=float, default=3e-4, help="Learning rate")
    parser.add_argument("--val-frac", type=float, default=0.2, help="Validation fraction for splits")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for splits and loaders")
    parser.add_argument("--reconstruct-only", action="store_true", help="Only reconstruct best_model.pth if best_model/ exists, then exit")
    
    args = parser.parse_args()
    
    if args.reconstruct_only:
        print("Reconstruct-only mode requested. Exiting.")
        sys.exit(0)
        
    archive_path = Path(args.archive_dir)
    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Device configured: {device} ({torch.cuda.get_device_name(0) if device=='cuda' else 'CPU'})")
    print(f"Archive Directory: {archive_path.resolve()}")
    
    # Steps resolution
    steps_to_run = []
    if args.steps.lower() == "all":
        steps_to_run = [0, 1, 2, 3]
    else:
        try:
            steps_to_run = [int(s.strip()) for s in args.steps.split(",")]
        except ValueError:
            print(f"Error parsing steps option: '{args.steps}'. Use numbers separated by commas, or 'all'.")
            sys.exit(1)
            
    models_to_train = [m.strip() for m in args.models.split(",") if m.strip()]
    
    # Execute stages
    if 0 in steps_to_run:
        run_build_splits(archive_path, args.val_frac, args.seed)
        
    if 1 in steps_to_run:
        run_extract_frames(archive_path, fps_sample=1, max_frames=10)
        
    if 2 in steps_to_run:
        run_crop_faces(archive_path, face_size=224, margin=20, device=device)
        
    if 3 in steps_to_run:
        run_train_models(
            archive_dir=archive_path,
            model_list=models_to_train,
            epochs=args.epochs,
            batch_size=args.batch_size,
            lr=args.lr,
            val_frac=args.val_frac,
            seed=args.seed,
            device=device
        )
        
    print("\nAll pipeline tasks completed successfully!")


if __name__ == "__main__":
    main()
