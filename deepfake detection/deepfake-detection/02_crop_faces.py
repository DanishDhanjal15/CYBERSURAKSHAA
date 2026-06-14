"""
Step 2 — Detect and crop faces from extracted frames using MTCNN.
Input : D:/archive/frames/{real,fake}/*.jpg
Output: D:/archive/faces/{real,fake}/*.jpg
Frames with no detected face are skipped.
"""

import torch
from facenet_pytorch import MTCNN
from PIL import Image
from pathlib import Path
from tqdm import tqdm

FRAME_DIR = Path(r"D:\archive\frames")
FACE_DIR  = Path(r"D:\archive\faces")
FACE_SIZE = 224       # pixels — matches EfficientNet input
MARGIN    = 20        # extra pixels around face box

device = "cuda" if torch.cuda.is_available() else "cpu"
print(f"Using device: {device}")

mtcnn = MTCNN(
    image_size=FACE_SIZE,
    margin=MARGIN,
    min_face_size=40,
    keep_all=False,     # largest face only
    device=device,
    post_process=False, # return uint8 PIL image
)

for label_dir in ["real", "fake"]:
    src = FRAME_DIR / label_dir
    dst = FACE_DIR  / label_dir
    dst.mkdir(parents=True, exist_ok=True)

    frames = sorted(src.glob("*.jpg"))
    skipped = 0

    for fp in tqdm(frames, desc=f"Cropping {label_dir}"):
        out_path = dst / fp.name
        if out_path.exists():
            continue
        try:
            img = Image.open(fp).convert("RGB")
            face = mtcnn(img)           # returns Tensor or None
            if face is None:
                skipped += 1
                continue
            # face is CHW float [0,255] — convert to PIL and save
            face_img = Image.fromarray(face.permute(1, 2, 0).byte().numpy())
            face_img.save(str(out_path), quality=92)
        except Exception as e:
            skipped += 1

    found = len(list(dst.glob("*.jpg")))
    print(f"  {label_dir}: {found} faces saved, {skipped} frames skipped (no face)")

real = len(list((FACE_DIR / "real").glob("*.jpg")))
fake = len(list((FACE_DIR / "fake").glob("*.jpg")))
print(f"\nTotal faces -> real: {real}  fake: {fake}")
