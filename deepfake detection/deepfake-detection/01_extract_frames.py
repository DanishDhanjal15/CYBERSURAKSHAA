"""
Step 1 — Extract frames from videos listed in train.csv / val.csv.
Saves frames as JPEGs under D:/archive/frames/{real,fake}/
One frame per second (configurable via FPS_SAMPLE).
Skips videos already processed (safe to re-run).
"""

import cv2, csv, os
from pathlib import Path
from tqdm import tqdm

SPLIT_DIR  = Path(r"D:\archive\dataset_split")
FRAME_DIR  = Path(r"D:\archive\frames")
FPS_SAMPLE = 1          # extract 1 frame per second
MAX_FRAMES = 10         # cap per video to keep dataset manageable

LABEL_DIRS = {0: FRAME_DIR / "real", 1: FRAME_DIR / "fake"}
for d in LABEL_DIRS.values():
    d.mkdir(parents=True, exist_ok=True)

def extract(video_path: str, label: int, fps_sample: int, max_frames: int):
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        return 0

    src_fps = cap.get(cv2.CAP_PROP_FPS) or 25
    interval = max(1, int(src_fps / fps_sample))
    stem = Path(video_path).stem
    out_dir = LABEL_DIRS[label]

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
for split_file in [SPLIT_DIR / "train.csv", SPLIT_DIR / "val.csv"]:
    with open(split_file) as f:
        all_rows.extend(list(csv.DictReader(f)))

print(f"Videos to process: {len(all_rows)}")
total_frames = 0
for row in tqdm(all_rows, desc="Extracting frames"):
    n = extract(row["path"], int(row["label"]), FPS_SAMPLE, MAX_FRAMES)
    total_frames += n

real_count = len(list((FRAME_DIR / "real").glob("*.jpg")))
fake_count = len(list((FRAME_DIR / "fake").glob("*.jpg")))
print(f"\nDone. Frames saved -> real: {real_count}  fake: {fake_count}  total: {real_count+fake_count}")
