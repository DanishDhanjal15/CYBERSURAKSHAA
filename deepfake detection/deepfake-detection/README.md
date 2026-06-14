# Deepfake Detection — DFD Dataset

Binary deepfake detector trained on the [Google DeepFake Detection (DFD)](https://ai.googleblog.com/2019/09/contributing-data-to-deepfake-detection.html) dataset.  
Uses **EfficientNet-B4** fine-tuned on face crops, achieving **93.2% validation accuracy**.

## Pipeline

```
01_extract_frames.py   →   02_crop_faces.py   →   03_train.py   →   04_predict.py
```

| Step | Script | What it does |
|------|--------|--------------|
| 1 | `01_extract_frames.py` | Extracts 1 fps frames (max 10/video) from DFD videos |
| 2 | `02_crop_faces.py` | MTCNN face detection → 224×224 crops |
| 3 | `03_train.py` | Fine-tunes EfficientNet-B4 for real/fake classification |
| 4 | `04_predict.py` | Inference on any video or image |

## Dataset

Download the [DFD dataset](https://github.com/ondyari/FaceForensics) and set paths in each script:

```
D:/archive/
  DFD_original sequences/      ← real videos
  DFD_manipulated_sequences/   ← deepfake videos
```

Run `dataset_split/build_splits.py` first to generate balanced train/val CSVs  
(subsamples fake videos to match real count — 363 real vs 363 fake).

## Setup

```bash
pip install -r requirements.txt
```

CUDA GPU strongly recommended. Tested on Python 3.11 + PyTorch 2.11 + CUDA 12.6.

## Run

```bash
python dataset_split/build_splits.py   # build balanced splits (run once)
python 01_extract_frames.py
python 02_crop_faces.py
python 03_train.py
```

## Inference

```bash
# on a video
python 04_predict.py path/to/video.mp4

# on an image
python 04_predict.py path/to/face.jpg
```

## Results

| Epoch | Val Accuracy |
|-------|-------------|
| 1 | 83.1% |
| 5 | 91.6% |
| 9 | **93.2%** (best) |
| 10 | 93.1% |

Model checkpoint: `checkpoints/best_model.pth` (not included in repo — train locally).
