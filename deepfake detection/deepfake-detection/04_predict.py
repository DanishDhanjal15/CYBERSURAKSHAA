"""
Step 4 (optional) — Run inference on a single video or image.
Usage:
    python 04_predict.py path/to/video.mp4 --checkpoint path/to/best_model.pth
    python 04_predict.py path/to/face.jpg  --checkpoint path/to/best_model.pth
"""

import sys, argparse, torch, timm, cv2
import torch.nn.functional as F
from facenet_pytorch import MTCNN
from torchvision import transforms
from PIL import Image
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("input", help="Video or image file to analyse")
parser.add_argument("--checkpoint", "-c", default=None, help="Path to best_model.pth (optional)")
args = parser.parse_args()

if args.checkpoint:
    CKPT = Path(args.checkpoint)
else:
    CKPT = Path(r"D:\archive\checkpoints\best_model.pth")
    if not CKPT.exists() and Path("best_model.pth").exists():
        CKPT = Path("best_model.pth")

LABELS = ["REAL", "FAKE"]

if not CKPT.exists():
    print(f"Error: checkpoint not found at {CKPT}")
    print("Please specify a valid checkpoint using --checkpoint or train a model first.")
    sys.exit(1)

device = "cuda" if torch.cuda.is_available() else "cpu"

model = timm.create_model("efficientnet_b4", pretrained=False, num_classes=2)
model.load_state_dict(torch.load(CKPT, map_location=device))
model.eval().to(device)


mtcnn = MTCNN(image_size=224, margin=20, min_face_size=40, keep_all=False, device=device, post_process=False)

tf = transforms.Compose([
    transforms.ToTensor(),
    transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225]),
])

def predict_image(img: Image.Image):
    face = mtcnn(img)
    if face is None:
        return None, None
    face_img = Image.fromarray(face.permute(1, 2, 0).byte().numpy())
    x = tf(face_img).unsqueeze(0).to(device)
    with torch.no_grad():
        prob = F.softmax(model(x), dim=1)[0]
    return LABELS[prob.argmax().item()], prob[1].item()

src = Path(args.input)
if not src.exists():
    print(f"Error: input file not found at {src}")
    sys.exit(1)

if src.suffix.lower() in {".jpg", ".jpeg", ".png"}:
    label, conf = predict_image(Image.open(src).convert("RGB"))
    print(f"{src.name}: {label}  (fake confidence: {conf:.2%})")

else:  # video — sample 10 frames and average
    cap = cv2.VideoCapture(str(src))
    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or 1
    interval = max(1, total // 10)
    scores = []
    for i in range(0, total, interval):
        cap.set(cv2.CAP_PROP_POS_FRAMES, i)
        ret, frame = cap.read()
        if not ret:
            break
        img = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
        label, conf = predict_image(img)
        if conf is not None:
            scores.append(conf)
    cap.release()
    if scores:
        avg = sum(scores) / len(scores)
        verdict = "FAKE" if avg > 0.5 else "REAL"
        print(f"{src.name}: {verdict}  (avg fake score: {avg:.2%}  over {len(scores)} frames)")
    else:
        print("No faces detected in video.")
