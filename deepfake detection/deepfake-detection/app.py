import os, uuid, torch, timm, cv2
import torch.nn.functional as F
from flask import Flask, request, jsonify, render_template
from facenet_pytorch import MTCNN
from torchvision import transforms
from PIL import Image
from pathlib import Path
from werkzeug.utils import secure_filename

CKPT = Path(os.environ.get("CHECKPOINT", r"D:\archive\checkpoints\best_model.pth"))
if not CKPT.exists():
    local_ckpt = Path("best_model.pth")
    if local_ckpt.exists():
        CKPT = local_ckpt

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
ALLOWED = {".mp4", ".avi", ".mov", ".mkv", ".jpg", ".jpeg", ".png"}

device = "cuda" if torch.cuda.is_available() else "cpu"
model = timm.create_model("efficientnet_b4", pretrained=False, num_classes=2)
model.load_state_dict(torch.load(CKPT, map_location=device))
model.eval().to(device)


mtcnn = MTCNN(image_size=224, margin=20, min_face_size=40, keep_all=False, device=device, post_process=False)

tf = transforms.Compose([
    transforms.ToTensor(),
    transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225]),
])

def predict_frame(img: Image.Image):
    face = mtcnn(img)
    if face is None:
        return None
    face_img = Image.fromarray(face.permute(1, 2, 0).byte().numpy())
    x = tf(face_img).unsqueeze(0).to(device)
    with torch.no_grad():
        prob = F.softmax(model(x), dim=1)[0]
    return prob[1].item()

def run_prediction(path: Path):
    suffix = path.suffix.lower()
    if suffix in {".jpg", ".jpeg", ".png"}:
        score = predict_frame(Image.open(path).convert("RGB"))
        if score is None:
            return None, None, 0
        return ("FAKE" if score > 0.5 else "REAL"), score, 1
    else:
        cap = cv2.VideoCapture(str(path))
        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or 1
        interval = max(1, total // 10)
        scores = []
        for i in range(0, total, interval):
            cap.set(cv2.CAP_PROP_POS_FRAMES, i)
            ret, frame = cap.read()
            if not ret:
                break
            img = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
            s = predict_frame(img)
            if s is not None:
                scores.append(s)
        cap.release()
        if not scores:
            return None, None, 0
        avg = sum(scores) / len(scores)
        return ("FAKE" if avg > 0.5 else "REAL"), avg, len(scores)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500 MB

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "Empty filename"}), 400
    suffix = Path(f.filename).suffix.lower()
    if suffix not in ALLOWED:
        return jsonify({"error": f"Unsupported file type: {suffix}"}), 400

    tmp = UPLOAD_DIR / f"{uuid.uuid4()}{suffix}"
    try:
        f.save(tmp)
        verdict, score, frames = run_prediction(tmp)
        if verdict is None:
            return jsonify({"error": "No face detected in file"}), 200
        return jsonify({
            "verdict": verdict,
            "score": round(score * 100, 1),
            "frames": frames,
        })
    finally:
        tmp.unlink(missing_ok=True)

if __name__ == "__main__":
    print(f"Model loaded from: {CKPT}")
    print(f"Device: {device}")
    app.run(debug=False, port=5001)
