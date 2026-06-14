"""
blueprints/deepfake.py
----------------------
Flask Blueprint for the Deepfake Detector.
Wraps the EfficientNet B4 + MTCNN prediction pipeline.
Model weights are loaded lazily on first request.
"""

import os
import uuid
from pathlib import Path
from flask import Blueprint, request, jsonify, render_template
from blueprints.auth import login_required

bp = Blueprint('deepfake', __name__, url_prefix='/deepfake')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEEPFAKE_DIR = os.path.join(BASE_DIR, 'deepfake detection', 'deepfake-detection')
UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED = {'.mp4', '.avi', '.mov', '.mkv', '.jpg', '.jpeg', '.png'}

# ── Lazy-loaded model components ─────────────────────────────
_model = None
_mtcnn = None
_transform = None
_device = None


def _load_model():
    """Load EfficientNet B4 and MTCNN on first use."""
    global _model, _mtcnn, _transform, _device
    if _model is not None:
        return

    import torch
    import timm
    from facenet_pytorch import MTCNN
    from torchvision import transforms

    _device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"[DEEPFAKE] Loading model on device: {_device}")

    # Find checkpoint
    ckpt = Path(DEEPFAKE_DIR) / "best_model.pth"
    if not ckpt.exists():
        raise FileNotFoundError(f"Deepfake model checkpoint not found at {ckpt}")

    _model = timm.create_model("efficientnet_b4", pretrained=False, num_classes=2)
    _model.load_state_dict(torch.load(ckpt, map_location=_device))
    _model.eval().to(_device)

    _mtcnn = MTCNN(
        image_size=224, margin=20, min_face_size=40,
        keep_all=False, device=_device, post_process=False,
    )

    _transform = transforms.Compose([
        transforms.ToTensor(),
        transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225]),
    ])

    print("[DEEPFAKE] Model loaded successfully.")


def _predict_frame(img):
    """Predict deepfake probability for a single PIL Image."""
    import torch
    import torch.nn.functional as F
    from PIL import Image

    _load_model()

    face = _mtcnn(img)
    if face is None:
        return None

    face_img = Image.fromarray(face.permute(1, 2, 0).byte().numpy())
    x = _transform(face_img).unsqueeze(0).to(_device)

    with torch.no_grad():
        prob = F.softmax(_model(x), dim=1)[0]

    return prob[1].item()


def _run_prediction(path):
    """Run prediction on an image or video file."""
    import cv2
    from PIL import Image

    suffix = path.suffix.lower()

    if suffix in {'.jpg', '.jpeg', '.png'}:
        score = _predict_frame(Image.open(path).convert("RGB"))
        if score is None:
            return None, None, 0
        return ("FAKE" if score > 0.5 else "REAL"), score, 1

    else:
        # Video — sample frames
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
            s = _predict_frame(img)
            if s is not None:
                scores.append(s)

        cap.release()

        if not scores:
            return None, None, 0

        avg = sum(scores) / len(scores)
        return ("FAKE" if avg > 0.5 else "REAL"), avg, len(scores)


# ── Routes ───────────────────────────────────────────────────
@bp.route('/')
@login_required
def index():
    return render_template('deepfake/index.html', active_page='deepfake')


@bp.route('/predict', methods=['POST'])
@login_required
def predict():
    """Accept a file upload, run deepfake prediction, return JSON."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'Empty filename'}), 400

    suffix = Path(f.filename).suffix.lower()
    if suffix not in ALLOWED:
        return jsonify({'error': f'Unsupported file type: {suffix}'}), 400

    # Ensure upload directory exists
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    tmp = Path(UPLOAD_DIR) / f"{uuid.uuid4()}{suffix}"

    try:
        f.save(tmp)
        verdict, score, frames = _run_prediction(tmp)

        if verdict is None:
            return jsonify({'error': 'No face detected in file'}), 200

        import hashlib
        with open(tmp, 'rb') as tf:
            file_hash = hashlib.sha256(tf.read()).hexdigest()

        # Save media permanently for CTI reports
        from services.report_generator import save_scanned_media
        if suffix in ('.jpg', '.jpeg', '.png'):
            save_scanned_media(file_hash, file_path=tmp)
        else:
            try:
                import cv2
                cap = cv2.VideoCapture(str(tmp))
                ret, frame = cap.read()
                if ret:
                    frame_path = tmp.with_suffix('.frame.png')
                    cv2.imwrite(str(frame_path), frame)
                    save_scanned_media(file_hash, file_path=frame_path)
                    if frame_path.exists():
                        frame_path.unlink()
                cap.release()
            except Exception as e:
                print(f"[DEEPFAKE] Failed to save representative frame: {e}")

        if verdict == 'FAKE':
            recommendation = (
                "RECOMMENDATION: Critical Alert: Highly probable AI-generated synthetic manipulation (Deepfake) detected. "
                "Analysts should mark this media as manipulated. Under Section 66D of the IT Act, dissemination of impersonated "
                "digital content is a punishable offense. Do not share; flag for takedown."
            )
        else:
            recommendation = (
                "RECOMMENDATION: Media analyzed as authentic. No significant structural signs of GAN or diffusion-based "
                "face swapping detected. Standard verification protocols apply."
            )

        return jsonify({
            'verdict': verdict,
            'score': round(score * 100, 1),
            'frames': frames,
            'file_hash': file_hash,
            'recommendation': recommendation
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
