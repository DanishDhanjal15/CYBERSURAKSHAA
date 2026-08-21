"""
blueprints/deepfake.py
----------------------
Flask Blueprint for the Deepfake Detector.
Wraps the EfficientNet B4 + MTCNN prediction pipeline.
Model weights are loaded lazily on first request.
"""

import os
import threading
import uuid
from pathlib import Path
from flask import Blueprint, request, jsonify, render_template
from blueprints.auth import login_required

bp = Blueprint('deepfake', __name__, url_prefix='/deepfake')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEEPFAKE_DIR = os.path.join(BASE_DIR, 'deepfake detection', 'deepfake-detection')
UPLOAD_DIR = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED = {'.mp4', '.avi', '.mov', '.mkv', '.jpg', '.jpeg', '.png'}

# Upper bound on frames analysed per video. MTCNN + EfficientNet-B4 costs a few
# seconds per frame on CPU, and gunicorn kills the worker at 120s, so this has
# to stay well inside that budget.
MAX_VIDEO_FRAMES_SCANNED = 10

# ── Lazy-loaded model components ─────────────────────────────
_model = None
_mtcnn = None
_transform = None
_device = None

# Serialises first-use loading — two concurrent requests would otherwise both
# see _model as None and each load a copy of EfficientNet-B4 (~250 MB) plus
# MTCNN, while racing on the module globals.
_model_lock = threading.Lock()

# Grad-CAM registers forward/backward hooks on a layer of the shared model and
# runs a backward pass through it. Two requests doing that concurrently would
# interleave hook state on the same module and produce a heatmap built from
# another request's gradients. Explanation is cheap relative to inference, so
# serialising it costs little and removes the whole class of problem.
_explain_lock = threading.Lock()


def _load_model():
    """Load EfficientNet B4 and MTCNN on first use."""
    global _model, _mtcnn, _transform, _device
    if _model is not None:
        return
    with _model_lock:
        if _model is not None:
            return
        _load_model_locked()


def _load_model_locked():
    global _model, _mtcnn, _transform, _device

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


def _predict_frame(img, want_artifacts=False):
    """
    Predict deepfake probability for a single PIL Image.

    With `want_artifacts`, also returns the cropped face and the exact input
    tensor that produced the score. Grad-CAM has to re-run the forward pass
    with gradients enabled on the *same* input, so handing back the crop and
    the tensor is what makes the explanation correspond to the number shown
    rather than to a second, slightly different crop.

    Returns None (or a (None, None, None) triple) when no face is found.
    """
    import torch
    import torch.nn.functional as F
    from PIL import Image

    _load_model()

    face = _mtcnn(img)
    if face is None:
        return (None, None, None) if want_artifacts else None

    # .cpu() before .numpy(): MTCNN was constructed with device=_device, so on
    # a CUDA host the cropped face comes back as a CUDA tensor and .numpy()
    # raises "can't convert cuda:0 device type tensor to numpy". CPU-only
    # deployments never hit it, which is why it stayed hidden.
    face_img = Image.fromarray(face.permute(1, 2, 0).byte().cpu().numpy())
    x = _transform(face_img).unsqueeze(0).to(_device)

    with torch.no_grad():
        prob = F.softmax(_model(x), dim=1)[0]

    score = prob[1].item()
    return (score, face_img, x) if want_artifacts else score


def _run_prediction(path):
    """
    Run prediction on an image or video file.

    Returns (verdict, score, frames_scanned, artefacts) where `artefacts` is
    (face_image, input_tensor) for the frame that scored highest -- the frame
    the verdict most rests on, and therefore the one worth explaining. It is
    None when nothing was scored.
    """
    import cv2
    from PIL import Image

    suffix = path.suffix.lower()

    if suffix in {'.jpg', '.jpeg', '.png'}:
        score, face_img, tensor = _predict_frame(
            Image.open(path).convert("RGB"), want_artifacts=True)
        if score is None:
            return None, None, 0, None
        return ("FAKE" if score > 0.5 else "REAL"), score, 1, (face_img, tensor)

    else:
        # Video — sample frames
        cap = cv2.VideoCapture(str(path))
        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

        # Several codecs report 0 or -1 here. `or 1` only caught the 0 case, so
        # a -1 produced range(0, -1, 1) — an empty loop that collected no
        # scores and surfaced to the user as the misleading "No face detected".
        # Fall back to reading sequentially when the metadata is unusable.
        sequential = total <= 0
        if sequential:
            total, interval = MAX_VIDEO_FRAMES_SCANNED * 10, 10
        else:
            interval = max(1, total // MAX_VIDEO_FRAMES_SCANNED)

        scores = []
        best = None          # (score, face_image, tensor) for the peak frame
        frame_index = 0
        scanned = 0

        while scanned < MAX_VIDEO_FRAMES_SCANNED:
            if sequential:
                # Sequential decode + skip. Per-frame seeking is unreliable and
                # slow on many codecs, and pointless without a frame count.
                ret, frame = cap.read()
                if not ret:
                    break
                if frame_index % interval != 0:
                    frame_index += 1
                    continue
            else:
                if frame_index >= total:
                    break
                cap.set(cv2.CAP_PROP_POS_FRAMES, frame_index)
                ret, frame = cap.read()
                if not ret:
                    break

            img = Image.fromarray(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))
            s, face_img, tensor = _predict_frame(img, want_artifacts=True)
            if s is not None:
                scores.append(s)
                if best is None or s > best[0]:
                    best = (s, face_img, tensor)

            scanned += 1
            frame_index += 1 if sequential else interval

        cap.release()

        if not scores:
            return None, None, 0, None

        avg = sum(scores) / len(scores)
        artefacts = (best[1], best[2]) if best else None
        return ("FAKE" if avg > 0.5 else "REAL"), avg, len(scores), artefacts


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
        verdict, score, frames, artefacts = _run_prediction(tmp)

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

        # ── Explanation ───────────────────────────────────────────────
        # A bare percentage from a classifier with no published validation
        # asks the analyst to trust it on nothing. Grad-CAM at least shows
        # which region of the face moved the score, so a heatmap sitting on
        # the background or on a watermark is visibly not a face-swap finding.
        from services.intel import explain, calibration, evidence, graph
        from services.intel.indicators import KIND_FILE_HASH
        from blueprints.auth import current_username

        # Deepfake was the only detector that never reached the entity graph,
        # so a synthetic-media finding contributed nothing to campaigns,
        # repeat-offender tracking or Watchtower — the correlation layer the
        # whole platform is built around simply had a hole where this module
        # should have been.
        #
        # There is no text to extract indicators from, so the artefact's own
        # file hash is the identifier: it is what links the same manipulated
        # video reappearing across cases, and it is exactly what a platform
        # takedown request cites.
        graph_summary = {'entities': 0, 'indicators': []}
        try:
            conn = graph.get_db_connection()
            try:
                eid = graph.upsert_entity(
                    conn, KIND_FILE_HASH, file_hash,
                    risk=int(round(score * 100)), confidence=0.9,
                    meta={'module': 'Deepfake Face', 'frames_scanned': frames},
                )
                graph.record_sighting(
                    conn, eid, module='Deepfake Face', verdict=verdict,
                    score=int(round(score * 100)),
                    context='Synthetic-media assessment of %s' % (f.filename or 'upload'),
                    source='deepfake',
                )
                conn.commit()
                graph_summary = {'entities': 1,
                                 'indicators': [{'kind': KIND_FILE_HASH,
                                                 'normalized': file_hash}]}
            finally:
                conn.close()
        except Exception as e:
            # Never fail a completed detection because the graph write did not
            # land — the verdict is the product, the correlation is the bonus.
            print("[DEEPFAKE] graph ingestion failed: %s" % e)

        heatmap = None
        if artefacts and artefacts[0] is not None:
            face_img, tensor = artefacts
            with _explain_lock:
                heatmap = explain.gradcam_overlay(_model, tensor, face_img)

        assessment = calibration.assess(score * 100, module='deepfake')

        evidence.append_event(
            evidence.EV_SCAN, actor=current_username(),
            subject_type='scan', subject_id=file_hash[:16],
            artefact_hash=file_hash,
            payload={
                'module': 'Deepfake Face',
                'verdict': verdict,
                'score': round(score * 100, 1),
                'frames_scanned': frames,
            },
        )

        return jsonify({
            'verdict': verdict,
            'score': round(score * 100, 1),
            'frames': frames,
            'file_hash': file_hash,
            'heatmap': heatmap,
            'assessment': assessment,
            'graph': graph_summary,
            'indicators_extracted': graph_summary.get('indicators', []),
            'explanation_note': explain.explanation_disclaimer(
                'deepfake', calibrated=assessment.get('calibrated', False)),
            'recommendation': recommendation
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
