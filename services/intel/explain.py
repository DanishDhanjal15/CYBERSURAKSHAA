"""
services/intel/explain.py
-------------------------
Explainability for the detection modules.

The deepfake detector previously returned a bare float. A module with no
validated accuracy (see evaluation/RESULTS.md) that outputs an unexplained
number and calls it a percentage is asking an analyst to trust it on nothing.
This module makes each verdict show its working:

    gradcam_overlay()   which facial region drove the deepfake score
    token_attributions()which words drove a text verdict, with character spans
    ocr_overlay()       which OCR box each extracted indicator came from

Every function degrades to None rather than raising, so an explanation that
cannot be produced omits itself instead of failing the detection response it
was meant to annotate.
"""

from __future__ import annotations

import base64
import io
import re


# -- Grad-CAM --------------------------------------------------------------

def gradcam_overlay(model, input_tensor, pil_image, target_layer=None,
                    class_index=1, alpha=0.45):
    """
    Produce a Grad-CAM heatmap overlaid on `pil_image`.

    Grad-CAM weights each channel of the last convolutional feature map by the
    gradient of the target logit with respect to it, giving a coarse spatial
    map of what the network responded to. For EfficientNet-B4 the natural
    target is the final `conv_head`/`bn2` output.

    Returns a base64-encoded PNG string, or None when torch is missing, the
    layer cannot be located, or anything else goes wrong -- the caller treats
    a missing overlay as "no explanation available", never as an error.

    Note the honest limitation: Grad-CAM shows where the model looked, not
    whether it was right to. On an unvalidated classifier a confident heatmap
    over a jawline is evidence about the *model*, not about the video.
    """
    try:
        import torch
        import torch.nn.functional as F
        import numpy as np
        from PIL import Image
    except Exception as e:
        print("[EXPLAIN] Grad-CAM unavailable: %s" % e)
        return None

    try:
        layer = target_layer or _find_target_layer(model)
        if layer is None:
            return None

        activations = {}
        gradients = {}

        def fwd_hook(_m, _i, out):
            activations["value"] = out.detach()

        def bwd_hook(_m, _gi, grad_out):
            gradients["value"] = grad_out[0].detach()

        h1 = layer.register_forward_hook(fwd_hook)
        # register_full_backward_hook is the non-deprecated form; fall back for
        # older torch builds rather than losing the explanation entirely.
        try:
            h2 = layer.register_full_backward_hook(bwd_hook)
        except AttributeError:
            h2 = layer.register_backward_hook(bwd_hook)

        try:
            model.zero_grad()
            output = model(input_tensor)
            if output.ndim == 2 and output.shape[1] > class_index:
                score = output[0, class_index]
            else:
                score = output.max()
            score.backward()
        finally:
            h1.remove()
            h2.remove()

        act = activations.get("value")
        grad = gradients.get("value")
        if act is None or grad is None:
            return None

        # Channel weights = global-average-pooled gradients.
        weights = grad.mean(dim=(2, 3), keepdim=True)
        cam = (weights * act).sum(dim=1, keepdim=True)
        cam = F.relu(cam)
        cam = F.interpolate(cam, size=(pil_image.height, pil_image.width),
                            mode="bilinear", align_corners=False)
        cam = cam[0, 0].cpu().numpy()

        cam_min, cam_max = float(cam.min()), float(cam.max())
        if cam_max - cam_min < 1e-8:
            return None
        cam = (cam - cam_min) / (cam_max - cam_min)

        heat = _colourise(cam)
        base = pil_image.convert("RGB")
        blended = Image.blend(base, Image.fromarray(heat), alpha)

        buf = io.BytesIO()
        blended.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode("ascii")

    except Exception as e:
        print("[EXPLAIN] Grad-CAM failed: %s" % e)
        return None


def _find_target_layer(model):
    """
    Locate the last convolutional layer of a timm/torchvision CNN.

    Walks named modules and keeps the last Conv2d. Works for EfficientNet,
    ResNet and most timm backbones without hardcoding an architecture.
    """
    try:
        import torch.nn as nn
    except Exception:
        return None

    # timm EfficientNet exposes conv_head, which is the canonical choice.
    for attr in ("conv_head", "conv_stem"):
        layer = getattr(model, attr, None)
        if layer is not None and attr == "conv_head":
            return layer

    last_conv = None
    try:
        for _, module in model.named_modules():
            if isinstance(module, nn.Conv2d):
                last_conv = module
    except Exception:
        return None
    return last_conv


def _colourise(cam):
    """
    Map a 0..1 array to an RGB heatmap (blue -> green -> red).

    Implemented directly rather than pulling in matplotlib for one colourmap.
    """
    import numpy as np

    c = np.clip(cam, 0.0, 1.0)
    r = np.clip(1.5 - np.abs(4.0 * c - 3.0), 0, 1)
    g = np.clip(1.5 - np.abs(4.0 * c - 2.0), 0, 1)
    b = np.clip(1.5 - np.abs(4.0 * c - 1.0), 0, 1)
    return (np.stack([r, g, b], axis=-1) * 255).astype("uint8")


# -- Text attribution ------------------------------------------------------

def token_attributions(text, patterns, normaliser=None):
    """
    Locate the spans of `text` that matched a scoring pattern bank.

    `patterns` is an iterable of (regex, weight, label) -- the shape used by
    nlp_analyzer.SCAM_KEYWORDS and multilingual.HINGLISH_SCAM_KEYWORDS -- so
    the same call explains either bank.

    Returns a list of {"start", "end", "text", "label", "weight"}, sorted by
    position and with overlaps resolved in favour of the higher weight, ready
    for the front-end to wrap in <mark> elements.

    When `normaliser` is supplied, matches found only in the normalised form
    (deobfuscated or transliterated) are reported with start/end of None: the
    signal is real but its position in the original string is not recoverable
    once the text has been rewritten. Reporting it without a span is honest;
    guessing an offset would highlight the wrong words.
    """
    if not text:
        return []

    spans = []
    lowered = text.lower()

    for pattern, weight, label in patterns:
        try:
            for m in re.finditer(pattern, lowered):
                spans.append({
                    "start": m.start(), "end": m.end(),
                    "text": text[m.start():m.end()],
                    "label": label, "weight": weight, "located": True,
                })
        except re.error:
            continue

    if normaliser:
        try:
            normalised = normaliser(text)
        except Exception:
            normalised = None
        if normalised and normalised != lowered:
            seen_labels = {s["label"] for s in spans}
            for pattern, weight, label in patterns:
                if label in seen_labels:
                    continue
                try:
                    if re.search(pattern, normalised):
                        spans.append({
                            "start": None, "end": None, "text": None,
                            "label": label, "weight": weight, "located": False,
                        })
                        seen_labels.add(label)
                except re.error:
                    continue

    located = [s for s in spans if s["located"]]
    unlocated = [s for s in spans if not s["located"]]

    located.sort(key=lambda s: (s["start"], -s["weight"]))
    resolved = []
    for span in located:
        if resolved and span["start"] < resolved[-1]["end"]:
            # Overlapping matches: keep the heavier one.
            if span["weight"] > resolved[-1]["weight"]:
                resolved[-1] = span
            continue
        resolved.append(span)

    return resolved + unlocated


def highlight_html(text, spans, escape=True):
    """
    Render `text` with matched spans wrapped in <mark data-label=...>.

    Escaping happens here, after the offsets have been used, because escaping
    first would shift every offset by the length of the entities inserted.
    """
    from html import escape as _esc

    if not text:
        return ""
    located = sorted([s for s in spans if s.get("located")], key=lambda s: s["start"])

    out = []
    cursor = 0
    for span in located:
        if span["start"] < cursor:
            continue
        chunk = text[cursor:span["start"]]
        out.append(_esc(chunk) if escape else chunk)
        matched = text[span["start"]:span["end"]]
        out.append(
            '<mark class="attr-hit" data-weight="%d" title="%s">%s</mark>'
            % (span["weight"], _esc(span["label"]), _esc(matched) if escape else matched)
        )
        cursor = span["end"]
    tail = text[cursor:]
    out.append(_esc(tail) if escape else tail)
    return "".join(out)


def attribution_summary(spans):
    """Aggregate spans into per-label contributions, heaviest first."""
    agg = {}
    for s in spans:
        entry = agg.setdefault(s["label"], {
            "label": s["label"], "weight": s["weight"], "count": 0, "examples": [],
        })
        entry["count"] += 1
        if s.get("text") and len(entry["examples"]) < 3:
            entry["examples"].append(s["text"])
    return sorted(agg.values(), key=lambda e: -e["weight"])


# -- OCR overlay -----------------------------------------------------------

def ocr_overlay(image_bytes, boxes, indicators=None, box_colour=(56, 189, 248),
                hit_colour=(239, 68, 68), width=3):
    """
    Draw OCR bounding boxes on the source image, highlighting those whose text
    produced an extracted indicator.

    `boxes` is a list of {"box": [[x,y], ...] or [x0,y0,x1,y1], "text": str}.
    `indicators` is a list of normalised indicator values; a box whose text
    contains one is drawn in the hit colour so the analyst can see exactly
    which pixels the flagged phone number was read from.

    Returns a base64 PNG, or None if Pillow is unavailable.
    """
    try:
        from PIL import Image, ImageDraw
    except Exception as e:
        print("[EXPLAIN] OCR overlay unavailable: %s" % e)
        return None

    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        draw = ImageDraw.Draw(img)

        needles = [str(v).lower() for v in (indicators or []) if v]
        digit_needles = [re.sub(r"\D", "", n) for n in needles]

        for entry in boxes or []:
            box = entry.get("box")
            text = (entry.get("text") or "").lower()
            if not box:
                continue

            digits = re.sub(r"\D", "", text)
            is_hit = any(n and n in text for n in needles) or \
                     any(d and len(d) >= 6 and d in digits for d in digit_needles)
            colour = hit_colour if is_hit else box_colour

            points = _normalise_box(box)
            if not points:
                continue
            draw.line(points + [points[0]], fill=colour, width=width)

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode("ascii")
    except Exception as e:
        print("[EXPLAIN] OCR overlay failed: %s" % e)
        return None


def _normalise_box(box):
    """Accept either a polygon [[x,y]...] or a rect [x0,y0,x1,y1]."""
    try:
        if len(box) == 4 and all(isinstance(v, (int, float)) for v in box):
            x0, y0, x1, y1 = box
            return [(x0, y0), (x1, y0), (x1, y1), (x0, y1)]
        pts = [(float(p[0]), float(p[1])) for p in box]
        return pts if len(pts) >= 3 else None
    except Exception:
        return None


def explanation_disclaimer(module, calibrated=False):
    """
    The sentence that must accompany every explanation in the UI.

    An explanation makes a model look more trustworthy whether or not it is,
    which is precisely why it has to travel with a statement of what it does
    and does not establish.
    """
    base = (
        "This explanation shows which parts of the input the model responded "
        "to. It does not establish that the model's conclusion is correct."
    )
    if not calibrated:
        base += (
            " No calibration set exists for the %s module, so the confidence "
            "figure is a raw model score rather than a probability."
            % (module or "this")
        )
    return base
