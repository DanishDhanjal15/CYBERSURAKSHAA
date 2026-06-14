"""
dashboard/app.py
----------------
Streamlit dashboard for the Betting Detector.

Features:
  - Upload an image and run full pipeline via the API
  - View OCR-extracted text
  - View detected betting logos and keywords
  - Confidence score gauge
  - Annotated image with bounding boxes
  - Historical results table with filter + export
  - Live stats: total analysed, BETTING %, SAFE %

Run with:
    streamlit run dashboard/app.py

Expects the FastAPI server to be running at API_BASE_URL (default http://localhost:8000).
"""

from __future__ import annotations

import io
import os
from datetime import datetime

from dotenv import load_dotenv
load_dotenv()

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st
from PIL import Image

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
DETECT_URL = f"{API_BASE_URL}/api/detect"
RESULTS_URL = f"{API_BASE_URL}/api/results"
EXPORT_JSON_URL = f"{API_BASE_URL}/api/export/json"
EXPORT_CSV_URL = f"{API_BASE_URL}/api/export/csv"
HEALTH_URL = f"{API_BASE_URL}/api/health"

CLASSIFICATION_COLOURS = {
    "BETTING": "#FF4444",
    "SUSPICIOUS": "#FFB347",
    "SAFE": "#44BB44",
}

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="Betting Detector",
    page_icon="🎰",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------
st.markdown(
    """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    .main { background: #0f1117; }

    .big-label {
        font-size: 2.4rem;
        font-weight: 700;
        background: linear-gradient(135deg, #FF4444, #FFB347, #FF4444);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-size: 200% auto;
        animation: shimmer 3s linear infinite;
    }

    @keyframes shimmer {
        to { background-position: 200% center; }
    }

    .classification-badge {
        display: inline-block;
        padding: 6px 20px;
        border-radius: 999px;
        font-weight: 700;
        font-size: 1.1rem;
        letter-spacing: 0.08em;
        text-transform: uppercase;
    }

    .metric-card {
        background: #1e2130;
        border-radius: 12px;
        padding: 16px 20px;
        border: 1px solid #2d3250;
    }

    .stProgress > div > div { border-radius: 999px; }

    .keyword-chip {
        display: inline-block;
        background: rgba(255,68,68,0.15);
        border: 1px solid #FF4444;
        color: #FF8888;
        padding: 3px 10px;
        border-radius: 999px;
        margin: 3px;
        font-size: 0.8rem;
    }
</style>
""",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("## 🎰 Betting Detector")
    st.markdown("---")

    # API health check
    try:
        health = requests.get(HEALTH_URL, timeout=3).json()
        st.success(f"✅ API Online")
        with st.expander("Components"):
            for k, v in health.get("components", {}).items():
                icon = "✅" if v == "available" else "⚠️"
                st.write(f"{icon} **{k}**: {v}")
    except Exception:
        st.error("❌ API Offline — start the FastAPI server first.")

    st.markdown("---")
    page = st.radio("Navigate", ["🔍 Analyse Image", "📊 Results History"])

# ---------------------------------------------------------------------------
# Page: Analyse Image
# ---------------------------------------------------------------------------
if "🔍" in page:
    st.markdown('<div class="big-label">Betting Content Detector</div>', unsafe_allow_html=True)
    st.markdown("Upload an Instagram post image to classify it as **Betting**, **Suspicious**, or **Safe**.")
    st.markdown("---")

    uploaded_file = st.file_uploader(
        "Drop an image here or click to upload",
        type=["jpg", "jpeg", "png", "webp"],
        help="Supports JPEG, PNG, and WebP formats.",
    )

    if uploaded_file:
        # Send to API
        with st.spinner("🔬 Analysing image…"):
            uploaded_file.seek(0)
            try:
                resp = requests.post(
                    DETECT_URL,
                    files={"image": (uploaded_file.name, uploaded_file.read(), uploaded_file.type)},
                    timeout=180,
                )
                resp.raise_for_status()
                result = resp.json()
            except requests.exceptions.ConnectionError:
                st.error("❌ Cannot connect to API. Make sure the FastAPI server is running.")
                st.stop()
            except Exception as e:
                st.error(f"❌ Analysis failed: {e}")
                st.stop()

        classification = result["classification"]
        confidence = result["confidence"]
        colour = CLASSIFICATION_COLOURS.get(classification, "#888")

        col_img, col_result = st.columns([1, 1], gap="large")

        with col_img:
            annotated_image_b64 = result.get("annotated_image")
            if annotated_image_b64:
                import base64
                st.markdown("### 📷 Annotated Image")
                try:
                    img_bytes = base64.b64decode(annotated_image_b64)
                    st.image(img_bytes, use_container_width=True, caption="YOLOv8 Bounding Boxes")
                except Exception as e:
                    pil_img = Image.open(uploaded_file)
                    st.image(pil_img, use_container_width=True, caption="Original Upload")
                # Add a download button for the annotated image
                st.download_button(
                    "⬇️ Download Annotated Image",
                    data=base64.b64decode(annotated_image_b64),
                    file_name="annotated_betting_detection.png",
                    mime="image/png",
                )
            else:
                st.markdown("### 📷 Uploaded Image")
                pil_img = Image.open(uploaded_file)
                st.image(pil_img, use_container_width=True, caption="Original Upload")

        with col_result:
            st.markdown("### 🎯 Detection Result")

            # Classification badge
            st.markdown(
                f'<div class="classification-badge" style="background:rgba(255,255,255,0.05);'
                f'border:2px solid {colour}; color:{colour}">{classification}</div>',
                unsafe_allow_html=True,
            )
            st.markdown("")

            # Confidence gauge
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=confidence * 100,
                number={"suffix": "%", "font": {"size": 32}},
                title={"text": "Confidence Score"},
                gauge={
                    "axis": {"range": [0, 100]},
                    "bar": {"color": colour},
                    "steps": [
                        {"range": [0, 40], "color": "#1a2a1a"},
                        {"range": [40, 70], "color": "#2a2a10"},
                        {"range": [70, 100], "color": "#2a1010"},
                    ],
                    "threshold": {
                        "line": {"color": colour, "width": 4},
                        "thickness": 0.75,
                        "value": confidence * 100,
                    },
                },
            ))
            fig_gauge.update_layout(
                height=250, margin=dict(l=20, r=20, t=40, b=10),
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#ffffff",
            )
            st.plotly_chart(fig_gauge, use_container_width=True)

        st.markdown("---")

        # Detailed breakdown
        col_text, col_vision = st.columns(2)

        with col_text:
            st.markdown("### 📝 OCR Analysis")
            st.metric("Text Probability", f"{result['text_probability']:.0%}")
            if result["matched_keywords"]:
                st.markdown("**Matched Keywords:**")
                chips = " ".join(
                    f'<span class="keyword-chip">{kw}</span>'
                    for kw in result["matched_keywords"]
                )
                st.markdown(chips, unsafe_allow_html=True)
            else:
                st.info("No betting keywords detected.")

            with st.expander("Full OCR Text"):
                st.text(result.get("ocr_text") or "(no text detected)")

        with col_vision:
            st.markdown("### 👁️ Vision Analysis")
            st.metric("Vision Probability", f"{result['vision_probability']:.0%}")
            logos = result.get("detected_logos", [])
            if logos:
                st.markdown("**Detected Objects:**")
                for logo in logos:
                    st.markdown(f"• `{logo}`")
            else:
                st.info("No betting logos/objects detected.")

        # Reasons
        if result.get("reasons"):
            st.markdown("### 💡 Explanation")
            for reason in result["reasons"]:
                st.markdown(f"• {reason}")

# ---------------------------------------------------------------------------
# Page: Results History
# ---------------------------------------------------------------------------
else:
    st.markdown("## 📊 Detection History")

    try:
        resp = requests.get(RESULTS_URL, params={"limit": 500}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        st.error(f"❌ Failed to load results: {e}")
        st.stop()

    stats = data.get("stats", {})
    results = data.get("results", [])

    # ── Stats row ──────────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Analysed", stats.get("total", 0))
    c2.metric("🔴 Betting", stats.get("BETTING", 0))
    c3.metric("🟡 Suspicious", stats.get("SUSPICIOUS", 0))
    c4.metric("🟢 Safe", stats.get("SAFE", 0))

    st.markdown("---")

    if not results:
        st.info("No results yet. Go to **Analyse Image** to get started.")
        st.stop()

    # ── Pie chart ──────────────────────────────────────────────────────
    col_pie, col_table = st.columns([1, 2])
    with col_pie:
        pie_df = pd.DataFrame([
            {"classification": "BETTING", "count": stats.get("BETTING", 0)},
            {"classification": "SUSPICIOUS", "count": stats.get("SUSPICIOUS", 0)},
            {"classification": "SAFE", "count": stats.get("SAFE", 0)},
        ])
        fig_pie = px.pie(
            pie_df, values="count", names="classification",
            color="classification",
            color_discrete_map=CLASSIFICATION_COLOURS,
            hole=0.5,
        )
        fig_pie.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="#ffffff",
            showlegend=True,
            margin=dict(l=0, r=0, t=20, b=0),
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    # ── Results table ──────────────────────────────────────────────────
    with col_table:
        df = pd.DataFrame(results)
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"]).dt.strftime("%Y-%m-%d %H:%M")

        filter_opt = st.selectbox("Filter by classification", ["All", "BETTING", "SUSPICIOUS", "SAFE"])
        if filter_opt != "All":
            df = df[df["classification"] == filter_opt]

        st.dataframe(
            df[["id", "image_name", "classification", "confidence", "timestamp"]].rename(
                columns={"image_name": "Image", "classification": "Result", "confidence": "Score"}
            ),
            use_container_width=True,
            hide_index=True,
        )

    st.markdown("---")

    # ── Export buttons ─────────────────────────────────────────────────
    col_j, col_c = st.columns(2)
    with col_j:
        try:
            json_resp = requests.get(EXPORT_JSON_URL, timeout=10)
            st.download_button(
                "⬇️ Download JSON",
                data=json_resp.content,
                file_name="betting_results.json",
                mime="application/json",
            )
        except Exception:
            st.warning("Could not fetch JSON export.")

    with col_c:
        try:
            csv_resp = requests.get(EXPORT_CSV_URL, timeout=10)
            st.download_button(
                "⬇️ Download CSV",
                data=csv_resp.content,
                file_name="betting_results.csv",
                mime="text/csv",
            )
        except Exception:
            st.warning("Could not fetch CSV export.")
