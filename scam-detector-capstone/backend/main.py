"""
main.py
-------
FastAPI entrypoint for the Scam & Ponzi Scheme Detector.

Run with:
    uvicorn main:app --reload --port 8000

POST /api/analyze
    Body : { "message": "<user text with optional URLs>" }
    Returns:
    {
        "traffic_light":   "red",
        "final_fraud_score":   <int 0-100>,
        "engine_breakdown": {
             "engine_a_xgboost": <int 0-100>,
             "engine_b_xlm_roberta": <int 0-100>
        },
        "reasons": ["...", "..."]
    }
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from services.nlp_analyzer import analyze_text
from services.link_checker import check_links
from services.fraud_scorer import compute_risk

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Scam & Ponzi Detector API",
    description=(
        "Analyses WhatsApp/Telegram messages for investment scam signals "
        "using NLP keyword matching, domain-age WHOIS checks, and a "
        "(mock) XGBoost classifier."
    ),
    version="1.0.0",
)

# Allow requests from the React dev server (Vite default port 5173 and fallbacks)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
        "http://localhost:5176",
        "http://127.0.0.1:5176",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------
class AnalyzeRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        description="Raw text (and/or URLs) from a WhatsApp or Telegram message.",
        examples=["Guaranteed 200% returns! Join our crypto Telegram group now."],
    )


class EngineBreakdown(BaseModel):
    engine_a_xgboost: int = Field(..., description="Engine A XGBoost risk score.")
    engine_b_xlm_roberta: int = Field(..., description="Engine B XLM-RoBERTa score.")

class EngineStatus(BaseModel):
    engine_a_online: bool = Field(..., description="Indicates if Engine A successfully loaded/ran.")
    engine_b_online: bool = Field(..., description="Indicates if Engine B successfully loaded/ran.")

class AnalyzeResponse(BaseModel):
    traffic_light: str = Field(..., description="Traffic-light colour: 'red', 'yellow', or 'green'.")
    final_fraud_score: int = Field(..., ge=0, le=100, description="Final risk score (0 = safe, 100 = definite scam).")
    engine_breakdown: EngineBreakdown
    engine_status: EngineStatus
    reasons: list[str] = Field(..., description="Human-readable list of detected risk signals.")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/", tags=["Health"])
def root():
    """Health check — confirms the API is running."""
    return {"status": "ok", "service": "Scam & Ponzi Detector API v1.0.0"}


@app.post(
    "/api/analyze",
    response_model=AnalyzeResponse,
    tags=["Analysis"],
    summary="Analyse a message for investment scam signals",
)
def analyze(payload: AnalyzeRequest) -> AnalyzeResponse:
    """
    Pipeline:
    1. NLP keyword analysis  → text_score (0–100), text_reasons
    2. URL / domain check    → link_risk  (0–60),  link_reasons
    3. Weighted combination  → final_score, colour
    """
    text = payload.message.strip()

    if not text:
        raise HTTPException(status_code=422, detail="Message cannot be empty.")

    # Step 1 — NLP analysis (Engines A and B)
    engine_a, engine_b, text_reasons, engine_status = analyze_text(text)

    # Step 2 — Link / domain check
    link_risk, link_reasons = check_links(text)

    # Step 3 — Combine into final risk 
    effective_nlp_score = max(engine_a, engine_b)
    final_score, colour = compute_risk(effective_nlp_score, link_risk)

    # Merge reasons; add a summary line if completely clean
    all_reasons = text_reasons + link_reasons
    if not all_reasons:
        all_reasons = ["✅ No scam signals detected in this message."]

    return AnalyzeResponse(
        traffic_light=colour, 
        final_fraud_score=final_score, 
        engine_breakdown=EngineBreakdown(
            engine_a_xgboost=engine_a,
            engine_b_xlm_roberta=engine_b
        ),
        engine_status=EngineStatus(**engine_status),
        reasons=all_reasons
    )
