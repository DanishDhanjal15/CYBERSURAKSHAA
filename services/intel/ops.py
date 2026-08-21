"""
services/intel/ops.py
---------------------
Operational support: health reporting, model warm-up, result caching and
impact metrics.

Three problems this addresses, all of which show up in a live demonstration
before they show up in production:

1. **Cold start.** Every model in the platform loads lazily behind a lock.
   PaddleOCR, EfficientNet-B4, MTCNN and XLM-RoBERTa together take tens of
   seconds on first use, so the first scan after a restart appears to hang.
   `warm_up()` loads them in a background thread at boot instead.

2. **No health signal.** The container HEALTHCHECK curls /auth/login, which
   returns 200 long before any model can serve a request. `health_report()`
   distinguishes "the web server is up" from "the detectors are ready".

3. **Repeated work.** Re-scanning the same artefact — which is exactly what a
   demonstration does — re-runs the full pipeline. A small hash-keyed cache
   makes a repeat scan instant and, more importantly, deterministic.
"""

from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict

from services.intel.db import get_db_connection

_START_TIME = time.time()

# -- Model readiness -------------------------------------------------------

_MODEL_STATE = {}
_state_lock = threading.Lock()


def set_model_state(name, status, detail=None):
    """Record a model's load state. Called by the lazy loaders."""
    with _state_lock:
        _MODEL_STATE[name] = {
            "status": status,           # unloaded | loading | ready | failed
            "detail": detail,
            "updated_at": time.time(),
        }


def get_model_states():
    with _state_lock:
        return dict(_MODEL_STATE)


# The registry of warm-up callables. Each entry is (name, loader). Loaders are
# imported lazily inside the function so that a module whose dependencies are
# missing degrades to "failed" instead of breaking application start-up.
def _warm_betting():
    from blueprints.betting import _get_ocr, _get_classifier, _get_detector, _get_fusion
    _get_ocr()
    _get_classifier()
    _get_detector()
    _get_fusion()


def _warm_deepfake():
    from blueprints.deepfake import _load_model
    _load_model()


def _warm_customer_care():
    from blueprints.customer_care import _get_detector, _get_scoring, _get_database
    det = _get_detector()
    _get_scoring()
    _get_database()
    # get_ocr() is what actually costs the time; touching the module is not
    # enough to pay the PaddleOCR initialisation cost up front.
    if hasattr(det, "get_ocr"):
        det.get_ocr()
    if hasattr(det, "get_nlp"):
        det.get_nlp()


def _warm_investment():
    from services.scam_detector import nlp_analyzer
    nlp_analyzer.ensure_engines_loaded()


WARM_UP_TARGETS = [
    ("customer_care", _warm_customer_care),
    ("betting", _warm_betting),
    ("investment", _warm_investment),
    ("deepfake", _warm_deepfake),
]


def warm_up(targets=None, background=True):
    """
    Pre-load detection models.

    Runs in a daemon thread by default so application start-up is not blocked;
    the health endpoint reports progress. Set WARM_UP_MODELS=0 to skip entirely,
    which is the right choice on a memory-constrained host where loading every
    model at once would be killed by the OOM reaper.
    """
    if os.environ.get("WARM_UP_MODELS", "1") != "1":
        print("[OPS] Model warm-up disabled via WARM_UP_MODELS=0.")
        for name, _ in (targets or WARM_UP_TARGETS):
            set_model_state(name, "unloaded", "warm-up disabled")
        return None

    selected = targets or WARM_UP_TARGETS
    for name, _ in selected:
        set_model_state(name, "queued")

    def _run():
        for name, loader in selected:
            set_model_state(name, "loading")
            started = time.time()
            try:
                loader()
                set_model_state(name, "ready", "loaded in %.1fs" % (time.time() - started))
                print("[OPS] Warm-up: %s ready in %.1fs" % (name, time.time() - started))
            except Exception as e:
                set_model_state(name, "failed", str(e))
                print("[OPS] Warm-up: %s FAILED — %s" % (name, e))

    if not background:
        _run()
        return None

    thread = threading.Thread(target=_run, name="model-warmup", daemon=True)
    thread.start()
    return thread


# -- Health ----------------------------------------------------------------

def health_report(deep=False):
    """
    Structured health information.

    `status` is:
        ok        database reachable and no model has failed
        degraded  database reachable but at least one model failed to load
        error     the database is unreachable

    A failed model is deliberately *not* fatal: the other four detectors still
    work, and returning 503 for the whole application because one optional
    dependency is missing would take a working system offline.
    """
    report = {
        "status": "ok",
        "uptime_seconds": round(time.time() - _START_TIME, 1),
        "database": {"reachable": False},
        "models": get_model_states(),
    }

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        report["database"]["reachable"] = True

        if deep:
            for table in ("users", "scans", "alerts", "entities",
                          "entity_edges", "campaigns", "cases", "evidence_chain"):
                try:
                    cur.execute("SELECT COUNT(*) FROM %s" % table)
                    report["database"][table] = cur.fetchone()[0]
                except Exception:
                    report["database"][table] = None
        conn.close()
    except Exception as e:
        report["status"] = "error"
        report["database"]["error"] = str(e)
        return report

    failed = [n for n, s in report["models"].items() if s.get("status") == "failed"]
    if failed:
        report["status"] = "degraded"
        report["degraded_models"] = failed

    return report


def readiness():
    """
    Whether the application can serve detection requests.

    Distinct from liveness: a process that is up but whose models are all still
    loading is alive and not ready. The container healthcheck should use the
    liveness form; a load balancer should use this.
    """
    states = get_model_states()
    if not states:
        return {"ready": True, "reason": "no warm-up configured"}
    pending = [n for n, s in states.items() if s.get("status") in ("queued", "loading")]
    return {
        "ready": not pending,
        "pending": pending,
        "ready_models": [n for n, s in states.items() if s.get("status") == "ready"],
        "failed_models": [n for n, s in states.items() if s.get("status") == "failed"],
    }


# -- Result cache ----------------------------------------------------------

class ResultCache:
    """
    Bounded LRU cache keyed by (module, artefact hash).

    Deliberately in-process and small. Detection results are a few kilobytes,
    the working set during a demonstration or an investigation session is tiny,
    and an external cache would add a dependency for no real gain. With more
    than one gunicorn worker each has its own copy, which is correct: the cache
    is an optimisation, never a source of truth.
    """

    def __init__(self, max_entries=128):
        self._data = OrderedDict()
        self._lock = threading.Lock()
        self.max_entries = max_entries
        self.hits = 0
        self.misses = 0

    def get(self, module, key):
        if not key:
            return None
        k = (module, key)
        with self._lock:
            if k in self._data:
                self._data.move_to_end(k)
                self.hits += 1
                return self._data[k]
            self.misses += 1
            return None

    def put(self, module, key, value):
        if not key:
            return
        k = (module, key)
        with self._lock:
            self._data[k] = value
            self._data.move_to_end(k)
            while len(self._data) > self.max_entries:
                self._data.popitem(last=False)

    def clear(self):
        with self._lock:
            self._data.clear()

    def stats(self):
        with self._lock:
            total = self.hits + self.misses
            return {
                "entries": len(self._data),
                "max_entries": self.max_entries,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": round(self.hits / total, 3) if total else None,
            }


result_cache = ResultCache(
    max_entries=int(os.environ.get("RESULT_CACHE_SIZE", "128"))
)


# -- Impact metrics --------------------------------------------------------

def impact_metrics():
    """
    What the platform has actually done, counted from the database.

    Every figure here is a real count. Nothing is seeded with a baseline and
    nothing is invented — a dashboard that pads its numbers cannot be used to
    argue that the system had an effect, which is the only thing these numbers
    are for.
    """
    metrics = {
        "scans_total": 0,
        "scans_flagged": 0,
        "entities_tracked": 0,
        "entities_repeat": 0,
        "campaigns_identified": 0,
        "largest_campaign": 0,
        "cases_open": 0,
        "cases_total": 0,
        "indicators_actionable": 0,
        "alerts_blocked": 0,
        "evidence_entries": 0,
        "phones_identified": 0,
        "upi_identified": 0,
        "domains_identified": 0,
    }

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        def scalar(sql, params=(), default=0):
            try:
                cur.execute(sql, params)
                row = cur.fetchone()
                return (row[0] if row and row[0] is not None else default)
            except Exception:
                return default

        metrics["scans_total"] = scalar("SELECT COUNT(*) FROM scans")
        metrics["scans_flagged"] = scalar("""
            SELECT COUNT(*) FROM scans WHERE
                LOWER(verdict) LIKE '%scam%' OR LOWER(verdict) LIKE '%betting%'
             OR LOWER(verdict) LIKE '%fake%'  OR LOWER(verdict) LIKE '%danger%'
             OR LOWER(verdict) LIKE '%high%'
        """)
        metrics["entities_tracked"] = scalar("SELECT COUNT(*) FROM entities")
        metrics["entities_repeat"] = scalar("SELECT COUNT(*) FROM entities WHERE sightings > 1")
        metrics["campaigns_identified"] = scalar("SELECT COUNT(*) FROM campaigns")
        metrics["largest_campaign"] = scalar("SELECT MAX(size) FROM campaigns")
        metrics["cases_total"] = scalar("SELECT COUNT(*) FROM cases")
        metrics["cases_open"] = scalar("SELECT COUNT(*) FROM cases WHERE status != 'CLOSED'")
        metrics["alerts_blocked"] = scalar("SELECT COUNT(*) FROM alerts WHERE status = 'BLOCKED'")
        metrics["evidence_entries"] = scalar("SELECT COUNT(*) FROM evidence_chain")

        metrics["phones_identified"] = scalar(
            "SELECT COUNT(*) FROM entities WHERE kind = ?", ("phone",))
        metrics["upi_identified"] = scalar(
            "SELECT COUNT(*) FROM entities WHERE kind = ?", ("upi",))
        metrics["domains_identified"] = scalar(
            "SELECT COUNT(*) FROM entities WHERE kind = ?", ("domain",))

        metrics["indicators_actionable"] = scalar("""
            SELECT COUNT(*) FROM entities
            WHERE kind IN ('phone','upi','bank_account','domain','url','telegram','whatsapp','crypto_wallet')
        """)

        conn.close()
    except Exception as e:
        metrics["error"] = str(e)

    metrics["provenance"] = (
        "Every figure is a live count from the database. No baseline values are "
        "added and no figures are simulated."
    )
    return metrics
