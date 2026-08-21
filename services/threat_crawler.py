"""
services/threat_crawler.py
--------------------------
Background threat-intelligence collection.

What changed and why
--------------------
This crawler used to choose at random between attempting a real scrape and
injecting one of eight hand-written fake alerts, and the dashboard rendered
both under a pulsing "LIVE INTEL SWEEP" banner. Nothing distinguished a real
observation from a fabricated one, in the UI or in the database. That is a
credibility problem before it is a technical one: a feed that cannot say which
of its entries are real cannot be used as intelligence.

The crawler now:

  1. Pulls from real public feeds (URLhaus, OpenPhish, PhishTank) via
     services/intel/feeds.py. Those records are tagged provenance=LIVE.
  2. Falls back to a clearly-labelled demonstration pool only when every live
     source is unreachable — and those records are tagged provenance=SIMULATED,
     which the UI renders as a visible amber "SIMULATED" chip.
  3. Feeds every collected indicator into the entity graph, so crawler
     observations and user scans share one intelligence picture.

Set CRAWLER_ALLOW_SIMULATED=0 to disable the fallback pool entirely; the feed
then simply stays empty when the live sources are unavailable, which is the
right setting for any deployment where the output might be quoted.
"""

import os
import random
import threading
import time

from services.auth_db import save_alert
from services.intel import feeds

# Interval between collection cycles. Live feeds update on the order of
# minutes, not seconds; the previous 30-second loop re-fetched the same data
# dozens of times per update and looked like abuse to the upstream sources.
CRAWL_INTERVAL_SECONDS = int(os.environ.get("CRAWLER_INTERVAL", "300"))

# Whether the simulated pool may be used when every live feed fails.
ALLOW_SIMULATED = os.environ.get("CRAWLER_ALLOW_SIMULATED", "1") == "1"

# Demonstration records. These are NOT observations. They exist so a machine
# with no outbound network access can still show the interface working, and
# every one of them is written to the database with provenance=SIMULATED and
# rendered with a "SIMULATED" chip. Do not remove the marker.
SIMULATED_POOL = [
    {
        "source": "[DEMONSTRATION DATA] Telegram channel pattern",
        "content": "Guaranteed 200% return in 24 hours, deposit via UPI. "
                   "Representative of observed investment-fraud copy.",
        "category": "Investment Scam",
        "risk_score": 92,
        "url": "http://example-invalid-demo-invest.invalid/offer",
    },
    {
        "source": "[DEMONSTRATION DATA] Betting creative pattern",
        "content": "IPL session prediction, free signup credit, APK download link. "
                   "Representative of observed illegal-betting promotion.",
        "category": "Betting Content",
        "risk_score": 89,
        "url": "http://example-invalid-demo-betting.invalid/ipl",
    },
    {
        "source": "[DEMONSTRATION DATA] Customer-care impersonation pattern",
        "content": "Account suspended, call the helpline number below to restore access. "
                   "Representative of observed vishing copy.",
        "category": "Customer Care",
        "risk_score": 94,
        "url": "http://example-invalid-demo-support.invalid/helpline",
    },
    {
        "source": "[DEMONSTRATION DATA] Synthetic-media tool pattern",
        "content": "Face-swap video generator, no verification required. "
                   "Representative of observed deepfake-tool promotion.",
        "category": "Deepfake Face",
        "risk_score": 86,
        "url": "http://example-invalid-demo-faceswap.invalid/app",
    },
]

crawler_thread = None
crawler_running = False

# Last cycle's outcome, surfaced through the API so the UI can report which
# sources are actually contributing.
last_status = {
    "last_run": None,
    "mode": None,
    "live_records": 0,
    "simulated_records": 0,
    "sources": {},
}


def _record_alert(record, provenance):
    """
    Persist one collected record and push its indicators into the graph.

    Provenance is prefixed onto the source string as well as being stored,
    because `alerts` has no provenance column and adding one would require a
    migration across an existing deployment. The prefix is what the front-end
    parses to render the chip.
    """
    source = "[%s] %s" % (provenance, record.get("source", "unknown"))
    alert_id = save_alert(
        source=source,
        content=record.get("content", ""),
        category=record.get("category", "Unknown"),
        risk_score=int(record.get("risk_score", 50)),
        url=record.get("url", ""),
    )

    # Only real observations enter the intelligence graph. Simulated records
    # must never create entities: a demonstration URL appearing as a node
    # would contaminate campaign clustering and could end up cited in a notice.
    if provenance == feeds.PROVENANCE_LIVE:
        try:
            from services.intel import graph
            graph.ingest(
                "%s %s" % (record.get("url", ""), record.get("content", "")),
                module=record.get("category", "Unknown"),
                verdict="ALERT",
                score=int(record.get("risk_score", 50)),
                alert_id=alert_id,
                source="crawler:%s" % record.get("feed", "live"),
            )
        except Exception as e:
            print("[CRAWLER] graph ingest failed: %s" % e)

    return alert_id


def run_crawler_loop(app):
    """Collect from live feeds on an interval."""
    global crawler_running, last_status
    print("[CRAWLER] Threat-intelligence collector started "
          "(interval %ds, simulated fallback %s)."
          % (CRAWL_INTERVAL_SECONDS, "enabled" if ALLOW_SIMULATED else "disabled"))

    time.sleep(5)   # let the database and app finish starting

    while crawler_running:
        with app.app_context():
            try:
                records, status = feeds.fetch_all(limit_per_feed=15)

                live_count = 0
                for record in records[:25]:
                    try:
                        _record_alert(record, feeds.PROVENANCE_LIVE)
                        live_count += 1
                    except Exception as e:
                        print("[CRAWLER] failed to record live alert: %s" % e)

                sim_count = 0
                if live_count == 0 and ALLOW_SIMULATED:
                    # Every live source failed. Emit one clearly-marked
                    # demonstration record so the interface is not blank, and
                    # say plainly in the log that this is not real data.
                    record = random.choice(SIMULATED_POOL)
                    _record_alert(record, feeds.PROVENANCE_SIMULATED)
                    sim_count = 1
                    print("[CRAWLER] All live feeds unavailable — emitted 1 "
                          "SIMULATED demonstration record. This is not an "
                          "observation.")

                last_status = {
                    "last_run": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "mode": "live" if live_count else ("simulated" if sim_count else "idle"),
                    "live_records": live_count,
                    "simulated_records": sim_count,
                    "sources": status,
                    "feeds_available": feeds.feeds_available(),
                }

                if live_count:
                    print("[CRAWLER] Collected %d live threat record(s) from %s."
                          % (live_count,
                             ", ".join(k for k, v in status.items() if v.get("ok"))))

            except Exception as loop_err:
                print("[CRAWLER] cycle failed: %s" % loop_err)
                last_status["last_error"] = str(loop_err)

        # Sleep in short slices so stop_crawler() takes effect promptly instead
        # of after a full interval.
        slept = 0
        while crawler_running and slept < CRAWL_INTERVAL_SECONDS:
            time.sleep(min(5, CRAWL_INTERVAL_SECONDS - slept))
            slept += 5


def start_crawler(app):
    """Start the collector thread if it is not already running."""
    global crawler_thread, crawler_running
    if crawler_thread is None or not crawler_thread.is_alive():
        crawler_running = True
        crawler_thread = threading.Thread(target=run_crawler_loop, args=(app,), daemon=True)
        crawler_thread.start()
        print("[CRAWLER] Background collector scheduled.")
    else:
        print("[CRAWLER] Collector already active.")


def stop_crawler():
    global crawler_running
    crawler_running = False
    print("[CRAWLER] Stopping background collector...")


def get_status():
    """Current collector status, for the dashboard."""
    return dict(last_status)
