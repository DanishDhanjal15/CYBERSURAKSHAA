#!/usr/bin/env python3
"""
manage.py
---------
Operator CLI for CYBERSURAKSHAA.

Everything here is an administrative action that either has no business in a
web UI or is safer outside one. Minting an API key is the clearest case: the
raw key exists exactly once, and a console that displays it puts it into a
screen recording, a screenshot, and a browser's rendering cache. A terminal
does not solve that, but it narrows it considerably and it keeps the secret
out of the application's own request logs.

Usage:
    python manage.py create-api-key --label "telegram bot" --channel telegram
    python manage.py list-api-keys
    python manage.py revoke-api-key <id>
    python manage.py verify-chain
    python manage.py chain-head
    python manage.py rebuild-campaigns
    python manage.py fit-calibrator <module>
    python manage.py submissions [--promoted]
    python manage.py promote-submission <id>
    python manage.py stats

    python manage.py ct-poll --brand sbi.co.in
    python manage.py ct-observations --min-score 60
    python manage.py takedown-sweep
    python manage.py takedown-report
    python manage.py resurrections
    python manage.py churn --anchor 42
"""

from __future__ import annotations

import argparse
import json
import sys


def _die(message, code=1):
    print(message, file=sys.stderr)
    sys.exit(code)


# ── API keys ─────────────────────────────────────────────────────────────

def cmd_create_api_key(args):
    from blueprints.public_api import init_api_db, create_key
    init_api_db()
    raw = create_key(args.label, args.channel)
    print("\nAPI key created for %r (channel: %s)\n" % (args.label, args.channel))
    print("    %s\n" % raw)
    print("This is the only time it will be shown. Only its SHA-256 hash is")
    print("stored, so it cannot be recovered — reissue if it is lost.\n")
    print("Configure the client with:")
    print("    export CYBERSURAKSHAA_API_KEY=%s" % raw)


def cmd_list_api_keys(args):
    from blueprints.public_api import init_api_db
    from services.intel.db import get_db_connection
    init_api_db()
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT id, label, channel, active, created_at, last_used, call_count
        FROM api_keys ORDER BY id
    """).fetchall()
    conn.close()

    if not rows:
        print("No API keys. Create one with: manage.py create-api-key --label ... --channel ...")
        return
    print("%-4s %-24s %-12s %-8s %-20s %s" %
          ("ID", "LABEL", "CHANNEL", "ACTIVE", "LAST USED", "CALLS"))
    for r in rows:
        print("%-4s %-24s %-12s %-8s %-20s %s" % (
            r["id"], (r["label"] or "")[:24], r["channel"],
            "yes" if r["active"] else "REVOKED",
            r["last_used"] or "never", r["call_count"]))


def cmd_revoke_api_key(args):
    from services.intel.db import get_db_connection
    conn = get_db_connection()
    cur = conn.execute("UPDATE api_keys SET active = 0 WHERE id = ?", (args.id,))
    conn.commit()
    conn.close()
    if cur.rowcount:
        print("Key %d revoked. Existing clients will start receiving 401." % args.id)
    else:
        _die("No key with id %d." % args.id)


# ── Evidence chain ───────────────────────────────────────────────────────

def cmd_verify_chain(args):
    from services.intel import evidence
    result = evidence.verify_chain()
    if result["valid"]:
        print("Chain intact. %d entries verified from the genesis hash."
              % result["checked"])
        print("Head: %s" % result.get("head"))
        return
    print("CHAIN BROKEN at sequence %s: %s"
          % (result["broken_at"], result["reason"]), file=sys.stderr)
    print("%d entries verified before the break. Everything recorded after it "
          "is unreliable." % result["checked"], file=sys.stderr)
    sys.exit(2)


def cmd_chain_head(args):
    from services.intel import evidence
    head = evidence.head()
    print(json.dumps(head, indent=2))
    print("\nPublish this hash somewhere outside this system's control — a "
          "public repository, a timestamping service, a printed log. Until a "
          "head is published externally, the chain proves internal consistency "
          "only: an operator with write access to the whole table could "
          "rewrite it end to end.")


# ── Intelligence ─────────────────────────────────────────────────────────

def cmd_rebuild_campaigns(args):
    from services.intel import campaigns
    result = campaigns.rebuild_campaigns()
    print("%d campaign(s) from %d of %d indicators. %d hub(s) suppressed."
          % (result["campaigns"], result["clustered_entities"],
             result["total_entities"], result["hubs_suppressed"]))


def cmd_fit_calibrator(args):
    from services.intel import calibration, feedback
    samples = feedback.calibration_samples(args.module)
    if len(samples) < calibration.MIN_CALIBRATION_SAMPLES:
        _die("Only %d confirmed feedback samples for %r; %d are required.\n"
             "Fitting on fewer would overfit them exactly, and the resulting "
             "'calibrated' badge would claim more than the raw score does."
             % (len(samples), args.module, calibration.MIN_CALIBRATION_SAMPLES))

    scores = [s for s, _ in samples]
    labels = [l for _, l in samples]
    model = calibration.fit_histogram(scores, labels)
    report = calibration.reliability_report(scores, labels, model)

    print("Samples: %d (%d positive, %d negative)"
          % (report["n"], report["positives"], report["negatives"]))
    print("ECE   before %.4f  ->  after %.4f" % (report["ece_before"], report["ece_after"]))
    print("Brier before %.4f  ->  after %.4f" % (report["brier_before"], report["brier_after"]))

    if not report["improved"]:
        _die("\nRefusing to save: calibration did not reduce expected "
             "calibration error. The raw score is closer to a probability "
             "than this model would be.", code=3)

    path = calibration.save_calibrator(args.module, model)
    print("\nSaved to %s. Assessments for %r will now report calibrated: true."
          % (path, args.module))


def cmd_stats(args):
    from services.intel import graph, campaigns, evidence, feedback
    print(json.dumps({
        "graph": graph.graph_stats(),
        "campaigns": len(campaigns.list_campaigns(limit=1000)),
        "evidence_head": evidence.head(),
        "feedback": feedback.summary(),
    }, indent=2, default=str))


# ── Public submissions (quarantine) ──────────────────────────────────────

def cmd_submissions(args):
    from blueprints.public_api import init_api_db
    from services.intel.db import get_db_connection
    init_api_db()
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT id, channel, verdict, score, promoted, created_at,
               substr(text, 1, 90) AS preview
        FROM public_submissions
        WHERE promoted = ?
        ORDER BY id DESC LIMIT 50
    """, (1 if args.promoted else 0,)).fetchall()
    conn.close()

    if not rows:
        print("No %s submissions." % ("promoted" if args.promoted else "pending"))
        return
    for r in rows:
        print("[%s] %s  %s (%s)\n     %s\n"
              % (r["id"], r["created_at"], r["verdict"], r["channel"],
                 (r["preview"] or "").replace("\n", " ")))


def cmd_promote_submission(args):
    """
    Move one quarantined citizen submission into the intelligence graph.

    This is a deliberate human step. Public submissions are attacker-
    controllable: anything auto-ingested would let one person forge arbitrary
    links between identifiers, and the campaign clustering would then report
    the fiction as a finding.
    """
    from services.intel import graph, evidence
    from services.intel.db import get_db_connection

    conn = get_db_connection()
    row = conn.execute(
        "SELECT * FROM public_submissions WHERE id = ?", (args.id,)).fetchone()
    if not row:
        conn.close()
        _die("No submission with id %d." % args.id)
    if row["promoted"]:
        conn.close()
        _die("Submission %d was already promoted." % args.id)
    text, channel, verdict, score = row["text"], row["channel"], row["verdict"], row["score"]
    conn.close()

    result = graph.ingest(text, module="Public Submission (%s)" % channel,
                          verdict=verdict, score=int(score or 0),
                          source="public:%s" % channel)

    conn = get_db_connection()
    conn.execute("UPDATE public_submissions SET promoted = 1 WHERE id = ?", (args.id,))
    conn.commit()
    conn.close()

    evidence.append_event(
        evidence.EV_ADMIN, actor="cli",
        subject_type="public_submission", subject_id=args.id,
        payload={"action": "PROMOTED", "entities": result["entities"]})

    print("Promoted submission %d: %d indicator(s) entered the graph."
          % (args.id, result["entities"]))


# ── Lifecycle monitors ───────────────────────────────────────────────────

def cmd_ct_poll(args):
    from services.intel import ctlog
    ctlog.init_ctlog_db()
    if args.brand:
        brands = [args.brand]
    else:
        ctlog.seed_watchlist()
        brands = [b["brand"] for b in ctlog.watchlist()]

    for brand in brands:
        print("\n%s" % brand)
        result = ctlog.poll_brand(brand)
        if result.get("error"):
            print("   discovery: UNAVAILABLE (%s)" % result["error"])
        else:
            print("   discovery: %d certificates examined, %d collisions, %d new"
                  % (result["certificates_examined"], result["matches"], result["new"]))
            for obs in sorted(result["observations"], key=lambda o: -o["score"])[:8]:
                print("      %3d  %-44s %s"
                      % (obs["score"], obs["domain"][:44],
                         (obs["reasons"][0][:44] if obs["reasons"] else "")))
        ns = ctlog.poll_namespace(brand)
        if ns.get("error"):
            print("   namespace: UNAVAILABLE (%s)" % ns["error"])
        else:
            print("   namespace: %d certificates, %d new hosts, %d unexpected CA"
                  % (ns["certificates"], ns["new_hosts"], len(ns["unexpected_ca"])))

    health = ctlog.source_health()
    if health["discovery_degraded"]:
        print("\n%s" % health["note"])


def cmd_ct_observations(args):
    from services.intel import ctlog
    rows = ctlog.recent_observations(limit=args.limit, min_score=args.min_score)
    if not rows:
        health = ctlog.source_health()
        print("No observations stored.")
        if health["discovery_degraded"]:
            print("\n%s" % health["note"])
        return
    print("%-5s %-46s %-16s %s" % ("SCORE", "DOMAIN", "BRAND", "RESOLVES"))
    for r in rows:
        print("%-5s %-46s %-16s %s"
              % (r["score"], r["domain"][:46], r["brand"][:16],
                 "yes" if r["resolves"] == 1 else "no" if r["resolves"] == 0 else "?"))


def cmd_takedown_sweep(args):
    from services.intel import takedown
    takedown.init_takedown_db()
    result = takedown.sweep(limit=args.limit)
    print("%d probed, %d still up, %d dark."
          % (result["probed"], result["alive"], result["dead"]))
    for t in result["newly_dead"]:
        print("   went dark: %s %s (%s)" % (t["kind"], t["value"], t["channel"]))
    for t in result["resurfaced"]:
        print("   CAME BACK: %s %s" % (t["kind"], t["value"]))


def cmd_takedown_report(args):
    from services.intel import takedown
    e = takedown.effectiveness()
    if not e["filed"]:
        print("No enforcement targets registered yet. Dispatch a scan's action "
              "pack, or register one with the API, to start the clock.")
        return

    print("Filed              %d" % e["filed"])
    print("Measurable         %d" % e["measurable"])
    print("Went dark          %d" % e["went_dark"])
    print("Still live         %d" % e["still_live"])
    print("No outcome         %d" % e["no_recorded_outcome"])
    if e["rate"] is not None:
        print("Rate               %.0f%% of measurable targets" % (e["rate"] * 100))
    if e["median_days_to_dark"] is not None:
        print("Median time        %.1f days (fastest %.1f, slowest %.1f)"
              % (e["median_days_to_dark"], e["fastest_days"], e["slowest_days"]))

    print("\n%-12s %6s %11s %6s %6s" % ("CHANNEL", "FILED", "MEASURABLE", "DARK", "RATE"))
    for c in e["by_channel"]:
        print("%-12s %6d %11d %6d %6s"
              % (c["channel"], c["filed"], c["measurable"], c["dead"],
                 "%.0f%%" % (c["rate"] * 100) if c["rate"] is not None else "n/a"))

    print("\n%s" % e["attribution_caveat"])
    if e["coverage_caveat"]:
        print("\n%s" % e["coverage_caveat"])


def cmd_resurrections(args):
    from services.intel import resurrection
    resurrection.init_resurrection_db()
    events = resurrection.detect(dormancy_days=args.dormancy)
    if not events:
        print("No resurrections detected.")
        dormant = resurrection.dormant_campaigns()
        if dormant:
            print("\n%d dormant campaign(s) being watched:" % len(dormant))
            for c in dormant[:10]:
                print("   %-40s quiet %.0f days" % (c["label"][:40], c["dormant_days"]))
        return

    for e in events:
        print("\n%s  %s" % (e["anchor_label"], e["anchor_value"]))
        print("   dormant %s -> %s (%.0f days)"
              % (e["dormant_from"][:10], e["dormant_until"][:10], e["gap_days"]))
        print("   new: %s" % ", ".join("%s=%s" % (n["kind"], n["value"])
                                       for n in e["new_infrastructure"][:6]))
        print("   confidence %.0f%%  (anchor seen in %d artefacts)"
              % (e["confidence"] * 100, e["anchor_degree"]))
    print("\n%s" % resurrection.stats()["caveat"])


def cmd_churn(args):
    from services.intel import resurrection
    profile = resurrection.churn_profile(campaign_id=args.campaign,
                                         anchor_id=args.anchor)
    if profile.get("error"):
        _die(profile["error"])
    print("%-30s %6s %18s" % ("INDICATOR", "COUNT", "MEDIAN LIFESPAN"))
    for p in profile["profile"]:
        print("%-30s %6d %15.1f d %s"
              % (p["label"][:30], p["count"], p["median_lifespan_days"],
                 "DURABLE" if p["durable"] else ""))
    print("\n%s" % profile["interpretation"])


# ── Entry point ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="manage.py",
        description="Operator CLI for CYBERSURAKSHAA.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create-api-key", help="Mint an API key for an integration")
    p.add_argument("--label", required=True, help="Human name, e.g. 'telegram bot'")
    p.add_argument("--channel", required=True,
                   choices=["telegram", "chrome", "whatsapp", "other"])
    p.set_defaults(func=cmd_create_api_key)

    p = sub.add_parser("list-api-keys", help="List issued keys (never the keys themselves)")
    p.set_defaults(func=cmd_list_api_keys)

    p = sub.add_parser("revoke-api-key", help="Deactivate one key")
    p.add_argument("id", type=int)
    p.set_defaults(func=cmd_revoke_api_key)

    p = sub.add_parser("verify-chain", help="Re-walk the evidence chain")
    p.set_defaults(func=cmd_verify_chain)

    p = sub.add_parser("chain-head", help="Print the current chain head for external publication")
    p.set_defaults(func=cmd_chain_head)

    p = sub.add_parser("rebuild-campaigns", help="Recompute campaign clusters")
    p.set_defaults(func=cmd_rebuild_campaigns)

    p = sub.add_parser("fit-calibrator", help="Fit a calibrator from confirmed analyst feedback")
    p.add_argument("module")
    p.set_defaults(func=cmd_fit_calibrator)

    p = sub.add_parser("submissions", help="List quarantined public submissions")
    p.add_argument("--promoted", action="store_true", help="Show promoted instead of pending")
    p.set_defaults(func=cmd_submissions)

    p = sub.add_parser("promote-submission", help="Move one submission into the graph")
    p.add_argument("id", type=int)
    p.set_defaults(func=cmd_promote_submission)

    p = sub.add_parser("stats", help="Platform counters")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("ct-poll", help="Poll Certificate Transparency for lookalike domains")
    p.add_argument("--brand", help="One brand; omit for the whole watchlist")
    p.set_defaults(func=cmd_ct_poll)

    p = sub.add_parser("ct-observations", help="Stored certificate observations")
    p.add_argument("--limit", type=int, default=40)
    p.add_argument("--min-score", type=int, default=0, dest="min_score")
    p.set_defaults(func=cmd_ct_observations)

    p = sub.add_parser("takedown-sweep", help="Re-probe reported targets")
    p.add_argument("--limit", type=int, default=120)
    p.set_defaults(func=cmd_takedown_sweep)

    p = sub.add_parser("takedown-report", help="Enforcement outcome metrics")
    p.set_defaults(func=cmd_takedown_report)

    p = sub.add_parser("resurrections", help="Detect operators rebuilding after takedown")
    p.add_argument("--dormancy", type=int, default=7,
                   help="Days of silence that count as dormant")
    p.set_defaults(func=cmd_resurrections)

    p = sub.add_parser("churn", help="What an operation replaces, and what it cannot")
    p.add_argument("--campaign", type=int)
    p.add_argument("--anchor", type=int)
    p.set_defaults(func=cmd_churn)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
