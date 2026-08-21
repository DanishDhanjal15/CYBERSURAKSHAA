"""
services/intel/campaigns.py
---------------------------
Operator-level clustering.

A single flagged poster is a nuisance. Thirty posters sharing one UPI address,
two phone numbers and a hosting IP are an *operation*, and that is the unit a
cyber cell actually acts on -- one notice covering thirty assets rather than
thirty notices covering one each.

Method
------
Union-find over the entity graph, with two refinements that matter:

1. **Hub suppression.** A phone number appearing in 400 artefacts is not
   evidence that those 400 artefacts share an operator -- it is a call centre
   number, a helpline, or an extraction error. Nodes whose degree exceeds
   HUB_DEGREE_LIMIT are excluded as merge bridges. Without this the whole graph
   collapses into one meaningless component within a few hundred scans.

2. **Anchor kinds only.** Merges propagate through identity-bearing indicators
   (UPI, phone, wallet, Telegram handle, signing certificate, domain) and not
   through incidental ones (a bare IP, a shortener URL). Sharing a hosting IP
   is suggestive; sharing a UPI address is close to conclusive.

Near-duplicate creative detection uses MinHash over character shingles. It
catches the reskinned copies -- same script, swapped brand name and number --
that exact hashing misses entirely.
"""

from __future__ import annotations

import json
import re
from datetime import datetime

from services.intel.db import get_db_connection
from services.intel.indicators import (
    KIND_UPI, KIND_PHONE, KIND_DOMAIN, KIND_TELEGRAM, KIND_WHATSAPP,
    KIND_CRYPTO, KIND_BANK_ACCT, KIND_APK_CERT, KIND_IFSC, KIND_IP,
    KIND_LABELS,
)

# Indicators strong enough to imply a shared operator when two artefacts share
# one. Ordered by strength -- used to pick a campaign's headline label.
ANCHOR_KINDS = (
    KIND_UPI, KIND_CRYPTO, KIND_BANK_ACCT, KIND_APK_CERT,
    KIND_PHONE, KIND_TELEGRAM, KIND_WHATSAPP, KIND_DOMAIN, KIND_IFSC,
)

# Weaker signals: recorded on the campaign, never used to merge components.
SUPPORTING_KINDS = (KIND_IP,)

# Degree above which an entity stops acting as a merge bridge.
HUB_DEGREE_LIMIT = 40

# Components smaller than this are just a single artefact's indicators, not a
# campaign worth naming.
MIN_CAMPAIGN_SIZE = 3

# MinHash configuration for near-duplicate creative detection.
SHINGLE_SIZE = 5
MINHASH_PERMUTATIONS = 64
NEAR_DUPLICATE_THRESHOLD = 0.55


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# -- Union-find ------------------------------------------------------------

class _DisjointSet:
    """Union-find with path compression and union by size."""

    def __init__(self):
        self.parent = {}
        self.size = {}

    def add(self, x):
        if x not in self.parent:
            self.parent[x] = x
            self.size[x] = 1

    def find(self, x):
        self.add(x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return
        if self.size[ra] < self.size[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        self.size[ra] += self.size[rb]

    def components(self):
        out = {}
        for node in self.parent:
            out.setdefault(self.find(node), []).append(node)
        return out


# -- Clustering ------------------------------------------------------------

def rebuild_campaigns(min_size=MIN_CAMPAIGN_SIZE, hub_limit=HUB_DEGREE_LIMIT):
    """
    Recompute every campaign from the current graph.

    A full rebuild rather than an incremental update: the graph is small (tens
    of thousands of nodes at most for this deployment), the operation is a few
    hundred milliseconds, and incremental clustering with hub suppression is
    genuinely hard to keep correct as degrees cross the threshold. Correct and
    cheap beats clever here.

    Returns a summary dict.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT id, kind, value, display, sightings, risk_max, first_seen, last_seen FROM entities")
    entities = {r["id"]: dict(r) for r in cur.fetchall()}
    if not entities:
        conn.close()
        return {"campaigns": 0, "clustered_entities": 0, "hubs_suppressed": 0}

    cur.execute("SELECT src_id, dst_id, relation, weight FROM entity_edges")
    edges = [dict(r) for r in cur.fetchall()]

    # Degree is computed over all edges, before any filtering -- an entity that
    # is a hub is a hub regardless of which relation produced the connections.
    degree = {}
    for e in edges:
        degree[e["src_id"]] = degree.get(e["src_id"], 0) + 1
        degree[e["dst_id"]] = degree.get(e["dst_id"], 0) + 1

    hubs = {eid for eid, d in degree.items() if d > hub_limit}

    ds = _DisjointSet()
    for eid, ent in entities.items():
        if ent["kind"] in ANCHOR_KINDS:
            ds.add(eid)

    for e in edges:
        a, b = e["src_id"], e["dst_id"]
        if a in hubs or b in hubs:
            continue
        ea, eb = entities.get(a), entities.get(b)
        if not ea or not eb:
            continue
        if ea["kind"] not in ANCHOR_KINDS or eb["kind"] not in ANCHOR_KINDS:
            continue
        ds.union(a, b)

    components = {
        root: members for root, members in ds.components().items()
        if len(members) >= min_size
    }

    # Replace wholesale. Campaign ids are not referenced by anything durable --
    # cases reference entities, not campaigns -- so a clean rebuild avoids
    # stale membership from a previous run.
    cur.execute("DELETE FROM campaign_entities")
    cur.execute("DELETE FROM campaigns")

    created = 0
    clustered = 0
    for root, members in sorted(components.items(), key=lambda kv: -len(kv[1])):
        member_ents = [entities[m] for m in members if m in entities]
        if not member_ents:
            continue

        label = _campaign_label(member_ents)
        risk = max((e["risk_max"] or 0) for e in member_ents)
        first = min((e["first_seen"] or "") for e in member_ents)
        last = max((e["last_seen"] or "") for e in member_ents)
        signature = _campaign_signature(member_ents)
        summary = _campaign_summary(member_ents)

        cur.execute("""
            INSERT INTO campaigns (label, method, size, risk, first_seen, last_seen,
                                   signature, summary, updated_at)
            VALUES (?, 'shared-infrastructure', ?, ?, ?, ?, ?, ?, ?)
        """, (label, len(member_ents), int(risk), first, last,
              json.dumps(signature), summary, _now()))
        campaign_id = cur.lastrowid
        for m in members:
            cur.execute(
                "INSERT OR IGNORE INTO campaign_entities (campaign_id, entity_id) VALUES (?, ?)",
                (campaign_id, m),
            )
        created += 1
        clustered += len(member_ents)

    conn.commit()
    conn.close()
    return {
        "campaigns": created,
        "clustered_entities": clustered,
        "hubs_suppressed": len(hubs),
        "total_entities": len(entities),
    }


def _campaign_label(member_ents):
    """
    Name a campaign after its strongest identity anchor.

    An analyst has to be able to say "the LootClub operation" out loud, so the
    label is a real indicator from the cluster rather than a serial number.
    """
    by_kind = {}
    for e in member_ents:
        by_kind.setdefault(e["kind"], []).append(e)
    for kind in ANCHOR_KINDS:
        candidates = by_kind.get(kind)
        if candidates:
            best = max(candidates, key=lambda e: (e["sightings"] or 0, e["risk_max"] or 0))
            return "%s: %s" % (KIND_LABELS.get(kind, kind), best["display"] or best["value"])
    return "Unnamed cluster (%d assets)" % len(member_ents)


def _campaign_signature(member_ents):
    """The indicator inventory that defines this cluster."""
    sig = {}
    for e in member_ents:
        sig.setdefault(e["kind"], []).append(e["value"])
    return {k: sorted(v)[:20] for k, v in sig.items()}


def _campaign_summary(member_ents):
    counts = {}
    for e in member_ents:
        counts[e["kind"]] = counts.get(e["kind"], 0) + 1
    parts = [
        "%d %s" % (n, KIND_LABELS.get(k, k).lower() + ("s" if n != 1 else ""))
        for k, n in sorted(counts.items(), key=lambda kv: -kv[1])
    ]
    total_sightings = sum((e["sightings"] or 0) for e in member_ents)
    return "%s across %d sighting%s." % (
        ", ".join(parts), total_sightings, "" if total_sightings == 1 else "s"
    )


def list_campaigns(limit=50):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM campaigns ORDER BY risk DESC, size DESC, last_seen DESC LIMIT ?
    """, (int(limit),))
    rows = []
    for r in cur.fetchall():
        d = dict(r)
        try:
            d["signature"] = json.loads(d.get("signature") or "{}")
        except Exception:
            d["signature"] = {}
        rows.append(d)
    conn.close()
    return rows


def get_campaign(campaign_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM campaigns WHERE id = ?", (campaign_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return None
    camp = dict(row)
    try:
        camp["signature"] = json.loads(camp.get("signature") or "{}")
    except Exception:
        camp["signature"] = {}
    cur.execute("""
        SELECT e.* FROM campaign_entities ce
        JOIN entities e ON e.id = ce.entity_id
        WHERE ce.campaign_id = ?
        ORDER BY e.risk_max DESC, e.sightings DESC
    """, (campaign_id,))
    camp["entities"] = [dict(r) for r in cur.fetchall()]
    conn.close()
    return camp


def campaign_for_entity(entity_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT c.* FROM campaign_entities ce
        JOIN campaigns c ON c.id = ce.campaign_id
        WHERE ce.entity_id = ?
    """, (entity_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


# -- Near-duplicate creative detection -------------------------------------

_WS = re.compile(r"\s+")


def _normalise_for_shingles(text):
    """
    Fold away the parts a reskin changes, keeping the structure it does not.

    Digits collapse to '#' and URLs to a token so that the same script with a
    different phone number and a different domain still hashes alike -- which
    is exactly the case exact-match hashing misses.
    """
    t = (text or "").lower()
    t = re.sub(r"https?://\S+", " <url> ", t)
    t = re.sub(r"\d+", "#", t)
    t = re.sub(r"[^a-z#<>\s]", " ", t)
    return _WS.sub(" ", t).strip()


def shingles(text, size=SHINGLE_SIZE):
    """Character n-grams of the normalised text."""
    norm = _normalise_for_shingles(text)
    if len(norm) < size:
        return {norm} if norm else set()
    return {norm[i:i + size] for i in range(len(norm) - size + 1)}


def minhash(text, permutations=MINHASH_PERMUTATIONS, size=SHINGLE_SIZE):
    """
    MinHash signature as a tuple of ints.

    Uses Python's built-in hash mixed with a per-permutation salt rather than a
    third-party library. Signatures are computed and compared within a single
    process run, so hash randomisation across interpreter restarts does not
    matter -- but they must NOT be persisted and compared later, and are not.
    """
    sh = shingles(text, size)
    if not sh:
        return tuple()
    sig = []
    for p in range(permutations):
        salt = (p * 0x9E3779B1) & 0xFFFFFFFF
        sig.append(min((hash(s) ^ salt) & 0xFFFFFFFF for s in sh))
    return tuple(sig)


def signature_similarity(sig_a, sig_b):
    """Estimated Jaccard similarity between two MinHash signatures."""
    if not sig_a or not sig_b or len(sig_a) != len(sig_b):
        return 0.0
    matches = sum(1 for a, b in zip(sig_a, sig_b) if a == b)
    return matches / float(len(sig_a))


def jaccard(text_a, text_b, size=SHINGLE_SIZE):
    """Exact Jaccard over shingles -- used when comparing only a few items."""
    a, b = shingles(text_a, size), shingles(text_b, size)
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / float(union) if union else 0.0


def group_near_duplicates(items, threshold=NEAR_DUPLICATE_THRESHOLD):
    """
    Group `items` -- an iterable of (id, text) -- into near-duplicate clusters.

    Returns a list of lists of ids. Singletons are included so the caller can
    report "1 of 34 creatives is unique" without a second pass.
    """
    entries = [(i, minhash(t)) for i, t in items]
    ds = _DisjointSet()
    for i, _ in entries:
        ds.add(i)
    for a in range(len(entries)):
        for b in range(a + 1, len(entries)):
            if signature_similarity(entries[a][1], entries[b][1]) >= threshold:
                ds.union(entries[a][0], entries[b][0])
    return sorted(ds.components().values(), key=lambda g: -len(g))


def find_near_duplicate_scans(threshold=NEAR_DUPLICATE_THRESHOLD, limit=400):
    """
    Cluster recent scan inputs by textual similarity.

    Surfaces the "same script, swapped brand" pattern that indicator-based
    clustering cannot see -- two creatives with no shared phone or domain but
    identical wording are still one operator's output.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, module, verdict, score, input_summary, timestamp
        FROM scans ORDER BY id DESC LIMIT ?
    """, (int(limit),))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()

    by_id = {r["id"]: r for r in rows}
    groups = group_near_duplicates(
        [(r["id"], r.get("input_summary") or "") for r in rows], threshold
    )
    out = []
    for g in groups:
        if len(g) < 2:
            continue
        members = [by_id[i] for i in g if i in by_id]
        out.append({
            "size": len(members),
            "modules": sorted({m.get("module") or "?" for m in members}),
            "max_score": max((m.get("score") or 0) for m in members),
            "sample": (members[0].get("input_summary") or "")[:160],
            "scan_ids": [m["id"] for m in members],
        })
    return out
