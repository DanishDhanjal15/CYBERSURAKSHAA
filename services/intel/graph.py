"""
services/intel/graph.py
-----------------------
The entity graph: the layer that turns five isolated detectors into one
intelligence platform.

Before this module, every scan wrote one flat row to `scans` and the indicators
it had extracted were rendered once and thrown away. An analyst could ask "is
this poster a scam?" but not the question they actually have -- "is this number
connected to that domain connected to that betting app?"

Model
-----
    entities        one node per (kind, value). A phone number seen in four
                    different scans is ONE entity with four sightings.
    entity_edges    undirected, weighted links between entities.
    sightings       provenance: which scan saw this entity, when, with what
                    verdict. This is what makes a node defensible in a notice.
    cases           an analyst's working folder of entities.
    campaigns       machine-derived clusters (see campaigns.py).

Edge semantics
--------------
    co_occurrence   the two entities appeared in the same artefact. This is the
                    workhorse -- a phone printed on the same poster as a UPI ID
                    is the link that unwinds an operator.
    same_infra      shared hosting IP / ASN / registrar.
    same_campaign   assigned by the clustering pass.
    resolves_to     domain -> IP.
    hosted_on       URL -> domain.

All writes are idempotent upserts: re-ingesting the same scan strengthens the
existing edges rather than duplicating them.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from services.intel.db import get_db_connection
from services.intel.indicators import (
    Indicator, extract_all, KIND_LABELS, KIND_DOMAIN, KIND_URL, KIND_IP,
)

# Relations
REL_CO_OCCURRENCE = "co_occurrence"
REL_SAME_INFRA = "same_infra"
REL_SAME_CAMPAIGN = "same_campaign"
REL_RESOLVES_TO = "resolves_to"
REL_HOSTED_ON = "hosted_on"

# A single artefact carrying more than this many indicators is almost always a
# scraped page rather than a scam creative. Linking all of them pairwise would
# add O(n^2) edges and create a hub that joins unrelated campaigns.
MAX_INDICATORS_PER_ARTEFACT = 25


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# -- Schema ----------------------------------------------------------------

def init_graph_db():
    """Create the graph tables. Idempotent; safe to call at every startup."""
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS entities (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            kind        TEXT NOT NULL,
            value       TEXT NOT NULL,
            display     TEXT,
            first_seen  TEXT NOT NULL,
            last_seen   TEXT NOT NULL,
            sightings   INTEGER NOT NULL DEFAULT 0,
            risk_max    INTEGER NOT NULL DEFAULT 0,
            risk_sum    INTEGER NOT NULL DEFAULT 0,
            confidence  REAL NOT NULL DEFAULT 1.0,
            meta        TEXT,
            UNIQUE(kind, value)
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_entities_kind ON entities(kind)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_entities_last ON entities(last_seen DESC)")

    # src_id < dst_id is enforced on write so an undirected edge has exactly
    # one row and UNIQUE can do the deduplication.
    cur.execute("""
        CREATE TABLE IF NOT EXISTS entity_edges (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            src_id      INTEGER NOT NULL,
            dst_id      INTEGER NOT NULL,
            relation    TEXT NOT NULL,
            weight      INTEGER NOT NULL DEFAULT 1,
            first_seen  TEXT NOT NULL,
            last_seen   TEXT NOT NULL,
            meta        TEXT,
            UNIQUE(src_id, dst_id, relation),
            FOREIGN KEY(src_id) REFERENCES entities(id) ON DELETE CASCADE,
            FOREIGN KEY(dst_id) REFERENCES entities(id) ON DELETE CASCADE
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_edges_src ON entity_edges(src_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_edges_dst ON entity_edges(dst_id)")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS entity_sightings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_id   INTEGER NOT NULL,
            scan_id     INTEGER,
            alert_id    INTEGER,
            module      TEXT,
            verdict     TEXT,
            score       INTEGER DEFAULT 0,
            context     TEXT,
            source      TEXT,
            timestamp   TEXT NOT NULL,
            FOREIGN KEY(entity_id) REFERENCES entities(id) ON DELETE CASCADE
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sight_entity ON entity_sightings(entity_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sight_scan ON entity_sightings(scan_id)")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ref         TEXT UNIQUE,
            title       TEXT NOT NULL,
            status      TEXT NOT NULL DEFAULT 'OPEN',
            severity    TEXT NOT NULL DEFAULT 'MEDIUM',
            summary     TEXT,
            created_by  INTEGER,
            created_by_name TEXT,
            assigned_to TEXT,
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS case_entities (
            case_id     INTEGER NOT NULL,
            entity_id   INTEGER NOT NULL,
            added_at    TEXT NOT NULL,
            added_by    TEXT,
            note        TEXT,
            PRIMARY KEY(case_id, entity_id),
            FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE,
            FOREIGN KEY(entity_id) REFERENCES entities(id) ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS case_scans (
            case_id     INTEGER NOT NULL,
            scan_id     INTEGER NOT NULL,
            added_at    TEXT NOT NULL,
            PRIMARY KEY(case_id, scan_id),
            FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS campaigns (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            label       TEXT NOT NULL,
            method      TEXT NOT NULL,
            size        INTEGER NOT NULL DEFAULT 0,
            risk        INTEGER NOT NULL DEFAULT 0,
            first_seen  TEXT,
            last_seen   TEXT,
            signature   TEXT,
            summary     TEXT,
            updated_at  TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS campaign_entities (
            campaign_id INTEGER NOT NULL,
            entity_id   INTEGER NOT NULL,
            PRIMARY KEY(campaign_id, entity_id),
            FOREIGN KEY(campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE,
            FOREIGN KEY(entity_id) REFERENCES entities(id) ON DELETE CASCADE
        )
    """)

    conn.commit()
    conn.close()


# -- Entity upsert ---------------------------------------------------------

def upsert_entity(conn, kind, value, display=None, risk=0, confidence=1.0, meta=None):
    """
    Insert or update one entity, returning its id.

    Uses a single INSERT ... ON CONFLICT so two concurrent requests seeing the
    same phone number cannot race into two rows -- the UNIQUE(kind, value)
    constraint plus the upsert makes the operation atomic.
    """
    now = _now()
    meta_json = json.dumps(meta or {})
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO entities (kind, value, display, first_seen, last_seen,
                              sightings, risk_max, risk_sum, confidence, meta)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
        ON CONFLICT(kind, value) DO UPDATE SET
            last_seen  = excluded.last_seen,
            sightings  = entities.sightings + 1,
            risk_max   = MAX(entities.risk_max, excluded.risk_max),
            risk_sum   = entities.risk_sum + excluded.risk_sum,
            confidence = MAX(entities.confidence, excluded.confidence),
            display    = COALESCE(entities.display, excluded.display)
    """, (kind, value, display or value, now, now, int(risk), int(risk),
          float(confidence), meta_json))

    cur.execute("SELECT id FROM entities WHERE kind = ? AND value = ?", (kind, value))
    row = cur.fetchone()
    return row["id"] if row else None


def link_entities(conn, src_id, dst_id, relation=REL_CO_OCCURRENCE, meta=None):
    """
    Create or strengthen an undirected edge.

    Node ids are ordered before writing so (A,B) and (B,A) are the same row and
    the weight accumulates instead of splitting across two directions.
    """
    if not src_id or not dst_id or src_id == dst_id:
        return None
    a, b = (src_id, dst_id) if src_id < dst_id else (dst_id, src_id)
    now = _now()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO entity_edges (src_id, dst_id, relation, weight, first_seen, last_seen, meta)
        VALUES (?, ?, ?, 1, ?, ?, ?)
        ON CONFLICT(src_id, dst_id, relation) DO UPDATE SET
            weight    = entity_edges.weight + 1,
            last_seen = excluded.last_seen
    """, (a, b, relation, now, now, json.dumps(meta or {})))
    return cur.lastrowid


def record_sighting(conn, entity_id, scan_id=None, alert_id=None, module=None,
                    verdict=None, score=0, context=None, source=None):
    """Append provenance for one entity observation."""
    conn.cursor().execute("""
        INSERT INTO entity_sightings
            (entity_id, scan_id, alert_id, module, verdict, score, context, source, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (entity_id, scan_id, alert_id, module, verdict, int(score or 0),
          context, source, _now()))


# -- Ingestion -------------------------------------------------------------

def ingest(text, module, verdict=None, score=0, scan_id=None, alert_id=None,
           source=None, extra_indicators=None):
    """
    Extract every indicator from `text`, persist them as entities, and link
    everything that co-occurred in this one artefact.

    `extra_indicators` lets a caller inject indicators it derived by other
    means -- an APK signing certificate, a perceptual image hash, a domain the
    URL checker already resolved -- so they join the same graph.

    Returns a summary dict for the API response. Never raises: a failure to
    enrich must not fail the detection request that triggered it.
    """
    try:
        indicators = list(extract_all(text or ""))
        if extra_indicators:
            known = {i.key for i in indicators}
            for extra in extra_indicators:
                if extra.key not in known:
                    indicators.append(extra)
                    known.add(extra.key)

        if not indicators:
            return {"entities": 0, "edges": 0, "indicators": []}

        # Bound the fan-out. Keep the highest-confidence indicators -- they are
        # the ones an action can actually be raised against.
        indicators.sort(key=lambda i: -i.confidence)
        truncated = len(indicators) > MAX_INDICATORS_PER_ARTEFACT
        indicators = indicators[:MAX_INDICATORS_PER_ARTEFACT]

        conn = get_db_connection()
        try:
            ids = []
            for ind in indicators:
                eid = upsert_entity(
                    conn, ind.kind, ind.normalized, display=ind.raw,
                    risk=score, confidence=ind.confidence, meta=ind.meta,
                )
                if eid:
                    ids.append((eid, ind))
                    record_sighting(
                        conn, eid, scan_id=scan_id, alert_id=alert_id,
                        module=module, verdict=verdict, score=score,
                        context=ind.context, source=source,
                    )

            edges = 0
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    link_entities(conn, ids[i][0], ids[j][0], REL_CO_OCCURRENCE)
                    edges += 1

            # Structural edges carry more meaning than bare co-occurrence, so
            # they are recorded as their own relation on top.
            by_kind = {}
            for eid, ind in ids:
                by_kind.setdefault(ind.kind, []).append((eid, ind))
            for url_id, url_ind in by_kind.get(KIND_URL, []):
                dom = (url_ind.meta or {}).get("domain")
                for dom_id, dom_ind in by_kind.get(KIND_DOMAIN, []):
                    if dom_ind.normalized == dom:
                        link_entities(conn, url_id, dom_id, REL_HOSTED_ON)
            for ip_id, _ in by_kind.get(KIND_IP, []):
                for dom_id, _ in by_kind.get(KIND_DOMAIN, []):
                    link_entities(conn, dom_id, ip_id, REL_RESOLVES_TO)

            conn.commit()
        finally:
            conn.close()

        return {
            "entities": len(ids),
            "edges": edges,
            "truncated": truncated,
            "indicators": [i.to_dict() for _, i in ids],
        }
    except Exception as e:
        print("[GRAPH] ingest failed: %s" % e)
        return {"entities": 0, "edges": 0, "indicators": [], "error": str(e)}


# -- Queries ---------------------------------------------------------------

def get_entity(kind, value):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM entities WHERE kind = ? AND value = ?", (kind, value))
    row = cur.fetchone()
    conn.close()
    return _entity_row(row) if row else None


def get_entity_by_id(entity_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM entities WHERE id = ?", (entity_id,))
    row = cur.fetchone()
    conn.close()
    return _entity_row(row) if row else None


def _entity_row(row):
    d = dict(row)
    try:
        d["meta"] = json.loads(d.get("meta") or "{}")
    except Exception:
        d["meta"] = {}
    d["label"] = KIND_LABELS.get(d["kind"], d["kind"])
    seen = max(1, d.get("sightings") or 1)
    d["risk_avg"] = int(round((d.get("risk_sum") or 0) / seen))
    return d


def search_entities(query, limit=25):
    """Substring search across entity values, strongest signals first."""
    if not query or len(query.strip()) < 2:
        return []
    q = "%" + query.strip().lower() + "%"
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM entities
        WHERE LOWER(value) LIKE ? OR LOWER(COALESCE(display, '')) LIKE ?
        ORDER BY risk_max DESC, sightings DESC, last_seen DESC
        LIMIT ?
    """, (q, q, int(limit)))
    rows = [_entity_row(r) for r in cur.fetchall()]
    conn.close()
    return rows


def neighbourhood(entity_id, depth=2, max_nodes=150):
    """
    Breadth-first expansion from one entity.

    Returns {"nodes": [...], "edges": [...], "truncated": bool} in the shape the
    Cytoscape front-end consumes directly.

    Expansion is capped by node count rather than purely by depth. A single
    heavily-reused phone number can pull in hundreds of neighbours at depth 2,
    and a graph that large is unreadable in the UI and slow to lay out; the cap
    keeps the highest-weight edges and reports that it trimmed.
    """
    conn = get_db_connection()
    cur = conn.cursor()

    seen_nodes = {}
    edges = {}
    frontier = [int(entity_id)]
    truncated = False

    cur.execute("SELECT * FROM entities WHERE id = ?", (entity_id,))
    root = cur.fetchone()
    if not root:
        conn.close()
        return {"nodes": [], "edges": [], "truncated": False, "root": None}
    seen_nodes[root["id"]] = _entity_row(root)
    seen_nodes[root["id"]]["depth"] = 0

    for level in range(1, int(depth) + 1):
        if not frontier:
            break
        placeholders = ",".join("?" for _ in frontier)
        cur.execute("""
            SELECT e.*,
                   CASE WHEN e.src_id IN (%s) THEN e.dst_id ELSE e.src_id END AS other_id
            FROM entity_edges e
            WHERE e.src_id IN (%s) OR e.dst_id IN (%s)
            ORDER BY e.weight DESC, e.last_seen DESC
        """ % (placeholders, placeholders, placeholders), frontier * 3)

        next_frontier = []
        for row in cur.fetchall():
            ekey = (row["src_id"], row["dst_id"], row["relation"])
            if ekey not in edges:
                edges[ekey] = {
                    "source": row["src_id"],
                    "target": row["dst_id"],
                    "relation": row["relation"],
                    "weight": row["weight"],
                    "last_seen": row["last_seen"],
                }
            other = row["other_id"]
            if other in seen_nodes:
                continue
            if len(seen_nodes) >= max_nodes:
                truncated = True
                continue
            cur2 = conn.cursor()
            cur2.execute("SELECT * FROM entities WHERE id = ?", (other,))
            r2 = cur2.fetchone()
            if r2:
                node = _entity_row(r2)
                node["depth"] = level
                seen_nodes[other] = node
                next_frontier.append(other)
        frontier = next_frontier

    # Drop edges pointing at nodes the cap excluded, otherwise the front-end
    # renders dangling references.
    kept = {
        k: v for k, v in edges.items()
        if v["source"] in seen_nodes and v["target"] in seen_nodes
    }

    conn.close()
    return {
        "nodes": list(seen_nodes.values()),
        "edges": list(kept.values()),
        "truncated": truncated,
        "root": seen_nodes.get(int(entity_id)),
    }


def entity_sightings(entity_id, limit=50):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM entity_sightings
        WHERE entity_id = ?
        ORDER BY timestamp DESC, id DESC
        LIMIT ?
    """, (entity_id, int(limit)))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def top_entities(kind=None, limit=20):
    conn = get_db_connection()
    cur = conn.cursor()
    if kind:
        cur.execute("""
            SELECT * FROM entities WHERE kind = ?
            ORDER BY sightings DESC, risk_max DESC LIMIT ?
        """, (kind, int(limit)))
    else:
        cur.execute("""
            SELECT * FROM entities
            ORDER BY sightings DESC, risk_max DESC LIMIT ?
        """, (int(limit),))
    rows = [_entity_row(r) for r in cur.fetchall()]
    conn.close()
    return rows


def graph_stats():
    """Counts for the dashboard. Real numbers, computed from the graph."""
    conn = get_db_connection()
    cur = conn.cursor()
    out = {}
    cur.execute("SELECT COUNT(*) FROM entities")
    out["entities"] = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM entity_edges")
    out["edges"] = cur.fetchone()[0]
    cur.execute("SELECT kind, COUNT(*) c FROM entities GROUP BY kind ORDER BY c DESC")
    out["by_kind"] = [{"kind": r[0], "label": KIND_LABELS.get(r[0], r[0]), "count": r[1]}
                      for r in cur.fetchall()]
    cur.execute("SELECT COUNT(*) FROM entities WHERE sightings > 1")
    out["repeat_entities"] = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM campaigns")
    out["campaigns"] = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM cases WHERE status != 'CLOSED'")
    out["open_cases"] = cur.fetchone()[0]
    conn.close()
    return out


# -- Cases -----------------------------------------------------------------

def create_case(title, created_by=None, created_by_name=None, severity="MEDIUM",
                summary=None, entity_ids=None, scan_ids=None):
    conn = get_db_connection()
    cur = conn.cursor()
    now = _now()
    cur.execute("""
        INSERT INTO cases (ref, title, status, severity, summary,
                           created_by, created_by_name, created_at, updated_at)
        VALUES (?, ?, 'OPEN', ?, ?, ?, ?, ?, ?)
    """, ("PENDING", title, severity, summary, created_by, created_by_name, now, now))
    case_id = cur.lastrowid
    # The human-facing reference embeds the id, so it can only be built after
    # the insert assigns one.
    ref = "CS-CASE-%05d" % case_id
    cur.execute("UPDATE cases SET ref = ? WHERE id = ?", (ref, case_id))

    for eid in (entity_ids or []):
        cur.execute("""
            INSERT OR IGNORE INTO case_entities (case_id, entity_id, added_at, added_by)
            VALUES (?, ?, ?, ?)
        """, (case_id, eid, now, created_by_name))
    for sid in (scan_ids or []):
        cur.execute("""
            INSERT OR IGNORE INTO case_scans (case_id, scan_id, added_at)
            VALUES (?, ?, ?)
        """, (case_id, sid, now))

    conn.commit()
    conn.close()
    return {"id": case_id, "ref": ref}


def add_to_case(case_id, entity_ids=None, scan_ids=None, added_by=None):
    conn = get_db_connection()
    cur = conn.cursor()
    now = _now()
    added = 0
    for eid in (entity_ids or []):
        cur.execute("""
            INSERT OR IGNORE INTO case_entities (case_id, entity_id, added_at, added_by)
            VALUES (?, ?, ?, ?)
        """, (case_id, eid, now, added_by))
        added += cur.rowcount
    for sid in (scan_ids or []):
        cur.execute("""
            INSERT OR IGNORE INTO case_scans (case_id, scan_id, added_at)
            VALUES (?, ?, ?)
        """, (case_id, sid, now))
        added += cur.rowcount
    cur.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id))
    conn.commit()
    conn.close()
    return added


def list_cases(status=None, limit=100):
    conn = get_db_connection()
    cur = conn.cursor()
    if status:
        cur.execute("""
            SELECT c.*, (SELECT COUNT(*) FROM case_entities ce WHERE ce.case_id = c.id) AS entity_count
            FROM cases c WHERE c.status = ? ORDER BY c.updated_at DESC LIMIT ?
        """, (status, int(limit)))
    else:
        cur.execute("""
            SELECT c.*, (SELECT COUNT(*) FROM case_entities ce WHERE ce.case_id = c.id) AS entity_count
            FROM cases c ORDER BY c.updated_at DESC LIMIT ?
        """, (int(limit),))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_case(case_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM cases WHERE id = ?", (case_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return None
    case = dict(row)
    cur.execute("""
        SELECT e.*, ce.added_at, ce.note FROM case_entities ce
        JOIN entities e ON e.id = ce.entity_id
        WHERE ce.case_id = ?
        ORDER BY e.risk_max DESC, e.sightings DESC
    """, (case_id,))
    case["entities"] = [_entity_row(r) for r in cur.fetchall()]
    cur.execute("""
        SELECT s.* FROM case_scans cs JOIN scans s ON s.id = cs.scan_id
        WHERE cs.case_id = ? ORDER BY s.id DESC
    """, (case_id,))
    case["scans"] = [dict(r) for r in cur.fetchall()]
    conn.close()
    return case


def update_case(case_id, status=None, severity=None, assigned_to=None, summary=None):
    fields, params = [], []
    if status:
        fields.append("status = ?")
        params.append(status)
    if severity:
        fields.append("severity = ?")
        params.append(severity)
    if assigned_to is not None:
        fields.append("assigned_to = ?")
        params.append(assigned_to)
    if summary is not None:
        fields.append("summary = ?")
        params.append(summary)
    if not fields:
        return False
    fields.append("updated_at = ?")
    params.append(_now())
    params.append(case_id)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE cases SET %s WHERE id = ?" % ", ".join(fields), params)
    conn.commit()
    changed = cur.rowcount
    conn.close()
    return changed > 0
