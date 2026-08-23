# CYBERSURAKSHAA — Round 2: Monetisation, Scalability, Adaptability, Feasibility

> **Scenario:** A worldwide emergency has been declared. A pandemic is disrupting
> economies globally, and for the next ninety days people are not allowed to gather.

This document is the engineering companion to the strategy deck. Where the deck
makes a claim, this file says **what was built to make the claim checkable** —
because the platform's own rule is that a number nobody can reproduce is not
evidence, and that rule has to apply to our business case too.

---

## 0. Corrections to the strategy draft (read this first)

Three things in the earlier strategy draft would have been caught by a judge,
and one of them is arithmetic.

### ❌ The ₹15 Crore/month figure is wrong by 10×

The draft states:

> ₹0.05 per API call × 10 million daily transactions = ₹5,00,000/day → ₹15 Crore/month

₹5,00,000 × 30 days = **₹1.5 Crore/month**, not ₹15 Crore. The per-day figure is
right; the monthly one is a decimal slip. Present the wrong number once and every
other number in the deck becomes suspect.

### ❌ The 10-million-calls-a-day assumption is not defensible either

No bank routes its entire daily transaction volume through a hackathon vendor's
API on day one. The honest model is bottom-up:

| Assumption | Value | Basis |
| :--- | :--- | :--- |
| Mid-size bank daily transactions | 10,000,000 | public UPI volumes |
| Fraction flagged for secondary screening | 0.5% | typical rules-engine flag rate |
| **Calls actually sent to us** | **50,000/day** | 10M × 0.5% |
| Billed at ₹0.05 | ₹2,500/day | |
| **Per bank, per month** | **≈ ₹75,000** | plus the ₹25,000 platform fee |

That is ₹1 lakh/month per bank customer — unglamorous, believable, and it
survives a follow-up question. Ten such customers is ₹1.2 Cr/year of recurring
revenue, which is a real business at our stage.

### ⚠️ Every borrowed statistic needs a citation or must be cut

The draft cites a "62% spike (RBI 2021)", "300% surge (CERT-In 2021)", a "4×
deepfake increase" and a "₹2,100 crore Ministry of Finance allocation". We could
not verify these. **Either attach the exact source (report name, page) or replace
them with the figures we can defend — our own measured results.** A platform
whose CI pipeline literally fails the build when fabricated data markers appear
cannot put unsourced statistics on slide 2.

**What we can defend without a footnote:**

| Claim | Value | Where it comes from |
| :--- | :--- | :--- |
| Deepfake accuracy | 97.4%, F1 97.4% (n=153) | `evaluation/eval_deepfake.py` |
| Calibration improvement | ECE 0.0577 → 0.0260 | `evaluation/calibrate_deepfake.py` |
| Betting text classifier | F1 95.5% (5-fold CV) | `build_training_corpus.py` |
| Automated tests | **453 passing**, 3-job CI | `pytest tests/` |
| Emergency pattern bank | 27 patterns, switchable | `services/intel/pandemic.py` |
| Infra cost at pilot scale | ₹2,000–3,000/month | 4 GB VPS, measured footprint |

---

## 1. 💰 Monetisation — built, not described

**What was built:** `services/intel/metering.py`, a per-tenant plan, quota and
invoicing engine, wired into the public API and surfaced at `/admin/operations`.

A pitch can name a price. Only a running meter proves the product can charge for
what it does. Every billable API call is now recorded against the tenant that
made it, and the month-to-date invoice is derived from that record.

### Plan catalogue (in code, `metering.PLANS`)

| Plan | Monthly fee | Included calls | Overage | Intended for |
| :--- | :--- | :--- | :--- | :--- |
| **Citizen / Free** | ₹0 | 1,000 | Throttled, never cut off | Citizen channels, NGOs |
| **Pilot / District** | ₹0 | 25,000 | Throttled | 90-day proof-of-value |
| **Standard API** | ₹25,000 | 500,000 | ₹0.05/call | Banks, NBFCs, payment apps |
| **Enterprise / Sovereign** | ₹2,00,000 | Unmetered | — | State cyber cell, telecom |

### Three revenue streams, in priority order

**1. B2G sovereign licence (primary).** A state cyber cell deploys the whole
platform on its own infrastructure — this matters during an emergency, because
data never leaves government control and no gathering is needed to install it.
₹25L/year per state at the deck's figure; the Enterprise plan above is the
monthly-billed equivalent for departments that prefer opex.

**2. B2B fraud-check API (fastest to close).** Banks and payment apps call
`/api/v1/check` on flagged onboarding and transaction events. Bottom-up model
above: ≈₹1 lakh/month per mid-size bank. Self-service usage at `/api/v1/usage`
means an integrator can answer "what will this cost me" without a sales call.

**3. Threat-intelligence feed (highest margin).** A daily export of verified
scam indicators — phone numbers, UPI VPAs, domains — for telecom and bank
blocklists. This sells the *data* the platform already produces, at near-zero
marginal cost. Priced per subscriber, annual.

### Why an emergency is a buying trigger, not a freeze

Cybersecurity is one of the few line items that survives an emergency budget
cut, because the emergency itself is what drives the fraud. Two of our three
streams need **no procurement of hardware and no site visit** — the third
(sovereign licence) is a Docker deployment an admin performs from home.

### The commercial dashboard

`/admin/operations` shows tenants, month-to-date calls, the invoice each
produces, and total revenue. It reads **zero on a fresh install** — no seeded
MRR, the same rule the detection counters follow. That zero is the point: it
proves the number is real when it is not zero.

---

## 2. 📈 Scalability

### What is already true

* **Stateless request path.** Nothing but the database is shared, so workers
  scale horizontally behind any load balancer.
* **Lazy, single-instance model loading.** Models load on first use and one copy
  serves every request in the process — which is why the container runs one
  worker and scales at the container level instead.
* **The intelligence layer is stdlib-only.** The entity graph, campaign
  clustering, indicator extraction, evidence chain, calibration and the new
  emergency bank need no ML stack at all. That half of the platform scales at
  the cost of a regex, and it is the half that runs on every request.
* **Metering is per-tenant from day one**, so a noisy tenant is visible and
  rate-limitable without touching anyone else.

### Growth path

| Phase | Load | Infrastructure | Monthly cost |
| :--- | :--- | :--- | :--- |
| Now | <10k scans/day | 1 container, SQLite | ₹2,000–3,000 |
| 3 months | 10k–100k/day | 3 nodes, PostgreSQL, Redis rate-limit store | ₹15,000 |
| 6 months | 100k+/day | Autoscaled workers, text and vision paths split | ₹60,000 |

**The one migration that matters:** SQLite → PostgreSQL. Every query goes through
`services/intel/db.get_db_connection()`, so the change is confined to that helper
plus the rate-limiter's `storage_uri`. Splitting the text path (cheap, stdlib)
from the vision path (expensive, GPU-optional) is the second step — text checks
are ~99% of emergency-period volume and should never queue behind a video.

---

## 3. 🔄 Adaptability — proven by shipping one

**What was built:** `services/intel/pandemic.py` — 27 emergency-fraud patterns
in English and Hinglish, behind a single switch, with tests.

This is the adaptability argument stated as a diff rather than a promise. When
the emergency was declared, the fraud *pretexts* changed within days — relief
funds, oxygen cylinders, vaccine slots, e-passes, quarantine fines,
work-from-home income. The *delivery* did not change at all.

So nothing in the platform had to change either:

* no model retrained
* no database migration
* no route added
* no detector rewritten

A new keyword bank in the shape the scorers already consume, plus a switch.
That is the entire adaptation surface.

### The switch matters as much as the bank

Emergency vocabulary is **inert until an emergency is declared**
(`EMERGENCY_MODE=1`, or the toggle on `/admin/operations`). Outside one, "relief
fund" and "oxygen supply" appear in legitimate circulars, and scoring them
permanently would manufacture false positives in exactly the population we are
trying to protect. Tests assert both halves: nothing scores while stood down,
and the score rises once declared — and the API response says which posture
produced it, so two results are comparable.

Declaring or standing down is written to the tamper-evident evidence chain,
because a score that changed due to posture must be explainable months later.

### Other adaptation axes (unchanged from the strategy draft, still true)

* **Hardware supply shock:** QR fallback is already live and shares the exact
  analysis pipeline; NFC uses 180nm-class silicon unaffected by leading-edge
  shortages; Android HCE needs no new hardware at all.
* **New language:** add to the multilingual bank — same shape, same scorer.
* **New jurisdiction:** `KIND_AUTHORITY` maps indicator types to the body that
  can act on them. Another country is a different mapping, not a different
  codebase.

---

## 4. ✅ Feasibility under a ninety-day gathering ban

| Constraint | Why it is not a blocker |
| :--- | :--- |
| No teams may gather | Browser-based; `docker compose up --build` from a home laptop |
| No hardware procurement | Runs on any 4 GB Linux VM; the analyst's own phone is the NFC/QR sensor |
| Budgets frozen | ₹2,000–3,000/month at pilot scale, coverable by one Standard API customer |
| Offices closed | The Citizen Quick Check at `/check` replaces the physical complaint counter — no login, plain-language verdict, 1930 guidance |
| Supply chain broken | QR fallback live; HCE needs no procurement |
| Nobody can be trained in person | Every verdict ships with its reasons; the highlighted evidence *is* the training |

**Already done, not planned:** 8 detector modules, 453 passing tests, 3-job CI,
Dockerfile, measured accuracy on a held-out set, calibrated probabilities, a
tamper-evident evidence chain, court-ready PDF export.

---

## 5. 🛒 How we actually sell it

**Land → prove → expand**, on a 90-day clock that matches the scenario.

| Days | Move | Deliverable | Ask |
| :--- | :--- | :--- | :--- |
| 0–15 | **Land one district.** Existing GPCSSI channel. Free Pilot plan key. | Deployed instance + 3 analysts trained over video | Nothing. Free. |
| 15–45 | **Prove it.** Run their real backlog through it. | Weekly measured report: artefacts flagged, indicators extracted, campaigns linked, hours saved | Written feedback |
| 45–60 | **Convert.** Same numbers, now theirs. | Sovereign licence proposal | ₹25L/year state licence |
| 30–60 | **Parallel: one bank.** Start with the API, not the platform — 2-day integration. | 30-day usage report from `/api/v1/usage` | Standard plan, ₹25k/month |
| 60–90 | **Expand.** District → state; bank pilot → production. Telecom feed conversation opens with the indicator volume the first two produced. | Threat-feed sample export | Feed subscription |

**Why this order:** the district pilot costs us nothing and produces the only
asset that actually sells to the next buyer — *their own numbers*. The bank runs
in parallel because it has a far shorter procurement cycle and pays first.

**What we say when asked "why you and not an incumbent":**
1. Every verdict shows its reasons — the words, the boxes, the calibrated
   probability. Incumbent scores are opaque.
2. Detection produces **evidence**, not an alert: hash-chained, court-ready.
3. Built India-first — Hinglish and Devanagari, UPI rails, NPCI handles,
   Indian reporting authorities — not localised after the fact.
4. Physical-world coverage: QR stickers and NFC tags, scanned from the phone
   the officer already has.

---

## 6. What shipped for round 2 (verified)

| Item | File | Verification |
| :--- | :--- | :--- |
| Emergency scam bank (27 patterns, EN + Hinglish) | `services/intel/pandemic.py` | 11 tests |
| Emergency posture switch + evidence logging | `blueprints/admin.py` | tested; chain-logged |
| Per-tenant plans, quotas, usage accounting | `services/intel/metering.py` | 10 tests |
| Self-service usage/invoice endpoint | `GET /api/v1/usage` | tested |
| Tenant provisioning + revenue dashboard | `/admin/operations` | renders; zero on fresh install |
| Billing honesty: failed calls are not billed | `blueprints/public_api.py` | asserted in tests |

**Full suite: 453 passed.**

---

> **The one line to leave a judge with:**
> A pandemic does not create new fraud mechanics — it creates new pretexts, at a
> speed no retraining cycle can match. We shipped the emergency pretext bank in
> an afternoon, behind a switch, with tests, without touching a model. That is
> what adaptability looks like when it is code instead of a slide.
