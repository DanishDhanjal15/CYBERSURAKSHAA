# CYBERSURAKSHAA — Round 2 Submission

**Monetisation · Scalability · Adaptability · Feasibility**

---

## 1. The Round 2 Problem Statement

> *"A worldwide emergency has been declared. A pandemic is disrupting economies
> all around the globe, and for the next ninety days people are not allowed to
> gather."*

### What that actually does to fraud

A gathering ban does not slow digital crime — it removes every offline
alternative to it. The pattern is the same in every emergency:

| What the emergency changes | What it does to fraud |
| :--- | :--- |
| Every transaction moves online | The attack surface stops being a subset of daily life and becomes all of it |
| Physical verification is impossible | Nobody can walk into a branch to check; a deepfake or a spoofed voice has no counter-evidence |
| Cash gives way to UPI and QR | Payment fraud becomes the default fraud |
| Relief money is disbursed at speed | "Claim your relief fund" becomes the single highest-volume lure |
| Jobs are lost | "Work from home, earn ₹3,000 daily" finds an audience it never had |
| The elderly are isolated | The most targeted group loses the family member who used to say *don't send that* |

**The mechanics of fraud do not change. The pretexts change — within days.**
That distinction is the whole of our Round 2 answer.

### Our original problem statement, restated for the emergency

> India's digital fraud arrives in every format — images, deepfakes, calls,
> APKs, QR stickers, NFC tags — and in Hinglish, not English. Defences are
> single-format, siloed, unexplainable, and produce no court-ready evidence.
> Under a ninety-day gathering ban this gap becomes total: the analyst cannot
> reach the office, the citizen cannot reach a counter, and the scammer reaches
> both.

---

## 2. Core Thesis: this platform was built for exactly this scenario

CYBERSURAKSHAA needs **no gathering to deploy, no hardware to procure, and no
in-person training to use**:

- Deployment is one Docker command run from a home laptop.
- The analyst's own phone is the NFC and QR sensor — no readers to buy.
- Every verdict ships with its reasons, so the evidence *is* the training.
- The citizen-facing check needs no login and no app install.

A global lockdown is not an obstacle to this platform. It is its primary
deployment scenario.

---

## 3. 💰 Monetisation — built, not described

**Shipped:** `services/intel/metering.py` — per-tenant plans, quotas and
invoicing, wired into the public API and surfaced at `/admin/operations`.

A pitch can name a price. Only a running meter proves the product can charge
for what it does. Every billable API call is recorded against the tenant that
made it; the month-to-date invoice is derived from that record.

### Plan catalogue (in code, `metering.PLANS`)

| Plan | Monthly fee | Included calls | Overage | Buyer |
| :--- | :--- | :--- | :--- | :--- |
| **Citizen / Free** | ₹0 | 1,000 | Throttled, never cut off | Citizen channels, NGOs |
| **Pilot / District** | ₹0 | 25,000 | Throttled | 90-day proof of value |
| **Standard API** | ₹25,000 | 500,000 | ₹0.05/call | Banks, NBFCs, payment apps |
| **Enterprise / Sovereign** | ₹2,00,000 | Unmetered | — | State cyber cell, telecom |

### Three revenue streams, in priority order

**1. B2G sovereign licence — primary.** A state cyber cell deploys the whole
platform on its own infrastructure. During an emergency this matters twice
over: data never leaves government control, and installing it needs nobody to
travel. **₹25 lakh/year per state.**

**2. B2B fraud-check API — fastest to close.** Banks and payment apps call
`/api/v1/check` on flagged onboarding and transaction events. Two-day
integration, far shorter procurement than government. Self-service usage at
`/api/v1/usage` means an integrator can answer "what will this cost me"
without a sales call.

**3. Threat-intelligence feed — highest margin.** A daily export of verified
scam indicators — phone numbers, UPI VPAs, domains — for telecom and bank
blocklists. This sells the *data* the platform already produces, at near-zero
marginal cost.

### The revenue arithmetic, done honestly

An earlier draft claimed ₹15 crore/month from ₹0.05 × 1 crore calls/day. That
is wrong twice, and a judge with a calculator finds both.

| | Wrong | Right |
| :--- | :--- | :--- |
| Arithmetic | ₹5,00,000/day → "₹15 crore/month" | ₹5,00,000 × 30 = **₹1.5 crore/month** |
| Assumption | A bank sends its entire daily volume on day one | It sends the fraction its rules engine flags |

**Bottom-up model that survives a follow-up question:**

| Assumption | Value |
| :--- | :--- |
| Mid-size bank daily transactions | 1,00,00,000 |
| Fraction flagged for secondary screening | 0.5% |
| **Calls actually sent to us** | **50,000/day** |
| Billed at ₹0.05 | ₹2,500/day |
| **Per bank, per month** (with platform fee) | **≈ ₹1,00,000** |

Ten such customers is **₹1.2 crore/year recurring**. Unglamorous, believable,
and defensible.

### Two deliberate rules, both enforced by tests

- **A failed call is never billed.** A caller who gets a 400 has consumed
  nothing. Charging for errors destroys trust faster than any outage.
- **A free tenant over quota is never cut off.** During an emergency,
  silencing a citizen channel is a worse failure than an unpaid invoice.

The operations dashboard reads **zero on a fresh install** — no seeded MRR.
That zero is the point: it is what makes a non-zero number believable.

---

## 4. 📈 Scalability

### What is already true

- **Stateless request path.** Nothing but the database is shared; workers
  scale horizontally behind any load balancer.
- **Lazy, single-instance model loading.** Models load on first use and one
  copy serves every request in the process — which is why the container runs
  one worker and scales at the container level instead.
- **The intelligence layer is stdlib-only.** Entity graph, campaign
  clustering, indicator extraction, evidence chain, calibration, emergency
  vocabulary and metering need no ML stack at all. That half runs on every
  request at the cost of a regex.
- **Metering is per-tenant from day one**, so a noisy tenant is visible and
  rate-limitable without touching anyone else.

### Growth path

| Phase | Load | Infrastructure | Monthly cost |
| :--- | :--- | :--- | :--- |
| **Now** | < 10k scans/day | 1 container, SQLite | ₹2,000–3,000 |
| Phase 2 | 10k–100k/day | 3 nodes, PostgreSQL, Redis limiter | ₹15,000 |
| Phase 3 | 100k+/day | Autoscaled workers, text/vision split | ₹60,000 |

**The one migration that matters:** SQLite → PostgreSQL, confined to
`services/intel/db.get_db_connection()` plus the rate limiter's `storage_uri`.
Splitting the cheap text path from the expensive vision path is the second
step — text checks are ~99% of emergency-period volume and should never queue
behind a video.

### Measured, not estimated

| Metric | Value |
| :--- | :--- |
| Working set, all four stacks resident | **1.3 GB** |
| Committed memory | **3.3 GB** |
| Recommended container limit | 4 GB |
| Docker image size | 1.97 GB |

---

## 5. 🔄 Adaptability — proven by shipping one

**Shipped:** `services/intel/pandemic.py` — 27 emergency-fraud patterns in
English and Hinglish, behind a single switch, with 11 tests.

When the emergency was declared, the fraud *pretexts* changed within days:
relief funds, oxygen cylinders, vaccine slots, e-passes, quarantine fines,
work-from-home income. The *delivery* did not change at all.

So nothing in the platform had to change either:

| | |
| :--- | :--- |
| ❌ Model retrained | No |
| ❌ Database migrated | No |
| ❌ Route added | No |
| ✅ New keyword bank + one switch | Yes — shipped in an afternoon |

### Coverage of the emergency bank

| Category | Examples caught |
| :--- | :--- |
| Relief / aid disbursement | "Government has approved ₹5000 relief package", fabricated sanctions, free-ration registration |
| Medical supply | Oxygen cylinders, remdesivir, paid vaccine slots, hospital-bed brokering, forged test certificates |
| Movement documents | E-pass lures, quarantine-fine extortion, curfew passes |
| Charity | Donation appeals paired with a UPI rail |
| Income replacement | Work-from-home earnings, advance-fee job scams, job-loss targeting |
| Teleconsultation & delivery | Advance-fee consults, prepaid-only essentials |

### The switch matters as much as the bank

Emergency vocabulary is **inert until an emergency is declared**
(`EMERGENCY_MODE=1`, or the toggle on `/admin/operations` and `/round2`).
Outside one, "relief fund" and "oxygen supply" appear in legitimate government
circulars, and scoring them permanently would manufacture false positives in
exactly the population we are protecting.

Tests assert both halves: nothing scores while stood down, and the score rises
once declared. The API response states which posture produced it
(`emergency_mode: true`) so two results are comparable. Every declaration is
written to the tamper-evident evidence chain, because a score that changed due
to posture must still be explainable months later.

### Other adaptation axes

- **Hardware supply shock:** QR fallback is already live and shares the exact
  analysis pipeline; NFC uses 180nm-class silicon unaffected by leading-edge
  shortages; Android HCE needs no procurement at all.
- **New language:** add to the multilingual bank — same shape, same scorer.
- **New jurisdiction:** `KIND_AUTHORITY` maps indicator types to the body that
  can act on them. Another country is a different mapping, not a new codebase.

---

## 6. ✅ Feasibility under a ninety-day gathering ban

| Constraint | Why it is not a blocker |
| :--- | :--- |
| No teams may gather | Browser-based; `docker compose up --build` from a home laptop |
| No hardware procurement | Any 4 GB Linux VM; the analyst's own phone is the NFC/QR sensor |
| Budgets frozen | ₹2,000–3,000/month at pilot scale — one Standard customer covers it |
| Offices closed | The public Citizen Quick Check replaces the physical complaint counter |
| Supply chain broken | QR fallback live; HCE needs no procurement |
| No in-person training | Every verdict ships with its reasons — the highlighted evidence *is* the training |

### Already done, not planned

| | |
| :--- | :--- |
| Detector modules | **8** (betting, deepfake, customer care, investment, voice, APK, QR/UPI, NFC) |
| Automated tests | **453 passing** |
| CI jobs on every push | 3 |
| Deepfake accuracy | **97.4%**, F1 97.4% (n=153 held-out) |
| Calibration improvement | ECE 0.0577 → **0.0260** (Platt, n=153) |
| Betting text classifier | F1 **95.5%** (5-fold CV), Hinglish + English |
| Docker image | Builds end to end; boots healthy; all four detectors reach `ready` |

**Deployment is verified, not assumed.** A pre-deployment audit found seven
blockers — a numpy pin that would have installed an untested combination, the
wrong OpenCV build silently breaking QR decoding, model weights excluded by
gitignore, the calibrator excluded by `.dockerignore` (which would have made
the app report raw scores as probabilities), an unpinned CUDA torch, a spaCy
download that failed the build, and `http://localhost:5000` baked into legal
takedown notices. All fixed; see `docs/DEPLOYMENT.md`.

---

## 7. 🛒 How we sell it — 90-day plan

| Days | Move | Deliverable | Ask |
| :--- | :--- | :--- | :--- |
| 0–15 | **Land one district** (existing GPCSSI channel). Free Pilot key. | Deployed instance, 3 analysts trained over video | Nothing. Free. |
| 15–45 | **Prove it.** Run their real backlog through it. | Weekly measured report: artefacts flagged, indicators extracted, campaigns linked, hours saved | Written feedback |
| 45–60 | **Convert.** Same numbers, now theirs. | Sovereign licence proposal | ₹25 lakh/year state licence |
| 30–60 | **Parallel: one bank.** API first, not the platform — 2-day integration. | 30-day usage report from `/api/v1/usage` | Standard plan, ₹25k/month |
| 60–90 | **Expand.** District → state; bank pilot → production. | Threat-feed sample export | Feed subscription |

**Why this order:** the district pilot costs us nothing and produces the only
asset that sells to the next buyer — *their own numbers*. The bank runs in
parallel because it has a far shorter procurement cycle and pays first.

**Why an emergency is a buying trigger, not a freeze:** cybersecurity is one of
the few line items that survives an emergency budget cut, because the emergency
itself is what drives the fraud. Two of our three streams need no hardware
procurement and no site visit.

### "Why you and not an incumbent?"

1. Every verdict shows its reasons — the words, the boxes, the calibrated
   probability. Incumbent scores are opaque.
2. Detection produces **evidence**, not an alert: hash-chained, court-ready.
3. Built India-first — Hinglish and Devanagari, UPI rails, NPCI handles,
   Indian reporting authorities — not localised after the fact.
4. Physical-world coverage: QR stickers and NFC tags, scanned from the phone
   the officer already has.

---

## 8. What shipped for Round 2

| Item | File | Verification |
| :--- | :--- | :--- |
| Emergency scam bank (27 patterns, EN + Hinglish) | `services/intel/pandemic.py` | 11 tests |
| Emergency posture switch + evidence logging | `blueprints/admin.py` | tested; chain-logged |
| Per-tenant plans, quotas, usage accounting | `services/intel/metering.py` | 10 tests |
| Self-service usage/invoice endpoint | `GET /api/v1/usage` | tested |
| Tenant provisioning + revenue dashboard | `/admin/operations` | renders; zero on fresh install |
| Business & Resilience page (all four criteria live) | `/round2` | renders |
| Billing honesty: failed calls are not billed | `blueprints/public_api.py` | asserted in tests |
| Deployment hardening (7 blockers) | `Dockerfile`, `requirements.txt`, `services/public_url.py` | image built and run |
| Post-deployment verification | `scripts/smoke_test.py` | 11 checks, 0 failures |

**Full suite: 453 passed.**

---

## 9. Live demo — 90 seconds, one page

Open **`/round2`**. Everything below happens on that single screen.

1. **Check the message** (pre-filled):
   > *"Government has approved Rs 5000 covid relief package for you. Claim your
   > relief fund now, pay processing fee to claim."*

   → Low score. *"The system does not assume 'relief fund' means fraud — in
   normal times that is a real government circular."*

2. **Declare emergency.** One toggle.

3. **Check the same message again.**

   → Score rises, with named reasons: *relief-fund disbursement lure*,
   *fabricated government sanction*. *"The message is identical. The posture
   changed. The response says `emergency_mode: true` so the two results are
   comparable."*

4. **Scroll to Monetisation** — tenants, calls, invoice, revenue. *"Reading
   zero because nothing is seeded. The day a customer arrives, that number is
   real."*

---

## 10. Prepared answers

| Question | Answer |
| :--- | :--- |
| *"Keyword matching is an old technique."* | And that is its strength here — an emergency demands speed with accuracy. Retraining takes weeks; we shipped in an afternoon. It is also not our only layer: EfficientNet for deepfakes, YOLO + OCR fusion for betting. |
| *"What about false positives?"* | That is why there is a switch. A test asserts a genuine government circular stays below 20. |
| *"Justify the revenue projection."* | Bottom-up: 0.5% flag rate, ₹1 lakh/month per bank. We claim ₹1.2 crore/year for ten customers, not ₹15 crore/month. |
| *"Did you build this for the hackathon?"* | 453 automated tests, a 3-job CI pipeline, and a CI check that **fails the build if fabricated-data markers appear**. We apply that rule to our own numbers. |
| *"Can it read bank cards over NFC?"* | No, by design. Web NFC cannot read EMV cards. We read NDEF tags — the medium scammers actually deploy. |

---

> **The line to leave them with:**
> A pandemic does not create new fraud mechanics — it creates new pretexts, at
> a speed no retraining cycle can match. We shipped the emergency pretext bank
> in an afternoon, behind a switch, with tests, without touching a model. That
> is what adaptability looks like when it is code instead of a slide.
