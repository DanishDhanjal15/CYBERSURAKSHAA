# The Intelligence Layer

*`services/intel/` — the correlation, evidence and enforcement layer that sits
above the five detectors.*

---

## Why it exists

The platform began as five detectors sharing a login page. Each one read an
artefact, produced a verdict and a score, wrote a row to the `scans` table, and
discarded everything else it had learned.

That "everything else" was the valuable part.

A betting poster that has been OCR'd contains a deposit UPI address and a
Telegram channel. A customer-care scam screenshot contains a mule account
number and an IFSC code. An investment fraud page contains a domain and a
WhatsApp number. These are the strings that identify the *operator*, and they
were being rendered once in the UI and thrown away.

The consequence was structural: the system could tell you that thirty
individual posters were betting content, but not that the same person made all
thirty. Enforcement works on operators, not on posters. Thirty takedown
notices against thirty images achieve almost nothing; one notice naming the
UPI ID that collects from all thirty achieves a great deal.

The intelligence layer is the answer to that gap, plus the four things that
follow from it: knowing which artefacts belong together, being able to prove
what the system concluded and when, routing a finding to the authority that
can act on it, and measuring whether the verdicts are any good.

---

## Modules

| Module | Responsibility |
|---|---|
| `indicators.py` | Extracts 14 kinds of identifier from arbitrary text |
| `graph.py` | Entity graph — entities, undirected weighted edges, sightings, cases |
| `campaigns.py` | Clusters entities into campaigns; near-duplicate creative detection |
| `actions.py` | Routes indicators to the seven Indian enforcement channels |
| `evidence.py` | Tamper-evident hash chain and public verification |
| `feedback.py` | Analyst corrections, review queue, training export |
| `calibration.py` | Platt scaling, histogram binning, ECE, abstention bands |
| `explain.py` | Grad-CAM, token attribution, OCR overlays |
| `lookalike.py` | Typosquat generation and live DNS resolution |
| `multilingual.py` | Devanagari transliteration, Hinglish scoring, deobfuscation |
| `voice.py` | Call-transcript scoring and acoustic screening |
| `apk.py` | Binary AndroidManifest parsing and APK risk scoring |
| `feeds.py` | Live threat feeds with explicit provenance |
| `ctlog.py` | Certificate Transparency — lookalike domains at issuance |
| `takedown.py` | Enforcement outcome tracking — did the notice work? |
| `resurrection.py` | Temporal detection — operators rebuilding after takedown |
| `ops.py` | Warm-up, health, readiness, impact counters |
| `db.py` | One connection policy, shared with `services/auth_db.py` |

The package imports **no Flask**. Every module runs on a bare interpreter,
which is what lets `tests/` execute in CI without downloading several
gigabytes of model weights — and means a failure anywhere in the ML stack
degrades one detector rather than taking the correlation layer down with it.

---

## Indicator extraction

`indicators.py` recognises phone numbers, UPI VPAs, bank accounts, IFSC codes,
domains, URLs, IP addresses, emails, Telegram handles, WhatsApp invites, crypto
wallets, APK signing certificates, perceptual image hashes and file hashes.

The hard part is not the patterns; it is the false positives, and each guard
below exists because the extractor got it wrong:

- **A 16-digit card number contains ten-digit substrings that look exactly like
  an Indian mobile.** `_digit_run_length()` rejects any match sitting inside a
  digit run longer than 13, which removes cards and Aadhaar numbers.
- **`help@sbi-verification-login.com` reads as the VPA `help@sbi`.** The UPI
  pattern's trailing guard is `(?![\w\-])(?!\.[a-zA-Z0-9])` — a sentence-ending
  full stop is allowed, a domain label is not. Both halves are needed: an
  earlier fix rejected the email and broke `scamguy@okhdfcbank.` at the end of
  a sentence.
- **"Your account is blocked. Call 98765-43210"** produced the phone number as
  a bank account too, because the account cue matched across the sentence
  boundary. `_deconflict()` drops a bank-account match identical to a valid
  ten-digit mobile.
- **Every scam message links to Telegram or WhatsApp.** `t.me`,
  `whatsapp.com`, `wa.me` and the URL shorteners are stoplisted as *domains*
  while the channel or handle is still extracted — the channel belongs to the
  operator, the platform does not.

Each indicator carries `raw` (what appeared, for quoting in a notice),
`normalized` (the graph join key), `confidence`, and surrounding `context`.

---

## The entity graph

Eight tables. Entities are `UNIQUE(kind, value)` and upserted atomically with a
single `INSERT … ON CONFLICT`, so two concurrent scans of the same poster
cannot race into two rows.

Edges are **undirected**: node ids are ordered before writing, so `link(A,B)`
and `link(B,A)` are one row whose weight accumulates. Two rows would double
every co-occurrence weight and make every clustering threshold meaningless.

`ingest()` extracts, upserts, records a sighting with full provenance
(which scan, which module, what verdict, what score), and links every indicator
in the artefact to every other. It is capped at
`MAX_INDICATORS_PER_ARTEFACT = 25`: an OCR dump of a spam wall can contain
hundreds of numbers, and a clique of that size is O(n²) edges and a graph
nobody can read.

`neighbourhood()` is a BFS bounded by **node count**, not depth. A single
heavily-reused number pulls in hundreds of neighbours at depth 2. The cap keeps
the highest-weight edges, drops any edge whose endpoint was trimmed, and
reports `truncated: true` rather than pretending to be complete.

---

## Campaign clustering

Union-find over the graph, restricted to identity-bearing edge kinds, with one
critical guard.

**Hub suppression.** The 1930 helpline appears in a great many scam messages —
often because the scammer quotes it to look official. Clustering through it
merges every unrelated operation into a single component, and the feature
becomes worse than useless: it reports one campaign containing everything.
`HUB_DEGREE_LIMIT = 40` excludes any indicator seen in more than forty
artefacts from acting as a merge point. It stays in the graph and stays
visible; it just cannot join two clusters.

`MIN_CAMPAIGN_SIZE = 3` — two co-occurring indicators is a coincidence.

Clustering is a **full rebuild**, not incremental. Union-find has no efficient
un-merge, so a single wrongly-merged pair would be permanent under incremental
updates; a rebuild over a graph of this size costs a second or two.

**Near-duplicate creatives** use MinHash over character shingles, after
folding digits to `#` and URLs to `<url>`. That folding is what makes the same
script with a swapped brand name and phone number group together — which is
exactly how these are actually produced.

---

## Evidence chain

```
entry_hash = SHA256( seq | timestamp | event | actor | payload_hash | prev_hash )
```

Each entry commits to its predecessor, so editing any historical entry breaks
every link after it and `verify_chain()` reports the first break. Appends are
serialised by a process lock and a `BEGIN IMMEDIATE` transaction, because two
threads reading the same head would fork the chain.

**What this proves, stated honestly.** This is tamper-*evidence*, not
tamper-*prevention*, and it is not a digital signature. An operator with write
access to the whole table could rewrite the log end to end and recompute it.
The defence is publishing `head()` somewhere the operator does not control —
once a head is published externally, no rewrite that changes anything before it
can reproduce it. `manage.py chain-head` exists for exactly that.

`/verify/<sha256>` is **unauthenticated by design**: a verification endpoint
that only the operator can call verifies nothing to anybody outside the
operator. It discloses existence, timestamp, module, verdict and chain
integrity — never the scanned content, the submitting user, or extracted
personal data. Partial hashes are rejected rather than prefix-matched, so it
cannot be walked as an enumeration oracle.

---

## Enforcement action packs

Seven channels: NCRP (cybercrime.gov.in / 1930), Sanchar Saathi–Chakshu (DoT),
the bank nodal officer and NPCI for payment rails, the domain registrar, the
hosting intermediary, the platform abuse desk, and an IT Act s.79(3)(b)
intermediary notice.

Each indicator kind maps to the authority that can actually act on it — a UPI
ID to NPCI and the sponsor bank, a phone number to DoT, a domain to the
registrar — and the pack renders a draft notice per channel with the relevant
indicators, the evidence hash and the verification URL.

**No recipient address is ever invented.** Where the correct abuse contact is
not known, the field contains
`[RESOLVE: confirm current abuse contact before dispatch]`. A notice addressed
to a plausible-looking but fictional mailbox is worse than no notice: it looks
actioned and reaches nobody. Every document is labelled a draft requiring an
authorised officer's signature.

---

## Calibration and abstention

`assess()` turns a raw detector score into a band — SAFE, INSUFFICIENT
EVIDENCE, THREAT — and reports `calibrated: true|false`.

When false, the percentage on screen is a raw model output and **the UI says
so**. This matters more than it sounds: a detector showing "94% confidence"
without that caveat is claiming a rigour it does not have, and an analyst
acting on it is acting on a number nobody ever checked against a labelled set.

The abstention band exists so the system can decline. "The score is 52, I am
not classifying this, route it to a human" is a better output than a coin flip
dressed as a verdict.

Two implementation notes worth recording:

- **Platt scaling is fitted by Newton–Raphson**, using the exact 2×2 Hessian
  with a ridge term. The first implementation used gradient descent at lr=0.1
  for 200 iterations, did not converge, and *raised* ECE from 0.055 to 0.198 —
  it was adopted silently because nothing measured it.
- `reliability_report()` now returns `improved`, and both the CLI and the API
  **refuse to save a calibrator that does not reduce ECE**.

For the noisy-OR fusion output, histogram binning is the right family and
reaches ECE ≈ 0.

---

## The feedback loop

Nothing in the original system could answer *how often is it wrong, and wrong
in which direction*, because no correction was ever recorded.

An analyst marks a verdict from the results panel: right, false positive,
missed a real threat, or cannot tell. That lands in a review queue as
**one person's opinion**. A *different* analyst confirms it — enforced
server-side; a correction cannot be confirmed by its author — and only then
does it count as a label, enter the confusion matrix, or reach the training
export.

Rates are computed but marked `reportable: false` until a module has 30
confirmed reviews, and every response carries the sampling caveat: these are
rates over artefacts an analyst *chose* to review, not over all traffic, so
they must not be quoted as accuracy figures.

`calibration_samples()` reconstructs ground truth from the verdict and the
correction (`THREAT + FALSE_POSITIVE → 0`, `SAFE + FALSE_NEGATIVE → 1`) and
hands the pairs to the calibrator. That is the path by which
`calibrated: false` eventually becomes true and stops being a caveat.

---

## Citizen-facing channels

The analyst console is the wrong shape for the person actually being defrauded.
`blueprints/public_api.py` is the machine-to-machine surface behind the Chrome
extension and the Telegram bot.

- **Key-authenticated, not open.** An unauthenticated classifier is a free
  oracle: an operator tunes a creative against it until it scores clean, then
  sends the tuned version.
- **Quarantined, not ingested.** Public submissions land in
  `public_submissions` and are promoted into the graph by an analyst. Anything
  auto-ingested would let one person forge arbitrary links between any two
  identifiers, and the campaign clustering would faithfully report the fiction.
- **Bands, not percentages.** A citizen asking "is this a scam" needs
  SAFE / UNSURE / LIKELY SCAM and what to do next.
- **A failed check is never reported as clean.** Both clients say the message
  was *not* checked, rather than defaulting to reassurance.

---

## Three things that were removed

Worth recording, because each would have been found by a judge clicking twice.

1. **Fabricated dashboard baselines.** The home page added invented numbers to
   real counts. `/api/impact` now returns live database counts only, and the
   page starts at zero with a note saying so.
2. **Simulated feed data presented as live.** The threat crawler's fallback
   pool was indistinguishable from real observations. Records now carry
   explicit `[LIVE]` / `[SIMULATED]` provenance, simulated rows use `.invalid`
   URLs, and only live records reach the graph.
3. **Randomised "forensic diagnostics".** The deepfake panel showed five named
   sub-metrics — landmark consistency, temporal coherence, boundary blending,
   spectral noise, illumination vectors — computed in JavaScript from the
   single model score plus a random jitter. The network computes none of them,
   and the numbers changed between runs on the same file. The panel now shows
   the model's actual Grad-CAM attribution, with a note explaining that a
   heatmap on the background rather than the face is a reason to discard the
   result.

A CI step greps for the last one so it cannot come back.

---

## The lifecycle layer

Everything above answers *"is this artefact malicious, and who is behind it?"*.
Three further modules answer a different question: **what is this operator
doing over time?** They compose into one arc — see it born, watch it die, catch
it come back — and share one surface at `/watchtower`.

### Stage 1 — appearing: `ctlog.py`

`lookalike.py` works backwards. It enumerates the permutation space around a
brand and DNS-probes the results, which finds only what it thought to guess.

Certificate Transparency inverts that. Every publicly-trusted TLS certificate
is published to append-only public logs, because browsers reject certificates
that are not. A phishing kit needs HTTPS — a browser warning kills the campaign
before it starts — so CT is a near-complete register of every domain someone
provisioned for the purpose. `sbi-verify-kyc.com` appears at issuance, which is
typically hours to days before the first message goes out.

**Two sources, answering two different questions.** They are not fallbacks for
each other:

| Source | Query shape | Answers |
|---|---|---|
| **crt.sh** | substring across all logs | *Who registered a name like ours?* The only way to discover a name nobody knew to look for. No substitute exists. |
| **Cert Spotter** | by domain, with subdomains | *What exists inside our own namespace, and did an unexpected CA issue it?* Mis-issuance and forgotten subdomains — the original reason CT exists. |

**Scoring** is a transparent weighted sum, with every weight a named constant
because these are judgement calls rather than measurements. A brand token
appearing as a whole domain label scores 45; one edit away, 35; embedded in a
longer label, 25. Phishing vocabulary adds 25, a suspicious TLD 15, multiple
hyphens 10, a free instantly-issued certificate 10.

Three guards earn their place:

- **`BRAND_ALIASES`.** `onlinesbi.sbi` is State Bank's real net-banking domain
  and scores 55 on the name alone — it is *supposed* to look like SBI. Without
  the alias list, every routine renewal on the brand's own infrastructure fires
  an alert, and an alert stream that cries wolf on the brand itself is one
  nobody reads.
- **Word-boundary matching for short tokens.** A four-character token is
  distinctive enough to match anywhere; three characters is not. But `sbi` is a
  real brand, and `sbibank.com` / `mysbi.net` are textbook squats that a length
  floor alone scores at zero. A short token counts at a word boundary — where a
  brand name goes and where random collisions do not.
- **Deterministic token order.** `hdfcbank` must be tried before its stem
  `hdfc`, or a domain containing the full name scores as though it only
  contained the stem. Iterating a set made this depend on hash ordering.

**A hit is a lead, never a verdict.** Issuance means somebody provisioned HTTPS
for a confusingly similar name, which has legitimate explanations including
defensive registration by the brand. Only observations scoring 60 or above
enter the entity graph; below that they are stored for an analyst and kept out,
or every site containing "sbi" becomes a node and drowns the thing the graph is
for.

**Source outages are surfaced, never swallowed.** This is the module's most
important property. A monitor reporting "no new observations" when its feed is
unreachable converts an outage into a false all-clear. `source_health()`
distinguishes three states — reachable, down, and *never contacted* — and the
UI banners the last two rather than showing an empty list that reads as a quiet
day. crt.sh returns 502 under load with some regularity, so this is not
hypothetical.

### Stage 2 — disappearing: `takedown.py`

`actions.py` builds a notice for every indicator and routes it to the right
authority. Then nothing. The platform could describe its own activity but never
its own effect.

That is the difference between *"41 notices generated"* — a measure of how busy
the tool was — and *"27 of those went dark, median 3.2 days"* — a measure of
whether any of it mattered.

**What can and cannot be probed** is the constraint that shapes everything, and
it is a fact about observability rather than a limitation to work around:

- `domain`, `url`, `ip` — machine-checkable by DNS and HTTP.
- `upi`, `bank_account`, `phone`, `telegram`, `apk_cert` — **not checkable**.
  No public endpoint reports whether a UPI handle was frozen, and probing
  payment rails to find out would be indistinguishable from abuse. These stay
  `UNKNOWN` until an analyst records an outcome, and are **excluded from the
  rate rather than counted as failures**.

That exclusion matters more than it sounds: payment-rail freezes are the most
effective enforcement available in India, so folding them into the denominator
would make the best channel look like the least effective one.

**A single failed probe is not a takedown.** Resolvers hiccup and networks
blip. A target is declared `DEAD` only after three consecutive failures, and a
single success resets the counter — otherwise three unrelated blips spread over
three weeks add up to a fictional takedown. HTTP 451 is called out separately,
because "unavailable for legal reasons" is a takedown *succeeding* rather than
a target vanishing.

**Filing is distinct from previewing.** `POST /intel/api/scan/<id>/actions/dispatch`
starts the clock; `GET .../actions` only renders drafts. Conflating them would
time every median from the moment an analyst glanced at a pack.

**Attribution is correlation, not causation.** Operators rotate infrastructure,
hosts suspend accounts for non-payment, registrations lapse. There is no
control group. Every metric carries that sentence, because *"66% success rate"*
is a causal claim the data cannot support while *"66% of reported targets went
dark within the window"* is exactly what was measured.

### Stage 3 — returning: `resurrection.py`

Operators do not stop when taken down. They rebuild — and what they replace
versus what they keep is dictated by cost, not preference:

| Cheap, replaced every time | Expensive, kept as long as possible |
|---|---|
| Domains, hosting, SIM cards, Telegram channels, artwork | UPI address and the mule account behind it (needs a new person with fresh KYC) · APK signing certificate (rotating it orphans every install) · crypto wallet (moving funds is visible) |

So the signature is precise and checkable: **new disposable infrastructure
attached to a durable anchor that has been seen before.**

Detection walks each durable anchor's sighting timeline for a gap of seven days
or more, then looks for neighbours whose `first_seen` falls after the gap
ended. Confidence weights anchor durability (a mule account outranks an IFSC
code) and exclusivity — an anchor seen in more than 25 artefacts is suppressed
entirely, because a payment aggregator handle spread across dozens of unrelated
artefacts is infrastructure, not identity.

One subtle bug worth recording: detection originally filtered on
`entities.sightings`, a denormalized counter maintained only by
`upsert_entity()`. Any path recording a sighting without it — the crawler, a
backfill — leaves the counter behind, and the detector was silently skipping
exactly the anchors with the most interesting history. It now counts real
`entity_sightings` rows.

`churn_profile()` produces the output an investigator acts on: which
infrastructure an operation replaces fastest, and which it holds. *"The
longest-lived indicator is the UPI address — held for a median of 37 days while
domains were replaced every few. That is where this operation is least able to
absorb pressure."*

**What it cannot tell you:** shared infrastructure produces the same signature
without a shared operator. Resold bulletproof hosting, an aggregator payment
handle, a stolen wallet reused by whoever obtained it. No alert here is an
attribution; each is a reason to examine two clusters together.

### Operating them

Both background monitors are **off by default** — they contact third-party
services and re-probe reported domains, and a developer running this locally
should opt in rather than discover it in their egress logs:

```bash
WATCHTOWER_MONITORS=1 python app.py
```

Or drive them from the CLI:

```bash
python manage.py ct-poll --brand sbi.co.in
python manage.py ct-observations --min-score 60
python manage.py takedown-sweep
python manage.py takedown-report
python manage.py resurrections
python manage.py churn --anchor 42
```
