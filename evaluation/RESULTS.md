# CYBERSURAKSHAA — Measured Performance

Generated from `python evaluation/run_all.py`.
Reproduce with the commands in each section.

This document reports what was measured, on what data, and — where it matters
most — **what was not measured**. Several figures below do not mean what their
label suggests, and those cases are called out explicitly rather than buried.

---

## Summary

| Module | Measured? | Headline | n | Data provenance |
|---|---|---|---|---|
| Customer care — phone extraction | ✅ | **100%** (33/33) | 33 | Authored, mechanical ground truth |
| Customer care — risk scoring | ✅ | **100%** (16/16) | 16 | Specification tests |
| Customer care — OCR → image path | ❌ | *unmeasured* | — | No screenshot corpus |
| Investment — classification | ⚠️ | **96.2% acc / 96.3% F1** | 320 | Real, but **wrong domain** — see §2 (Engine A only) |
| Investment — on actual investment fraud | ❌ | *unmeasured* | — | No such dataset exists |
| Betting — text classifier | ⚠️ | 87.5% acc / 88.9% F1 *(was 83.3 / 85.7)* | 24 | **Synthetic** — regression only |
| Betting — image pipeline | ❌ | *unmeasured* | — | **No vision model, no dataset** |
| Deepfake — accuracy | ❌ | *unmeasured* | 0/153 | Split defined, **media missing from all drives** |
| Deepfake — pipeline runs | ✅ | 5/5 files, no errors | 5 | Unlabelled smoke test — see §4a |

**Three of the four detection modules have no validated real-world accuracy.**
That is the honest headline, and it is more useful than a number would be.

---

## 1. Customer care — extraction and scoring ✅

```bash
python evaluation/eval_extraction.py
python evaluation/eval_customer_care.py
```

| Suite | Result |
|---|---|
| Phone extraction (must find) | **14/14** |
| Phone rejection (must not invent) | **5/5** |
| Brand detection | **14/14** |
| Risk scoring scenarios | **16/16** |

These are the most trustworthy numbers here. "Does this text contain
`1800-1080`, and did we extract `18001080`?" has one correct answer that does
not depend on anyone's opinion, so the cases can be authored without the label
becoming a judgement call.

**What these suites lock in.** They cover four formats that the extractor
previously could not represent at all — short codes (`121`), short toll-free
numbers (`1800-1080`), and landlines (`0120-4456-456`, `080-68727374`). Because
those official numbers were unextractable, a genuine Airtel / ICICI / Paytm /
PhonePe poster produced a **CRITICAL MISMATCH** against the brand's own
records. All 16 scoring scenarios now pass, including the six genuine-poster
cases that previously scored "High Risk".

The rejection suite covers the opposite failure: two of the three text
normalisation passes strip whitespace between digits across the whole document,
which turned `Order 1234 5678 90` into a "detected phone number".

**Not covered:** the image path. Extraction is measured on clean text. How
often PaddleOCR reads a real scam screenshot correctly is unmeasured, and that
is the dominant error source in production. See `LABELLING_GUIDE.md` §3.

---

## 2. Investment — the number is real, the label is wrong ⚠️

```bash
python evaluation/eval_investment.py
```

**Measured: 96.2% accuracy, 94.6% precision, 98.1% recall, F1 96.3% (n=320).**

That looks excellent. It is also close to meaningless as a claim about
investment-fraud detection, for two independent reasons.

### 2a. The corpus is SMS spam, not investment fraud

`multilingual_scams_real.csv` is the **UCI SMS Spam Collection** — UK mobile
spam from roughly 2003–2005 — with 120 of the 320 rows machine-translated into
Hindi and Marathi. Evidence from the corpus itself:

| Token | Occurrences |
|---|---|
| `£` | 81 |
| `txt`, `claim`, `prize`, `ringtone`, `freefone` | present throughout |
| `investment` | **0** |
| `crypto`, `bitcoin`, `trading`, `returns`, `ponzi` | **0** |
| `sebi`, `paytm`, `lakh`, `rupees` | **0** |

Representative "scam" row:
> *Great News! Call FREEFONE 08006344447 to claim your guaranteed £1000 CASH…*

Representative "benign" row:
> *Sorry about that this is my mates phone and i didnt write it love Kate*

This is spam-vs-personal-SMS classification. It is a legitimate task, but it is
not the task the module is named for.

### 2b. The fraud-specific logic contributes nothing on this corpus

Running the investment keyword bank alone, with both ML engines disabled:

| Configuration | Precision | Recall | F1 |
|---|---|---|---|
| Full pipeline | 94.6% | 98.1% | **96.3%** |
| Keyword rules only | 0.0% | **0.0%** | 0.0% |

The keyword baseline flags **zero of 320 rows**. Every rule in `SCAM_KEYWORDS`
— guaranteed returns, doubling claims, Ponzi references, crypto lures — matches
nothing in a 2000s UK SMS corpus. So the entire 96.3% comes from the XGBoost
model, which was itself trained to recognise SMS spam.

**Conclusion:** the module currently ships a competent **SMS spam classifier**
under an investment-fraud label. The investment-fraud rules are unmeasured and,
on the only available corpus, inert.

### 2c. Possible train/test contamination

The corpus sits in `scam-detector-capstone/data/` next to the trained model in
`scam-detector-capstone/saved_models/`. The training script did not survive —
`notebooks/ScamGuard_Core_Pipeline.ipynb` is 0 bytes — so it cannot be proven
that these rows were held out. **Treat 96.2% as an upper bound.**

### 2d. Engine B was not measured — and it is slow

The figures above are **Engine A only** (`ALLOW_HF_DOWNLOAD=0`). An attempt to
evaluate with Engine B (XLM-RoBERTa) enabled — which is the *production*
default — did not complete within a 400-second budget on CPU.

That is worth recording as an operational number in its own right: Engine B
costs on the order of **>1 second per message** on CPU. `/investment/analyze`
runs it synchronously inside the request, so under concurrent load it, not the
keyword rules, is the bottleneck.

It also compounds §2a. Engine B is `nahiar/spam-detection-xlm-roberta-v1` — a
**spam** classifier — being scored against a **spam** corpus. Whatever number
it produces would measure agreement between two spam detectors, and would say
nothing about investment fraud.

To measure it anyway, on a GPU box or with patience:

```bash
ALLOW_HF_DOWNLOAD=1 python evaluation/eval_investment.py
```

### Per-language breakdown

| Language | n | Precision | Recall | F1 |
|---|---|---|---|---|
| English | 200 | 94.3% | 99.0% | 96.6% |
| Hindi | 60 | 100.0% | 96.7% | 98.3% |
| Marathi | 60 | 90.6% | 96.7% | 93.5% |

Marathi is the weakest slice. Since the Hindi and Marathi rows are translations
of the English ones, this measures translation robustness, not genuine
multilingual coverage.

### Failure cases

Missed (scored safe, actually spam):

| Score | Text |
|---|---|
| 13 | *…it to 80488. Your 500 free text messages are valid until 31 December 2005.* |
| 23 | *बधाई! 2 मोबाइल 3जी वीडियोफोन आर आपके। अभी 09061744553 पर कॉल करें!* |

False alarms (scored scam, actually personal messages):

| Score | Text |
|---|---|
| 66 | *Baaaaabe! I misss youuuuu ! Where are you ?…* |
| 63 | *Do you know why god created gap between your fingers..?* |
| 62 | *Also sir, i sent you an email about how to log into the usc payment portal…* |

The false alarms share a signature: emotional intensity, repeated characters,
urgency. A spam model keys on those; so would a fraud model, which is why a
real Indian fraud corpus with hard negatives is the top priority.

---

## 3. Betting — text only, synthetic ⚠️ *(retrained)*

```bash
python evaluation/eval_betting_text.py
```

**Measured: 87.5% accuracy, 80.0% precision, 100% recall, F1 88.9% (n=24).**
Active strategy: TF-IDF.

### 3a. What was retrained, and why

The original classifier scored **66.7% specificity** — one benign text in three
flagged as betting. Inspecting `train_text_classifier.py` explained it exactly:
its synthetic generator drew the entire negative class from **twenty lifestyle
phrases** ("beautiful sunset at the beach", "homemade pasta recipe", "selfie
with my dog") plus one filler word.

The model had therefore never seen sports reporting, finance, corporate,
technical or regulatory language. Those texts were not being misread as
betting — they were simply *out of distribution*, and the betting class, being
the lexically richer of the two, absorbed them. Every misfire had an **empty
keyword-match list**, confirming the word-boundary matcher was innocent.

A new corpus (`danish betting/betting_detector/build_training_corpus.py`)
supplies negatives across nine domains: sports news, fantasy sports, finance,
corporate, tech, government advisories, gaming, app downloads, e-commerce,
plus deliberate lexical traps (*alphabet*, *mistake*, *spinach*, *chipset*,
*stakeholder*). 282 rows, 81 positive / 201 negative.

| Metric | Before | After |
|---|---|---|
| Accuracy | 83.3% | **87.5%** |
| Precision | 75.0% | **80.0%** |
| Recall | 100% | 100% |
| **Specificity** | **66.7%** | **75.0%** |
| F1 | 85.7% | **88.9%** |

5-fold CV F1 on the training corpus: 0.964 ± 0.034.

### 3b. Three caveats on that improvement

**It is a one-case improvement.** At n=24 a single item is worth 4.2%. False
alarms went from 4 to 3. The direction is right; the magnitude is inside the
noise.

**The test set has now been looked at twice.** Two retrain iterations were run
while observing these results — the second added app-download negatives after
the first introduced a new false alarm on *"Download the official banking app
from Google Play Store"* (the betting positives were heavy with "download our
app" phrasing). Iterating on training data while watching a test set is a soft
form of contamination. This set is no longer a clean measure and should be
replaced with collected data before the number is quoted anywhere.

**Positives were not touched.** Recall stayed at 100% across every threshold,
which on a set this small mostly means the betting examples are too easy.

### 3c. What still fails

| p | Benign text still flagged | Keywords matched |
|---|---|---|
| 0.54 | *Our pilots complete recurrent training every six months* | `[]` |
| 0.46 | *The stock market closed higher today on strong earnings* | `[]` |
| 0.43 | *India won the cricket match by 5 wickets* | `[]` |

All three sit just above the 0.40 threshold, and which ones fail **moved
between iterations** — the banking-app case appeared and then vanished, the
cricket case vanished and then returned. That instability around p≈0.45 says
the model is uncertain in that band rather than confidently wrong, which is
what 201 authored negatives buys you. Real field negatives are what would
settle it.

### 3d. The vision half is still unmeasured

Unchanged by any of the above. The fusion engine combines text with vision, and
no custom model exists at `detector/saved/betting_yolo.pt`, so YOLO falls back
to COCO — whose classes (`person`, `laptop`, `chair`) carry no betting signal
and are now excluded from scoring. **The betting image pipeline has never been
measured.**

---

## 4. Deepfake — not measured ❌

```bash
python evaluation/eval_deepfake.py --media-root /path/to/archive
```

**0 of 153 clips available.**

`dataset_split/val_small.csv` defines a proper held-out split (79 manipulated /
74 original from the DFD corpus), but every path points at `D:\archive\…`,
which does not exist on this machine. The split is a list of pointers; the media
is gone.

**The deepfake detector therefore has no measured accuracy at all.** It was
trained, a validation split was defined, and the resulting metrics were never
recorded anywhere in the repository. Any figure quoted for it today would be
unsupported.

The archive was searched for across `C:`, `D:` and `E:` — it is not on this
machine under any of `archive`, `DFD*`, `faces` or `checkpoints`.

This is the **cheapest gap to close** — no labelling required, only the files.
Restore the archive and run the command above.

### 4a. Pipeline smoke test — functional, not accuracy

```bash
python evaluation/eval_deepfake.py --smoke-test
```

Since accuracy cannot be computed, the pipeline was instead exercised against
the unlabelled media sitting in `static/uploads/` (31 files, 5 unique by size)
to answer a different question: **does the code path still work?** Two recent
fixes had never been run against real media.

```
  033cc239_ChatGPT_Image_…            ran, no face detected
  1bfcfe76_ChatGPT_Image_…            ran, no face detected
  26129fab-…-a77643662950.mp4         FAKE (95.1%) over 10 frame(s)
  4502b652_ChatGPT_Image_…            ran, no face detected
  99ac6e94_ChatGPT_Image_…            ran, no face detected

  pipeline ran without error on 5/5 file(s)
```

**What this does confirm.** The video decoded, MTCNN found faces, the
classifier scored them, and the frame sampler took exactly **10 frames** —
the `MAX_VIDEO_FRAMES_SCANNED` cap — which is the fixed frame-count path
working. Under the previous code a codec reporting a non-positive frame count
produced an empty sampling loop and reported "No face detected".

**What this does NOT confirm.** The clip is unlabelled, so "FAKE 95.1%" is a
prediction, not a correct answer. One file is not a sample. And the CUDA
`.cpu()` fix cannot be exercised here — this machine has no GPU — so it stays
verified by inspection only.

The images returning "no face detected" is expected behaviour rather than a
failure: they are generated graphics, and the module is a face-manipulation
detector.

---

## What to do next, in order

1. **Restore the deepfake media.** No labelling; one command turns an
   unmeasured module into a measured one. The pipeline is already confirmed
   working (§4a), so this is purely a file-recovery task.
2. **Collect ~400 real Indian investment-fraud messages** (200 fraud + 200
   hard negatives). This is what makes the investment module's name accurate.
   `LABELLING_GUIDE.md` explains sourcing and format.
3. **Replace the betting test set with collected examples.** The retrain in §3
   moved specificity 66.7% → 75.0%, but two iterations were run against the
   same 24 authored cases, so that set is no longer a clean measure. Real
   negatives — cricket coverage, fantasy sports, market news — would both
   improve the model further and restore an honest yardstick.
4. **Label ~300 betting ad images and train the custom YOLO model.** Until
   then the vision half of that pipeline is decorative.
5. **Re-split and retrain the investment model** on data with a genuinely
   held-out test set, so §2c stops applying.

### Done in this pass

- Betting TF-IDF retrained on a 282-row corpus with nine domains of hard
  negatives: specificity **66.7% → 75.0%**, F1 **85.7% → 88.9%** (§3).
  A contamination guard in `build_training_corpus.py` refuses to emit a corpus
  that exact- or near-matches any evaluation sentence; it caught four leaks
  while the corpus was being written.
- Deepfake pipeline verified end to end on real media (§4a). The old model is
  preserved at `models/saved/tfidf_classifier.pkl.bak` if a rollback is needed.

---

## How to read these numbers

- Every figure is quoted with its sample size. `n=24` and `n=320` do not carry
  the same weight, and the small ones should not be presented as if they do.
- "Synthetic" means the test cases were authored. Those numbers detect
  regressions; they do not establish field accuracy.
- A module marked *unmeasured* should be described that way in any writeup.
  Saying "we have not validated this yet" costs nothing; being caught claiming
  otherwise costs the credibility of everything else in the report.
