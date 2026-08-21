# Labelling guide — building real test sets

The evaluation harness works. What it mostly lacks is **data that matches what
the tool claims to detect**. This document explains what to collect, how to
label it, and where to put it.

Read `RESULTS.md` first for why each gap matters.

---

## Priority order

| # | Dataset needed | Why it is the priority | Target size |
|---|---|---|---|
| 1 | **Indian investment-fraud messages** | The current corpus is 2000s UK SMS spam. The investment keyword bank scores **zero** on it, so the fraud-specific logic is entirely unmeasured. | 200 fraud + 200 benign |
| 2 | **Betting advertisement images** | No custom vision model exists; the image pipeline has never been measured at all. | 150 betting + 150 benign |
| 3 | **Customer-care scam screenshots** | The OCR path is untested end to end. Extraction is measured on clean text only. | 100 scam + 100 genuine |
| 4 | **Deepfake clips** | A split exists (`val_small.csv`, 153 clips) but the media is missing from this machine. Cheapest win: just restore the files. | already defined |

Item 4 needs no labelling at all — only the files. Do it first.

---

## Rules that apply to every dataset

**Never put a training example in a test set.** If a message was used to fit
a model, its score tells you the model memorised it, not that the model works.
This is not hypothetical here — see the contamination note in `RESULTS.md`.

**Balance the classes.** Roughly 50/50. An unbalanced set makes accuracy
meaningless: on a set that is 90% benign, a detector that flags nothing scores
90%.

**Collect the benign half as carefully as the fraud half.** It is tempting to
grab obvious scams and pad the rest with random text. Don't. The benign half
should contain the *hard* cases — legitimate messages that look alarming:
genuine bank alerts, real OTP messages, actual promotional offers, real
helpline posters. Those are what generate false alarms in the field, and false
alarms are what make analysts stop trusting a tool.

**Record where each item came from.** A `source` column costs nothing and
settles later arguments about provenance.

**Two labellers where the call is subjective.** For anything ambiguous, have a
second person label independently and record disagreements. The disagreement
rate is itself a useful number — it caps how well any detector can possibly do.

**Strip personal data.** These are real victims' messages. Redact names,
account numbers, and any number belonging to a victim rather than a scammer.

---

## Format

### Text datasets — CSV, UTF-8

```csv
text,is_scam,language,source,notes
"Guaranteed 30% monthly returns. Join our Telegram group",1,English,telegram_report,classic high-return lure
"Your SBI a/c XXXX debited by Rs 5000 on 12-03-25",0,English,personal_sms,genuine bank alert - hard negative
```

| column | meaning |
|---|---|
| `text` | the message, verbatim |
| `is_scam` | `1` = fraud, `0` = legitimate |
| `language` | English / Hindi / Marathi / … |
| `source` | where it came from — free text |
| `notes` | optional; especially useful on hard cases |

Save as `evaluation/datasets/investment_real.csv`, then point
`eval_investment.py`'s `DATASET` at it (or pass it in).

### Image datasets — directory + manifest

```
evaluation/datasets/betting_images/
├── manifest.csv
├── betting/     img_001.jpg …
└── benign/      img_101.jpg …
```

```csv
filename,is_betting,source,notes
betting/img_001.jpg,1,instagram_ad,1xbet logo + odds table
benign/img_101.jpg,0,news_screenshot,cricket scorecard - hard negative
```

**Hard negatives matter most here.** Include cricket scorecards, fantasy-sports
apps, genuine casino *news* articles, and photos of people holding phones. Those
are what a weak detector flags.

### Customer-care screenshots — add transcribed ground truth

```csv
filename,is_scam,brand,phone_shown,ocr_text,source
scam/img_001.jpg,1,SBI,9876543210,"SBI helpline call 9876543210 urgently",whatsapp_forward
```

`ocr_text` — what a human reads in the image — lets you measure OCR quality
separately from detection quality. When the tool gets a case wrong, that column
tells you immediately whether OCR failed or the scoring failed. Worth the extra
minute per image.

---

## Where to source data legitimately

- **Public corpora** — search for Indian SMS/UPI fraud datasets on Kaggle and
  HuggingFace. Check the licence before use.
- **Your own devices** — personal spam folders and WhatsApp forwards, with the
  owner's consent and with personal data redacted.
- **Public reporting portals** — cybercrime.gov.in and RBI/SEBI advisories
  publish example scam text.
- **Public social media** — betting ads are openly posted on Instagram and
  Telegram. Screenshot the ad, not the accounts of private individuals.
- **Your own tool** — every scan already lands in the `scans` table. Export it,
  have a human relabel each row, and you have a field-collected test set. This
  is the highest-value source you have and it is already accumulating.

Do **not** scrape private groups, and do not include content involving
identifiable private individuals.

---

## How many is enough?

At **n = 200** (100 per class), a measured 90% accuracy carries roughly a ±4%
confidence interval. That is enough to state a figure honestly.

Below **n = 50** the interval is so wide the number means very little — report
it as a smoke test, not as accuracy.

Reporting the sample size alongside every figure is not optional. "94%" invites
a follow-up question; "94% (n=320)" answers it.

---

## After collecting

```bash
python evaluation/run_all.py          # full report -> evaluation/REPORT.txt
python evaluation/run_all.py --quick  # skip the ML suites
python evaluation/run_all.py --json   # machine-readable summary
```

Then update `RESULTS.md`: the numbers, the sample sizes, the date, and — most
importantly — the failure cases. A reviewer trusts a report that documents its
own failure modes considerably more than one that reports only a headline.
