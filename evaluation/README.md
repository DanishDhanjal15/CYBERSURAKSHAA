# evaluation/

Measured performance for the CYBERSURAKSHAA detection modules.

```bash
python evaluation/run_all.py            # everything -> REPORT.txt
python evaluation/run_all.py --quick    # skip suites that load ML models
python evaluation/run_all.py --json     # machine-readable summary
```

Individual suites:

```bash
python evaluation/eval_extraction.py      # phone + brand extraction (exact match)
python evaluation/eval_customer_care.py   # risk scoring scenarios
python evaluation/eval_betting_text.py    # betting text classifier
python evaluation/eval_investment.py      # investment / scam classification
python evaluation/eval_deepfake.py --media-root /path/to/archive
```

## Read this first

**[RESULTS.md](RESULTS.md)** — the measured numbers, with provenance for each
dataset and explicit notes on which figures do not mean what their label
suggests. Do not quote a number from `REPORT.txt` without reading it.

**[LABELLING_GUIDE.md](LABELLING_GUIDE.md)** — how to collect and label the
data the suites are still missing.

## Files

| File | Purpose |
|---|---|
| `metrics.py` | Confusion matrix, precision/recall/F1, threshold sweeps, failure-case extraction. No third-party dependencies. |
| `eval_extraction.py` | Phone and brand extraction, exact match |
| `eval_customer_care.py` | Risk-scoring specification tests |
| `eval_betting_text.py` | Betting text classifier (synthetic cases) |
| `eval_investment.py` | Investment/scam classification on the capstone corpus |
| `eval_deepfake.py` | Deepfake video classification |
| `run_all.py` | Runs every suite, writes `REPORT.txt` |
| `datasets/` | Test data and templates |
| `REPORT.txt` | Generated output — regenerate, don't edit |

## Conventions

Positive class is always **"threat"**, so:

- **precision** — of what we flagged, how much was real. Low precision wastes
  analyst time.
- **recall** — of real threats, how many we caught. Low recall means threats
  get through.

Both are always reported together, because a detector that flags everything
has perfect recall and no value.

Every figure carries its sample size. A suite that cannot run reports **NOT
RUN** rather than being silently skipped — a module with no measured accuracy
is a finding, not a blank.
