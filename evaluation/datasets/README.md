# evaluation/datasets/

Test data lives here. See `../LABELLING_GUIDE.md` for how to build it.

## What is here now

| File | Status |
|---|---|
| `investment_real_TEMPLATE.csv` | **Template only — 10 illustrative rows.** Not a test set. Shows the required columns and, importantly, what a *hard negative* looks like. Replace it with collected data. |

## What the suites currently read

| Suite | Dataset | Real data? |
|---|---|---|
| Investment | `../../scam-detector-capstone/data/multilingual_scams_real.csv` | Yes — but it is **SMS spam, not investment fraud**. See `../RESULTS.md`. |
| Deepfake | `../../deepfake detection/deepfake-detection/dataset_split/val_small.csv` | Split exists, **media files missing** |
| Customer care — extraction | authored in `../eval_extraction.py` | Mechanical ground truth, so authoring is fine |
| Customer care — scoring | authored in `../eval_customer_care.py` | Specification tests |
| Betting — text | authored in `../eval_betting_text.py` | **Synthetic** — regression suite only |
| Betting — images | *nothing* | **No dataset exists** |

## Naming convention

```
<module>_<provenance>.csv
```

`provenance` is one of:

- `real` — collected from the field, human-labelled
- `synthetic` — authored; usable for regression, **not** for accuracy claims
- `TEMPLATE` — structure example only, never evaluated against

Keeping provenance in the filename means nobody has to guess later which
numbers are quotable.
